"""Python codec of agent <-> controller protocol v1 (specs/005-agent-controller/contracts/protocol.md).

Used by the protocol-corpus tests to play a fake agent or a fake controller, and to craft malformed
messages the C encoder would never produce. Independent of the C code on purpose: a bug shared by
both would show up as a byte-vector mismatch, not as agreement.
"""
import socket
import struct

VERSION = 1

# message types
HELLO, HELLO_ACK, REJECT, BIND, UNBIND, BIND_END, SYNC_BEGIN, UPDATE, SYNC_END, ACK, KEEPALIVE = range(1, 12)

# attribute types
NODE_NAME, UNDERLAY_IP, RMAC, KEEPALIVE_S, HOLD_S, ERR_CODE, ERR_TEXT, VERSION_SUPPORTED, GEN, ACKED_SEQ = range(1, 11)
BINDING, ENTRY_ADD, ENTRY_DEL, ERROR = 20, 21, 22, 23
KIND, NAME, ID, VNI, VRF, IP, PREFIX, MAC, PORT, LABEL, ENCAP, TAG, NODE, VMI = range(30, 44)

# entry kinds
K_VRF, K_VNI, K_NODE, K_PORT, K_NEIGH, K_LABEL, K_ROUTE = range(1, 8)
ENCAP_MPLSOUDP, ENCAP_VXLAN = 1, 2

# ERR_CODE values
(E_BAD_VERSION, E_UNKNOWN_NODE, E_DUPLICATE_SESSION, E_MALFORMED, E_UNEXPECTED, E_HOLD_EXPIRED, E_SLOW_PEER,
 E_UNKNOWN_VMI, E_PORT_IN_USE, E_ENTRY_REJECTED, E_SHUTDOWN, E_BAD_ENTRY, E_TABLE_FULL) = range(1, 14)


def ip_bytes(addr):
    return socket.inet_aton(addr)


def mac_bytes(mac):
    return bytes(int(x, 16) for x in mac.split(":"))


def attr(atype, value=b""):
    """One TLV: type, length (header + value, no padding), value, zero padding to 4."""
    total = 4 + len(value)
    pad = (-total) % 4
    return struct.pack(">HH", atype, total) + value + b"\0" * pad


def u8(atype, v):
    return attr(atype, struct.pack(">B", v))


def u16(atype, v):
    return attr(atype, struct.pack(">H", v))


def u32(atype, v):
    return attr(atype, struct.pack(">I", v))


def string(atype, s):
    return attr(atype, s.encode())


def prefix(addr, plen):
    return ip_bytes(addr) + struct.pack(">B", plen)


def message(mtype, seq, body=b"", *, version=VERSION, flags=0, length=None):
    """Header + body. `length` overrides the length field (for malformed cases)."""
    if length is None:
        length = 12 + len(body)
    return struct.pack(">BBHII", version, mtype, flags, length, seq) + body


def entry(kind, key_only=False, **f):
    """Nested ENTRY_ADD / ENTRY_DEL attribute. Fields per the 'Entry fields per KIND' table."""
    body = u8(KIND, kind)
    if kind == K_VRF:
        body += string(NAME, f["name"]) + (b"" if key_only else u8(ID, f["id"]))
    elif kind == K_VNI:
        body += u32(VNI, f["vni"]) + (b"" if key_only else string(VRF, f["vrf"]))
    elif kind == K_NODE:
        body += string(NAME, f["name"])
        if not key_only:
            body += u32(IP, struct.unpack(">I", ip_bytes(f["ip"]))[0]) + attr(RMAC, mac_bytes(f["rmac"]))
    elif kind == K_PORT:
        body += string(NAME, f["name"])
        if not key_only:
            body += string(VRF, f["vrf"]) + attr(PREFIX, prefix(f["prefix"], f["plen"]))
    elif kind == K_NEIGH:
        body += string(VRF, f["vrf"]) + u32(IP, struct.unpack(">I", ip_bytes(f["ip"]))[0])
        if not key_only:
            body += attr(MAC, mac_bytes(f["mac"])) + string(PORT, f["port"])
    elif kind == K_LABEL:
        body += u32(LABEL, f["label"])
        if not key_only:
            body += string(PORT, f["port"])
    elif kind == K_ROUTE:
        body += string(VRF, f["vrf"]) + attr(PREFIX, prefix(f["prefix"], f["plen"]))
        if not key_only:
            body += string(NODE, f["node"]) + u8(ENCAP, f["encap"]) + u32(TAG, f["tag"])
    return attr(ENTRY_DEL if key_only else ENTRY_ADD, body)


def binding(vmi, port=None):
    return attr(BINDING, string(VMI, vmi) + (string(PORT, port) if port else b""))


def error_attr(code, text="", vmi=None):
    body = b""
    if vmi:
        body += string(VMI, vmi)
    body += u16(ERR_CODE, code)
    if text:
        body += string(ERR_TEXT, text)
    return attr(ERROR, body)


# ---- ready-made messages ----

def keepalive(seq):
    return message(KEEPALIVE, seq)


def hello(seq, node, underlay_ip, rmac):
    return message(HELLO, seq, string(NODE_NAME, node) + attr(UNDERLAY_IP, ip_bytes(underlay_ip)) + attr(RMAC, mac_bytes(rmac)))


def hello_ack(seq, keepalive_s=3, hold_s=9):
    return message(HELLO_ACK, seq, u16(KEEPALIVE_S, keepalive_s) + u16(HOLD_S, hold_s))


def reject(seq, code, text, version_supported=None):
    body = u16(ERR_CODE, code) + string(ERR_TEXT, text)
    if version_supported is not None:
        body += u8(VERSION_SUPPORTED, version_supported)
    return message(REJECT, seq, body)


def bind(seq, bindings):
    return message(BIND, seq, b"".join(binding(v, p) for v, p in bindings))


def unbind(seq, vmis):
    return message(UNBIND, seq, b"".join(binding(v) for v in vmis))


def bind_end(seq):
    return message(BIND_END, seq)


def sync_begin(seq, gen):
    return message(SYNC_BEGIN, seq, u32(GEN, gen))


def sync_end(seq, gen):
    return message(SYNC_END, seq, u32(GEN, gen))


def update(seq, gen, entries=b""):
    return message(UPDATE, seq, u32(GEN, gen) + entries)


def ack(seq, acked, errors=b""):
    return message(ACK, seq, u32(ACKED_SEQ, acked) + errors)


# ---- decoding (enough to assert on what the real daemons send) ----

class Malformed(Exception):
    pass


def parse_attrs(buf):
    out = []
    i = 0
    while i < len(buf):
        if len(buf) - i < 4:
            raise Malformed("attr-short")
        t, ln = struct.unpack_from(">HH", buf, i)
        if ln < 4:
            raise Malformed("attr-short")
        if i + ln > len(buf):
            raise Malformed("attr-overrun")
        out.append((t, buf[i + 4:i + ln]))
        i += (ln + 3) & ~3
    return out


def decode(data):
    """-> (type, seq, [(attr type, value)]). Raises Malformed for structural problems."""
    if len(data) < 12:
        raise Malformed("truncated")
    ver, mtype, flags, length, seq = struct.unpack_from(">BBHII", data)
    if ver != VERSION:
        raise Malformed("bad-version")
    if flags:
        raise Malformed("bad-flags")
    if length < 12:
        raise Malformed("bad-length")
    if length > 65536:
        raise Malformed("too-large")
    if len(data) < length:
        raise Malformed("truncated")
    return mtype, seq, parse_attrs(data[12:length])


def read_message(sock, timeout=5.0):
    """Read exactly one framed message from a socket; None on orderly close."""
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 12:
        chunk = sock.recv(12 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    length = struct.unpack_from(">I", hdr, 4)[0]
    if length < 12 or length > 65536:
        raise Malformed("bad-length")
    body = b""
    while len(body) < length - 12:
        chunk = sock.recv(length - 12 - len(body))
        if not chunk:
            raise Malformed("truncated")
        body += chunk
    return hdr + body
