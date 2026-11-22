"""Codec self-test of fakepeer.py: no root, no lab. The vectors are the ones in
contracts/protocol.md and tests/unit/test_proto.c; a mismatch here means the Python or the C
codec drifted from the contract."""
import pytest

import fakepeer as fp

KEEPALIVE_7 = bytes.fromhex("010b0000 0000000c 00000007")
HELLO_CN1 = bytes.fromhex(
    "01010000 00000028 00000001"
    "00010007 636e3100"
    "00020008 ac100001"
    "0003000a 020000ff 00010000"
)


def test_keepalive_vector():
    assert fp.keepalive(7) == KEEPALIVE_7
    assert fp.decode(KEEPALIVE_7) == (fp.KEEPALIVE, 7, [])


def test_hello_vector():
    assert fp.hello(1, "cn1", "172.16.0.1", "02:00:00:ff:00:01") == HELLO_CN1
    mtype, seq, attrs = fp.decode(HELLO_CN1)
    assert (mtype, seq) == (fp.HELLO, 1)
    assert attrs[0] == (fp.NODE_NAME, b"cn1")
    assert attrs[1] == (fp.UNDERLAY_IP, bytes([172, 16, 0, 1]))


@pytest.mark.parametrize("msg,mtype", [
    (fp.hello_ack(2), fp.HELLO_ACK),
    (fp.reject(3, fp.E_BAD_VERSION, "version 2 not supported", 1), fp.REJECT),
    (fp.bind(4, [("red1", "red1"), ("blue1", "blue1")]), fp.BIND),
    (fp.unbind(5, ["red1"]), fp.UNBIND),
    (fp.bind_end(6), fp.BIND_END),
    (fp.sync_begin(7, 3), fp.SYNC_BEGIN),
    (fp.update(8, 3), fp.UPDATE),
    (fp.sync_end(9, 3), fp.SYNC_END),
    (fp.ack(10, 8, fp.error_attr(fp.E_UNKNOWN_VMI, "no such vmi", vmi="red9")), fp.ACK),
])
def test_every_message_type_round_trips(msg, mtype):
    got, _, attrs = fp.decode(msg)
    assert got == mtype
    assert isinstance(attrs, list)


def test_every_entry_kind_encodes_and_decodes():
    entries = b"".join([
        fp.entry(fp.K_VRF, name="red", id=1),
        fp.entry(fp.K_VNI, vni=100, vrf="red"),
        fp.entry(fp.K_NODE, name="cn2", ip="172.16.0.2", rmac="02:00:00:ff:00:02"),
        fp.entry(fp.K_PORT, name="red1", vrf="red", prefix="10.1.1.1", plen=24),
        fp.entry(fp.K_NEIGH, vrf="red", ip="10.1.1.11", mac="02:00:00:01:01:11", port="red1"),
        fp.entry(fp.K_LABEL, label=1011, port="red1"),
        fp.entry(fp.K_ROUTE, vrf="red", prefix="10.1.1.12", plen=32, node="cn2",
                 encap=fp.ENCAP_MPLSOUDP, tag=1012),
        fp.entry(fp.K_ROUTE, key_only=True, vrf="red", prefix="10.1.1.12", plen=32),
    ])
    _, _, attrs = fp.decode(fp.update(1, 1, entries))
    kinds = [t for t, _ in attrs]
    assert kinds.count(fp.ENTRY_ADD) == 7 and kinds.count(fp.ENTRY_DEL) == 1


def test_malformed_headers_are_named():
    with pytest.raises(fp.Malformed, match="bad-version"):
        fp.decode(fp.message(fp.KEEPALIVE, 1, version=2))
    with pytest.raises(fp.Malformed, match="bad-flags"):
        fp.decode(fp.message(fp.KEEPALIVE, 1, flags=1))
    with pytest.raises(fp.Malformed, match="bad-length"):
        fp.decode(fp.message(fp.KEEPALIVE, 1, length=11))
    with pytest.raises(fp.Malformed, match="too-large"):
        fp.decode(fp.message(fp.KEEPALIVE, 1, length=65537))
    with pytest.raises(fp.Malformed, match="truncated"):
        fp.decode(HELLO_CN1[:39])


def test_malformed_attributes_are_named():
    with pytest.raises(fp.Malformed, match="attr-short"):
        fp.decode(fp.message(fp.HELLO, 1, b"\x00\x01\x00\x03abc\x00"))
    with pytest.raises(fp.Malformed, match="attr-overrun"):
        fp.decode(fp.message(fp.HELLO, 1, b"\x00\x01\x00\x20cn1\x00"))
