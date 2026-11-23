"""Malformed and unexpected control traffic (specs/005 quickstart C14, SC-006): every case with the
reason counter it must land in. Built with fakepeer.py; the real C decoders are on the other end."""
import struct

import fakepeer as fp

NODE = "cn3"            # allowed by the intent, no agent runs for it
UL_IP, UL_MAC = "172.16.0.4", "02:00:00:ff:00:04"


def hello(node=NODE, seq=1):
    return fp.hello(seq, node, UL_IP, UL_MAC)


def hello_body(node=NODE):
    return fp.string(fp.NODE_NAME, node) + fp.attr(fp.UNDERLAY_IP, fp.ip_bytes(UL_IP)) + fp.attr(fp.RMAC, fp.mac_bytes(UL_MAC))


def _entry_in_entry():
    inner = fp.attr(fp.ENTRY_ADD, fp.u8(fp.KIND, fp.K_VRF))
    return fp.attr(fp.ENTRY_ADD, inner)


# name -> (list of byte strings to send in order, whether to HELLO/ACK first, expected counter, optional close-early)
# `pre` = messages sent before (a completed HELLO), `send` = the offending bytes.
AGENT_CASES = [
    # (name, pre_hello, send, counter, close_after_send)
    ("length_11", False, fp.message(fp.KEEPALIVE, 1, length=11), "bad-length"),
    ("length_65537", False, fp.message(fp.KEEPALIVE, 1, length=65537), "too-large"),
    ("truncated_39_of_40", False, hello()[:39], "truncated"),
    ("attr_length_3", False, fp.message(fp.HELLO, 1, b"\x00\x01\x00\x03abc\x00" + hello_body()[8:]), "attr-short"),
    ("attr_overrun", False, fp.message(fp.HELLO, 1, b"\x00\x01\x00\x40cn3\x00" + hello_body()[8:]), "attr-overrun"),
    ("rmac_5_bytes", False, fp.message(fp.HELLO, 1, fp.string(fp.NODE_NAME, NODE) + fp.attr(fp.UNDERLAY_IP, fp.ip_bytes(UL_IP)) + fp.attr(fp.RMAC, fp.mac_bytes(UL_MAC)[:5])), "attr-size"),
    ("hello_without_node_name", False, fp.message(fp.HELLO, 1, hello_body()[8:]), "attr-missing"),
    ("hello_two_node_names", False, fp.message(fp.HELLO, 1, fp.string(fp.NODE_NAME, NODE) + hello_body()), "attr-dup"),
    ("entry_nested_three_deep", False, fp.message(fp.HELLO, 1, hello_body() + _entry_in_entry()), "nest-depth"),
    ("wrong_version", False, fp.message(fp.HELLO, 1, hello_body(), version=2), "bad-version"),
    ("flags_set", False, fp.message(fp.HELLO, 1, hello_body(), flags=1), "bad-flags"),
    ("unknown_message_type", False, struct.pack(">BBHII", 1, 99, 0, 12, 1), "unknown-type"),
    ("update_from_the_agent", True, fp.update(2, 1), "unexpected"),
    ("bind_before_hello", False, fp.bind(1, [("red1", "red1")]), "unexpected"),
    ("second_hello", True, hello(seq=2), "unexpected"),
]
