# Agent ⇄ controller protocol, version 1

The wire protocol between `minivr-ctld` and every `minivr-agent`. It is minivr's own, small and
documented on purpose: the point of the project is to learn how a control plane talks to its
nodes (compare TF's XMPP/IF-MAP, or BGP-EVPN), so the bytes are simple enough to read in a hex
dump. Implementation: `src/proto/msg.c` (header, attributes, messages) and `src/proto/entry.c`
(the seven entry kinds); both are in the pure library `libminivr_ctrl`, with byte-vector tests
in `tests/unit/test_proto.c` and an independent Python codec in `tests/e2e_ctl/fakepeer.py`.

## Why this shape

- **Binary TLV** (netlink style): bounds-checkable, unknown attributes are skipped, so version 1
  can grow without breaking old peers. XML (XMPP) would need a parser dependency; JSON hides
  every length behind a text scanner, and the constitution wants the bounds lessons visible.
- **State, not events.** The controller sends the *desired node state* (a keyed set of entries),
  first as a full sync, then as diffs. A lost update is repaired by the next full sync, so the
  agent never has to reason about history.
- **Two classes of error.** A structurally broken message closes the session (it cannot be
  trusted); a broken *entry* inside a well-delimited message is rejected alone and reported in the
  ACK, so one bad route never costs a node its whole state.



## Transport

TCP. The controller listens on `10.98.0.254:7700` in the lab (`--listen` overrides); the agent
connects from its control interface (`--controller`, `--bind`). One session per node.

## Message header (12 bytes, big-endian)

```
 0               1               2               3
+---------------+---------------+-------------------------------+
|  version = 1  |     type      |          flags = 0            |
+---------------+---------------+-------------------------------+
|                    length (whole message, bytes)              |
+---------------------------------------------------------------+
|                           seq                                 |
+---------------------------------------------------------------+
|                attributes (length − 12 bytes) …               |
```

- `length` 12 … 65,536. Receivers read 12 bytes, validate `version`, `flags == 0` and `length`
  **before** reading the body; a body that ends early (TCP close) is `truncated`.
- `seq`: per-sender counter starting at 1, +1 per message (KEEPALIVE included). ACKs name it.
- Unknown `type` → session closed (`unknown-type`). A message that is not valid in the current
  session state → closed (`unexpected`).

## Attributes (netlink-style TLV)

```
+-------------------------------+-------------------------------+
|        attr type (u16)        |  attr length (u16, hdr+value) |
+-------------------------------+-------------------------------+
|  value (length − 4 bytes), then zero padding to a multiple of 4 |
```

Rules (each violation has the named reason in brackets):
- `length ≥ 4` [`attr-short`]; `length` must not run past the enclosing message/attribute
  [`attr-overrun`]; the padding is included in the walk but not in `length`.
- Fixed-size values must have exactly their size [`attr-size`]; strings are 1–15 bytes
  `[a-z0-9_-]`, no NUL [`attr-value`]; other value checks (prefix length ≤ 32, label 16–1,048,575,
  VNI ≤ 2^24−1, unicast MAC, enum ranges) [`attr-value`].
- Nesting depth ≤ 2 (message → entry → field) [`nest-depth`].
- **Two classes of error.** *Structural* errors (header, any attribute length/overrun/padding,
  nesting, a message-level attribute missing, duplicated or with a bad value) make the message
  undecodable: the receiver closes the session with `REJECT(malformed)` and counts the reason.
  *Entry* errors (inside one well-delimited `ENTRY_ADD`/`ENTRY_DEL`/`BINDING`: a field with a bad
  value such as `LABEL` 15 or `PREFIX` with host bits, a missing or duplicated field, an unknown
  `KIND`) reject **that entry only**: the receiver skips it, applies the rest of the message and
  reports it in the `ACK` as `ERROR(bad-entry)` with the reason in `ERR_TEXT`, counted as
  `entry-<reason>` (e.g. `entry-attr-value`). The entry's previous state is kept (spec US6 sc.4,
  FR-018).
- A mandatory attribute missing [`attr-missing`]; the same attribute twice where one is allowed
  [`attr-dup`]. Unknown attribute types are **skipped** (forward compatibility).

| Type | Name | Value |
|---|---|---|
| 1 | `NODE_NAME` | string |
| 2 | `UNDERLAY_IP` | u32 IPv4 |
| 3 | `RMAC` | 6 bytes |
| 4 | `KEEPALIVE_S` | u16 |
| 5 | `HOLD_S` | u16 |
| 6 | `ERR_CODE` | u16 (table below) |
| 7 | `ERR_TEXT` | 1–200 bytes UTF-8 |
| 8 | `VERSION_SUPPORTED` | u8 |
| 9 | `GEN` | u32 sync generation |
| 10 | `ACKED_SEQ` | u32 |
| 20 | `BINDING` | nested: `VMI`, `PORT` (`PORT` absent in UNBIND) |
| 21 | `ENTRY_ADD` | nested entry (below) — add or replace by key |
| 22 | `ENTRY_DEL` | nested entry, key fields only |
| 23 | `ERROR` | nested: `KIND`+key fields or `VMI`, `ERR_CODE`, `ERR_TEXT` |
| 30 | `KIND` | u8: 1 VRF, 2 VNI, 3 NODE, 4 PORT, 5 NEIGH, 6 LABEL, 7 ROUTE |
| 31 | `NAME` | string |
| 32 | `ID` | u8 (1–63) |
| 33 | `VNI` | u32 (≤ 2^24−1) |
| 34 | `VRF` | string |
| 35 | `IP` | u32 |
| 36 | `PREFIX` | 5 bytes: u32 address, u8 length (host bits zero) |
| 37 | `MAC` | 6 bytes |
| 38 | `PORT` | string |
| 39 | `LABEL` | u32 (16–1,048,575) |
| 40 | `ENCAP` | u8: 1 mplsoudp, 2 vxlan |
| 41 | `TAG` | u32 (label or VNI per `ENCAP`) |
| 42 | `NODE` | string |
| 43 | `VMI` | string |

Entry fields per `KIND` (key fields **bold**; `data-model.md` §3):

| KIND | Fields |
|---|---|
| VRF | **`NAME`**, `ID` |
| VNI | **`VNI`**, `VRF` |
| NODE | **`NAME`**, `IP`, `RMAC` |
| PORT | **`NAME`**, `VRF`, `PREFIX` (gateway address / subnet length) |
| NEIGH | **`VRF`**, **`IP`**, `MAC`, `PORT` |
| LABEL | **`LABEL`**, `PORT` |
| ROUTE | **`VRF`**, **`PREFIX`**, `NODE`, `ENCAP`, `TAG` |

## Messages

| Type | Name | Dir | Attributes | Valid in state |
|---|---|---|---|---|
| 1 | `HELLO` | A→C | `NODE_NAME`, `UNDERLAY_IP`, `RMAC` | first message |
| 2 | `HELLO_ACK` | C→A | `KEEPALIVE_S` (3), `HOLD_S` (9) | after HELLO |
| 3 | `REJECT` | both | `ERR_CODE`, `ERR_TEXT`, [`VERSION_SUPPORTED`] | any; sender closes after it |
| 4 | `BIND` | A→C | `BINDING`… | after HELLO_ACK |
| 5 | `UNBIND` | A→C | `BINDING`… (VMI only) | after BIND_END |
| 6 | `BIND_END` | A→C | — | once, ends the initial binding list |
| 7 | `SYNC_BEGIN` | C→A | `GEN` | after BIND_END |
| 8 | `UPDATE` | C→A | `GEN`, `ENTRY_DEL`…, `ENTRY_ADD`… (dels applied first) | after SYNC_BEGIN |
| 9 | `SYNC_END` | C→A | `GEN` | after SYNC_BEGIN |
| 10 | `ACK` | both | `ACKED_SEQ`, `ERROR`… | A acks UPDATE and SYNC_END; C acks BIND and UNBIND |
| 11 | `KEEPALIVE` | both | — | after HELLO_ACK |

## Session sequence

```
agent                                   controller
  │── HELLO(cn1, 172.16.0.1, rmac) ───────▶│ unknown node / live session / version → REJECT, close
  │◀────────────────── HELLO_ACK(3, 9) ────│
  │── BIND(red1→red1, blue1→blue1) ───────▶│ replaces cn1's bindings with the reported list
  │── BIND_END ───────────────────────────▶│
  │◀──────────────── ACK(seq of BIND, errors: unknown-vmi …)
  │◀──────────────── SYNC_BEGIN(gen 7) ────│
  │◀──────────────── UPDATE(gen 7, adds…)… │ full node state, as many entries per message as fit
  │◀──────────────── SYNC_END(gen 7) ──────│
  │── ACK(each UPDATE, SYNC_END; errors) ─▶│ agent ACKs after applying (SYNC_END: after the sweep)
  │       … steady state: BIND/UNBIND ▶, ◀ UPDATE (diffs, same gen), ACKs, KEEPALIVE every 3 s
```

- The agent applies a full sync only at `SYNC_END` with the same `GEN` (R5); `UPDATE`s with a
  `GEN` that is not the current one are `unexpected`.
- Incremental `UPDATE`s after `SYNC_END` are applied immediately and ACKed with per-entry errors.
- A node is in sync when every `UPDATE`/`SYNC_END` it was sent is ACKed with no `ERROR`.
- A `BIND` for a VMI bound to another node moves it (R14); unknown VMI → `ERROR(unknown-vmi)` in
  the ACK, binding not recorded; port name already bound on that node to another VMI →
  `ERROR(port-in-use)`.
- Hold timer: no message received for `HOLD_S` → close with `hold-expired` (counted).

## Error codes (`ERR_CODE`)

| Code | Name | Used for |
|---|---|---|
| 1 | `bad-version` | header version ≠ 1 (REJECT carries `VERSION_SUPPORTED`) |
| 2 | `unknown-node` | `NODE_NAME` not in intent |
| 3 | `duplicate-session` | node already has a live session (existing one untouched) |
| 4 | `malformed` | any decode error; `ERR_TEXT` names the reason |
| 5 | `unexpected` | message not valid in state |
| 6 | `hold-expired` | peer silent |
| 7 | `slow-peer` | send buffer > 1 MiB |
| 8 | `unknown-vmi` | BIND of an undefined VMI |
| 9 | `port-in-use` | BIND of a port already bound to another VMI on the node |
| 10 | `entry-rejected` | forwarder refused an entry; `ERR_TEXT` = forwarder `code: message` |
| 11 | `shutdown` | orderly stop |
| 12 | `bad-entry` | one entry failed entry-level validation (ACK only; session stays up) |
| 13 | `table-full` | BIND would exceed 16 bound VMIs on the node (ACK only) |

Protocol error counters (shown by both CLIs), one per reason: `truncated`, `bad-version`,
`bad-flags`, `bad-length`, `too-large`, `unknown-type`, `unexpected`, `attr-short`,
`attr-overrun`, `attr-size`, `attr-value`, `attr-missing`, `attr-dup`, `nest-depth`,
`hold-expired`; and entry-level counters `entry-attr-value`, `entry-attr-missing`,
`entry-attr-dup`, `entry-unknown-kind`.

## Known-good byte vectors (also in `tests/unit/test_proto.c`)

`KEEPALIVE`, seq 7:
```
01 0b 00 00  00 00 00 0c  00 00 00 07
```

`HELLO` from cn1 (seq 1, underlay 172.16.0.1, rmac 02:00:00:ff:00:01):
```
01 01 00 00  00 00 00 28  00 00 00 01      header, length 40
00 01 00 07  63 6e 31 00                   NODE_NAME "cn1" + 1 pad
00 02 00 08  ac 10 00 01                   UNDERLAY_IP
00 03 00 0a  02 00 00 ff 00 01 00 00       RMAC + 2 pad
```

Malformed examples (each its own test): length field 11; length 65,537; length 40 with 39 bytes
then close; `NODE_NAME` attr length 3; attr length running 1 byte past the message; `RMAC` of 5
bytes; HELLO without `NODE_NAME`; two `NODE_NAME`s; `UPDATE` before `SYNC_BEGIN`; `ENTRY_ADD`
nested 3 deep (all structural: session closed). Entry-level (session stays up, `bad-entry` in the
ACK, other entries applied): `PREFIX` with host bits set; `LABEL` 15; ROUTE without `NODE`;
`KIND` 9.

## Security

None in version 1: the control network is trusted (FR-023). Known gaps, documented: no
authentication of node identity beyond its name, no encryption, a node can claim any defined VMI.
