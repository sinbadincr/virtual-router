#!/usr/bin/env python3
"""ctl-diff (SC-005): for every connected node compare the controller's intended node state
(`node state`) with the agent-owned entries read from that node's forwarder. Exit 0 only when
every connected node matches. Usage: ctl_diff.py <vrctl> <ctld.sock> <run-dir-prefix> [node...]"""
import json
import subprocess
import sys


def vrctl(vr, sock, *cmd):
    out = subprocess.run([vr, "-j", "-s", sock, *cmd], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} on {sock}: {out.stdout}{out.stderr}")
    return json.loads(out.stdout)["data"]


def paged(vr, sock, cmd, key):
    rows, off = [], 0
    while True:
        d = vrctl(vr, sock, *(cmd + (["offset", str(off)] if off else [])))
        rows += d[key]
        if d.get("next_offset") is None:
            return rows
        off = d["next_offset"]


def canon(e):
    k = e["kind"]
    f = {"vrf": ("name", "id"), "vni": ("vni", "vrf"), "node": ("name", "ip", "rmac"),
         "port": ("name", "vrf", "prefix"), "neigh": ("vrf", "ip", "mac", "port"),
         "label": ("label", "port"), "route": ("vrf", "prefix", "node", "encap", "tag")}[k]
    return (k,) + tuple(str(e[x]) for x in f)


def forwarder_state(vr, sock):
    have = set()
    for v in vrctl(vr, sock, "vrf", "show")["vrfs"]:
        if v["owner"] == "agent":
            have.add(canon({"kind": "vrf", "name": v["name"], "id": v["id"]}))
    for n in vrctl(vr, sock, "node", "show")["nodes"]:
        if n["owner"] == "agent":
            have.add(canon({"kind": "node", "name": n["name"], "ip": n["ip"], "rmac": n["rmac"]}))
    for p in vrctl(vr, sock, "port", "show")["ports"]:
        if p["owner"] == "agent":
            have.add(canon({"kind": "port", "name": p["name"], "vrf": p["vrf"], "prefix": p["ip"]}))
    for n in paged(vr, sock, ["neigh", "show"], "neighbours"):
        if n["owner"] == "agent" and n["kind"] == "static":
            have.add(canon({"kind": "neigh", "vrf": n["vrf"], "ip": n["ip"], "mac": n["mac"], "port": n["port"]}))
    for v in vrctl(vr, sock, "vrf", "show")["vrfs"]:
        if v["name"] == "default":
            continue
        for r in paged(vr, sock, ["route", "show", "vrf", v["name"]], "routes"):
            if r["owner"] == "agent" and r["origin"] == "remote":
                have.add(canon({"kind": "route", "vrf": r["vrf"], "prefix": r["prefix"], "node": r["node"],
                                "encap": r["encap"], "tag": r["tag"]}))
    t = vrctl(vr, sock, "tunnel", "show")
    for l in t["labels"]:
        if l["owner"] == "agent":
            have.add(canon({"kind": "label", "label": l["label"], "port": l["port"]}))
    for v in t["vnis"]:
        if v["owner"] == "agent":
            have.add(canon({"kind": "vni", "vni": v["vni"], "vrf": v["vrf"]}))
    return have


def main():
    vr, csock, prefix = sys.argv[1:4]
    only = sys.argv[4:]
    bad = 0
    for n in vrctl(vr, csock, "node", "show")["nodes"]:
        name = n["name"]
        if only and name not in only:
            continue
        if n["session"]["state"] in ("none", "hello", "binding"):
            continue
        want = {canon(e) for e in paged(vr, csock, ["node", "state", name], "entries")}
        have = forwarder_state(vr, f"{prefix}-{name}/minivr.sock")
        for e in sorted(want - have):
            print(f"{name}: missing in forwarder: {e}")
        for e in sorted(have - want):
            print(f"{name}: unexpected in forwarder: {e}")
        bad += bool(want ^ have)
    sys.exit(1 if bad else 0)


main()
