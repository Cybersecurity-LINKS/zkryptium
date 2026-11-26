#!/usr/bin/env python3
"""Builds the initial fuzz corpus from the draft test vectors in ../fixture_data.

Run from the fuzz/ directory: python3 seeds/make_corpus.py
"""
import hashlib, json, pathlib, re

ROOT = pathlib.Path(__file__).resolve().parents[2] / "fixture_data"
OUT = pathlib.Path(__file__).resolve().parents[1] / "corpus"
HEX = re.compile(r"^(?:[0-9a-f]{2})+$")

def put(target, data):
    d = OUT / target
    d.mkdir(parents=True, exist_ok=True)
    (d / hashlib.sha1(data).hexdigest()).write_bytes(data)

def walk(v):
    if isinstance(v, dict):
        for x in v.values():
            yield from walk(x)
    elif isinstance(v, list):
        for x in v:
            yield from walk(x)
    elif isinstance(v, str) and HEX.match(v):
        yield bytes.fromhex(v)

DISC = {"DISCLOSE": 0, "COMMIT": 1, "HIDE": 2}

for f in ROOT.rglob("*.json"):
    j = json.loads(f.read_text())
    blobs = set(walk(j))
    for b in blobs:
        for sel in range(10):
            put("parse", bytes([sel]) + (bytes([b.count(0) % 8]) if sel == 1 else b"") + b)
        put("blind_sign", b"\x01" + b)
    if "proof" not in j or not isinstance(j["proof"], str):
        continue
    proof = bytes.fromhex(j["proof"])
    if "disclosedIndexes" in j:
        mask = sum(1 << i for i in j["disclosedIndexes"] if i < 32)
        put("proof_verify", bytes([0, 0, 0]) + mask.to_bytes(4, "little") + proof)
    if "messageDisclosures" in j:
        disc = j.get("messageDisclosures", []) + j.get("blindMessageDisclosures", [])
        disc = disc[:16]
        bits = sum(DISC[d] << (2 * i) for i, d in enumerate(disc))
        n_commit = disc.count("COMMIT")
        L = len(j.get("messageDisclosures", []))
        put("proof_verify", bytes([1, len(disc), L]) + bits.to_bytes(4, "little") + proof)
        for sel in (1,):
            put("parse", bytes([sel, n_commit]) + proof)

# A handful of serde seeds: the JSON shape of each type.
for s in ['{"BBSplus":{"A":"%s","e":"%s"}}' % ("c0" + "00" * 47, "00" * 32), '"%s"' % ("c0" + "00" * 95)]:
    put("serde", s.encode())
print("corpus written to", OUT)
