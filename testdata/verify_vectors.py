#!/usr/bin/env python3
"""A second implementation of the bounded-authority digests, in another language.

This exists to answer one question a reader should ask of any specification:
is it precise enough that an implementation written from the prose gets the
same bytes? It was written from SPEC.md rather than by transliterating the Go,
and it recomputes every digest in vectors.json from the field values recorded
there.

It is not an independent audit: the same author wrote both. What it does show
is that the specification is complete enough to implement from, which a reader
can confirm by ignoring this file and writing their own.

Run:  python3 testdata/verify_vectors.py
"""
import hashlib, json, pathlib, sys

VERSION = b"bounded-authority/1"


def field(data: bytes) -> bytes:
    """A field is its length as 8 bytes big-endian, then its bytes."""
    return len(data).to_bytes(8, "big") + data


def integer(v: int) -> bytes:
    """An integer is its two's-complement value as 8 bytes big-endian."""
    return (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")


def binding_digest(b: dict) -> str:
    h = hashlib.sha256()
    h.update(field(VERSION))
    h.update(field(b["payer"].encode()))
    h.update(field(b["payee"].encode()))
    h.update(integer(b["amountMinor"]))
    h.update(integer(b["feeMinor"]))
    h.update(field(b["currency"].encode()))
    h.update(field(b["reference"].encode()))
    h.update(field(b["context"].encode()))
    return h.hexdigest()


def receipt_hash(r: dict) -> str:
    h = hashlib.sha256()
    h.update(field(VERSION))
    for value in (
        r["id"], r["reference"], r["effectId"], r["payer"], r["payee"],
        r["currency"], r["description"], r["grantId"], r["method"],
        r["binding"], r["issuedAt"],
    ):
        h.update(field(value.encode()))
    h.update(integer(r["amountMinor"]))
    h.update(integer(r["feeMinor"]))
    # Context mirrors the binding's context; empty when the receipt carries none.
    h.update(field(r.get("context", "").encode()))
    return h.hexdigest()


def main() -> int:
    path = pathlib.Path(__file__).with_name("vectors.json")
    v = json.loads(path.read_text())
    if v["version"] != VERSION.decode():
        print(f"version mismatch: {v['version']}")
        return 1

    failures = 0
    for entry in v["bindings"]:
        got = binding_digest(entry["binding"])
        ok = got == entry["digest"]
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} binding {entry['name']}")
        if not ok:
            print(f"       want {entry['digest']}\n       got  {got}")

    got = receipt_hash(v["receipt"]["receipt"])
    ok = got == v["receipt"]["contentHash"]
    failures += not ok
    print(f"  {'ok  ' if ok else 'FAIL'} receipt content hash")
    if not ok:
        print(f"       want {v['receipt']['contentHash']}\n       got  {got}")

    print(f"\n{len(v['bindings']) + 1 - failures} of {len(v['bindings']) + 1} reproduced")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
