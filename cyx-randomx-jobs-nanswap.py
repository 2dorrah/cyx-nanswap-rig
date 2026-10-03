#!/usr/bin/env python3
"""CYTHANX RandomX job generator/adapter.

This module generates and validates RandomX/Monero-style Stratum jobs.
It deliberately does not reinterpret RandomX work as CYTHANX work.

A real RandomX hash requires a RandomX implementation (for example pyrx or
librandomx). The module therefore separates job generation/header preparation
from the optional native hashing backend.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import time
from dataclasses import dataclass, asdict
from typing import Any, Optional

ZERO32 = "00" * 32
RANDOMX_ALGO = "rx/0"
NANSWAP_POOL = "xmrig.nanswap.com:3333"
NANSWAP_ALGO = "rx/0"
MAX_U32 = 0xFFFFFFFF


def _hex(value: Any, name: str, sizes=(32,)) -> str:
    s = str(value).strip().lower().removeprefix("0x")
    if len(s) not in {n * 2 for n in sizes} or any(c not in "0123456789abcdef" for c in s):
        raise ValueError(f"invalid {name}: expected hexadecimal length {sizes}")
    return s


def _int(value: Any, name: str, minimum: int = 0) -> int:
    try:
        if isinstance(value, str):
            v = int(value, 0)
        else:
            v = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {name}: {value!r}") from exc
    if v < minimum:
        raise ValueError(f"invalid {name}: {v}")
    return v


def target_from_difficulty(difficulty: float) -> int:
    """Return a 256-bit pool target from a positive share difficulty."""
    if difficulty <= 0:
        raise ValueError("difficulty must be positive")
    # Bitcoin/Monero-style conventional difficulty normalization. Pools may
    # use a different scalar; explicit target from the pool always wins.
    return min((1 << 256) - 1, int(((1 << 256) - 1) / difficulty))


@dataclass(frozen=True)
class RandomXJob:
    job_id: str
    blob: str
    target: str
    height: int
    seed_hash: str = ZERO32
    algo: str = RANDOMX_ALGO
    clean_jobs: bool = True
    variant: str = "monero-stratum"

    def __post_init__(self):
        _hex(self.blob, "blob", sizes=(76, 80, 84, 88))
        _hex(self.target, "target", sizes=(4, 8, 32))
        _hex(self.seed_hash, "seed_hash", sizes=(32,))
        _int(self.height, "height")
        if not self.job_id:
            raise ValueError("job_id cannot be empty")
        if not self.algo.lower().startswith("rx"):
            raise ValueError(f"unsupported RandomX algorithm: {self.algo}")

    @property
    def target_int(self) -> int:
        # Monero-style RandomX Stratum targets are commonly compact 32-bit
        # targets. A full 256-bit target is also accepted for custom pools.
        return int(self.target, 16)

    def accepts_digest(self, digest: bytes) -> bool:
        if len(digest) != 32:
            raise ValueError("RandomX digest must be 32 bytes")
        if len(self.target) <= 8:
            # Stratum RandomX/Monero compact target compares the low-order
            # 32-bit little-endian portion of the hash.
            return int.from_bytes(digest[:4], "little") <= self.target_int
        return int.from_bytes(digest, "little") <= self.target_int

    @property
    def blob_bytes(self) -> bytes:
        return bytes.fromhex(self.blob)

    def worker_blob(self, extra_nonce: int, nonce: int) -> bytes:
        """Insert an extranonce/nonce into common Monero-style blob layouts.

        For a real pool, the pool's documented nonce offsets must be used.
        Default: last 4 bytes are nonce; preceding 4 bytes are extranonce.
        """
        b = bytearray(self.blob_bytes)
        if len(b) < 8:
            raise ValueError("RandomX blob is too short for nonce/extranonce")
        struct.pack_into("<I", b, len(b) - 8, extra_nonce & MAX_U32)
        struct.pack_into("<I", b, len(b) - 4, nonce & MAX_U32)
        return bytes(b)

    def notify_params(self) -> list[Any]:
        """Return a common Monero-style mining.notify parameter list."""
        return [self.job_id, self.blob, self.target, self.algo, self.height]


class RandomXJobGenerator:
    """Generate deterministic test jobs or parse real pool notifications."""

    def __init__(self, network: str = "randomx", chain_id: str = "RANDOMX"):
        self.network = network
        self.chain_id = chain_id
        self.sequence = 0

    def generate(
        self,
        height: int,
        previous_hash: str = ZERO32,
        target: Optional[str] = None,
        difficulty: Optional[float] = None,
        blob_size: int = 76,
        seed_hash: str = ZERO32,
        clean_jobs: bool = True,
    ) -> RandomXJob:
        height = _int(height, "height")
        previous_hash = _hex(previous_hash, "previous_hash", sizes=(32,))
        seed_hash = _hex(seed_hash, "seed_hash", sizes=(32,))
        if target is None:
            target = f"{target_from_difficulty(difficulty or 1.0):064x}"
        target = _hex(target, "target", sizes=(4, 8, 32))
        if blob_size not in (76, 80, 84, 88):
            raise ValueError("blob_size must be one of 76, 80, 84, 88 bytes")

        self.sequence += 1
        job_id = f"cyx-rx-{height:x}-{self.sequence:08x}"
        # Synthetic blob for testing. It is NOT a claim of a valid network
        # block template; a real pool must supply the canonical blob.
        header = bytearray(blob_size)
        header[0:4] = struct.pack("<I", 0x10000000)
        header[4:36] = bytes.fromhex(previous_hash)
        struct.pack_into("<I", header, 36, height)
        struct.pack_into("<I", header, 40, int(time.time()))
        digest_seed = hashlib.sha256(
            f"{self.network}|{self.chain_id}|{height}|{job_id}".encode()
        ).digest()
        header[44:76] = digest_seed[:32]
        return RandomXJob(
            job_id=job_id,
            blob=bytes(header).hex(),
            target=target,
            height=height,
            seed_hash=seed_hash,
            clean_jobs=clean_jobs,
        )

    @staticmethod
    def from_notify(params: list[Any]) -> RandomXJob:
        """Parse common RandomX/Monero Stratum notify layouts.

        Supported layouts:
          [job_id, blob, target, algo, height]
          [job_id, blob, target, algo, seed_hash, height]
          [job_id, blob, target, height]
        """
        if not isinstance(params, (list, tuple)) or len(params) < 4:
            raise ValueError("RandomX mining.notify requires at least 4 parameters")
        job_id, blob, target = str(params[0]), str(params[1]), str(params[2])
        algo = RANDOMX_ALGO
        seed_hash = ZERO32
        height = None
        for item in params[3:]:
            s = str(item)
            try:
                candidate = _int(s, "height")
                if height is None:
                    height = candidate
                    continue
            except ValueError:
                pass
            if len(s.removeprefix("0x")) == 64 and all(c in "0123456789abcdefABCDEF" for c in s.removeprefix("0x")):
                seed_hash = s.removeprefix("0x")
                continue
            if s.lower().startswith("rx"):
                algo = s
        if height is None:
            raise ValueError("RandomX notify did not contain a block height")
        return RandomXJob(job_id, blob, target, height, seed_hash, algo)


def randomx_hash(blob: bytes, seed_hash: bytes = b"") -> bytes:
    """Hash one prepared blob using an installed RandomX backend.

    Accepted backends are pyrx-style modules exposing `get_rx_hash`, or a
    `randomx` module exposing `hash`. No SHA-256 fallback is used because that
    would produce an invalid RandomX share.
    """
    try:
        import pyrx  # type: ignore
        fn = getattr(pyrx, "get_rx_hash", None)
        if fn is not None:
            return bytes(fn(blob))
    except ImportError:
        pass
    try:
        import randomx  # type: ignore
        fn = getattr(randomx, "hash", None)
        if fn is not None:
            return bytes(fn(blob, seed_hash))
    except ImportError:
        pass
    raise RuntimeError(
        "RandomX backend not installed. Install a RandomX native binding "
        "(for example pyrx/librandomx) before hashing jobs."
    )


def check_share(job: RandomXJob, digest: bytes) -> bool:
    if len(digest) != 32:
        raise ValueError("RandomX digest must be 32 bytes")
    return job.accepts_digest(digest)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate/inspect RandomX Stratum jobs for NanoSwap/XMRig")
    ap.add_argument("--height", type=int, default=1)
    ap.add_argument("--previous-hash", default=ZERO32)
    ap.add_argument("--target")
    ap.add_argument("--difficulty", type=float)
    ap.add_argument("--blob-size", type=int, default=76)
    ap.add_argument("--pool", default=NANSWAP_POOL)
    ap.add_argument("--user", help="Nano address used as the NanoSwap payout username")
    ap.add_argument("--password", default="x")
    ap.add_argument("--xmrig-config", action="store_true", help="emit an XMRig config instead of a synthetic job")
    ap.add_argument("--notify", help="JSON array containing mining.notify params")
    args = ap.parse_args()

    if args.xmrig_config:
        if not args.user:
            ap.error("--user is required with --xmrig-config")
        config = {
            "autosave": True,
            "cpu": True,
            "opencl": False,
            "cuda": False,
            "pools": [{
                "algo": "rx/0",
                "coin": "monero",
                "url": args.pool,
                "user": args.user,
                "pass": args.password,
                "keepalive": True,
                "tls": False
            }]
        }
        print(json.dumps(config, indent=2))
        return 0

    if args.notify:
        params = json.loads(args.notify)
        job = RandomXJobGenerator.from_notify(params)
    else:
        job = RandomXJobGenerator().generate(
            height=args.height,
            previous_hash=args.previous_hash,
            target=args.target,
            difficulty=args.difficulty,
            blob_size=args.blob_size,
        )
    print(json.dumps(asdict(job), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
