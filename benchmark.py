"""Benchmark DES, 3DES and AES-128 in CBC mode and export raw CSV data."""

from __future__ import annotations

import argparse
import csv
import gc
import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from time import perf_counter_ns
from typing import Callable

from Crypto import __version__ as pycryptodome_version

from crypto_algorithms import (
    EncryptionResult,
    aes_decrypt,
    aes_encrypt,
    des_decrypt,
    des_encrypt,
    generate_3des_key,
    generate_aes_key,
    generate_des_key,
    triple_des_decrypt,
    triple_des_encrypt,
)


Encrypt = Callable[[bytes, bytes], EncryptionResult]
Decrypt = Callable[[bytes, bytes, bytes], bytes]


@dataclass(frozen=True)
class Algorithm:
    name: str
    encrypt: Encrypt
    decrypt: Decrypt
    make_key: Callable[[], bytes]


ALGORITHMS = (
    Algorithm("DES-CBC", des_encrypt, des_decrypt, generate_des_key),
    Algorithm("3DES-CBC", triple_des_encrypt, triple_des_decrypt, generate_3des_key),
    Algorithm("AES-128-CBC", aes_encrypt, aes_decrypt, generate_aes_key),
)

DEFAULT_SIZES = (1_024, 10_240, 102_400, 1_048_576, 5_242_880)
FIELDNAMES = (
    "algorithm",
    "data_size_bytes",
    "operation",
    "run",
    "time_seconds",
    "throughput_mib_per_second",
)


def measure_ns(function: Callable[[], object]) -> tuple[int, object]:
    start = perf_counter_ns()
    result = function()
    return perf_counter_ns() - start, result


def throughput_mib(size_bytes: int, elapsed_ns: int) -> float:
    return (size_bytes / (1024**2)) / (elapsed_ns / 1_000_000_000)


def benchmark_case(algorithm: Algorithm, data: bytes, runs: int, warmups: int):
    key = algorithm.make_key()

    for _ in range(warmups):
        encrypted = algorithm.encrypt(data, key)
        recovered = algorithm.decrypt(encrypted.ciphertext, key, encrypted.iv)
        if recovered != data:
            raise RuntimeError(f"warm-up correctness failed for {algorithm.name}")

    rows = []
    gc.disable()
    try:
        for run in range(1, runs + 1):
            encrypt_ns, encrypted = measure_ns(lambda: algorithm.encrypt(data, key))
            decrypt_ns, recovered = measure_ns(
                lambda: algorithm.decrypt(encrypted.ciphertext, key, encrypted.iv)
            )
            if recovered != data:
                raise RuntimeError(f"correctness failed for {algorithm.name}")

            for operation, elapsed_ns in (
                ("encrypt", encrypt_ns),
                ("decrypt", decrypt_ns),
            ):
                rows.append(
                    {
                        "algorithm": algorithm.name,
                        "data_size_bytes": len(data),
                        "operation": operation,
                        "run": run,
                        "time_seconds": f"{elapsed_ns / 1_000_000_000:.9f}",
                        "throughput_mib_per_second": f"{throughput_mib(len(data), elapsed_ns):.3f}",
                    }
                )
    finally:
        gc.enable()
    return rows


def write_environment(path: Path, runs: int, warmups: int, sizes: tuple[int, ...]) -> None:
    details = [
        f"Platform: {platform.platform()}",
        f"Processor: {platform.processor() or 'not reported'}",
        f"Python: {sys.version.split()[0]}",
        f"PyCryptodome: {pycryptodome_version}",
        f"Runs per case: {runs}",
        f"Warm-ups per case: {warmups}",
        f"Data sizes (bytes): {', '.join(map(str, sizes))}",
        "Mode: CBC with PKCS#7 padding and a fresh random IV per encryption",
        "Timer: time.perf_counter_ns()",
    ]
    path.write_text("\n".join(details) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--sizes", type=int, nargs="+", default=DEFAULT_SIZES)
    parser.add_argument("--output", type=Path, default=Path("results/performance_raw.csv"))
    args = parser.parse_args()
    if args.runs < 1 or args.warmups < 0 or any(size < 1 for size in args.sizes):
        parser.error("runs and sizes must be positive; warmups cannot be negative")

    sizes = tuple(args.sizes)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for size in sizes:
        data = os.urandom(size)  # generated outside the timed section
        for algorithm in ALGORITHMS:
            print(f"Benchmarking {algorithm.name:11} | {size:>9,} bytes")
            rows.extend(benchmark_case(algorithm, data, args.runs, args.warmups))

    with args.output.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    write_environment(args.output.parent / "environment.txt", args.runs, args.warmups, sizes)
    print(f"\nSaved {len(rows)} raw measurements to {args.output}")

    for algorithm in ALGORITHMS:
        values = [
            float(row["throughput_mib_per_second"])
            for row in rows
            if row["algorithm"] == algorithm.name and row["operation"] == "encrypt"
        ]
        print(f"Mean encryption throughput, {algorithm.name}: {mean(values):.2f} MiB/s")


if __name__ == "__main__":
    main()
