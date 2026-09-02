#!/usr/bin/env python3
"""Run a small deterministic end-to-end performance smoke test for tzap.

This is intentionally not a throughput benchmark. It catches broken release
workflows and records operation timings without making CI depend on a noisy
machine-specific timing baseline.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path


def run(command: list[str], *, cwd: Path, timeout: float) -> tuple[float, subprocess.CompletedProcess[str]]:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    elapsed = time.perf_counter() - started
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed with exit {completed.returncode}: {' '.join(command)}\n"
            f"stdout: {completed.stdout}\n"
            f"stderr: {completed.stderr}"
        )
    return elapsed, completed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tzap", type=Path, required=True, help="path to the tzap binary")
    parser.add_argument("--max-operation-seconds", type=float, default=30.0)
    args = parser.parse_args()
    if args.max_operation_seconds <= 0:
        parser.error("--max-operation-seconds must be positive")
    tzap = args.tzap.resolve()
    if not tzap.is_file():
        parser.error(f"--tzap does not point to a file: {tzap}")

    with tempfile.TemporaryDirectory(prefix="tzap-benchmark-smoke-") as temporary:
        work = Path(temporary)
        source = work / "資料"
        nested = source / "проекты" / "مرحبا-日本語"
        nested.mkdir(parents=True)
        expected: dict[Path, bytes] = {}
        for index in range(32):
            path = nested / f"данные-{index:02d}-équipe.bin"
            payload = (f"record {index}: こんにちは世界 / Привет мир / مرحبا بالعالم\n".encode("utf-8") * (index + 1))
            path.write_bytes(payload)
            expected[path.relative_to(source)] = payload

        archive = work / "unicode-smoke.tzap"
        output = work / "restored"
        timings: dict[str, float] = {}

        timings["create"], _ = run(
            [str(tzap), "create", "--no-encryption", "--bit-rot-buffer-pct", "0", "-o", str(archive), source.name],
            cwd=work,
            timeout=args.max_operation_seconds,
        )
        timings["list"], listed = run(
            [str(tzap), "list", str(archive)],
            cwd=work,
            timeout=args.max_operation_seconds,
        )
        selected_name = f"資料/проекты/مرحبا-日本語/{next(iter(expected)).name}"
        if selected_name not in listed.stdout:
            raise RuntimeError(f"list output did not contain {selected_name!r}: {listed.stdout}")

        timings["verify"], _ = run(
            [str(tzap), "verify", str(archive)],
            cwd=work,
            timeout=args.max_operation_seconds,
        )
        timings["extract"], _ = run(
            [str(tzap), "extract", "--directory", str(output), str(archive)],
            cwd=work,
            timeout=args.max_operation_seconds,
        )

        restored_root = output / source.name
        for relative_path, payload in expected.items():
            restored = restored_root / relative_path
            if restored.read_bytes() != payload:
                raise RuntimeError(f"restored payload mismatch for {relative_path}")

        print(json.dumps({"operations_seconds": timings, "files": len(expected)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
