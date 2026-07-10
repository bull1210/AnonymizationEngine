#!/usr/bin/env python3
"""Minimal stdlib test runner for constrained environments (no pytest).

Discovers tests/test_*.py, runs every top-level test_* callable, reports
results. With pytest installed, prefer: `pytest`.
"""
from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    passed = failed = 0
    failures: list[tuple[str, str]] = []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        sys.modules[path.stem] = mod  # keep functions picklable (multiprocessing)
        try:
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
        except Exception:
            failures.append((path.stem, traceback.format_exc()))
            failed += 1
            continue
        for name in sorted(dir(mod)):
            if not name.startswith("test_"):
                continue
            fn = getattr(mod, name)
            if not callable(fn) or getattr(fn, "is_hypothesis_test", False):
                # hypothesis-decorated tests need pytest; the randomized
                # stdlib equivalents cover the same properties here
                continue
            try:
                fn()
                passed += 1
                print(f"PASS {path.stem}::{name}")
            except Exception:
                failed += 1
                failures.append((f"{path.stem}::{name}", traceback.format_exc()))
                print(f"FAIL {path.stem}::{name}")
    print(f"\n{passed} passed, {failed} failed")
    for name, tb in failures:
        print(f"\n--- {name} ---\n{tb}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
