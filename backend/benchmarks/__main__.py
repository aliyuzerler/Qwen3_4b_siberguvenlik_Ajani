"""`python -m benchmarks` girişi (run_benchmark CLI'sına delege eder)."""

from __future__ import annotations

import sys

from benchmarks.run_benchmark import main

if __name__ == "__main__":
    sys.exit(main())
