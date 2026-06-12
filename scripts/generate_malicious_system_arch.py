#!/usr/bin/env python3
"""
Regenerate malicious_system_arch.svg for the malicious-domain detection module.

The diagram source is kept in malicious_system_arch.svg. This script copies
that reviewed SVG into the requested output path, preserving the current
paper-style layout exactly.
"""

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "malicious_system_arch.svg"


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate the malicious-domain system architecture SVG.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=ROOT / "malicious_system_arch.svg",
        help="Output SVG path. Defaults to ./malicious_system_arch.svg.",
    )
    args = parser.parse_args()

    svg = SOURCE.read_text(encoding="utf-8")
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.write_text(svg, encoding="utf-8")
    print(f"wrote {output}")


if __name__ == "__main__":
    main()
