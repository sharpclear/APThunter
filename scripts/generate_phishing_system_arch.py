#!/usr/bin/env python3
"""
Regenerate system_arch.svg for the impersonation-domain detection module.

The diagram source is kept in system_arch.svg. This script intentionally
copies that checked-in SVG into the requested output path so the reproducible
artifact stays byte-for-byte aligned with the reviewed diagram.
"""

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "system_arch.svg"


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate the phishing system architecture SVG.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=ROOT / "system_arch.svg",
        help="Output SVG path. Defaults to ./system_arch.svg.",
    )
    args = parser.parse_args()

    svg = SOURCE.read_text(encoding="utf-8")
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.write_text(svg, encoding="utf-8")
    print(f"wrote {output}")


if __name__ == "__main__":
    main()
