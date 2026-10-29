"""Entry point: python3 -B -m pyref.examiner_package --candidates DIR --stills DIR --logs DIR --inputs DIR --out DIR."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import PackageError, build


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pyref.examiner_package",
        description="Build the examiner package for one onvif-mcp specimen (custody profile v0.1). "
                    "Not part of the verifier: the unchanged verifier runs as a subprocess.",
    )
    parser.add_argument("--candidates", required=True, type=Path, metavar="DIR", help="receipts/aar: one directory per bundle")
    parser.add_argument("--stills", required=True, type=Path, metavar="DIR", help="directory holding snap-*.jpg")
    parser.add_argument("--logs", required=True, type=Path, metavar="DIR", help="receipts: chain.jsonl here, journal/anchor here or under aar/")
    parser.add_argument("--inputs", required=True, type=Path, metavar="DIR", help="frozen inputs: specimen-facts.json, acquisition.json")
    parser.add_argument("--out", required=True, type=Path, metavar="DIR", help="output directory (must be empty or absent)")
    parser.add_argument("--camera", default="q6358", help="meta.camera of the specimen to take (default q6358)")
    args = parser.parse_args(argv)
    try:
        return build(args.candidates, args.stills, args.logs, args.inputs, args.out, args.camera)
    except PackageError as exc:
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
