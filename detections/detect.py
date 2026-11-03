#!/usr/bin/env python3
"""Entry point: python3 detections/detect.py watch|rules|eval ..."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aegis_detect.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())