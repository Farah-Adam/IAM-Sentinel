#!/usr/bin/env python3
"""One-command entrypoint: `python main.py` starts the dashboard on http://127.0.0.1:8000 with ./iam-small.json.

Any extra arguments are passed to the CLI, e.g. `python main.py scan iam-small.json --fail-on HIGH`.
"""
import sys

from cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["serve"]))
