"""Entry point for the virtual-schemas engine.

Run by setup/lib/virtual-schemas.sh / .ps1 with the kit-managed Python and
-I (isolated mode: no PYTHONPATH, no user site-packages, no current
directory on the import path), so only this folder and the venv are trusted.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
