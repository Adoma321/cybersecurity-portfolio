"""
main.py — Entry point for Mini Network Scanner GUI.

Run:
    python main.py

Build .exe (Windows):
    pyinstaller --onefile --windowed --name MiniNetScanner main.py
"""

import sys
import os

# Ensure the project root is in sys.path when running as a bundled .exe
if getattr(sys, "frozen", False):
    # Running inside PyInstaller bundle
    _BASE = sys._MEIPASS  # type: ignore[attr-defined]
else:
    _BASE = os.path.dirname(os.path.abspath(__file__))

if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from utils import setup_logger

logger = setup_logger("main")


def main():
    logger.info("Starting Mini Network Scanner …")
    try:
        from gui import ScannerApp
        app = ScannerApp()
        app.mainloop()
    except ImportError as exc:
        print(f"[FATAL] Missing dependency: {exc}")
        print("Run:  pip install -r requirements.txt")
        sys.exit(1)
    except Exception as exc:
        logger.exception("Unhandled exception: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
