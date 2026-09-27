"""Entry point: command-line mode, the SSH password helper, or the window."""

import os
import sys

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication, QInputDialog, QLineEdit,
)

from .cli import cli_main, self_test
from .devices import app_settings, make_portable
from .theme import apply_theme
from .window import MainWindow

ICON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons", "netscan.png")


def askpass_main(prompt):
    """--askpass mode: show a password box, print the answer for ssh, exit."""
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("NetScan")
    app.setWindowIcon(QIcon(ICON))
    apply_theme(app, app_settings().value("theme", "system", type=str))
    text, ok = QInputDialog.getText(None, "NetScan: router login", prompt.strip() or "Password:",
                                    QLineEdit.Password)
    if not ok:
        return 1
    sys.stdout.write(text + "\n")
    return 0


def main():
    cli = cli_main(sys.argv[1:]) if any(a in sys.argv for a in ("--scan", "--internet", "--help", "-h")) else None
    if cli is not None:
        sys.exit(cli)
    if len(sys.argv) >= 2 and sys.argv[1] == "--askpass":
        sys.exit(askpass_main(" ".join(sys.argv[2:])))
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    if "--portable" in sys.argv:
        folder, created = make_portable()
        print(("Portable mode is on. Your devices, history and settings were copied to:\n  " if created else
               "Portable mode is already on. Everything is kept in:\n  ") + folder
              + "\nCopy this whole NetScan folder (with NetScan-data) to a USB stick or another computer and run "
                "netscan.py there.\nTo stop, move or delete the NetScan-data folder.")
        sys.exit(0)
    app = QApplication(sys.argv)
    app.setApplicationName("NetScan")
    app.setDesktopFileName("netscan")
    app.setWindowIcon(QIcon(ICON))
    apply_theme(app, app_settings().value("theme", "system", type=str))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
