"""Entry point: command-line mode, the SSH password helper, or the window."""

import sys

from PySide6.QtCore import (
    QSettings,
)
from PySide6.QtWidgets import (
    QApplication, QInputDialog, QLineEdit,
)

from .cli import cli_main, self_test
from .theme import apply_theme
from .window import MainWindow


def askpass_main(prompt):
    """--askpass mode: show a password box, print the answer for ssh, exit."""
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("NetScan")
    apply_theme(app, QSettings("netscan", "netscan").value("theme", "system", type=str))
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
    app = QApplication(sys.argv)
    app.setApplicationName("NetScan")
    app.setDesktopFileName("netscan")
    apply_theme(app, QSettings("netscan", "netscan").value("theme", "system", type=str))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
