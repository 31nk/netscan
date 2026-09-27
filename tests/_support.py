"""Shared setup for the tests: import NetScan from this checkout, no display needed, and a throwaway
data folder and settings file so nothing touches your real device list, history or preferences."""

import atexit
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

TMP = tempfile.mkdtemp(prefix="netscan-test-")
atexit.register(shutil.rmtree, TMP, True)

from PySide6.QtCore import QSettings  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from netscan_app import devices  # noqa: E402


class _Paths:
    """Stands in for QStandardPaths inside devices.data_dir(), which every module uses for its files."""
    AppDataLocation = None

    @staticmethod
    def writableLocation(_kind):
        return os.path.join(TMP, "data")


devices.QStandardPaths = _Paths


def settings(*_args):
    return QSettings(os.path.join(TMP, "settings.ini"), QSettings.IniFormat)


def app():
    return QApplication.instance() or QApplication([])
