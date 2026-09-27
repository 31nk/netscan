"""Light/dark themes, the stylesheet and icons. Colours are read as theme.NAME so that switching themes live works everywhere."""

import os

from PySide6.QtCore import (
    QStandardPaths, Qt,
)
from PySide6.QtGui import (
    QColor, QFontDatabase, QGuiApplication, QPalette,
)
from PySide6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QStyleFactory, QVBoxLayout,
)


# ---- theme -----------------------------------------------------------------

THEMES = {
    # Neutral greys (no blue cast), one violet-indigo accent, and status colours soft enough to sit together.
    "dark": dict(
        BG="#0c0c0f", SURFACE="#141418", RAISED="#1b1b21", BORDER="#26262e", BORDER_HI="#363640",
        TEXT="#ececf1", MUTED="#8d8d99", DIM="#5a5a66", ACCENT="#7b73ff", ACCENT_HI="#958fff",
        GREEN="#4ccf95", AMBER="#f2b454", RED="#f47a7a",
        HOVER="#202027", PRESSED="#18181d", PRIMARY_PRESSED="#6a61f0", PRIMARY_OFF_BG="#2a2940",
        PRIMARY_OFF_FG="#7d7a9e", ALT_ROW="#16161b", ROW_LINE="#1d1d23", SCROLL="#2c2c35",
        SCROLL_HI="#3c3c47", SELECT="#2a2850", SELECT_TEXT="#ffffff"),
    "light": dict(
        BG="#f6f6f8", SURFACE="#ffffff", RAISED="#f0f0f3", BORDER="#e4e4e9", BORDER_HI="#cfcfd8",
        TEXT="#16161b", MUTED="#686874", DIM="#a7a7b3", ACCENT="#5a4ff0", ACCENT_HI="#4a3fe0",
        GREEN="#12915c", AMBER="#b8650a", RED="#d63a3a",
        HOVER="#ececf1", PRESSED="#e3e3ea", PRIMARY_PRESSED="#4a3fe0", PRIMARY_OFF_BG="#d4d1fb",
        PRIMARY_OFF_FG="#ffffff", ALT_ROW="#fafafb", ROW_LINE="#f0f0f3", SCROLL="#d2d2da",
        SCROLL_HI="#b6b6c2", SELECT="#e6e4fe", SELECT_TEXT="#16161b"),
}
THEME_MODES = ["system", "light", "dark"]
THEME = "dark"
# The current theme's colours as module globals (apply_theme() swaps them); other modules read
# them as theme.NAME, so a theme switch is seen everywhere.
(ACCENT, ACCENT_HI, ALT_ROW, AMBER, BG, BORDER, BORDER_HI, DIM, GREEN, HOVER, MUTED, PRESSED,
 PRIMARY_OFF_BG, PRIMARY_OFF_FG, PRIMARY_PRESSED, RAISED, RED, ROW_LINE, SCROLL, SCROLL_HI, SELECT,
 SELECT_TEXT, SURFACE, TEXT) = [""] * 24
globals().update(THEMES[THEME])  # BG, TEXT, ACCENT... are read at use time, so switching works live

_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">{}</svg>'
_LINE = 'fill="none" stroke="{c}" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"'


def icon_svgs():
    """SVG sources for stylesheet images and device-type icons, in the current theme's colours."""
    line = _LINE.format(c=MUTED)
    dot = f'fill="{MUTED}"'
    return {
        "check": _SVG.format('<path d="M3.5 8.5l3 3 6-7" fill="none" stroke="#ffffff" stroke-width="2.2" '
                             'stroke-linecap="round" stroke-linejoin="round"/>'),
        "chevron": _SVG.format(f'<path d="M4 6l4 4 4-4" {_LINE.format(c=MUTED).replace("1.4", "1.8")}/>'),
        "search": _SVG.format(f'<circle cx="7" cy="7" r="4.5" {line}/><path d="M10.5 10.5L14 14" {line}/>'),
        # Tools group headings
        "briefcase": _SVG.format(f'<rect x="1.8" y="4.8" width="12.4" height="8.7" rx="1.5" {line}/>'
                                 f'<path d="M5.8 4.8V3.4a1 1 0 0 1 1-1h2.4a1 1 0 0 1 1 1v1.4M1.8 8.6h12.4" {line}/>'),
        "link": _SVG.format(f'<path d="M6.8 9.2a2.9 2.9 0 0 0 4.1 0l2.2-2.2a2.9 2.9 0 0 0-4.1-4.1l-.9.9" {line}/>'
                            f'<path d="M9.2 6.8a2.9 2.9 0 0 0-4.1 0L2.9 9a2.9 2.9 0 0 0 4.1 4.1l.9-.9" {line}/>'),
        "wifi": _SVG.format(f'<path d="M1.6 6.2a9.2 9.2 0 0 1 12.8 0M3.9 8.7a5.9 5.9 0 0 1 8.2 0M6.2 11.1a2.6 2.6 0 0 1 '
                            f'3.6 0" {line}/><circle cx="8" cy="13.2" r=".9" {dot}/>'),
        "hash": _SVG.format(f'<path d="M6 2l-1.5 12M11.5 2L10 14M2.5 5.5h11.5M2 10.5h11.5" {line}/>'),
        "clock": _SVG.format(f'<circle cx="8" cy="8" r="6.2" {line}/><path d="M8 4.6V8l2.4 1.5" {line}/>'),
        # Dashboard quick actions
        "globe": _SVG.format(f'<circle cx="8" cy="8" r="6.2" {line}/><path d="M1.8 8h12.4M8 1.8c2.2 2.4 2.2 9.9 0 '
                             f'12.4M8 1.8c-2.2 2.4-2.2 9.9 0 12.4" {line}/>'),
        "gauge": _SVG.format(f'<path d="M2.2 11.5a6.2 6.2 0 1 1 11.6 0" {line}/><path d="M8 10l3-4" {line}/>'
                             f'<circle cx="8" cy="10" r="1" {dot}/>'),
        "pulse": _SVG.format(f'<path d="M1.5 8.5h3l1.8-4.5 3 9 1.8-4.5h3.4" {line}/>'),
        "shield": _SVG.format(f'<path d="M8 1.6l5.4 2v4.1c0 3.3-2.3 5.6-5.4 6.7-3.1-1.1-5.4-3.4-5.4-6.7V3.6z" {line}/>'
                              f'<path d="M5.7 8l1.6 1.6 3-3.2" {line}/>'),
        "doc": _SVG.format(f'<path d="M4 1.6h5.3L12.5 5v9.4H4z" {line}/><path d="M9.2 1.8V5h3.1M6 8.3h4.4M6 11h4.4" '
                           f'{line}/>'),
        "port": _SVG.format(f'<rect x="2" y="4" width="12" height="9" rx="1.4" {line}/>'
                            f'<path d="M5 13V10.3h1.2V8.8h3.6v1.5H11V13" {line}/>'),
        "copy": _SVG.format(f'<rect x="5" y="5" width="8.5" height="9.5" rx="1.4" {line}/>'
                            f'<path d="M3 11V3a1.4 1.4 0 0 1 1.4-1.4H10" {line}/>'),
        # theme switcher: a circle, half filled
        "theme": _SVG.format(f'<circle cx="8" cy="8" r="6" fill="none" stroke="{TEXT}" stroke-width="1.5"/>'
                             f'<path d="M8 2a6 6 0 0 1 0 12z" fill="{TEXT}"/>'),
        # device types
        "type-router": _SVG.format(f'<rect x="1.5" y="8.5" width="13" height="5" rx="1.5" {line}/>'
                                   f'<path d="M4.5 8.5L3.5 3M11.5 8.5l1-5.5" {line}/>'
                                   f'<circle cx="4.5" cy="11" r=".9" {dot}/><circle cx="7" cy="11" r=".9" {dot}/>'),
        "type-phone": _SVG.format(f'<rect x="4.5" y="1.5" width="7" height="13" rx="1.6" {line}/>'
                                  f'<path d="M7 12.3h2" {line}/>'),
        "type-computer": _SVG.format(f'<rect x="1.5" y="2.5" width="13" height="8.5" rx="1.2" {line}/>'
                                     f'<path d="M8 11v3M5 14h6" {line}/>'),
        "type-printer": _SVG.format(f'<path d="M4.5 5.5v-4h7v4" {line}/>'
                                    f'<rect x="1.5" y="5.5" width="13" height="6" rx="1.2" {line}/>'
                                    f'<path d="M4.5 9.5h7v5h-7z" {line}/>'),
        "type-media": _SVG.format(f'<rect x="1.5" y="3.5" width="13" height="8.5" rx="1.2" {line}/>'
                                  f'<path d="M5.5 14.5h5M6 1.5l2 2 2-2" {line}/>'),
        "type-pi": _SVG.format(f'<rect x="1.5" y="3.5" width="13" height="9" rx="1.2" {line}/>'
                               f'<rect x="6" y="7" width="4" height="3.5" rx=".5" {line}/>'
                               + "".join(f'<circle cx="{x}" cy="5.3" r=".6" {dot}/>' for x in (4, 6, 8, 10, 12))),
        "type-nas": _SVG.format(f'<rect x="3" y="1.5" width="10" height="13" rx="1.2" {line}/>'
                                f'<path d="M5.5 4.5h5M5.5 7h5" {line}/><circle cx="8" cy="11" r="1.1" {line}/>'),
        "type-iot": _SVG.format(f'<path d="M8 1.8a4.4 4.4 0 0 0-2.6 8V11.5h5.2V9.8A4.4 4.4 0 0 0 8 1.8z" {line}/>'
                                f'<path d="M6.2 14h3.6" {line}/>'),
        "type-unknown": _SVG.format(f'<circle cx="8" cy="8" r="6.5" {line}/>'
                                    f'<path d="M6.2 6.3a1.9 1.9 0 1 1 2.6 1.8c-.5.2-.8.6-.8 1.1v.4" {line}/>'
                                    f'<circle cx="8" cy="11.6" r=".7" {dot}/>'),
    }


STYLESHEET = """
QMainWindow, QWidget#central {{ background: {BG}; }}
QToolTip {{ background: {RAISED}; color: {TEXT}; border: 1px solid {BORDER}; padding: 6px; }}

QLabel#title {{ font-size: 17pt; font-weight: 700; }}
QLabel#subtitle, QLabel#muted {{ color: {MUTED}; }}
QLabel#cardTitle, QLabel#fieldLabel {{ color: {MUTED}; font-size: 8pt; font-weight: 700; }}
QLabel#bigName {{ font-size: 13pt; font-weight: 700; }}
QLabel#heroTitle {{ font-size: 18pt; font-weight: 700; }}
QLabel#pill {{ background: {RAISED}; border: 1px solid {BORDER}; border-radius: 11px;
               padding: 3px 11px; color: {MUTED}; }}

QFrame#card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 12px; }}
QFrame#statusbar {{ background: {SURFACE}; border-top: 1px solid {BORDER}; }}
QFrame#tile {{ background: {BG}; border: 1px solid {BORDER}; border-radius: 10px; }}
QFrame#tile[link="true"]:hover, QFrame#card[link="true"]:hover {{ border-color: {ACCENT}; }}
QLabel#tileValue {{ font-size: 16pt; font-weight: 700; }}
QLabel#tileLabel {{ color: {MUTED}; font-size: 8pt; font-weight: 700; }}
QScrollArea#plain, QScrollArea#plain > QWidget > QWidget {{ background: transparent; border: none; }}

QPushButton {{ background: {RAISED}; border: 1px solid {BORDER}; border-radius: 8px;
               padding: 7px 14px; color: {TEXT}; }}
QPushButton:hover {{ background: {HOVER}; border-color: {BORDER_HI}; }}
QPushButton:pressed {{ background: {PRESSED}; }}
QPushButton:disabled {{ color: {DIM}; background: {SURFACE}; border-color: {BORDER}; }}
QPushButton#primary {{ background: {ACCENT}; border: 1px solid {ACCENT}; color: #ffffff;
                       font-weight: 600; padding: 7px 20px; }}
QPushButton#primary:hover {{ background: {ACCENT_HI}; border-color: {ACCENT_HI}; }}
QPushButton#action {{ text-align: left; padding: 9px 12px; }}
QPushButton#searchButton {{ background: {BG}; color: {MUTED}; text-align: left; padding: 7px 12px 7px 10px;
                            min-width: 96px; }}
QPushButton#searchButton:hover {{ color: {TEXT}; border-color: {ACCENT}; }}
QPushButton#searchButton[compact="true"] {{ min-width: 36px; padding-left: 0; padding-right: 0; text-align: center; }}
QPushButton#chip {{ border-radius: 11px; padding: 3px 12px; min-height: 16px; color: {MUTED}; background: transparent; }}
QPushButton#chip:hover {{ color: {TEXT}; border-color: {ACCENT}; background: {HOVER}; }}
QPushButton#primary:pressed {{ background: {PRIMARY_PRESSED}; }}
QPushButton#primary:disabled {{ background: {PRIMARY_OFF_BG}; border-color: {PRIMARY_OFF_BG};
                                color: {PRIMARY_OFF_FG}; }}
QPushButton::menu-indicator {{ image: url("{chevron}"); width: 12px; height: 12px;
                               subcontrol-origin: padding; subcontrol-position: right center;
                               right: 8px; }}
QPushButton#menuButton {{ padding-right: 28px; }}
QPushButton#iconMenu {{ padding-left: 0; padding-right: 0; min-width: 36px; }}
QPushButton#iconMenu::menu-indicator {{ image: none; width: 0px; }}
QPushButton#helpButton {{ padding-left: 0; padding-right: 0; min-width: 36px; font-weight: 600; }}

QTextBrowser {{ background: {BG}; border: 1px solid {BORDER}; border-radius: 8px; padding: 8px; color: {TEXT}; }}
QListWidget#toolNav {{ background: transparent; border: none; outline: 0; }}
QListWidget#toolNav::item {{ padding: 8px 10px; border-radius: 8px; color: {MUTED}; }}
QListWidget#toolNav::item:hover {{ background: {HOVER}; color: {TEXT}; }}
QListWidget#toolNav::item:selected {{ background: {ACCENT}; color: #ffffff; }}
QListWidget#toolNav::item:disabled {{ background: transparent; color: {DIM}; padding-bottom: 2px; }}
QLineEdit, QComboBox, QPlainTextEdit, QSpinBox {{ background: {BG}; border: 1px solid {BORDER}; border-radius: 8px;
                        padding: 6px 10px; color: {TEXT}; selection-background-color: {ACCENT};
                        selection-color: #ffffff; }}
QLineEdit:hover, QComboBox:hover, QPlainTextEdit:hover, QSpinBox:hover {{ border-color: {BORDER_HI}; }}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QSpinBox:focus {{ border-color: {ACCENT}; }}
QLineEdit:disabled, QComboBox:disabled {{ color: {DIM}; }}
QComboBox::drop-down {{ border: none; width: 28px; }}
QComboBox::down-arrow {{ image: url("{chevron}"); width: 12px; height: 12px; }}
QComboBox QAbstractItemView {{ background: {RAISED}; border: 1px solid {BORDER}; padding: 4px;
                               outline: 0; color: {TEXT}; selection-background-color: {ACCENT};
                               selection-color: #ffffff; }}

QCheckBox {{ spacing: 8px; color: {TEXT}; }}
QCheckBox:disabled {{ color: {DIM}; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 5px;
                        border: 1px solid {BORDER_HI}; background: {BG}; }}
QCheckBox::indicator:hover {{ border-color: {ACCENT}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; image: url("{check}"); }}
QCheckBox::indicator:disabled {{ background: {SURFACE}; border-color: {BORDER}; }}
QCheckBox::indicator:checked:disabled {{ background: {PRIMARY_OFF_BG}; border-color: {PRIMARY_OFF_BG}; }}

QTableWidget {{ background: {SURFACE}; alternate-background-color: {ALT_ROW}; border: none;
                color: {TEXT}; gridline-color: transparent; outline: 0;
                selection-background-color: {SELECT}; selection-color: {SELECT_TEXT}; }}
QTableWidget::item {{ padding: 0 10px; border-bottom: 1px solid {ROW_LINE}; }}
QTableWidget::item:selected {{ background: {SELECT}; color: {SELECT_TEXT}; }}
QHeaderView {{ background: {SURFACE}; border: none; }}
QHeaderView::section {{ background: {SURFACE}; color: {MUTED}; border: none;
                        border-bottom: 1px solid {BORDER}; padding: 8px 10px;
                        font-size: 8pt; font-weight: 700; }}
QHeaderView::section:hover {{ color: {TEXT}; }}
QTableCornerButton::section {{ background: {SURFACE}; border: none; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle {{ background: {SCROLL}; border-radius: 3px; }}
QScrollBar::handle:vertical {{ min-height: 30px; }}
QScrollBar::handle:horizontal {{ min-width: 30px; }}
QScrollBar::handle:hover {{ background: {SCROLL_HI}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}

QProgressBar {{ background: {RAISED}; border: none; border-radius: 7px; color: {TEXT};
                text-align: center; font-size: 8pt; max-height: 14px; min-height: 14px; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 7px; }}

QSplitter::handle {{ background: transparent; }}

QFrame#segment {{ background: {RAISED}; border: 1px solid {BORDER}; border-radius: 11px; }}
QTabBar#pages {{ background: transparent; }}
QTabBar#pages::tab {{ background: transparent; color: {MUTED}; border: none; border-radius: 8px;
                      padding: 7px 11px; margin: 2px; font-weight: 600; }}
QTabBar#pages::tab:hover:!selected {{ color: {TEXT}; background: {HOVER}; }}
QTabBar#pages::tab:selected {{ background: transparent; color: #ffffff; }}
QFrame#tabPill {{ background: {ACCENT}; border-radius: 8px; }}
QFrame#toast {{ background: {RAISED}; border: 1px solid {BORDER_HI}; border-radius: 10px; }}
QLabel#toastText {{ color: {TEXT}; }}

QMenu {{ background: {RAISED}; border: 1px solid {BORDER}; padding: 6px; color: {TEXT}; }}
QMenu::item {{ padding: 6px 22px 6px 14px; border-radius: 6px; }}
QMenu::item:selected {{ background: {ACCENT}; color: #ffffff; }}
QMenu::item:disabled {{ color: {DIM}; }}
QMenu::separator {{ height: 1px; background: {BORDER}; margin: 5px 8px; }}
QMenu::indicator {{ width: 14px; height: 14px; }}
"""


def theme_icon_dir():
    """Write the current theme's SVGs and return their folder (one folder per theme)."""
    base = QStandardPaths.writableLocation(QStandardPaths.CacheLocation) or os.path.expanduser("~/.cache/netscan")
    folder = os.path.join(base, "theme-" + THEME)
    os.makedirs(folder, exist_ok=True)
    for name, svg in icon_svgs().items():
        path = os.path.join(folder, name + ".svg")
        try:
            with open(path) as f:
                if f.read() == svg:
                    continue
        except OSError:
            pass
        with open(path, "w") as f:
            f.write(svg)
    return folder


_ICON_DIR = {}


def icon_path(name):
    # Qt stylesheet url()s want forward slashes, even on Windows.
    if THEME not in _ICON_DIR:
        _ICON_DIR[THEME] = theme_icon_dir()
    return os.path.join(_ICON_DIR[THEME], name + ".svg").replace("\\", "/")


def system_prefers_dark():
    hints = QGuiApplication.styleHints()
    if hasattr(hints, "colorScheme"):
        scheme = hints.colorScheme()
        if scheme != Qt.ColorScheme.Unknown:
            return scheme == Qt.ColorScheme.Dark
    # Older Qt or no preference reported: guess from the platform's window colour.
    return QGuiApplication.palette().color(QPalette.Window).lightness() < 128


def apply_theme(app, mode="system"):
    """Fusion palette plus stylesheet in the chosen theme, so dialogs and menus match too.

    mode: 'system' (follow the desktop's light/dark setting), 'light' or 'dark'.
    """
    global THEME
    THEME = mode if mode in THEMES else "dark" if system_prefers_dark() else "light"
    globals().update(THEMES[THEME])
    app.setStyle(QStyleFactory.create("Fusion"))
    pal = QPalette()
    for role, color in ((QPalette.Window, BG), (QPalette.WindowText, TEXT), (QPalette.Base, SURFACE),
                        (QPalette.AlternateBase, RAISED), (QPalette.Text, TEXT),
                        (QPalette.Button, RAISED), (QPalette.ButtonText, TEXT),
                        (QPalette.ToolTipBase, RAISED), (QPalette.ToolTipText, TEXT),
                        (QPalette.Highlight, ACCENT), (QPalette.HighlightedText, "#ffffff"),
                        (QPalette.PlaceholderText, DIM), (QPalette.Link, ACCENT_HI),
                        (QPalette.Mid, BORDER), (QPalette.Dark, BG), (QPalette.Light, BORDER_HI)):
        pal.setColor(role, QColor(color))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        pal.setColor(QPalette.Disabled, role, QColor(DIM))
    app.setPalette(pal)
    app.setStyleSheet(STYLESHEET.format(**THEMES[THEME], check=icon_path("check"), chevron=icon_path("chevron")))


def mix(color, into, amount):
    """`amount` of `color` blended into `into` (0 = all `into`, 1 = all `color`), as #rrggbb."""
    a, b = QColor(color), QColor(into)
    return QColor(round(a.red() * amount + b.red() * (1 - amount)), round(a.green() * amount + b.green() * (1 - amount)),
                  round(a.blue() * amount + b.blue() * (1 - amount))).name()


def set_tone(widget, tone):
    """Mark a tile's state ("good", "warn", "bad", "accent", or "" / None for none) with a small coloured dot
    beside its name. Cards (no name label) just keep the state as a property."""
    tone = tone or ""
    if widget.property("tone") == tone:
        return
    widget.setProperty("tone", tone)
    name = widget.findChild(QLabel, "tileLabel")
    if name is None:
        return
    if name.property("plain") is None:
        name.setProperty("plain", name.text())
    color = {"good": GREEN, "warn": AMBER, "bad": RED, "accent": ACCENT}.get(tone)
    name.setText(f'<span style="color:{color}">●</span>&nbsp; {name.property("plain")}' if color
                 else name.property("plain"))


def mono_font():
    f = QFontDatabase.systemFont(QFontDatabase.FixedFont)
    f.setPointSizeF(QApplication.font().pointSizeF() * 0.95)
    return f


def make_card(title=None):
    """A rounded panel; returns (frame, vertical layout, header row or None)."""
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(10)
    header = None
    if title:
        header = QHBoxLayout()
        header.setSpacing(10)
        label = QLabel(title.upper())
        label.setObjectName("cardTitle")
        header.addWidget(label)
        layout.addLayout(header)
    return frame, layout, header
