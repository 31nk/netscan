"""Small, quick animations that show what changed and then get out of the way: the tab highlight slides to the
new tab, the health ring sweeps to its score, the status dot pulses while work runs, and toasts slide in for
finished jobs. All of them can be switched off (Theme menu → Animations); then everything simply jumps."""

from PySide6.QtCore import QEasingCurve, QEvent, QObject, QPoint, QPropertyAnimation, QRect, QTimer, QVariantAnimation, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel

from . import theme as T

FAST, NORMAL = 160, 260  # ms: long enough to follow, short enough never to wait for
_STATE = {"on": True}


def enabled():
    return _STATE["on"]


def set_enabled(on):
    _STATE["on"] = bool(on)


class SlidingPill(QObject):
    """The selected-tab highlight as its own widget behind a QTabBar, so it can slide from tab to tab."""

    def __init__(self, tabbar, container):
        super().__init__(container)
        self.tabbar, self.container = tabbar, container
        self.pill = QFrame(container)
        self.pill.setObjectName("tabPill")
        self.pill.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.pill.lower()  # under the tab bar, whose own background is transparent
        self.anim = QPropertyAnimation(self.pill, b"geometry", self)
        self.anim.setDuration(NORMAL)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)
        tabbar.currentChanged.connect(lambda _i: self.place(animate=True))
        tabbar.installEventFilter(self)
        QTimer.singleShot(0, self.place)

    def target(self):
        i = self.tabbar.currentIndex()
        if i < 0:
            return None
        r = self.tabbar.tabRect(i)
        top_left = self.tabbar.mapTo(self.container, r.topLeft())
        return QRect(top_left, r.size()).adjusted(2, 2, -2, -2)  # the tab's margin

    def place(self, animate=False):
        goal = self.target()
        if goal is None:
            return
        self.pill.show()
        if animate and enabled() and self.pill.geometry().isValid() and self.pill.width() > 0:
            self.anim.stop()
            self.anim.setStartValue(self.pill.geometry())
            self.anim.setEndValue(goal)
            self.anim.start()
        else:
            self.anim.stop()
            self.pill.setGeometry(goal)

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Resize, QEvent.Move, QEvent.Show, QEvent.LayoutRequest, QEvent.FontChange):
            QTimer.singleShot(0, self.place)  # after the tab bar has laid itself out
        return False


def sweep(start, end, on_value, ms=NORMAL * 2):
    """Animate a number from start to end, calling on_value(v) each frame. Returns the animation (keep it)."""
    if not enabled() or start is None or end is None:
        on_value(end)
        return None
    anim = QVariantAnimation()
    anim.setStartValue(float(start))
    anim.setEndValue(float(end))
    anim.setDuration(ms)
    anim.setEasingCurve(QEasingCurve.OutCubic)
    anim.valueChanged.connect(on_value)
    anim.start()
    return anim


class Pulse(QObject):
    """A status dot that breathes between two colours while work is running."""

    def __init__(self, label):
        super().__init__(label)
        self.label = label
        self.anim = QVariantAnimation(self)
        self.anim.setDuration(1100)
        self.anim.setStartValue(0.0)
        self.anim.setKeyValueAt(0.5, 1.0)
        self.anim.setEndValue(0.0)
        self.anim.setLoopCount(-1)
        self.anim.setEasingCurve(QEasingCurve.InOutSine)
        self.anim.valueChanged.connect(self._paint)

    def _paint(self, v):
        a, b = QColor(T.ACCENT), QColor(T.DIM)
        mix = QColor(round(a.red() * (1 - v) + b.red() * v), round(a.green() * (1 - v) + b.green() * v),
                     round(a.blue() * (1 - v) + b.blue() * v))
        self.label.setStyleSheet(f"color: {mix.name()};")

    def start(self):
        if enabled():
            self.anim.start()

    def stop(self):
        self.anim.stop()


class Toast(QFrame):
    """A small notice in the bottom-right corner: slides up, stays a few seconds, slides away. Click to close.
    One at a time; a new one replaces the old."""

    MARGIN = 18

    def __init__(self, parent, bottom_offset=lambda: 0):
        super().__init__(parent)
        self.setObjectName("toast")
        self.bottom_offset = bottom_offset
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 16, 10)
        lay.setSpacing(10)
        self.dot = QLabel("●")
        self.text = QLabel("")
        self.text.setObjectName("toastText")
        self.text.setWordWrap(True)
        self.text.setMaximumWidth(360)
        lay.addWidget(self.dot, 0, Qt.AlignTop)
        lay.addWidget(self.text, 1)
        self.setCursor(Qt.PointingHandCursor)
        self.hide()
        self.anim = QPropertyAnimation(self, b"pos", self)
        self.anim.setDuration(NORMAL)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.dismiss)
        self.leaving = False
        self.anim.finished.connect(lambda: self.leaving and self.hide())

    def _spot(self):
        p = self.parentWidget()
        x = p.width() - self.width() - self.MARGIN
        y = p.height() - self.height() - self.MARGIN - self.bottom_offset()
        return QPoint(x, y)

    def show_message(self, text, level="good", seconds=3.5):
        self.text.setText(text)
        self.dot.setStyleSheet(f"color: {dict(good=T.GREEN, warn=T.AMBER, bad=T.RED).get(level, T.ACCENT)};")
        self.adjustSize()
        goal = self._spot()
        self.leaving = False
        self.anim.stop()
        self.raise_()
        if enabled() and not self.isVisible():
            self.move(goal + QPoint(0, 24))
            self.show()
            self.anim.setStartValue(self.pos())
            self.anim.setEndValue(goal)
            self.anim.start()
        else:
            self.move(goal)
            self.show()
        self.timer.start(int(seconds * 1000))

    def dismiss(self):
        if not self.isVisible():
            return
        self.timer.stop()
        if enabled():
            self.leaving = True
            self.anim.stop()
            self.anim.setStartValue(self.pos())
            self.anim.setEndValue(self.pos() + QPoint(0, 24))
            self.anim.start()
        else:
            self.hide()

    def mousePressEvent(self, _event):
        self.dismiss()

    def reposition(self):
        if self.isVisible() and not self.leaving:
            self.anim.stop()
            self.move(self._spot())
