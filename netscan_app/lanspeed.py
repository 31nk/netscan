"""LAN speed test between two computers running NetScan (no internet involved).

One side turns on "Allow LAN speed tests" (a small listener on TCP port LAN_PORT that only accepts
connections from private addresses, only speaks this test, and switches itself off after 15 idle
minutes). The other side connects and measures download and upload for a few seconds each.
"""

import ipaddress
import os
import socket
import threading
import time

LAN_PORT = 5299
MAGIC = b"NETSCAN-LANSPEED 1 "
IDLE_OFF_SECONDS = 15 * 60


class LanSpeedServer:
    def __init__(self, on_event=None):
        self.sock = None
        self.running = False
        self.last_used = 0.0
        self.on_event = on_event or (lambda text: None)
        self.block = os.urandom(1 << 20)

    def start(self, host="0.0.0.0"):
        if self.running:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, LAN_PORT))
        s.listen(2)
        s.settimeout(1.0)
        self.sock, self.running, self.last_used = s, True, time.time()
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _serve(self):
        while self.running:
            if time.time() - self.last_used > IDLE_OFF_SECONDS:
                self.on_event("LAN speed test listener switched off after 15 idle minutes.")
                self.stop()
                break
            try:
                conn, (peer, _port) = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not ipaddress.ip_address(peer).is_private:
                conn.close()  # only computers on your own network
                continue
            self.last_used = time.time()
            threading.Thread(target=self._handle, args=(conn, peer), daemon=True).start()

    def _handle(self, conn, peer):
        with conn:
            conn.settimeout(10)
            try:
                line = b""
                while not line.endswith(b"\n") and len(line) < 64:
                    chunk = conn.recv(1)
                    if not chunk:
                        return
                    line += chunk
                if not line.startswith(MAGIC):
                    return
                mode, _, secs = line[len(MAGIC):].strip().decode().partition(" ")
                secs = min(max(int(secs or 5), 1), 15)
                if mode == "DOWN":  # we send, they measure
                    end = time.time() + secs
                    while time.time() < end:
                        conn.sendall(self.block)
                elif mode == "UP":  # they send, we count and report back
                    got, first, last = 0, None, None
                    while True:
                        data = conn.recv(1 << 20)
                        if not data:
                            break
                        now = time.time()
                        first = first or now
                        last = now
                        got += len(data)
                    conn.sendall(f"{got} {((last or 0) - (first or 0)):.4f}\n".encode())
                self.on_event(f"LAN speed test ({mode.lower()}) from {peer}")
            except (OSError, ValueError, UnicodeError):
                pass
            self.last_used = time.time()


def lan_speed_test(host, seconds=5):
    """Download then upload against another NetScan's listener: {"down", "up"} in Mbit/s."""
    block = os.urandom(1 << 20)

    def connect(mode):
        s = socket.create_connection((host, LAN_PORT), timeout=5)
        s.sendall(MAGIC + f"{mode} {seconds}\n".encode())
        return s

    with connect("DOWN") as s:
        s.settimeout(seconds + 5)
        got, t = 0, time.perf_counter()
        start = None
        while True:
            data = s.recv(1 << 20)
            if not data:
                break
            if start is None:
                start = time.perf_counter()
            got += len(data)
        down = got * 8 / max(time.perf_counter() - (start or t), 0.01) / 1e6
    with connect("UP") as s:
        s.settimeout(seconds + 10)
        end = time.perf_counter() + seconds
        while time.perf_counter() < end:
            s.sendall(block)
        s.shutdown(socket.SHUT_WR)
        reply = b""
        while not reply.endswith(b"\n"):
            chunk = s.recv(64)
            if not chunk:
                break
            reply += chunk
        got, elapsed = reply.decode().split()
        up = int(got) * 8 / max(float(elapsed), 0.01) / 1e6  # measured where it arrived
    return {"down": down, "up": up, "host": host}
