"""NetScan's packet capture helper: captures on one network interface and writes a pcap stream to stdout.

It runs on its own (no NetScan imports), because on Linux it runs as root after the password prompt and
should be small enough to read in a minute. It only reads packets; it never sends any. It stops when NetScan
closes its end of the pipe (or after MAX_SECONDS as a safety net).

Frames are trimmed to TRIM bytes, which keeps every header, except ones NetScan reads in full: switch
announcements (LLDP, CDP), ARP, DNS, DHCP, mDNS and NetBIOS.

    python3 capture_helper.py IFACE            (Linux: AF_PACKET; Windows: Npcap's wpcap.dll)
"""

import os
import struct
import sys
import threading
import time

TRIM, FULL = 128, 1600
MAX_SECONDS = 4 * 3600
FULL_UDP_PORTS = {53, 67, 68, 137, 138, 5353, 5355, 1900}


def keep_length(frame):
    """How much of a frame to keep: all of the ones NetScan decodes, the headers of everything else."""
    if len(frame) <= TRIM:
        return len(frame)
    etype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if etype == 0x8100 and len(frame) >= 18:  # VLAN tag
        etype = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if etype <= 1500 or etype in (0x88CC, 0x0806):  # 802.3 (CDP, STP), LLDP, ARP
        return min(len(frame), FULL)
    if etype == 0x0800 and len(frame) >= off + 20:
        ihl = (frame[off] & 0x0F) * 4
        if frame[off + 9] == 17 and len(frame) >= off + ihl + 4:
            sport, dport = struct.unpack("!HH", frame[off + ihl:off + ihl + 4])
            if sport in FULL_UDP_PORTS or dport in FULL_UDP_PORTS:
                return min(len(frame), FULL)
    if etype == 0x86DD and len(frame) >= off + 44 and frame[off + 6] == 17:
        sport, dport = struct.unpack("!HH", frame[off + 40:off + 44])
        if sport in FULL_UDP_PORTS or dport in FULL_UDP_PORTS:
            return min(len(frame), FULL)
    return TRIM


def pcap_header():
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, FULL, 1)  # linktype 1 = Ethernet


def pcap_record(frame, ts=None):
    ts = time.time() if ts is None else ts
    keep = keep_length(frame)
    return struct.pack("<IIII", int(ts), int(ts % 1 * 1e6), keep, len(frame)) + frame[:keep]


def linux_frames(iface):
    import socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((iface, 0))
    s.settimeout(1.0)
    while True:
        try:
            yield s.recv(65535)
        except socket.timeout:
            yield None


def windows_frames(iface_ip):
    """Npcap (installed with nmap) via ctypes; the device is the one holding iface_ip."""
    import ctypes
    from ctypes import POINTER, Structure, byref, c_char_p, c_long, c_ubyte, c_uint, c_ushort, c_void_p

    dll = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll")
    os.add_dll_directory(os.path.dirname(dll))
    pcap = ctypes.CDLL(dll)

    class SockAddr(Structure):
        _fields_ = [("family", c_ushort), ("data", c_ubyte * 14)]

    class PcapAddr(Structure):
        pass

    PcapAddr._fields_ = [("next", POINTER(PcapAddr)), ("addr", POINTER(SockAddr)), ("netmask", POINTER(SockAddr)),
                         ("broadaddr", POINTER(SockAddr)), ("dstaddr", POINTER(SockAddr))]

    class PcapIf(Structure):
        pass

    PcapIf._fields_ = [("next", POINTER(PcapIf)), ("name", c_char_p), ("description", c_char_p),
                       ("addresses", POINTER(PcapAddr)), ("flags", c_uint)]

    class TimeVal(Structure):
        _fields_ = [("sec", c_long), ("usec", c_long)]

    class PktHdr(Structure):
        _fields_ = [("ts", TimeVal), ("caplen", c_uint), ("len", c_uint)]

    errbuf = ctypes.create_string_buffer(256)
    alldevs = POINTER(PcapIf)()
    if pcap.pcap_findalldevs(byref(alldevs), errbuf) != 0:
        raise OSError(errbuf.value.decode(errors="replace"))
    name, dev = None, alldevs
    want = bytes(int(x) for x in iface_ip.split("."))
    while dev and name is None:
        a = dev.contents.addresses
        while a:
            sa = a.contents.addr
            if sa and sa.contents.family == 2 and bytes(sa.contents.data[2:6]) == want:
                name = dev.contents.name
                break
            a = a.contents.next
        dev = dev.contents.next
    if name is None:
        raise OSError(f"no capture device has the address {iface_ip}")
    pcap.pcap_open_live.restype = c_void_p
    handle = pcap.pcap_open_live(name, FULL, 0, 500, errbuf)
    if not handle:
        raise OSError(errbuf.value.decode(errors="replace"))
    pcap.pcap_next_ex.argtypes = [c_void_p, POINTER(POINTER(PktHdr)), POINTER(POINTER(c_ubyte))]
    hdr, data = POINTER(PktHdr)(), POINTER(c_ubyte)()
    while True:
        rc = pcap.pcap_next_ex(handle, byref(hdr), byref(data))
        if rc == 1:
            yield ctypes.string_at(data, hdr.contents.caplen)
        elif rc == 0:
            yield None
        else:
            raise OSError("capture stopped")


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: capture_helper.py IFACE (Windows: the interface's IPv4 address)\n")
        return 2
    out = sys.stdout.buffer
    started = time.time()

    def watch_stdin():  # NetScan closing the pipe is the signal to stop (a root process can't be killed by it)
        try:
            sys.stdin.buffer.read()
        except (OSError, ValueError):
            pass
        os._exit(0)

    threading.Thread(target=watch_stdin, daemon=True).start()
    frames = windows_frames(argv[1]) if sys.platform == "win32" else linux_frames(argv[1])
    last_flush = 0.0
    try:
        out.write(pcap_header())
        out.flush()
        for frame in frames:
            now = time.time()
            if now - started > MAX_SECONDS:
                return 0
            if frame is not None:
                out.write(pcap_record(frame, now))
            if frame is None or now - last_flush > 0.2:  # a few writes a second, not one per packet
                out.flush()
                last_flush = now
    except (BrokenPipeError, KeyboardInterrupt):
        return 0
    except OSError as e:
        sys.stderr.write(f"capture failed: {e}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
