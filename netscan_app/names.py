"""Device name lookups: mDNS, NetBIOS and DNS."""

import socket
import threading


def _read_dns_name(buf, off):
    """Decode a (possibly compressed) DNS name starting at off."""
    labels, jumps = [], 0
    while off < len(buf) and jumps < 20:
        n = buf[off]
        if n == 0:
            break
        if n & 0xC0 == 0xC0:
            off = ((n & 0x3F) << 8) | buf[off + 1]
            jumps += 1
            continue
        labels.append(buf[off + 1:off + 1 + n].decode(errors="replace"))
        off += 1 + n
    return ".".join(labels)


def mdns_name(ip, timeout=1.0):
    """Ask the host itself for its name over unicast mDNS (PTR on in-addr.arpa)."""
    qname = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    q = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\0"
    packet = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q + b"\x00\x0c\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(packet, (ip, 5353))
            buf, _ = s.recvfrom(4096)
        except OSError:
            return ""
    try:
        ancount = int.from_bytes(buf[6:8], "big")
        if not ancount:
            return ""
        off = 12
        for _ in range(int.from_bytes(buf[4:6], "big")):  # skip questions
            while buf[off] != 0 and buf[off] & 0xC0 != 0xC0:
                off += buf[off] + 1
            off += 2 if buf[off] & 0xC0 == 0xC0 else 1
            off += 4
        while buf[off] != 0 and buf[off] & 0xC0 != 0xC0:  # answer name
            off += buf[off] + 1
        off += 2 if buf[off] & 0xC0 == 0xC0 else 1
        if int.from_bytes(buf[off:off + 2], "big") != 12:  # not a PTR
            return ""
        return _read_dns_name(buf, off + 10).removesuffix(".local")
    except IndexError:
        return ""


def netbios_name(ip, timeout=1.0):
    """NetBIOS node-status query (Windows machines, Samba, many NAS boxes)."""
    name = b"\x20" + b"CK" + b"A" * 30 + b"\x00"  # encoded "*"
    packet = b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x21\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(packet, (ip, 137))
            buf, _ = s.recvfrom(4096)
        except OSError:
            return ""
    try:
        count, off = buf[56], 57
        for i in range(count):
            entry = buf[off + i * 18:off + i * 18 + 18]
            flags = int.from_bytes(entry[16:18], "big")
            if entry[15] == 0x00 and not flags & 0x8000:  # workstation, unique
                return entry[:15].decode(errors="replace").strip()
    except IndexError:
        pass
    return ""


def dns_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def lookup_name(ip):
    """Query mDNS, NetBIOS and DNS at once; return the first hit in that order, or ''.

    Each silent source costs a 1s timeout, so asking in parallel instead of
    one after another halves the wait for devices that don't answer.
    """
    results = {}
    threads = [threading.Thread(target=lambda fn=fn: results.__setitem__(fn, fn(ip)), daemon=True)
               for fn in (netbios_name, dns_name)]
    for t in threads:
        t.start()
    name = mdns_name(ip)
    for fn, t in zip((netbios_name, dns_name), threads):
        if name:
            break
        t.join()
        name = results.get(fn, "")
    return name
