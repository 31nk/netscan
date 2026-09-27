"""The device list: remembering devices, port changes, merging lists, type guesses, risks, spoofing."""

import os
import unittest

import _support

from netscan_app.devices import DeviceStore, guess_type, label_risky, port_risk, risky, spoof_check

TCP = lambda n, s="": {"port": n, "proto": "tcp", "service": s, "version": ""}


class Store(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(_support.TMP, f"devices-{self.id()}.json")
        self.store = DeviceStore(self.path)

    def test_record_and_reload(self):
        a = {"ip": "10.0.0.2", "mac": "AA:00:00:00:00:02", "hostname": "nas", "vendor": "Synology"}
        self.assertEqual(self.store.record([a, {"ip": "10.0.0.3", "mac": ""}]), ["AA:00:00:00:00:02"])
        self.assertEqual(self.store.record([{**a, "ip": "10.0.0.4"}]), [])  # known now, even on a new IP
        again = DeviceStore(self.path)
        rec = again.devices["AA:00:00:00:00:02"]
        self.assertEqual(rec["ips"], ["10.0.0.2", "10.0.0.4"])
        self.assertEqual(rec["hostname"], "nas")
        self.assertEqual(len(again.checked_hours), 1)

    def test_port_changes_are_logged_after_baseline(self):
        mac = "AA:00:00:00:00:05"
        self.store.record([{"ip": "10.0.0.5", "mac": mac}])
        scanned = {"tcp": {22, 80, 443}, "udp": set()}
        self.assertEqual(self.store.update_ports(mac, [TCP(22, "ssh")], scanned), ([], []))  # baseline
        opened, closed = self.store.update_ports(mac, [TCP(80, "http")], scanned)
        self.assertEqual([p["port"] for p in opened], [80])
        self.assertEqual([p["port"] for p in closed], [22])
        log = self.store.devices[mac]["port_changes"]
        self.assertEqual((log[-1]["opened"], log[-1]["closed"]), (["80/http"], ["22/ssh"]))
        # a scan of other ports doesn't count 80 as closed
        self.assertEqual(self.store.update_ports(mac, [], {"tcp": {8080}, "udp": set()}), ([], []))

    def test_user_fields_trusted_and_forget(self):
        host = {"ip": "10.0.0.6", "mac": "AA:00:00:00:00:06"}
        self.assertFalse(self.store.any_trusted())
        self.store.set_nickname(host, "Printer")
        self.store.set_field(host, "trusted", True)
        self.assertEqual(self.store.nickname(host), "Printer")
        self.assertTrue(self.store.any_trusted())
        self.store.set_nickname(host, "")
        self.assertNotIn("nickname", self.store.get(host))
        self.store.forget("AA:00:00:00:00:06")
        self.assertFalse(self.store.any_trusted())

    def test_merge_from_fills_only_empty_user_fields(self):
        mine = {"ip": "10.0.0.7", "mac": "AA:00:00:00:00:07"}
        self.store.record([mine])
        self.store.set_nickname(mine, "Mine")
        added, updated = self.store.merge_from({
            "AA:00:00:00:00:07": {"nickname": "Theirs", "notes": "shelf", "first_seen": "2000-01-01T00:00:00"},
            "AA:00:00:00:00:08": {"mac": "AA:00:00:00:00:08", "nickname": "New"},
            "junk": "not a device"})
        self.assertEqual((added, updated), (1, 1))
        rec = self.store.devices["AA:00:00:00:00:07"]
        self.assertEqual((rec["nickname"], rec["notes"], rec["first_seen"]), ("Mine", "shelf", "2000-01-01T00:00:00"))
        self.assertIn("AA:00:00:00:00:08", DeviceStore(self.path).devices)

    def test_type_override(self):
        host = {"ip": "10.0.0.9", "mac": "AA:00:00:00:00:09", "vendor": "Raspberry Pi Trading"}
        self.assertEqual(self.store.device_type(host), ("pi", True))
        self.store.set_field(host, "type", "nas")
        self.assertEqual(self.store.device_type(host), ("nas", False))


class Guesses(unittest.TestCase):
    def test_guess_type(self):
        cases = [({"ip": "10.0.0.1"}, None, "10.0.0.1", "router"),
                 ({"ip": "1", "vendor": "(this computer)"}, None, None, "computer"),
                 ({"ip": "2"}, [TCP(9100)], None, "printer"),
                 ({"ip": "3"}, [TCP(62078)], None, "phone"),
                 ({"ip": "4", "hostname": "living-room-tv"}, None, None, "media"),
                 ({"ip": "5", "vendor": "Espressif Inc."}, None, None, "iot"),
                 ({"ip": "6", "vendor": "(private)"}, None, None, "phone"),
                 ({"ip": "7"}, [TCP(22)], None, "computer"),
                 ({"ip": "8"}, [TCP(5000), TCP(445)], None, "nas"),
                 ({"ip": "9"}, None, None, "unknown")]
        for host, ports, gw, want in cases:
            self.assertEqual(guess_type(host, ports, gw), want, host)

    def test_risks(self):
        self.assertTrue(port_risk(TCP(23)))
        self.assertFalse(port_risk(TCP(443)))
        self.assertFalse(port_risk({**TCP(23), "local_only": True}))
        self.assertTrue(port_risk({"port": 1900, "proto": "udp"}))  # a router's UPnP
        self.assertFalse(port_risk({"port": 1900, "proto": "udp", "program": "kdeconnectd"}))  # this computer's listener
        self.assertEqual([p["port"] for p in risky([TCP(23), TCP(443)])], [23])
        self.assertTrue(label_risky("23/telnet"))
        self.assertFalse(label_risky("443/https"))


class Spoofing(unittest.TestCase):
    NET = {"network": "10.0.0.0/24", "gateway": "10.0.0.1", "iface": "none0"}
    GW = "AA:00:00:00:00:01"

    def setUp(self):
        self.store = DeviceStore(os.path.join(_support.TMP, f"spoof-{self.id()}.json"))

    def test_first_sight_remembers_router(self):
        self.assertEqual(spoof_check(self.store, self.NET, {"10.0.0.1": self.GW}), [])
        self.assertEqual(self.store.gateways["10.0.0.0/24|10.0.0.1"]["mac"], self.GW)

    def test_router_mac_changed(self):
        spoof_check(self.store, self.NET, {"10.0.0.1": self.GW})
        warnings = spoof_check(self.store, self.NET, {"10.0.0.1": "BB:00:00:00:00:01"})
        self.assertEqual([w[0] for w in warnings], ["high"])

    def test_router_mac_on_another_address(self):
        warnings = spoof_check(self.store, self.NET, {"10.0.0.1": self.GW, "10.0.0.66": self.GW})
        self.assertEqual(warnings[0][0], "high")
        self.assertIn("10.0.0.66", warnings[0][1])

    def test_shared_mac_is_low(self):
        warnings = spoof_check(self.store, self.NET, {"10.0.0.1": self.GW, "10.0.0.5": "CC:00:00:00:00:05",
                                                      "10.0.0.6": "CC:00:00:00:00:05"})
        self.assertEqual([w[0] for w in warnings], ["low"])


if __name__ == "__main__":
    unittest.main()
