"""Unit tests for the SSRF protection (panel/netguard.py, security.check_upstream, redirect validation). No cluster, no network: DNS is replaced."""
import http.server
import ipaddress
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

os.environ.setdefault("SHIELD_DATA", tempfile.mkdtemp())
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "panel"))
import netguard  # noqa: E402
import security  # noqa: E402


class FakeDNS:
    """Replaces netguard._getaddrinfo with a table; unknown names do not resolve."""

    def __init__(self, table):
        self.table = table

    def __enter__(self):
        self.old = netguard._getaddrinfo
        netguard._getaddrinfo = self

    def __exit__(self, *a):
        netguard._getaddrinfo = self.old

    def __call__(self, host, port):
        if host not in self.table:
            raise OSError("no such host")
        return [(0, 0, 0, "", (ip, 0)) for ip in self.table[host]]


class Classify(unittest.TestCase):
    CASES = {
        "127.0.0.1": "loopback", "127.255.255.254": "loopback", "::1": "loopback",
        "169.254.169.254": "metadata", "169.254.170.2": "metadata", "fd00:ec2::254": "metadata", "100.100.100.200": "metadata", "168.63.129.16": "metadata",
        "169.254.1.1": "link-local", "fe80::1": "link-local", "0.0.0.0": "unspecified", "::": "unspecified",
        "224.0.0.1": "multicast", "ff02::1": "multicast", "240.0.0.1": "reserved", "255.255.255.255": "reserved",
        "10.1.2.3": "private", "172.16.0.1": "private", "172.31.255.255": "private", "192.168.1.1": "private", "100.64.0.1": "private", "fd12::1": "private",
        "8.8.8.8": "public", "1.1.1.1": "public", "2606:4700::1111": "public",
        # IPv6 wrapping an IPv4 address
        "::ffff:127.0.0.1": "loopback", "::ffff:169.254.169.254": "metadata", "::ffff:10.0.0.1": "private", "::ffff:8.8.8.8": "public",
        "64:ff9b::7f00:1": "loopback", "64:ff9b::a9fe:a9fe": "metadata", "2002:7f00:1::": "loopback", "2002:a9fe:a9fe::": "metadata",
    }

    def test_table(self):
        for ip, want in self.CASES.items():
            with self.subTest(ip=ip):
                self.assertEqual(netguard.classify(ip), want)


class NumericForms(unittest.TestCase):
    def test_every_spelling_of_loopback_is_recognised(self):
        for host in ("127.0.0.1", "0177.0.0.1", "0x7f.0.0.1", "0x7f000001", "2130706433", "127.1", "127.0.1", "017700000001"):
            with self.subTest(host=host):
                ip = netguard.literal_ip(host)
                self.assertIsNotNone(ip, host)
                self.assertEqual(netguard.classify(ip), "loopback")

    def test_metadata_in_decimal(self):
        self.assertEqual(netguard.classify(netguard.literal_ip("2852039166")), "metadata")        # 169.254.169.254

    def test_names_are_not_literals(self):
        for host in ("example.com", "a1.b2", "svc.cluster.local", "1a.com"):
            self.assertIsNone(netguard.literal_ip(host))


class Names(unittest.TestCase):
    def test_public_name_resolving_to_loopback_is_refused(self):
        with FakeDNS({"evil.example": ["127.0.0.1"]}):
            self.assertIn("loopback", netguard.check_host("evil.example")[0])

    def test_public_name_resolving_to_metadata_is_refused(self):
        with FakeDNS({"nip.example": ["169.254.169.254"]}):
            self.assertIn("metadata", netguard.check_host("nip.example")[0])

    def test_one_bad_answer_refuses_the_whole_name(self):
        with FakeDNS({"mixed.example": ["8.8.8.8", "127.0.0.1"]}):
            self.assertIsNotNone(netguard.check_host("mixed.example")[0])

    def test_ipv6_answer_wrapping_metadata(self):
        with FakeDNS({"v6.example": ["::ffff:169.254.169.254"]}):
            self.assertIsNotNone(netguard.check_host("v6.example")[0])

    def test_public_name_is_fine(self):
        with FakeDNS({"ok.example": ["93.184.216.34"]}):
            self.assertIsNone(netguard.check_host("ok.example")[0])

    def test_blocked_names_without_dns(self):
        for h in ("localhost", "metadata.google.internal", "metadata", "instance-data", "foo.localhost", "LOCALHOST."):
            with self.subTest(h=h):
                self.assertIsNotNone(netguard.check_host(h)[0])

    def test_unresolvable_names_are_accepted_by_default_and_refused_when_asked(self):
        with FakeDNS({}):
            self.assertIsNone(netguard.check_host("not-created-yet.svc")[0])
            self.assertIsNotNone(netguard.check_host("not-created-yet.svc", allow_unresolved=False)[0])


class PrivateAllowList(unittest.TestCase):
    def test_default_allows_rfc1918_like_2_3(self):
        with FakeDNS({"svc": ["10.96.1.1"]}):
            self.assertIsNone(netguard.check_host("svc")[0])

    def test_narrow_allowlist_refuses_other_private_ranges(self):
        with FakeDNS({"svc": ["10.96.1.1"], "other": ["192.168.5.5"]}):
            self.assertIsNone(netguard.check_host("svc", private_allow="10.96.0.0/12")[0])
            self.assertIn("not on the allowed list", netguard.check_host("other", private_allow="10.96.0.0/12")[0])

    def test_empty_allowlist_means_no_private_address_at_all(self):
        with FakeDNS({"svc": ["10.96.1.1"]}):
            self.assertIsNotNone(netguard.check_host("svc", private_allow="")[0])

    def test_allowlist_can_never_authorise_loopback_or_metadata(self):
        with FakeDNS({"a": ["127.0.0.1"], "b": ["169.254.169.254"], "c": ["::1"]}):
            for h in "abc":
                self.assertIsNotNone(netguard.check_host(h, private_allow="0.0.0.0/0 ::/0")[0], h)

    def test_cgnat_is_private_not_public(self):
        with FakeDNS({"x": ["100.64.1.1"]}):
            self.assertIsNotNone(netguard.check_host("x", private_allow="10.0.0.0/8")[0])

    def test_invalid_allowlist_raises(self):
        with self.assertRaises(ValueError):
            netguard.parse_networks("10.0.0.0/8 not-a-network")


class CheckUpstream(unittest.TestCase):
    """The function the panel calls when a site is saved."""

    def test_all_the_2_3_bypasses_are_refused(self):
        table = {"127.0.0.1.nip.io": ["127.0.0.1"], "169.254.169.254.nip.io": ["169.254.169.254"], "localtest.me": ["127.0.0.1"]}
        with FakeDNS(table):
            for url in ("http://127.0.0.1:80", "http://0177.0.0.1:80", "http://2130706433:80", "http://127.0.0.1.nip.io:80",
                        "http://169.254.169.254.nip.io:80", "http://localtest.me:80", "http://[::ffff:127.0.0.1]:80", "http://[::]:80",
                        "http://169.254.169.254", "http://localhost", "http://metadata.google.internal"):
                with self.subTest(url=url):
                    self.assertIsNotNone(security.check_upstream(url, log=False), url)

    def test_internal_service_names_still_work(self):
        with FakeDNS({"app.ns.svc.cluster.local": ["10.96.3.4"]}):
            self.assertIsNone(security.check_upstream("http://app.ns.svc.cluster.local:80", log=False))

    def test_suffix_list_is_an_explicit_authorisation_of_internal_names(self):
        with FakeDNS({"db.corp.example": ["10.9.9.9"], "x.evil.example": ["10.9.9.9"]}):
            self.assertIsNone(security.check_upstream("http://db.corp.example", "corp.example", "192.168.0.0/16", log=False))
            self.assertIsNotNone(security.check_upstream("http://x.evil.example", "corp.example", "192.168.0.0/16", log=False))

    def test_suffix_authorisation_does_not_reach_loopback(self):
        with FakeDNS({"a.corp.example": ["127.0.0.1"]}):
            self.assertIsNotNone(security.check_upstream("http://a.corp.example", "corp.example", log=False))

    def test_port_range(self):
        self.assertIsNotNone(security.check_upstream("http://app.example:99999", log=False))

    def test_unresolvable_is_accepted(self):
        with FakeDNS({}):
            self.assertIsNone(security.check_upstream("http://no-such-service.ns.svc.cluster.local:80", log=False))


class Redirects(unittest.TestCase):
    """Every redirect hop is checked with the same rules, not only the first address."""

    @classmethod
    def setUpClass(cls):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/hop":
                    self.send_response(302)
                    self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                    self.end_headers()
                elif self.path == "/ok":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"fine")

            def log_message(self, *a):
                pass
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def only_first(self):
        base = f"http://127.0.0.1:{self.port}/"
        return lambda url: None if url.startswith(base) else "destination refused by the test policy"

    def test_first_address_is_checked(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/ok")
        with self.assertRaises(urllib.error.URLError):
            netguard.safe_open(req)                                          # default policy: public https only

    def test_allowed_first_hop_works(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/ok")
        with netguard.safe_open(req, check=self.only_first()) as r:
            self.assertEqual(r.read(), b"fine")

    def test_redirect_to_the_metadata_service_is_refused(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/hop")
        with self.assertRaises(urllib.error.URLError) as cm:
            netguard.safe_open(req, check=self.only_first())
        self.assertIn("redirect", str(cm.exception))

    def test_real_policy_refuses_redirect_into_loopback(self):
        # no injected check: loopback is refused already at the first hop, with the real rules
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/hop")
        with self.assertRaises(urllib.error.URLError):
            netguard.safe_open(req, schemes=("http", "https"), private_allow="0.0.0.0/0 ::/0")


class Unwrap(unittest.TestCase):
    def test_unwrap_returns_the_embedded_ipv4(self):
        self.assertEqual(netguard.unwrap(ipaddress.ip_address("::ffff:1.2.3.4")), ipaddress.ip_address("1.2.3.4"))
        self.assertEqual(netguard.unwrap(ipaddress.ip_address("64:ff9b::102:304")), ipaddress.ip_address("1.2.3.4"))
        self.assertEqual(netguard.unwrap(ipaddress.ip_address("2002:102:304::")), ipaddress.ip_address("1.2.3.4"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
