import unittest

from detector import analyze_url


class AnalyzeUrlTests(unittest.TestCase):
    def test_normalizes_url_without_scheme(self):
        result = analyze_url("example.com")

        self.assertEqual(result["normalized_url"], "https://example.com")
        self.assertEqual(result["hostname"], "example.com")
        self.assertEqual(result["verdict"], "No obvious warning signs")

    def test_flags_brand_lookalike_with_account_language(self):
        result = analyze_url("http://paypal-login.example.com/verify")

        self.assertEqual(result["verdict"], "High risk")
        self.assertGreaterEqual(result["score"], 40)
        self.assertTrue(any("paypal" in reason for reason in result["reasons"]))

    def test_flags_url_credentials_and_ip_address(self):
        result = analyze_url("https://user:pass@192.0.2.1/login")

        self.assertEqual(result["verdict"], "High risk")
        self.assertGreaterEqual(result["score"], 40)

    def test_supports_ipv6_hosts(self):
        result = analyze_url("https://[2001:db8::1]/")

        self.assertEqual(result["hostname"], "2001:db8::1")
        self.assertEqual(result["verdict"], "Suspicious")

    def test_flags_shortened_links(self):
        result = analyze_url("https://bit.ly/example")

        self.assertEqual(result["verdict"], "Suspicious")
        self.assertTrue(any("shortened link" in reason for reason in result["reasons"]))

    def test_rejects_unsupported_scheme(self):
        with self.assertRaisesRegex(ValueError, "Only HTTP and HTTPS"):
            analyze_url("javascript:alert(1)")

    def test_rejects_malformed_hostname(self):
        with self.assertRaisesRegex(ValueError, "valid hostname"):
            analyze_url("https://-invalid.example")

    def test_rejects_overlong_url(self):
        with self.assertRaisesRegex(ValueError, "2048 characters"):
            analyze_url(f"https://example.com/{'a' * 2040}")


if __name__ == "__main__":
    unittest.main()
