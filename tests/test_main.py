import unittest

import main


class TestMainFunctions(unittest.TestCase):
    def test_normalise_domain(self):
        self.assertEqual(main.normalise_domain("https://Example.com/path"), "example.com")

    def test_format_age(self):
        years, days, label = main.format_age(400)
        self.assertEqual(years, 1)
        self.assertEqual(days, 35)
        self.assertIn("1 years", label)

    def test_calculate_risk_score_bounds(self):
        signals = {
            "domain_age": {"risk_points": -20, "domain_age_days": 1000},
            "typosquat": {"risk_points": 0},
            "email_security": {"risk_points": 10},
            "asn_reputation": {"risk_points": -10, "asn": "AS13335"},
            "dns_quality": {"risk_points": -10},
        }
        score, level, breakdown = main.calculate_risk_score(signals)
        self.assertGreaterEqual(score, 0)
        self.assertIn(level, {"LOW", "MEDIUM", "HIGH"})
        self.assertIn("domain_age", breakdown)

    def test_render_csv_batch(self):
        results = [
            {
                "domain": "example.com",
                "risk_score": 10,
                "risk_level": "LOW",
                "signals": {
                    "email_security": {"dmarc_policy": "reject", "spf_present": True},
                    "asn_reputation": {"asn": "AS13335", "provider": "Cloudflare", "country_code": "US"},
                    "dns_quality": {"mx_present": True},
                    "typosquat": {"typosquat_detected": False},
                },
            }
        ]
        csv_out = main.render_csv(results)
        self.assertIn("domain,risk_score,risk_level", csv_out)
        self.assertIn("example.com", csv_out)


if __name__ == "__main__":
    unittest.main()
