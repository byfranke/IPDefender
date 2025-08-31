import unittest
from unittest.mock import patch
from src.api.cloudflare import cf_block, cf_unblock, cf_find_rule

class TestCloudflareAPI(unittest.TestCase):

    @patch('src.api.cloudflare.requests.post')
    def test_cf_block(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.text = '{"success":true}'
        status, response = cf_block("192.0.2.1")
        self.assertEqual(status, 200)
        self.assertIn('"success":true', response)

    @patch('src.api.cloudflare.requests.get')
    def test_cf_find_rule_found(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "result": [{"id": "rule_id"}]
        }
        rule_id = cf_find_rule("192.0.2.1")
        self.assertEqual(rule_id, "rule_id")

    @patch('src.api.cloudflare.requests.get')
    def test_cf_find_rule_not_found(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "result": []
        }
        rule_id = cf_find_rule("192.0.2.1")
        self.assertIsNone(rule_id)

    @patch('src.api.cloudflare.requests.delete')
    @patch('src.api.cloudflare.cf_find_rule')
    def test_cf_unblock_success(self, mock_find_rule, mock_delete):
        mock_find_rule.return_value = "rule_id"
        mock_delete.return_value.status_code = 200
        mock_delete.return_value.text = '{"success":true}'
        status, response = cf_unblock("192.0.2.1")
        self.assertEqual(status, 200)
        self.assertIn('"success":true', response)

    @patch('src.api.cloudflare.cf_find_rule')
    def test_cf_unblock_rule_not_found(self, mock_find_rule):
        mock_find_rule.return_value = None
        status, response = cf_unblock("192.0.2.1")
        self.assertEqual(status, 404)
        self.assertIn('rule not found', response)

if __name__ == '__main__':
    unittest.main()