import os
import unittest
import collections.abc

from hmalib_extensions.gifct.tfp.trustedflaggerportal_api import (
    TrustedFlaggerPortalAPI,
)
from hmalib_extensions.gifct.tfp.trustedflaggerportal_representations import (
    HashRecord,
)

TFP_X_API_KEY = os.getenv("TFP_X_API_KEY")

TFP_BASE_URL = os.getenv("TFP_BASE_URL")

@unittest.skipUnless(
    TFP_X_API_KEY and TFP_BASE_URL,
    "Integration test requires api key and a base url"
)
class TrustedFlaggerPortalAPIIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.api = TrustedFlaggerPortalAPI(TFP_X_API_KEY, TFP_BASE_URL)

    def test_fetch_hashes(self):
        """
        Integration test to fetch records from the TFP fetch-hashes API.
        Assumes that the response has at least one hash record.
        """

        # Test getting hash records fro m the very beginning to ensure that we get at least one record.
        response = self.api.get_hash_records_page(start_timestamp=0, page_size=10)

        self.assertTrue(len(response.hash_records) > 0)

        self.assertTrue(
            isinstance(response.hash_records, collections.abc.Sequence)
            and not isinstance(response, staticmethod),
            "hash_records should be a list",
        )

        self.assertTrue(isinstance(response.hash_records[0], HashRecord))
