import typing as t
from hmalib.common.external_api import BaseAPI
from hmalib_extensions.gifct.tfp.trustedflaggerportal_representations import (
    HashRecordsPage
)

FETCH_HASHES_PATH = "/v1/fetch-hashes"

class TrustedFlaggerPortalAPI(BaseAPI):
    """
    A client for the Trusted Flagger Portal fetch-hashes API hosted by gifct.org.
    """

    def __init__(
        self,
        x_api_key: str,
        base_url: str
    ) -> None:
        self.x_api_key = x_api_key
        self._base_url = base_url

    def get_hash_records_page(
        self,
        start_timestamp: int,
        page_size: int = 1000,
        next_page_token: str = None
    ) -> HashRecordsPage:
        """
        Returns a paginated list of all hash records from start_timestamp.
        """

        params: t.Dict[str, t.Union[str, int]] = {
            'timestamp': start_timestamp,
            'limit': page_size
        }
        if next_page_token is not None:
            params["next_page_token"] = next_page_token
        url = super()._get_api_url(FETCH_HASHES_PATH, params)
        headers = {
            "x-api-key": self.x_api_key
        }

        # TODO: Add error handling for non-200 responses?
        response = super().get_json_from_url(url=url, headers=headers)
        return HashRecordsPage.from_dict(response.get('body'))
