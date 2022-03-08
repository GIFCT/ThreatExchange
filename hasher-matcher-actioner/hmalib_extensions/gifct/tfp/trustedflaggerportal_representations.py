"""
Typed representations (dataclasses only) for interfacing with the
Trusted Flagger Portal API classes.
"""

from datetime import datetime
from dataclasses import dataclass
import typing as t

@dataclass
class HashRecord:
    """
    An individual record of a hash from GIFCT.
    """

    # The date that was provided with the hashed item
    date: str

    # The date that the hash was added to TFP
    created_at: datetime

    # The actual hash values
    hash_value: str

    # The confidence of the hash
    confidence: int

    # A description provided with the hash
    description: str

    # A list of tags provided by the uploader
    tags: t.List[str]

    # The kind of signal the hash corresponds to (MD5, PDQ, etc)
    signal_type: str
    
    @classmethod
    def from_dict(cls, d: dict) -> "HashRecord":
        return cls(
            date = d.get("date", None),
            created_at = datetime.fromtimestamp(d.get("created_at", None)),
            hash_value = d.get("indicator", None),
            confidence = d.get("confidence", None),
            description = d.get("description", None),
            tags = d.get("tags", []),
            signal_type = d.get("type", None)
        )


@dataclass
class HashRecordsPage:
    """
    A page of HashRecords from the GIFCT TFP API.
    """

    # The number of records in the response page
    count: int

    # A lit of HashRecords
    hash_records: t.List[HashRecord]

    # The timestamp of the final page record, to use in the next call
    # as the query timestamp. Will be None for all but the last page of a set.
    # TODO: Maybe change this to int in the fetch-hashes API?
    next_set_timestamp: str

    # Indicates whether there are more pages beyond the current page.
    has_more_records: bool

    # An internal token that needs to be forwarded to get the next page.
    next_page_token: t.Optional[str]

    @classmethod
    def from_dict(cls, d: dict) -> "HashRecordsPage":
        return cls(
            count = d.get("count", None),
            hash_records = [HashRecord.from_dict(x) for x in d.get("hash_records", [])],
            next_set_timestamp = d.get("next_set_timestamp", None),
            has_more_records = d.get("has_more_records", None),
            next_page_token = d.get("next_page_token", None)
        )
