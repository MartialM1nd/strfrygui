import json
import socket

import pytest

import utils.nip05 as nip05
from utils.nip05 import (
    Nip05VerificationError,
    domain_matches,
    find_domain_candidates,
    normalize_domain,
    resolve_public_addresses,
    verify_nip05,
)


PUBKEY_A = "a" * 64
PUBKEY_B = "b" * 64


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (" Example.COM. ", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_normalize_domain(value, expected):
    assert normalize_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "127.0.0.1",
        "bad_label.example",
        "-bad.example",
    ],
)
def test_normalize_domain_rejects_non_hostnames(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


def test_domain_match_includes_subdomains_but_not_suffixes():
    assert domain_matches("example.com", "example.com")
    assert domain_matches("profiles.example.com", "example.com")
    assert not domain_matches("notexample.com", "example.com")
    assert not domain_matches("example.com.evil.test", "example.com")


def test_find_domain_candidates_uses_latest_profile_per_pubkey():
    events = [
        {
            "kind": 0,
            "pubkey": PUBKEY_A,
            "created_at": 1,
            "content": '{"nip05":"old@example.com"}',
        },
        {
            "kind": 0,
            "pubkey": PUBKEY_A,
            "created_at": 2,
            "content": '{"name":"No longer identified"}',
        },
        {
            "kind": 0,
            "pubkey": PUBKEY_B,
            "created_at": 3,
            "content": '{"nip05":"bob@profiles.example.com"}',
        },
        {
            "kind": 0,
            "pubkey": "invalid",
            "created_at": 4,
            "content": '{"nip05":"bad@example.com"}',
        },
    ]

    assert find_domain_candidates(events, "example.com") == [
        ("bob", "profiles.example.com", PUBKEY_B)
    ]


def test_find_domain_candidates_uses_lowest_event_id_for_timestamp_ties():
    events = [
        {
            "id": "b" * 64,
            "kind": 0,
            "pubkey": PUBKEY_A,
            "created_at": 1,
            "content": '{"nip05":"alice@example.com"}',
        },
        {
            "id": "a" * 64,
            "kind": 0,
            "pubkey": PUBKEY_A,
            "created_at": 1,
            "content": '{}',
        },
    ]

    assert find_domain_candidates(events, "example.com") == []


def test_verify_nip05_requires_remote_mapping_to_match_pubkey():
    def fetch(domain, name):
        return {"names": {name: PUBKEY_A}}

    assert verify_nip05("alice", "example.com", PUBKEY_A, fetcher=fetch)
    assert not verify_nip05("alice", "example.com", PUBKEY_B, fetcher=fetch)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.1.1", "::1"])
def test_resolve_public_addresses_rejects_non_global_results(address):
    def resolver(host, port, type):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
        return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]

    with pytest.raises(Nip05VerificationError):
        resolve_public_addresses("example.com", resolver=resolver)


def test_fetch_nip05_document_pins_tls_hostname_and_disables_redirects(monkeypatch):
    calls = {}

    class Response:
        status = 200
        headers = {}

        def read(self, limit):
            return json.dumps({"names": {"alice": PUBKEY_A}}).encode("utf-8")

        def release_conn(self):
            calls["released"] = True

        def close(self):
            calls["closed"] = True

    class Pool:
        def __init__(self, host, **kwargs):
            calls["pool"] = (host, kwargs)

        def request(self, method, path, **kwargs):
            calls["request"] = (method, path, kwargs)
            return Response()

        def close(self):
            calls["pool_closed"] = True

    monkeypatch.setattr(
        nip05,
        "resolve_public_addresses",
        lambda hostname, **kwargs: ["8.8.8.8"],
    )
    monkeypatch.setattr(nip05.urllib3, "HTTPSConnectionPool", Pool)

    document = nip05.fetch_nip05_document("example.com", "alice")

    assert document == {"names": {"alice": PUBKEY_A}}
    assert calls["pool"][0] == "8.8.8.8"
    assert calls["pool"][1]["assert_hostname"] == "example.com"
    assert calls["pool"][1]["server_hostname"] == "example.com"
    assert calls["request"][2]["redirect"] is False
    assert calls["request"][2]["headers"]["Host"] == "example.com"
    assert calls["released"] is True
