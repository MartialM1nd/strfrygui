import hashlib
import json
import socket
import time
from types import SimpleNamespace

import pytest

import utils.nip05 as nip05
from utils.nip05 import (
    InvalidNostrEvent,
    Nip05Directory,
    Nip05VerificationError,
    event_claims_nip05,
    lookup_profile_claim,
    lookup_external_kind0,
    parse_nip05_directory,
    domain_matches,
    find_domain_candidates,
    normalize_domain,
    resolve_public_addresses,
    verify_nip05,
    validate_nostr_event,
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
    assert calls["request"][2]["headers"]["User-Agent"] == "StrfryGUI/1.0"
    assert calls["released"] is True


def test_fetch_nip05_document_supports_unfiltered_directory(monkeypatch):
    calls = {}

    class Response:
        status = 200
        headers = {}

        def read(self, limit):
            return json.dumps({"names": {"alice": PUBKEY_A}}).encode("utf-8")

        def release_conn(self):
            pass

    class Pool:
        def __init__(self, host, **kwargs):
            pass

        def request(self, method, path, **kwargs):
            calls["path"] = path
            return Response()

    monkeypatch.setattr(
        nip05,
        "resolve_public_addresses",
        lambda hostname, **kwargs: ["8.8.8.8"],
    )
    monkeypatch.setattr(nip05.urllib3, "HTTPSConnectionPool", Pool)

    nip05.fetch_nip05_document("example.com")

    assert calls["path"] == "/.well-known/nostr.json"


def test_parse_nip05_directory_filters_invalid_entries_and_relay_hints():
    parsed = parse_nip05_directory({
        "names": {
            "alice": PUBKEY_A,
            "UPPER": PUBKEY_B,
            "bad-key": "not-a-pubkey",
        },
        "relays": {
            PUBKEY_A: ["wss://relay.example", "ws://insecure.example"],
        },
    })

    assert parsed == Nip05Directory(
        names={"alice": PUBKEY_A},
        relays={PUBKEY_A: ("wss://relay.example",)},
        invalid_entries=2,
    )


def test_parse_nip05_directory_rejects_non_enumerable_endpoint():
    with pytest.raises(Nip05VerificationError, match="does not expose"):
        parse_nip05_directory({"names": {}})


def test_parse_nip05_directory_rejects_truncated_enforcement():
    with pytest.raises(Nip05VerificationError, match="safety limit"):
        parse_nip05_directory(
            {"names": {"alice": PUBKEY_A, "bob": PUBKEY_B}},
            max_names=1,
        )


def test_event_claims_exact_nip05_identifier():
    event = {
        "pubkey": PUBKEY_A,
        "kind": 0,
        "content": json.dumps({"nip05": "alice@example.com"}),
    }

    assert event_claims_nip05(event, "alice", "example.com", PUBKEY_A)
    assert not event_claims_nip05(event, "bob", "example.com", PUBKEY_A)


def test_validate_nostr_event_rejects_id_mismatch():
    event = {
        "id": "0" * 64,
        "pubkey": PUBKEY_A,
        "created_at": 1,
        "kind": 0,
        "tags": [],
        "content": "{}",
        "sig": "0" * 128,
    }

    with pytest.raises(InvalidNostrEvent):
        validate_nostr_event(event, schnorr_verifier=lambda pubkey, signature, digest: True)


def test_lookup_profile_claim_rejects_unvalidated_local_event():
    forged_event = {
        "id": "0" * 64,
        "pubkey": PUBKEY_A,
        "created_at": 1,
        "kind": 0,
        "tags": [],
        "content": json.dumps({"nip05": "alice@example.com"}),
        "sig": "0" * 128,
    }

    result = lookup_profile_claim(
        "alice",
        "example.com",
        PUBKEY_A,
        (),
        (),
        time.monotonic() + 1,
        scanner=lambda event_filter, limit, timeout: [forged_event],
    )

    assert result.verified is False
    assert result.error == "No kind-0 profile found"


def test_validate_nostr_event_accepts_valid_bip340_signature():
    private_key = 3
    public_point = nip05._point_multiply(private_key, nip05._SECP256K1_G)
    public_key = public_point[0].to_bytes(32, "big")
    content = json.dumps({"nip05": "alice@example.com"}, separators=(",", ":"))
    serialized = json.dumps(
        [0, public_key.hex(), 1, 0, [], content],
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(serialized).digest()
    signature = sign_schnorr(private_key, digest)
    event = {
        "id": digest.hex(),
        "pubkey": public_key.hex(),
        "created_at": 1,
        "kind": 0,
        "tags": [],
        "content": content,
        "sig": signature.hex(),
    }

    assert validate_nostr_event(event) == event


def sign_schnorr(private_key, message):
    public_point = nip05._point_multiply(private_key, nip05._SECP256K1_G)
    secret = private_key if public_point[1] % 2 == 0 else nip05._SECP256K1_N - private_key
    public_key = public_point[0].to_bytes(32, "big")
    nonce = int.from_bytes(
        nip05._tagged_hash(
            "BIP0340/nonce",
            secret.to_bytes(32, "big") + public_key + message,
        ),
        "big",
    ) % nip05._SECP256K1_N
    nonce_point = nip05._point_multiply(nonce, nip05._SECP256K1_G)
    if nonce_point[1] % 2:
        nonce = nip05._SECP256K1_N - nonce
        nonce_point = nip05._point_multiply(nonce, nip05._SECP256K1_G)
    r = nonce_point[0].to_bytes(32, "big")
    challenge = int.from_bytes(
        nip05._tagged_hash("BIP0340/challenge", r + public_key + message),
        "big",
    ) % nip05._SECP256K1_N
    s = (nonce + challenge * secret) % nip05._SECP256K1_N
    return r + s.to_bytes(32, "big")


def test_external_lookup_continues_after_unusable_relay():
    attempted = []

    class Connection:
        def send(self, message):
            request = json.loads(message)
            if request[0] == "REQ":
                self.subscription_id = request[1]

        def settimeout(self, timeout):
            pass

        def recv_frame(self):
            return SimpleNamespace(
                opcode=nip05.websocket.ABNF.OPCODE_TEXT,
                fin=True,
                data=json.dumps(["EOSE", self.subscription_id]).encode("utf-8"),
            )

        def close(self):
            pass

    def opener(relay_url, timeout):
        attempted.append(relay_url)
        if len(attempted) == 1:
            raise Nip05VerificationError("private relay address")
        return Connection()

    lookup_external_kind0(
        PUBKEY_A,
        ["wss://bad.example", "wss://good.example"],
        time.monotonic() + 1,
        websocket_opener=opener,
    )

    assert attempted == ["wss://bad.example", "wss://good.example"]
