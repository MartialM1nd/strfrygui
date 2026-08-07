from models import BannedDomain, BannedPubkey, EventPurge, PubkeyBanSource, db
from utils.domain_view import domain_identity_page, unresolved_identity_page
from utils.strfry import hex_to_npub, npub_to_hex


PUBKEY_A = "a" * 64
PUBKEY_B = "b" * 64


def add_domain_source(domain, pubkey, local_name):
    ban = BannedPubkey.query.filter_by(pubkey=pubkey).first()
    if ban is None:
        ban = BannedPubkey(pubkey=pubkey, reason="Domain ban", banned_by=7)
        db.session.add(ban)
        db.session.flush()
    source = PubkeyBanSource(
        banned_pubkey_id=ban.id,
        source_type="domain",
        banned_domain_id=domain.id,
        local_name=local_name,
        reason="Domain ban",
        banned_by=7,
    )
    db.session.add(source)
    db.session.flush()
    return ban, source


def test_hex_to_npub_round_trip():
    npub = hex_to_npub(PUBKEY_A)

    assert npub.startswith("npub1")
    assert npub_to_hex(npub) == PUBKEY_A


def test_domain_identity_page_filters_sources_and_selects_latest_purge(app):
    domain = BannedDomain(domain="example.com", banned_by=7)
    other_domain = BannedDomain(domain="other.example", banned_by=7)
    db.session.add_all([domain, other_domain])
    db.session.flush()
    ban_a, source_a = add_domain_source(domain, PUBKEY_A, "alice")
    add_domain_source(domain, PUBKEY_B, "bob")
    add_domain_source(other_domain, PUBKEY_A, "alice")
    db.session.add(PubkeyBanSource(
        banned_pubkey_id=ban_a.id,
        source_type="direct",
        reason="Direct ban",
        banned_by=7,
    ))
    db.session.add_all([
        EventPurge(target_type="pubkey", target=PUBKEY_A, status="completed"),
        EventPurge(target_type="pubkey", target=PUBKEY_A, status="pending"),
    ])
    db.session.commit()

    page = domain_identity_page(domain.id, "alice", offset=0, limit=50)

    assert page.total == 1
    assert page.rows[0].source.id == source_a.id
    assert page.rows[0].npub == hex_to_npub(PUBKEY_A)
    assert page.rows[0].purge.status == "pending"
    assert page.rows[0].other_sources == ("direct", "other.example")


def test_domain_identity_page_searches_by_npub_and_paginates(app):
    domain = BannedDomain(domain="example.com", banned_by=7)
    db.session.add(domain)
    db.session.flush()
    add_domain_source(domain, PUBKEY_A, "alice")
    add_domain_source(domain, PUBKEY_B, "bob")
    db.session.commit()

    by_npub = domain_identity_page(domain.id, hex_to_npub(PUBKEY_B), 0, 50)
    by_upper_npub = domain_identity_page(domain.id, hex_to_npub(PUBKEY_B).upper(), 0, 50)
    first_page = domain_identity_page(domain.id, "", 0, 1)

    assert [row.source.local_name for row in by_npub.rows] == ["bob"]
    assert [row.source.local_name for row in by_upper_npub.rows] == ["bob"]
    assert first_page.total == 2
    assert len(first_page.rows) == 1


def test_unresolved_identity_page_filters_complete_feedback(app):
    domain = BannedDomain(domain="example.com", banned_by=7)
    domain.last_scan_details = """{
        "unresolved": 2,
        "unresolved_entries": [
            {"name": "alice", "pubkey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "error": "Not found"},
            {"name": "bob", "pubkey": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "error": "Timeout"}
        ]
    }"""
    db.session.add(domain)
    db.session.commit()

    page = unresolved_identity_page(domain, "bob", offset=0, limit=50)

    assert page.total == 1
    assert page.rows[0]["name"] == "bob"
    assert page.incomplete is False


def test_unresolved_identity_page_marks_legacy_truncation(app):
    domain = BannedDomain(domain="example.com", banned_by=7)
    domain.last_scan_details = """{
        "unresolved": 3,
        "unresolved_entries": [
            {"name": "alice", "pubkey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "error": "Not found"}
        ]
    }"""
    db.session.add(domain)
    db.session.commit()

    page = unresolved_identity_page(domain, "", offset=0, limit=50)

    assert page.reported_total == 3
    assert page.incomplete is True
