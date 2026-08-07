from dataclasses import dataclass

from sqlalchemy import or_
from sqlalchemy.orm import joinedload

from models import BannedPubkey, EventPurge, PubkeyBanSource
from utils.strfry import hex_to_npub, npub_to_hex


@dataclass(frozen=True)
class DomainIdentityRow:
    source: PubkeyBanSource
    npub: str
    purge: EventPurge | None
    other_sources: tuple[str, ...]


@dataclass(frozen=True)
class Page:
    rows: tuple
    total: int


@dataclass(frozen=True)
class UnresolvedPage:
    rows: tuple
    total: int
    reported_total: int
    incomplete: bool


def domain_identity_page(domain_id, search='', offset=0, limit=50):
    query = PubkeyBanSource.query.join(BannedPubkey).filter(
        PubkeyBanSource.source_type == 'domain',
        PubkeyBanSource.banned_domain_id == domain_id,
    )
    query = _filter_sources(query, search)
    total = query.count()
    query = query.options(
        joinedload(PubkeyBanSource.banned_pubkey)
        .selectinload(BannedPubkey.sources)
        .joinedload(PubkeyBanSource.banned_domain)
    ).order_by(
        PubkeyBanSource.local_name,
        BannedPubkey.pubkey,
        PubkeyBanSource.id,
    )
    if limit is not None:
        query = query.offset(offset).limit(limit)
    sources = query.all()
    purges = _latest_purges([source.banned_pubkey.pubkey for source in sources])
    rows = tuple(
        DomainIdentityRow(
            source=source,
            npub=hex_to_npub(source.banned_pubkey.pubkey),
            purge=purges.get(source.banned_pubkey.pubkey),
            other_sources=_other_source_labels(source),
        )
        for source in sources
    )
    return Page(rows=rows, total=total)


def unresolved_identity_page(domain, search='', offset=0, limit=50):
    rows = []
    search = search.strip().lower()
    search_pubkey = _search_pubkey(search)
    for entry in domain.scan_details.get('unresolved_entries', []):
        if not isinstance(entry, dict):
            continue
        name = entry.get('name')
        pubkey = entry.get('pubkey')
        error = entry.get('error')
        if not all(isinstance(value, str) for value in (name, pubkey, error)):
            continue
        identity = f'{name}@{domain.domain}'.lower()
        if search and not (
            search in name.lower()
            or search in identity
            or search in pubkey.lower()
            or search_pubkey == pubkey
        ):
            continue
        rows.append({'name': name, 'pubkey': pubkey, 'error': error})
    total = len(rows)
    reported_total = domain.scan_details.get('unresolved', total)
    if not isinstance(reported_total, int):
        reported_total = total
    stored_total = len([
        entry
        for entry in domain.scan_details.get('unresolved_entries', [])
        if isinstance(entry, dict)
    ])
    if limit is not None:
        rows = rows[offset:offset + limit]
    return UnresolvedPage(
        rows=tuple(rows),
        total=total,
        reported_total=reported_total,
        incomplete=reported_total > stored_total,
    )


def _filter_sources(query, search):
    search = search.strip()
    if not search:
        return query
    search_pubkey = _search_pubkey(search)
    local_search = search
    if '@' in search:
        local_search = search.split('@', 1)[0]
    conditions = [
        PubkeyBanSource.local_name.contains(local_search, autoescape=True),
        BannedPubkey.pubkey.contains(search.lower(), autoescape=True),
    ]
    if search_pubkey:
        conditions.append(BannedPubkey.pubkey == search_pubkey)
    return query.filter(or_(*conditions))


def _search_pubkey(search):
    search = search.lower()
    if not search.startswith('npub1'):
        return None
    try:
        return npub_to_hex(search)
    except ValueError:
        return None


def _latest_purges(pubkeys):
    if not pubkeys:
        return {}
    rows = EventPurge.query.filter(
        EventPurge.target_type == 'pubkey',
        EventPurge.target.in_(pubkeys),
    ).order_by(
        EventPurge.target,
        EventPurge.created_at.desc(),
        EventPurge.id.desc(),
    )
    purges = {}
    for purge in rows:
        purges.setdefault(purge.target, purge)
    return purges


def _other_source_labels(current_source):
    labels = []
    for source in current_source.banned_pubkey.sources:
        if source.id == current_source.id:
            continue
        if source.source_type == 'direct':
            labels.append('direct')
        elif source.banned_domain is not None:
            labels.append(source.banned_domain.domain)
        else:
            labels.append('deleted domain')
    return tuple(sorted(labels, key=lambda label: (label != 'direct', label)))
