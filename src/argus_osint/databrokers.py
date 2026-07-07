"""Data-broker / people-search exposure knowledge base.

Given a subject (a name or email), this produces *unverified leads*: the
public people-search and data-broker sites that may hold a record, with a
direct search URL for each. It is the reconnaissance analogue of
``UsernameCorrelationCollector`` — a matching listing does not establish that a
record belongs to the subject; an investigator must review each source.

This module is intentionally dependency-free so its logic is unit-testable
without the network/GUI stack. The collector wrapper lives in ``collectors.py``.

The registry is derived from the curated set maintained in the companion
Privacy-Reclaim project (people-search, background-check, marketing-data and
credit-bureau sites). Only lawful, public search surfaces are referenced.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote_plus


@dataclass(frozen=True, slots=True)
class Broker:
    slug: str
    name: str
    category: str
    home: str
    # search_url uses {q} for a URL-encoded query; empty => no direct search surface
    search_url: str


# A focused, high-signal set of public people-search / data-broker surfaces.
BROKERS: tuple[Broker, ...] = (
    Broker("spokeo", "Spokeo", "people-search", "https://www.spokeo.com",
           "https://www.spokeo.com/{q}"),
    Broker("whitepages", "Whitepages", "people-search", "https://www.whitepages.com",
           "https://www.whitepages.com/name/{q}"),
    Broker("beenverified", "BeenVerified", "people-search", "https://www.beenverified.com",
           "https://www.beenverified.com/people/{q}/"),
    Broker("truepeoplesearch", "TruePeopleSearch", "people-search",
           "https://www.truepeoplesearch.com",
           "https://www.truepeoplesearch.com/results?name={q}"),
    Broker("fastpeoplesearch", "FastPeopleSearch", "people-search",
           "https://www.fastpeoplesearch.com",
           "https://www.fastpeoplesearch.com/name/{q}"),
    Broker("radaris", "Radaris", "people-search", "https://radaris.com",
           "https://radaris.com/p/{q}"),
    Broker("intelius", "Intelius", "background-check", "https://www.intelius.com",
           "https://www.intelius.com/people-search/{q}/"),
    Broker("peoplefinders", "PeopleFinders", "people-search",
           "https://www.peoplefinders.com",
           "https://www.peoplefinders.com/name/{q}"),
    Broker("mylife", "MyLife", "people-search", "https://www.mylife.com",
           "https://www.mylife.com/search?q={q}"),
    Broker("searchpeoplefree", "SearchPeopleFree", "people-search",
           "https://www.searchpeoplefree.com",
           "https://www.searchpeoplefree.com/find/{q}"),
    Broker("usphonebook", "USPhonebook", "people-search",
           "https://www.usphonebook.com",
           "https://www.usphonebook.com/{q}"),
    Broker("clustrmaps", "ClustrMaps", "people-search", "https://clustrmaps.com",
           "https://clustrmaps.com/persons/{q}"),
    Broker("192com", "192.com", "people-search", "https://www.192.com",
           "https://www.192.com/people/search/?name={q}"),
    Broker("nuwber", "Nuwber", "people-search", "https://nuwber.com",
           "https://nuwber.com/search?name={q}"),
    Broker("peekyou", "PeekYou", "people-search", "https://www.peekyou.com",
           "https://www.peekyou.com/{q}"),
    Broker("thatsthem", "ThatsThem", "people-search", "https://thatsthem.com",
           "https://thatsthem.com/name/{q}"),
    Broker("zabasearch", "ZabaSearch", "people-search", "https://www.zabasearch.com",
           "https://www.zabasearch.com/people/{q}/"),
    Broker("ussearch", "US Search", "background-check", "https://www.ussearch.com",
           "https://www.ussearch.com/name/{q}/"),
    Broker("anywho", "AnyWho", "people-search", "https://www.anywho.com",
           "https://www.anywho.com/people/{q}/"),
    Broker("cyberbackgroundchecks", "CyberBackgroundChecks", "background-check",
           "https://www.cyberbackgroundchecks.com",
           "https://www.cyberbackgroundchecks.com/people/{q}"),
    Broker("advancedbackgroundchecks", "Advanced Background Checks", "background-check",
           "https://www.advancedbackgroundchecks.com",
           "https://www.advancedbackgroundchecks.com/names/{q}"),
    Broker("peoplelooker", "PeopleLooker", "people-search",
           "https://www.peoplelooker.com",
           "https://www.peoplelooker.com/f/name/{q}"),
    Broker("truthfinder", "TruthFinder", "background-check", "https://www.truthfinder.com",
           "https://www.truthfinder.com/results/?fn={q}"),
    Broker("ukphonebook", "UKPhonebook", "people-search", "https://www.ukphonebook.com",
           "https://www.ukphonebook.com/search/people?name={q}"),
)


def _looks_like_email(query: str) -> bool:
    q = query.strip()
    return "@" in q and "." in q.split("@")[-1]


def candidate_links(query: str) -> list[dict]:
    """Return one candidate-lead dict per broker for the given subject.

    For a name, ``{q}`` is filled with the URL-encoded name. For an email, the
    local part is used as the search term (brokers do not search by full email).
    """
    q = (query or "").strip()
    if not q:
        raise ValueError("Enter a name or email to check for data-broker exposure")

    term = q.split("@", 1)[0] if _looks_like_email(q) else q
    encoded = quote_plus(term)

    leads = []
    for b in BROKERS:
        if not b.search_url:
            continue  # no public search surface -> not an actionable lead
        leads.append({
            "broker": b.name,
            "category": b.category,
            "search_url": b.search_url.replace("{q}", encoded),
            "home": b.home,
            "status": "unverified candidate",
            "identity_match": False,
        })
    return leads


def categories() -> list[str]:
    return sorted({b.category for b in BROKERS})
