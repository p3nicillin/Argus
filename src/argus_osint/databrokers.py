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
    opt_out_url: str = ""
    privacy_url: str = ""
    note: str = ""


# A focused, high-signal set of public people-search / data-broker surfaces.
BROKERS: tuple[Broker, ...] = (
    Broker("spokeo", "Spokeo", "people-search", "https://www.spokeo.com",
           "https://www.spokeo.com/{q}",
           "https://www.spokeo.com/optout",
           "https://www.spokeo.com/privacy-policy"),
    Broker("whitepages", "Whitepages", "people-search", "https://www.whitepages.com",
           "https://www.whitepages.com/name/{q}",
           "https://www.whitepages.com/suppression-requests",
           "https://www.whitepages.com/privacy"),
    Broker("beenverified", "BeenVerified", "people-search", "https://www.beenverified.com",
           "https://www.beenverified.com/people/{q}/",
           "https://www.beenverified.com/app/optout/search"),
    Broker("truepeoplesearch", "TruePeopleSearch", "people-search",
           "https://www.truepeoplesearch.com",
           "https://www.truepeoplesearch.com/results?name={q}",
           "https://www.truepeoplesearch.com/removal"),
    Broker("fastpeoplesearch", "FastPeopleSearch", "people-search",
           "https://www.fastpeoplesearch.com",
           "https://www.fastpeoplesearch.com/name/{q}",
           "https://www.fastpeoplesearch.com/removal"),
    Broker("radaris", "Radaris", "people-search", "https://radaris.com",
           "https://radaris.com/p/{q}",
           "https://radaris.com/control/privacy"),
    Broker("intelius", "Intelius", "background-check", "https://www.intelius.com",
           "https://www.intelius.com/people-search/{q}/",
           "https://suppression.peopleconnect.us/login"),
    Broker("peoplefinders", "PeopleFinders", "people-search",
           "https://www.peoplefinders.com",
           "https://www.peoplefinders.com/name/{q}",
           "https://www.peoplefinders.com/opt-out"),
    Broker("mylife", "MyLife", "people-search", "https://www.mylife.com",
           "https://www.mylife.com/search?q={q}",
           "https://www.mylife.com/ccpa/index.pubview"),
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
           "https://nuwber.com/search?name={q}",
           "https://nuwber.com/removal/link"),
    Broker("peekyou", "PeekYou", "people-search", "https://www.peekyou.com",
           "https://www.peekyou.com/{q}"),
    Broker("thatsthem", "ThatsThem", "people-search", "https://thatsthem.com",
           "https://thatsthem.com/name/{q}",
           "https://thatsthem.com/optout"),
    Broker("zabasearch", "ZabaSearch", "people-search", "https://www.zabasearch.com",
           "https://www.zabasearch.com/people/{q}/"),
    Broker("ussearch", "US Search", "background-check", "https://www.ussearch.com",
           "https://www.ussearch.com/name/{q}/",
           "https://suppression.peopleconnect.us/login"),
    Broker("anywho", "AnyWho", "people-search", "https://www.anywho.com",
           "https://www.anywho.com/people/{q}/"),
    Broker("cyberbackgroundchecks", "CyberBackgroundChecks", "background-check",
           "https://www.cyberbackgroundchecks.com",
           "https://www.cyberbackgroundchecks.com/people/{q}"),
    Broker("advancedbackgroundchecks", "Advanced Background Checks", "background-check",
           "https://www.advancedbackgroundchecks.com",
           "https://www.advancedbackgroundchecks.com/names/{q}",
           "https://www.advancedbackgroundchecks.com/removal"),
    Broker("peoplelooker", "PeopleLooker", "people-search",
           "https://www.peoplelooker.com",
           "https://www.peoplelooker.com/f/name/{q}",
           "https://www.peoplelooker.com/f/optout/search"),
    Broker("truthfinder", "TruthFinder", "background-check", "https://www.truthfinder.com",
           "https://www.truthfinder.com/results/?fn={q}",
           "https://www.truthfinder.com/opt-out"),
    Broker("ukphonebook", "UKPhonebook", "people-search", "https://www.ukphonebook.com",
           "https://www.ukphonebook.com/search/people?name={q}"),
    Broker("instantcheckmate", "Instant Checkmate", "background-check",
           "https://www.instantcheckmate.com",
           "https://www.instantcheckmate.com/people-search/{q}/",
           "https://www.instantcheckmate.com/opt-out"),
    Broker("familytreenow", "FamilyTreeNow", "people-search", "https://www.familytreenow.com",
           "https://www.familytreenow.com/search/genealogy/results?firstlast={q}",
           "https://www.familytreenow.com/optout"),
    Broker("peoplewhiz", "PeopleWhiz", "people-search", "https://www.peoplewhiz.com",
           "https://www.peoplewhiz.com/search?name={q}"),
    Broker("publicrecordsnow", "PublicRecordsNow", "public-records",
           "https://www.publicrecordsnow.com",
           "https://www.publicrecordsnow.com/name/{q}"),
    Broker("addresses", "Addresses.com", "people-search", "https://www.addresses.com",
           "https://www.addresses.com/people/{q}"),
    Broker("411", "411.com", "people-search", "https://www.411.com",
           "https://www.411.com/name/{q}"),
    Broker("numlookup", "NumLookup", "phone-lookup", "https://www.numlookup.com",
           "https://www.numlookup.com/people-search/{q}"),
    Broker("spytox", "Spytox", "people-search", "https://www.spytox.com",
           "https://www.spytox.com/people/search?name={q}"),
    Broker("spyfly", "SpyFly", "background-check", "https://www.spyfly.com",
           "https://www.spyfly.com/people-search/{q}"),
    Broker("idcrawl", "IDCrawl", "people-search", "https://www.idcrawl.com",
           "https://www.idcrawl.com/{q}"),
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
            "opt_out_url": b.opt_out_url,
            "privacy_url": b.privacy_url,
            "removal_status": "manual opt-out available" if b.opt_out_url else "review source policy",
            "note": b.note,
            "status": "unverified candidate",
            "identity_match": False,
        })
    return leads


def categories() -> list[str]:
    return sorted({b.category for b in BROKERS})
