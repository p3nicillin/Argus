from __future__ import annotations

from typing import Any
from urllib.parse import quote_plus

US_STATES_AND_TERRITORIES: dict[str, str] = {
    "AL": "Alabama",
    "AK": "Alaska",
    "AZ": "Arizona",
    "AR": "Arkansas",
    "CA": "California",
    "CO": "Colorado",
    "CT": "Connecticut",
    "DE": "Delaware",
    "DC": "District of Columbia",
    "FL": "Florida",
    "GA": "Georgia",
    "HI": "Hawaii",
    "ID": "Idaho",
    "IL": "Illinois",
    "IN": "Indiana",
    "IA": "Iowa",
    "KS": "Kansas",
    "KY": "Kentucky",
    "LA": "Louisiana",
    "ME": "Maine",
    "MD": "Maryland",
    "MA": "Massachusetts",
    "MI": "Michigan",
    "MN": "Minnesota",
    "MS": "Mississippi",
    "MO": "Missouri",
    "MT": "Montana",
    "NE": "Nebraska",
    "NV": "Nevada",
    "NH": "New Hampshire",
    "NJ": "New Jersey",
    "NM": "New Mexico",
    "NY": "New York",
    "NC": "North Carolina",
    "ND": "North Dakota",
    "OH": "Ohio",
    "OK": "Oklahoma",
    "OR": "Oregon",
    "PA": "Pennsylvania",
    "RI": "Rhode Island",
    "SC": "South Carolina",
    "SD": "South Dakota",
    "TN": "Tennessee",
    "TX": "Texas",
    "UT": "Utah",
    "VT": "Vermont",
    "VA": "Virginia",
    "WA": "Washington",
    "WV": "West Virginia",
    "WI": "Wisconsin",
    "WY": "Wyoming",
    "AS": "American Samoa",
    "GU": "Guam",
    "MP": "Northern Mariana Islands",
    "PR": "Puerto Rico",
    "VI": "U.S. Virgin Islands",
}


def normalize_state(value: str) -> tuple[str, str] | None:
    cleaned = value.strip().casefold().replace(".", "")
    if not cleaned:
        return None
    upper = cleaned.upper()
    if upper in US_STATES_AND_TERRITORIES:
        return upper, US_STATES_AND_TERRITORIES[upper]
    for code, name in US_STATES_AND_TERRITORIES.items():
        if cleaned == name.casefold():
            return code, name
    return None


def election_resources(state: tuple[str, str] | None = None) -> list[dict[str, Any]]:
    state_code = state[0] if state else ""
    state_name = state[1] if state else ""
    return [
        {
            "name": "Vote.gov registration and updates",
            "url": "https://vote.gov/register",
            "source": "U.S. Election Assistance Commission / Vote.gov",
            "purpose": "Register, update registration, check status, or get a registration card.",
            "state_code": state_code,
            "state": state_name,
            "requires_user_input": True,
            "cost": "free",
        },
        {
            "name": "NASS Can I Vote registration status",
            "url": "https://www.nass.org/can-I-vote/voter-registration-status",
            "source": "National Association of Secretaries of State",
            "purpose": "Select a state and go to the official state registration-status resource.",
            "state_code": state_code,
            "state": state_name,
            "requires_user_input": True,
            "cost": "free",
        },
        {
            "name": "NASS Can I Vote polling place",
            "url": "https://www.nass.org/can-I-vote/find-your-polling-place",
            "source": "National Association of Secretaries of State",
            "purpose": "Find official polling-place resources by state.",
            "state_code": state_code,
            "state": state_name,
            "requires_user_input": True,
            "cost": "free",
        },
        {
            "name": "USA.gov registration confirmation guide",
            "url": "https://www.usa.gov/confirm-voter-registration",
            "source": "USA.gov",
            "purpose": "Federal guidance for checking registration through official state sites.",
            "state_code": state_code,
            "state": state_name,
            "requires_user_input": True,
            "cost": "free",
        },
    ]


def census_geocoder_params(address: str) -> dict[str, str]:
    return {
        "address": address,
        "benchmark": "Public_AR_Current",
        "vintage": "Current_Current",
        "format": "json",
    }


def census_matches(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return list(((payload or {}).get("result") or {}).get("addressMatches") or [])


def best_census_match(payload: dict[str, Any]) -> dict[str, Any]:
    matches = census_matches(payload)
    return matches[0] if matches else {}


def state_from_census_match(match: dict[str, Any]) -> tuple[str, str] | None:
    components = match.get("addressComponents", {}) if match else {}
    return normalize_state(str(components.get("state", "")))


def geography_summary(match: dict[str, Any]) -> dict[str, Any]:
    geographies = match.get("geographies", {}) if match else {}
    summary: dict[str, Any] = {}
    for layer, values in geographies.items():
        if isinstance(values, list) and values:
            item = values[0]
            summary[layer] = {
                key: item.get(key)
                for key in ("NAME", "GEOID", "BASENAME", "CENTLAT", "CENTLON")
                if item.get(key) not in (None, "")
            }
    return summary


def government_record_leads(address: str, match: dict[str, Any]) -> list[dict[str, Any]]:
    components = match.get("addressComponents", {}) if match else {}
    geographies = geography_summary(match)
    county = ""
    state = components.get("state", "")
    county_values = geographies.get("Counties") or geographies.get("County")
    if county_values:
        county = str(county_values.get("NAME") or county_values.get("BASENAME") or "")
    queries = [
        ("County property assessor", f"{county} {state} property assessor {address}"),
        ("County recorder property records", f"{county} {state} recorder property records {address}"),
        ("County GIS parcel search", f"{county} {state} GIS parcel search {address}"),
        ("County election office", f"{county} {state} election office voter registration"),
        ("State voter registration", f"{state} voter registration official"),
    ]
    leads = []
    for title, query in queries:
        cleaned = " ".join(query.split())
        leads.append({
            "title": title,
            "query": cleaned,
            "search_url": "https://search.usa.gov/search?affiliate=usagov&query="
            + quote_plus(cleaned),
            "status": "official public-record search lead",
            "identity_match": False,
        })
    return leads
