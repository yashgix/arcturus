"""Versioned, manually populated candidate profile. No document extraction."""

from .store import normalized


def _text(value, maximum):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= maximum


def _strings(value, limit, maximum):
    return (
        isinstance(value, list)
        and len(value) <= limit
        and all(_text(item, maximum) for item in value)
        and len(set(value)) == len(value)
    )


def load_profile(raw):
    keys = {"schema_version", "revision", "mode", "sources", "variants", "facts", "locations"}
    if (
        not isinstance(raw, dict)
        or set(raw) != keys
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or not _text(raw["revision"], 48)
        or raw["mode"] not in ("synthetic", "operator_verified")
    ):
        raise ValueError("invalid candidate profile header")
    sources, variants, facts = (raw[key] for key in ("sources", "variants", "facts"))
    for collection, maximum in ((sources, 20), (variants, 10), (facts, 30)):
        if (
            not isinstance(collection, dict)
            or not 1 <= len(collection) <= maximum
            or not all(_text(key, 48) for key in collection)
        ):
            raise ValueError("invalid candidate profile collection")
    for source in sources.values():
        if (
            not isinstance(source, dict)
            or set(source) != {"document", "locator"}
            or not all(_text(value, 160) for value in source.values())
        ):
            raise ValueError("invalid candidate source reference")
    for fact in facts.values():
        if (
            not isinstance(fact, dict)
            or set(fact) != {"claim", "verified", "technologies", "metrics", "source_refs"}
            or not _text(fact["claim"], 500)
            or type(fact["verified"]) is not bool
            or not _strings(fact["technologies"], 12, 64)
            or not _strings(fact["metrics"], 8, 120)
            or not _strings(fact["source_refs"], 8, 48)
            or not fact["source_refs"]
            or not set(fact["source_refs"]) <= set(sources)
        ):
            raise ValueError("invalid candidate fact")
    for fact_ids in variants.values():
        if not _strings(fact_ids, 30, 48) or not fact_ids or not set(fact_ids) <= set(facts):
            raise ValueError("invalid candidate variant")
    if not any(facts[key]["verified"] for ids in variants.values() for key in ids):
        raise ValueError("at least one resume variant needs a verified fact")
    locations = raw["locations"]
    if (
        not isinstance(locations, dict)
        or set(locations) != {"allowed_terms", "require_match"}
        or not _strings(locations["allowed_terms"], 30, 80)
        or not locations["allowed_terms"]
        or type(locations["require_match"]) is not bool
    ):
        raise ValueError("invalid candidate location constraints")
    return {
        **raw,
        "locations": {**locations, "allowed_terms": [normalized(term) for term in locations["allowed_terms"]]},
    }


def model_facts(profile):
    """Expose approved claims and reference IDs without local document locators."""
    variants = {
        name: [key for key in ids if profile["facts"][key]["verified"]] for name, ids in profile["variants"].items()
    }
    keys = set().union(*variants.values())
    facts = {key: profile["facts"][key] for key in sorted(keys)}
    return facts, variants
