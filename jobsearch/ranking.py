"""Transparent rule ranking over public text and operator-supplied preferences."""

import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta

from .store import normalized

H1B = r"h\s*-?\s*1\s*-?\s*b"
VISA = rf"(?:{H1B}(?: visa)?(?: sponsorship)?|(?:visa|immigration|work[- ]authorization) sponsorship)"
PUNCTUATION = str.maketrans(
    {
        **dict.fromkeys("‘’ʼ", "'"),
        **dict.fromkeys("‐‑‒–—―−", "-"),
    }
)
EMPLOYER = r"(?:we|(?:the|our) (?:company|employer))"
SUBJECT = rf"(?:{EMPLOYER}|[\w.&-]+(?: [\w.&-]+){{0,3}})"  # "Acme AI is unable to ..." names the company
LEAD_IN = re.compile(r"^(?:(?:please )?note:?|at this time|currently|unfortunately|at the moment)[,:]?\s+", re.I)
ROLE = r"(?:(?:this|the) (?:role|position|opening|job)|role-specific)"
ACTION = (
    rf"(?:(?:offer|provide|support) (?:any )?(?:employment )?{VISA}|sponsor (?:{H1B}(?: visas?)?|(?:work )?visas?))"
)
VISA_CONTEXT = re.compile(rf"{VISA}\b|\bsponsor (?:work )?visas?\b", re.I)
NEGATIVE = re.compile(
    rf"(?:for {ROLE}, )?(?:no {VISA}(?: is available)?|"
    rf"{SUBJECT} (?:cannot|can't|don't|do not|does not|will not|won't|"
    rf"(?:are|is) unable to) (?:currently )?{ACTION}|"
    rf"{VISA} (?:is |will be )?(?:not (?:currently )?(?:available|offered|provided|supported)|unavailable)|"
    rf"{ROLE} is (?:not eligible|ineligible) for {VISA})(?: for {ROLE})?",
    re.I,
)
POSITIVE = re.compile(
    rf"^(?:{EMPLOYER} (?:(?:do|can|will|currently) )?"
    rf"(?:(?:offer|provide|support) {VISA}|sponsor {H1B}(?: visas?)?)|"
    rf"{VISA} (?:is |will be )(?:currently )?(?:available|offered|provided|supported)|"
    rf"{ROLE} is eligible for {VISA})"
    rf"(?: (?:for {ROLE}|for eligible candidates))?$",
    re.I,
)

ROLE_SCOPE = re.compile(rf"\b{ROLE}\b", re.I)
QUALIFIER = re.compile(r"\b(?:may|might|could|subject to|depending on|only|unless|if|except)\b", re.I)


def _sponsorship(description):
    text = unicodedata.normalize("NFKC", description).translate(PUNCTUATION)
    general_support = role_support = ""
    restricted = uncertain = role_uncertain = mentioned = False
    for sentence in re.findall(r"[^.!?]+[.!?]?", text):
        statement = " ".join(sentence.rstrip(".!?").split())
        statement = re.sub(r"(sponsorship)\s*:\s*", r"\1 is ", statement, flags=re.I)
        while LEAD_IN.match(statement):
            statement = LEAD_IN.sub("", statement, count=1)
        if not VISA_CONTEXT.search(statement):
            continue
        mentioned = True
        if sentence.endswith("?"):
            continue
        if QUALIFIER.search(statement):
            uncertain = True
            role_uncertain |= bool(ROLE_SCOPE.search(statement))
            continue
        for clause in re.split(rf"\s*;\s*|,?\s+but\s+(?=(?:{EMPLOYER}|{VISA}|{ROLE})\b)", statement, flags=re.I):
            if not VISA_CONTEXT.search(clause):
                continue
            if NEGATIVE.fullmatch(clause):
                restricted = True
            elif POSITIVE.fullmatch(clause):
                if ROLE_SCOPE.search(clause):
                    if re.search(H1B, clause, re.I):
                        role_support = "explicit role-level H-1B sponsorship wording"
                    elif not role_support:
                        role_support = "role-level visa sponsorship wording"
                elif re.search(H1B, clause, re.I):
                    general_support = "general H-1B sponsorship wording"
                elif not general_support:
                    general_support = "general visa sponsorship wording"
            elif ROLE_SCOPE.search(clause):
                role_uncertain = True
    if restricted and (role_support or general_support):
        return "conflicting wording", False
    if role_uncertain:
        return "uncertain role eligibility", False
    if uncertain:
        return "ambiguous sponsorship wording", False
    if restricted:
        return "sponsorship restriction wording", True
    if role_support:
        return role_support, False
    if general_support:
        return general_support, False
    return ("ambiguous sponsorship wording" if mentioned else "no explicit evidence found"), False


@dataclass(frozen=True)
class Profile:
    roles: tuple[str, ...]
    skills: tuple[str, ...]
    excluded_titles: tuple[str, ...]
    locations: tuple[str, ...]
    prefer_remote: bool
    require_location: bool
    exclude_visa_denials: bool
    freshness_days: int
    shortlist_size: int

    @classmethod
    def load(cls, value):
        if not isinstance(value, dict) or set(value) != set(cls.__annotations__):
            raise ValueError("invalid profile keys")
        for key in ("roles", "skills", "excluded_titles", "locations"):
            terms = value[key]
            if (
                not isinstance(terms, list)
                or len(terms) > 50
                or any(not isinstance(term, str) or not term.strip() or len(term) > 100 for term in terms)
            ):
                raise ValueError(f"invalid {key} terms")
        if not value["roles"]:
            raise ValueError("profile needs role terms")
        for key in ("prefer_remote", "require_location", "exclude_visa_denials"):
            if type(value[key]) is not bool:
                raise ValueError(f"invalid {key}")
        for key, limit in (("freshness_days", 365), ("shortlist_size", 200)):
            if type(value[key]) is not int or not 1 <= value[key] <= limit:
                raise ValueError(f"invalid {key}")
        return cls(
            **{
                key: tuple(dict.fromkeys(map(normalized, item))) if isinstance(item, list) else item
                for key, item in value.items()
            }
        )


def _hits(terms, text):
    return [term for term in terms if re.search(r"(?<!\w)" + re.escape(term) + r"(?!\w)", text)]


def rank(rows, profile, now, *, include_older=False, sponsorship_informational=False):
    candidates = []
    for row in rows:
        posting = json.loads(row["body"])
        title = normalized(posting["title"])
        roles = _hits(profile.roles, title)
        excluded = _hits(profile.excluded_titles, title)
        skills = _hits(profile.skills, normalized(posting["description"]))
        location = _hits(profile.locations, normalized(" / ".join([posting["location"], *posting["secondary"]])))
        # Remote is a workplace signal. Eligibility still comes from location text.
        remote = posting["workplace"] == "Remote" and profile.prefer_remote
        visa, denied = _sponsorship(posting["description"])
        denied = denied and not sponsorship_informational
        changed_at = datetime.fromisoformat(row["changed_at"])
        fresh = changed_at >= now - timedelta(days=profile.freshness_days)
        eligible = (
            bool(roles)
            and not excluded
            and (bool(location) or not profile.require_location)
            and not (denied and profile.exclude_visa_denials)
        )
        if not row["selected"] and (not eligible or not (fresh or include_older)):
            continue
        score = 40 * bool(roles) + min(24, 6 * len(skills)) + 10 * bool(row["startup"])
        score += 12 * bool(location) + 5 * remote - 20 * bool(denied)
        score -= 30 * bool(excluded)
        reasons = [f"Role match: {', '.join(roles)}" if roles else "No configured role match"]
        if excluded:
            reasons.append(f"Excluded title terms: {', '.join(excluded)}")
        if skills:
            reasons.append(f"Skills: {', '.join(skills)}")
        if row["startup"]:
            reasons.append("Startup marked in the board list")
        if location:
            reasons.append(f"Location match: {', '.join(location)}")
        elif profile.require_location:
            reasons.append("No configured location match")
        if remote:
            reasons.append("Remote workplace listed")
        if posting["published"]:
            age = (now - datetime.fromisoformat(posting["published"])).days
            if 0 <= age <= profile.freshness_days:
                score += 12
                reasons.append(f"Last published {age}d ago")
        if fresh:
            score += 8
            reasons.append("First discovered or changed in the freshness window")
        reasons.append(f"H-1B: {visa}")
        if row["possible_duplicate"]:
            reasons.append("Possible duplicate across sources")
        candidates.append(dict(row) | {"posting": posting, "score": score, "reasons": reasons})
    candidates.sort(
        key=lambda item: (
            -item["score"],
            -datetime.fromisoformat(item["changed_at"]).timestamp(),
            normalized(item["company"]),
            normalized(item["posting"]["title"]),
            item["posting"]["url"],
            item["id"],
        )
    )
    selected = [item for item in candidates if item["selected"]]
    available = [item for item in candidates if not item["selected"]]
    return selected, available[: profile.shortlist_size]
