import csv
import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

LIVE_STATUSES = {"active", "renewed"}
FIELD_ALIASES = {
    "name": ("data handler name", "name", "organisation", "organization", "entity name"),
    "type": ("data handler type", "type", "registration type"),
    "registration_number": ("registration number", "registration no", "reg no"),
    "county": ("county",),
    "country": ("country",),
    "status": ("status", "registration status"),
}
STOPWORDS = {
    "and",
    "co",
    "company",
    "for",
    "inc",
    "incorporated",
    "limited",
    "llp",
    "ltd",
    "of",
    "plc",
    "the",
}


class _TableParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows = []
        self._row = None
        self._cell = None
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "tr":
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag in ("td", "th") and self._cell is not None:
            self._row.append("".join(self._cell).strip())
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if any(self._row):
                self.rows.append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)


def _key(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _get(row, field):
    aliases = {_key(alias) for alias in FIELD_ALIASES[field]}
    for key, value in row.items():
        if _key(key) in aliases:
            return str(value or "").strip()
    return ""


def _read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _read_json(path):
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        data = data.get("rows") or data.get("data") or []
    if not isinstance(data, list):
        raise ValueError("ODPC register JSON must be a list of rows")
    return [row for row in data if isinstance(row, dict)]


def _read_html(path):
    parser = _TableParser()
    parser.feed(path.read_text(encoding="utf-8-sig", errors="replace"))
    if not parser.rows:
        return []

    headers = parser.rows[0]
    rows = []
    for cells in parser.rows[1:]:
        padded = cells + [""] * (len(headers) - len(cells))
        rows.append(dict(zip(headers, padded)))
    return rows


def _normalize_row(row, source):
    return {
        "name": _get(row, "name"),
        "type": _get(row, "type"),
        "registration_number": _get(row, "registration_number"),
        "county": _get(row, "county"),
        "country": _get(row, "country"),
        "status": _get(row, "status"),
        "source": str(source),
    }


def load_register(path, timeout=10):
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"ODPC register file not found: {source}")

    suffix = source.suffix.lower()
    if suffix == ".csv":
        rows = _read_csv(source)
    elif suffix == ".json":
        rows = _read_json(source)
    elif suffix in (".html", ".htm"):
        rows = _read_html(source)
    else:
        raise ValueError("Unsupported ODPC register file type: use CSV, JSON, or HTML")

    return [_normalize_row(row, source) for row in rows if _get(row, "name")]


def _tokens(value):
    text = re.sub(r"[^a-z0-9]+", " ", str(value or "").lower())
    return {token for token in text.split() if token not in STOPWORDS}


def _match_level(organization, candidate):
    query = _tokens(organization)
    registered = _tokens(candidate)
    if not query or not registered:
        return None
    if query == registered:
        return "exact"
    if min(len(query), len(registered)) >= 2:
        if query.issubset(registered) or registered.issubset(query):
            return "possible"
        overlap = len(query & registered) / min(len(query), len(registered))
        if overlap >= 0.8:
            return "possible"
    return None


def _live(row):
    return row["status"].strip().lower() in LIVE_STATUSES


def _rank(row):
    return (0 if _live(row) else 1, 0 if "controller" in row["type"].lower() else 1)


def lookup_registration(organization, rows, timeout=10, checked_at=None):
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    name = str(organization or "").strip()
    if not name:
        raise ValueError("organization is required for ODPC lookup")

    exact = []
    possible = []
    for row in rows:
        level = _match_level(name, row["name"])
        if level == "exact":
            exact.append(row)
        elif level == "possible":
            possible.append(row)

    checked = checked_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    candidates = exact or possible
    if not candidates:
        return {
            "status": "red",
            "confidence": "none",
            "matched_name": "",
            "registration_number": "",
            "handler_type": "",
            "county": "",
            "country": "",
            "register_status": "",
            "source": rows[0]["source"] if rows else "ODPC register snapshot",
            "checked_at": checked,
            "note": "No matching active entry found in the ODPC register snapshot",
        }

    chosen = sorted(candidates, key=_rank)[0]
    live = _live(chosen)
    if exact:
        status = "green" if live else "red"
    else:
        status = "amber" if live else "red"
    return {
        "status": status,
        "confidence": "exact" if exact else "possible",
        "matched_name": chosen["name"],
        "registration_number": chosen["registration_number"],
        "handler_type": chosen["type"],
        "county": chosen["county"],
        "country": chosen["country"],
        "register_status": chosen["status"],
        "source": chosen["source"],
        "checked_at": checked,
        "note": "" if live else "Register status is not active or renewed",
    }
