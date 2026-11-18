"""Offline DIVIPOLA lookup used to validate the admin location selectors."""

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path


CATALOG_PATH = Path(__file__).with_name("assets") / "colombia-divipola.json"


@lru_cache(maxsize=1)
def load_location_catalog() -> dict[str, object]:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def _normalise(value: object) -> str:
    if not isinstance(value, str):
        return ""
    decomposed = unicodedata.normalize("NFKD", value.strip())
    without_marks = "".join(char for char in decomposed if not unicodedata.combining(char))
    without_punctuation = re.sub(r"[^\w\s]", " ", without_marks, flags=re.UNICODE)
    return " ".join(without_punctuation.casefold().split())


def is_valid_colombian_location(department: object, municipality: object) -> bool:
    """Return true only for a DIVIPOLA municipality within the selected department."""
    department_key = _normalise(department)
    municipality_key = _normalise(municipality)
    if not department_key or not municipality_key:
        return False

    for item in load_location_catalog()["departments"]:
        if _normalise(item["name"]) != department_key:
            continue
        return any(
            _normalise(place["name"]) == municipality_key
            for place in item["municipalities"]
        )
    return False
