"""Network-free export from the existing recon pipeline to the local companion."""
import json
from pathlib import Path

from .data import canonical_url


def write_seed(urls, destination, observations=None):
    observations = observations or {}
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output:
        for url in sorted(set(urls)):
            try:
                normalized = canonical_url(url)
            except ValueError:
                continue
            record = {"url": normalized, "method": "GET", "status_code": observations.get(url, {}).get("status_code", 0),
                      "webserver": observations.get(url, {}).get("webserver", ""),
                      "tech": observations.get(url, {}).get("tech", [])}
            output.write(json.dumps(record, ensure_ascii=False) + "\n")
