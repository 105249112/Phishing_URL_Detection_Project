
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, quote
import sys

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.tests.evasion_attack import generate_variants

DATA_PATH = (
    ROOT / "Datasets" /
    "section_2_8_targeted_malicious.csv"
)

API_URL = "http://127.0.0.1:8000/predict"

df = pd.read_csv(DATA_PATH)

sample = df.loc[df["sample_id"] == "T002"]

if sample.empty:
    raise ValueError("T002 not found")

original = sample.iloc[0]["url"]

variants = generate_variants(original)

zero_width = [
    url for attack_type, url in variants
    if attack_type == "zero_width"
]

if not zero_width:
    raise ValueError("No zero-width variation found")

modified = zero_width[0]

parsed = urlsplit(modified)

encoded = urlunsplit(
    parsed._replace(
        path=quote(
            parsed.path,
            safe="/:@!$&'()*+,;=-._~%"
        ),
        query=quote(
            parsed.query,
            safe="/?:@!$&'()*+,;=-._~%"
        )
    )
)

tests = [
    ("Original", original),
    ("Raw Unicode", modified),
    ("Percent-encoded", encoded),
]

for name, url in tests:
    response = requests.post(
        API_URL,
        json={"url": url},
        timeout=10
    )

    print(f"\n=== {name} ===")
    print("HTTP status:", response.status_code)

    if response.status_code == 200:
        result = response.json()

        print("Prediction:", result["prediction"])
        print(
            "Malicious probability:",
            result["malicious_probability"]
        )
    else:
        print("Response:", response.text[:300])
