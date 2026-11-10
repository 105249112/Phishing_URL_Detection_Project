
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, quote
import sys

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from Source_code.feature_extraction import extract_features
from Source_code.url_normalization import normalize_url_for_features
from backend.tests.evasion_attack import generate_variants

MODEL_PATH = ROOT / "Models" / "phishing_classifier.joblib"
DATA_PATH = ROOT / "Datasets" / "section_2_8_targeted_malicious.csv"

model = joblib.load(MODEL_PATH)
df = pd.read_csv(DATA_PATH)

sample = df.loc[df["sample_id"] == "T002"]
if sample.empty:
    raise ValueError("T002 not found")

original = sample.iloc[0]["url"]

variants = generate_variants(original)
modified = next(
    url for attack, url in variants
    if attack == "zero_width"
)

parsed = urlsplit(modified)
encoded = urlunsplit(
    parsed._replace(
        path=quote(parsed.path, safe="/:@!$&'()*+,;=-._~%"),
        query=quote(parsed.query, safe="/?:@!$&'()*+,;=-._~%")
    )
)

def test_prediction(name, url):
    cleaned = normalize_url_for_features(url)
    features = extract_features(cleaned)
    X = pd.DataFrame([features])[model.feature_names_in_]

    prediction = int(model.predict(X)[0])
    probability = float(
        model.predict_proba(X)[0][list(model.classes_).index(1)]
    )

    print(f"\n{name}")
    print("Prediction:", "MALICIOUS" if prediction else "BENIGN")
    print("Malicious probability:", round(probability, 5))
    print("Suspicious keyword:", features["has_suspicious_keyword"])
    print("Preprocessing changed input:", cleaned != url)

test_prediction("Original with defence", original)
test_prediction("Raw Unicode with defence", modified)
test_prediction("Percent-encoded with defence", encoded)
