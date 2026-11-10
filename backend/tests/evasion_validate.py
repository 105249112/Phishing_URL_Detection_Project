
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, quote
import sys

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from Source_code.feature_extraction import extract_features
from backend.tests.evasion_attack import generate_variants

DATA_PATH = ROOT / "Datasets" / "section_2_8_targeted_malicious.csv"
MODEL_PATH = ROOT / "Models" / "phishing_classifier.joblib"

model = joblib.load(MODEL_PATH)
df = pd.read_csv(DATA_PATH)

sample = df.loc[df["sample_id"] == "T002"]

if sample.empty:
    raise ValueError("T002 sample not found")

original_url = sample.iloc[0]["url"]

def evaluate(label, url):
    features = extract_features(url)
    X = pd.DataFrame([features])[model.feature_names_in_]

    prediction = int(model.predict(X)[0])
    classes = list(model.classes_)
    probability = float(
        model.predict_proba(X)[0][classes.index(1)]
    )

    print(f"\n{label}")
    print("Prediction:", "MALICIOUS" if prediction else "BENIGN")
    print("Malicious probability:", round(probability, 5))
    print("URL length:", features["url_length"])
    print("Suspicious keyword:", features["has_suspicious_keyword"])

evaluate("Original URL", original_url)

variants = generate_variants(original_url)
zero_width = [
    url for attack, url in variants
    if attack == "zero_width"
]

if not zero_width:
    raise ValueError("No zero-width variant generated")

modified_url = zero_width[0]
evaluate("Raw Unicode variation", modified_url)

# Encode non-ASCII characters in the URL path and query.
parsed = urlsplit(modified_url)

encoded_path = quote(
    parsed.path, safe="/:@!$&'()*+,;=-._~%"
)
encoded_query = quote(
    parsed.query, safe="/?:@!$&'()*+,;=-._~%"
)

encoded_url = urlunsplit(
    parsed._replace(
        path=encoded_path,
        query=encoded_query
    )
)

evaluate("Percent-encoded variation", encoded_url)

print("\nRaw variant has zero-width:",
      "\u200b" in modified_url)
print("Encoded variant has percent encoding:",
      "%E2%80%8B" in encoded_url.upper())
