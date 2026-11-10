
from pathlib import Path
import sys

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from Source_code.feature_extraction import extract_features

DATASET_PATH = ROOT / "Datasets" / "feature_dataset.csv"
MODEL_PATH = ROOT / "Models" / "phishing_classifier.joblib"
OUTPUT_PATH = ROOT / "Datasets" / "section_2_8_selected_malicious.csv"

SAMPLE_SIZE = 30

# 1. Load the labelled dataset
df = pd.read_csv(DATASET_PATH)

required = {"url", "type"}
if not required.issubset(df.columns):
    raise ValueError("Dataset must contain url and type columns.")

df["label"] = df["type"].map({
    "benign": 0,
    "malicious": 1
})

if df["label"].isna().any():
    raise ValueError("Unexpected dataset labels.")

# 2. Reconstruct the split from Classification.py
train_idx, temp_idx = train_test_split(
    df.index,
    test_size=0.30,
    random_state=42,
    stratify=df["label"]
)

val_idx, test_idx = train_test_split(
    temp_idx,
    test_size=0.50,
    random_state=42,
    stratify=df.loc[temp_idx, "label"]
)

# 3. Select malicious test samples
candidates = df.loc[test_idx]
candidates = candidates[
    candidates["label"] == 1
].copy()

# Use only HTTP/HTTPS URLs accepted by the app
def valid_url(url):
    try:
        if not isinstance(url, str):
            return False
        parsed = urlsplit(url)
        _ = parsed.port
        return (
            parsed.scheme.lower() in ("http", "https")
            and parsed.hostname is not None
            and "." in parsed.hostname
            and not any(c.isspace() for c in url)
            and 0 < len(url) <= 2048
        )
    except ValueError:
        return False

candidates = candidates[
    candidates["url"].apply(valid_url)
]

# 4. Load the saved Random Forest pipeline
# Only load model artifacts from your trusted project.
model = joblib.load(MODEL_PATH)

# Prefer the model's saved feature order
feature_names = list(model.feature_names_in_)

# 5. Evaluate candidates using fresh feature extraction
feature_rows = [
    extract_features(url)
    for url in candidates["url"]
]

X = pd.DataFrame(feature_rows)[feature_names]

predictions = model.predict(X)
probabilities = model.predict_proba(X)

malicious_index = list(model.classes_).index(1)

candidates["prediction"] = predictions
candidates["malicious_probability"] = (
    probabilities[:, malicious_index]
)

# 6. Keep correctly detected malicious examples
selected = candidates[
    candidates["prediction"] == 1
].copy()

selected = selected.sample(
    n=min(SAMPLE_SIZE, len(selected)),
    random_state=42
)

selected = selected[
    ["url", "type", "prediction", "malicious_probability"]
].reset_index(drop=True)

selected.insert(
    0,
    "sample_id",
    [f"URL{i:03d}" for i in range(1, len(selected) + 1)]
)

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
selected.to_csv(OUTPUT_PATH, index=False)

print("Original dataset rows:", len(df))
print("Held-out test rows:", len(test_idx))
print("Eligible malicious test URLs:", len(candidates))
print("Correctly detected malicious URLs:",
      int((candidates["prediction"] == 1).sum()))
print("Selected samples:", len(selected))
print("Saved to:", OUTPUT_PATH)

print("\nSelected sample probabilities:")
print(
    selected[
        ["sample_id", "malicious_probability"]
    ].to_string(index=False)
)


# 7. Select correctly detected malicious URLs
# containing suspicious keywords

keywords = [
    "login", "verify", "secure", "account",
    "update", "confirm", "signin",
    "banking", "password"
]

# Use ALL correctly detected malicious candidates,
# not just the 30 random URLs from Step 6.
correctly_detected = candidates[
    candidates["prediction"] == 1
].copy()

targeted = correctly_detected[
    correctly_detected["url"].str.lower().apply(
        lambda url: any(word in url for word in keywords)
    )
].copy()

print("\nTotal correctly detected keyword URLs:",
      len(targeted))

# Sort by model confidence to obtain different
# confidence levels for the evasion experiment.
targeted = targeted.sort_values(
    "malicious_probability"
)

# Select a reproducible set of up to 100 URLs
# distributed across the available confidence range.
if len(targeted) > 100:
    positions = [
        round(i * (len(targeted) - 1) / 99)
        for i in range(100)
    ]
    targeted = targeted.iloc[positions].copy()

targeted = targeted.reset_index(drop=True)

targeted.insert(
    0,
    "sample_id",
    [
        f"T{i:03d}"
        for i in range(1, len(targeted) + 1)
    ]
)

targeted_path = (
    ROOT / "Datasets" /
    "section_2_8_targeted_malicious.csv"
)

targeted[
    [
        "sample_id",
        "url",
        "type",
        "prediction",
        "malicious_probability"
    ]
].to_csv(targeted_path, index=False)

print("\n========== TARGETED SAMPLES ==========")
print("Selected targeted URLs:", len(targeted))

if not targeted.empty:
    print(
        "Minimum probability:",
        targeted["malicious_probability"].min()
    )
    print(
        "Maximum probability:",
        targeted["malicious_probability"].max()
    )
else:
    print("No eligible targeted URLs found.")

print("Saved to:", targeted_path)
