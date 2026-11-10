
from pathlib import Path
import sys
import time

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from Source_code.feature_extraction import extract_features
from Source_code.url_normalization import normalize_url_for_features

DATA_PATH = ROOT / "Datasets" / "feature_dataset.csv"
MODEL_PATH = ROOT / "Models" / "phishing_classifier.joblib"

OUTPUT_PATH = (
    ROOT / "security_evidence" /
    "section_2.8" /
    "defended" /
    "benign_regression_results.csv"
)

SAMPLE_SIZE = 500

df = pd.read_csv(DATA_PATH)

df["label"] = df["type"].map({
    "benign": 0,
    "malicious": 1
})

# Reconstruct the training/test split
train_idx, temp_idx = train_test_split(
    df.index,
    test_size=0.30,
    random_state=42,
    stratify=df["label"]
)

_, test_idx = train_test_split(
    temp_idx,
    test_size=0.50,
    random_state=42,
    stratify=df.loc[temp_idx, "label"]
)

benign = df.loc[test_idx]
benign = benign[benign["label"] == 0]

benign = benign.sample(
    n=min(SAMPLE_SIZE, len(benign)),
    random_state=42
)

model = joblib.load(MODEL_PATH)
feature_names = list(model.feature_names_in_)

def predict_batch(urls, normalize=False):
    start = time.perf_counter()

    feature_rows = []

    for url in urls:
        processed = (
            normalize_url_for_features(url)
            if normalize else url
        )
        feature_rows.append(extract_features(processed))

    features = pd.DataFrame(feature_rows)[feature_names]
    predictions = model.predict(features)

    elapsed = time.perf_counter() - start

    return predictions, elapsed

urls = benign["url"].tolist()

before, time_before = predict_batch(
    urls, normalize=False
)

after, time_after = predict_batch(
    urls, normalize=True
)

results = pd.DataFrame({
    "sample_id": [
        f"B{i:04d}" for i in range(1, len(urls) + 1)
    ],
    "prediction_before": before,
    "prediction_after": after,
    "prediction_changed": before != after
})

OUTPUT_PATH.parent.mkdir(
    parents=True, exist_ok=True
)
results.to_csv(OUTPUT_PATH, index=False)

print("\n=== BENIGN REGRESSION TEST ===")
print("Benign URLs tested:", len(results))
print("False positives before:", int(sum(before == 1)))
print("False positives after:", int(sum(after == 1)))
print(
    "Changed predictions:",
    int(results["prediction_changed"].sum())
)

print("\nProcessing time before:",
      round(time_before, 4), "seconds")
print("Processing time after:",
      round(time_after, 4), "seconds")

print("\nSaved to:", OUTPUT_PATH)
