
from pathlib import Path
import sys

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from Source_code.feature_extraction import extract_features
from Source_code.url_normalization import normalize_url_for_features
from backend.tests.evasion_attack import generate_variants

DATA_PATH = (
    ROOT / "Datasets" /
    "section_2_8_targeted_malicious.csv"
)

MODEL_PATH = (
    ROOT / "Models" /
    "phishing_classifier.joblib"
)

OUTPUT_PATH = (
    ROOT / "security_evidence" /
    "section_2.8" /
    "defended" /
    "evasion_defended_results.csv"
)

def evaluate(model, url):
    normalized = normalize_url_for_features(url)

    features = extract_features(normalized)

    X = pd.DataFrame(
        [features],
        columns=model.feature_names_in_
    )

    prediction = int(model.predict(X)[0])

    malicious_probability = float(
        model.predict_proba(X)[0][
            list(model.classes_).index(1)
        ]
    )

    return prediction, malicious_probability, features

def main():
    df = pd.read_csv(DATA_PATH)

    # Load only the trusted local project model.
    model = joblib.load(MODEL_PATH)

    results = []

    for _, row in df.iterrows():
        original_url = row["url"]

        original_pred, original_prob, _ = evaluate(
            model, original_url
        )

        if original_pred != 1:
            continue

        variants = generate_variants(original_url)

        for attack_type, modified_url in variants:
            new_pred, new_prob, features = evaluate(
                model, modified_url
            )

            results.append({
                "sample_id": row["sample_id"],
                "attack_type": attack_type,
                "original_prediction": original_pred,
                "modified_prediction": new_pred,
                "original_probability": original_prob,
                "modified_probability": new_prob,
                "keyword_after": features[
                    "has_suspicious_keyword"
                ],
                "candidate_flip": (
                    original_pred == 1 and new_pred == 0
                )
            })

    results_df = pd.DataFrame(results)

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if results_df.empty:
        print("No variants available for evaluation.")
        return

    results_df.to_csv(OUTPUT_PATH, index=False)

    print("\n=== DEFENDED EVASION EXPERIMENT ===")
    print("Original samples:", len(df))
    print("Generated variants:", len(results_df))

    for attack_type, group in results_df.groupby(
        "attack_type"
    ):
        total = len(group)
        flips = int(group["candidate_flip"].sum())

        print(f"\nAttack: {attack_type}")
        print("Tested:", total)
        print("Candidate prediction flips:", flips)
        print(
            "Candidate flip rate:",
            f"{flips / total * 100:.2f}%"
        )

    print("\nSaved to:", OUTPUT_PATH)

if __name__ == "__main__":
    main()
