
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import sys
import re

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from Source_code.feature_extraction import extract_features

DATASET_PATH = (
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
    "baseline" /
    "evasion_attack_results.csv"
)

KEYWORDS = [
    "login", "verify", "secure", "account",
    "update", "confirm", "signin",
    "banking", "password"
]

# Unicode look-alike substitution
LOOKALIKE = {
    "a": "\u0430",  # Cyrillic a
    "e": "\u0435",  # Cyrillic e
    "o": "\u043e",  # Cyrillic o
    "p": "\u0440",  # Cyrillic p
    "c": "\u0441",  # Cyrillic c
}

def find_keyword(text):
    for keyword in KEYWORDS:
        match = re.search(
            re.escape(keyword), text,
            flags=re.IGNORECASE
        )
        if match:
            return match
    return None

def generate_variants(url):
    parsed = urlsplit(url)
    variants = []

    for component in ("path", "query"):
        original = getattr(parsed, component)
        match = find_keyword(original)

        if match is None:
            continue

        word = match.group()
        start, end = match.span()

        # Variant 1: Unicode look-alike
        replacement = None
        for i, char in enumerate(word):
            if char.lower() in LOOKALIKE:
                replacement = (
                    word[:i] +
                    LOOKALIKE[char.lower()] +
                    word[i + 1:]
                )
                break

        if replacement:
            new_component = (
                original[:start] +
                replacement +
                original[end:]
            )

            parts = parsed._replace(
                **{component: new_component}
            )

            variants.append((
                "unicode_lookalike",
                urlunsplit(parts)
            ))

        # Variant 2: Zero-width insertion
        if len(word) >= 2:
            midpoint = len(word) // 2

            modified_word = (
                word[:midpoint] +
                "\u200b" +
                word[midpoint:]
            )

            new_component = (
                original[:start] +
                modified_word +
                original[end:]
            )

            parts = parsed._replace(
                **{component: new_component}
            )

            variants.append((
                "zero_width",
                urlunsplit(parts)
            ))

        # Use the first matching component
        break

    return variants

def predict(model, url):
    features = extract_features(url)
    columns = list(model.feature_names_in_)

    X = pd.DataFrame([features])[columns]

    prediction = int(model.predict(X)[0])

    malicious_index = list(
        model.classes_
    ).index(1)

    probability = float(
        model.predict_proba(X)[0][malicious_index]
    )

    return prediction, probability, features

def main():
    df = pd.read_csv(DATASET_PATH)

    # Only load trusted local model artifacts
    model = joblib.load(MODEL_PATH)

    results = []

    for _, row in df.iterrows():
        original = row["url"]

        original_pred, original_prob, original_features = (
            predict(model, original)
        )

        if original_pred != 1:
            continue

        for attack_type, modified in generate_variants(original):

            new_pred, new_prob, new_features = (
                predict(model, modified)
            )

            results.append({
                "sample_id": row["sample_id"],
                "attack_type": attack_type,
                "original_prediction": original_pred,
                "modified_prediction": new_pred,
                "original_probability": original_prob,
                "modified_probability": new_prob,
                "keyword_before": original_features[
                    "has_suspicious_keyword"
                ],
                "keyword_after": new_features[
                    "has_suspicious_keyword"
                ],
                "candidate_flip": (
                    original_pred == 1 and new_pred == 0
                )
            })

    OUTPUT_PATH.parent.mkdir(
        parents=True, exist_ok=True
    )

    results_df = pd.DataFrame(results)

    if results_df.empty:
        print("No matching URL variants generated.")
        return

    results_df.to_csv(
        OUTPUT_PATH, index=False
    )

    print("\n=== EVASION EXPERIMENT ===")
    print("Original samples:", len(df))
    print("Generated variants:", len(results_df))

    for attack_type, group in results_df.groupby(
        "attack_type"
    ):
        flips = int(group["candidate_flip"].sum())
        total = len(group)

        print(f"\nAttack: {attack_type}")
        print("Tested:", total)
        print("Candidate prediction flips:", flips)
        print(
            "Candidate flip rate:",
            f"{flips / total * 100:.2f}%"
        )

    print("\nSaved results to:", OUTPUT_PATH)

if __name__ == "__main__":
    main()
