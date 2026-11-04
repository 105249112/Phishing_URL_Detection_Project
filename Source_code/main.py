import json
import subprocess
import sys

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

from feature_extraction import extract_features


# SAVED MODEL PATHS

CLASSIFIER_PATH = "../Models/phishing_classifier.joblib"
CLUSTER_MODEL_PATH = "../Models/clustering_kmeans.joblib"
CLUSTER_SCALER_PATH = "../Models/clustering_scaler.joblib"

CNN_MODEL_PATH = "../Models/innovation_cnn.keras"
VOCAB_PATH = "../Models/char_to_id.json"


# Same feature order used during classification and clustering

FEATURE_COLUMNS = [
    "url_length",
    "hyphen_count",
    "number_count",
    "uses_https",
    "has_ip",
    "subdomain_count",
    "has_at_symbol",
    "has_double_slash_redirect",
    "path_depth",
    "has_lookalike_chars",
    "tld_risk",
    "has_suspicious_keyword"
]

MAX_LENGTH = 200
PAD_ID = 0
UNK_ID = 1


# RUN EXISTING PROJECT SCRIPTS

def run_script(filename):
    """Run one of the existing project scripts."""
    subprocess.run([sys.executable, filename])


# CNN

def load_innovation_model():
    """Load the saved CNN and character vocabulary."""

    model = tf.keras.models.load_model(CNN_MODEL_PATH)

    with open(VOCAB_PATH, "r", encoding="utf-8") as file:
        char_to_id = json.load(file)

    return model, char_to_id


def encode_url(url, char_to_id):
    """Convert a URL into the format used by the CNN."""

    encoded = [
        char_to_id.get(char, UNK_ID)
        for char in url
    ]

    encoded = encoded[:MAX_LENGTH]

    encoded += [PAD_ID] * (MAX_LENGTH - len(encoded))

    return np.array([encoded])


# CLUSTER DESCRIPTION

def get_cluster_description(cluster):

    descriptions = {
        1: "General malicious URL pattern",

        2: (
            "Long and complex malicious URL with many "
            "digits, hyphens or suspicious keywords"
        ),

        3: "Double-slash redirect malicious URL pattern",

        4: "IP-address-based malicious URL pattern",

        5: "Risky top-level-domain malicious URL pattern"
    }

    return descriptions.get(
        cluster,
        "Unknown malicious URL pattern"
    )


# TEST ONE URL

def test_url():

    url = input("\nEnter a URL to test: ").strip()

    if not url:
        print("No URL entered.")
        return


    # FEATURE EXTRACTION

    feature_values = extract_features(url)

    features = pd.DataFrame(
        [[feature_values[column] for column in FEATURE_COLUMNS]],
        columns=FEATURE_COLUMNS
    )


    # RANDOM FOREST

    classifier = joblib.load(CLASSIFIER_PATH)

    rf_prediction = int(
        classifier.predict(features)[0]
    )

    rf_probability = float(
        classifier.predict_proba(features)[0][1]
    )

    if rf_prediction == 1:
        rf_result = "MALICIOUS"
    else:
        rf_result = "BENIGN"


    # INNOVATION CNN

    cnn_model, char_to_id = load_innovation_model()

    encoded_url = encode_url(
        url,
        char_to_id
    )

    cnn_probability = float(
        cnn_model.predict(
            encoded_url,
            verbose=0
        )[0][0]
    )

    if cnn_probability >= 0.5:
        cnn_result = "MALICIOUS"
    else:
        cnn_result = "BENIGN"


    # RESULTS

    print("\n====================================")
    print("          URL ANALYSIS RESULT")
    print("====================================")

    print("\nURL:")
    print(url)

    print("\nRandom Forest:")
    print("Prediction:", rf_result)
    print(
        f"Malicious probability: "
        f"{rf_probability:.4f}"
    )

    print("Test Accuracy: 99.00%")
    print("Test F1 Score: 98.06%")

    print("\nInnovation CNN:")
    print("Prediction:", cnn_result)
    print(
        f"Malicious probability: "
        f"{cnn_probability:.4f}"
    )
    print("Test Accuracy: 99.81%")
    print("Test F1 Score: 99.63%")


    # SUSPICIOUS FEATURES

    suspicious_features = []

    if feature_values["has_ip"] == 1:
        suspicious_features.append(
            "IP address used as host"
        )

    if feature_values["has_at_symbol"] == 1:
        suspicious_features.append(
            "@ symbol detected"
        )

    if feature_values["has_double_slash_redirect"] == 1:
        suspicious_features.append(
            "Double-slash redirect pattern"
        )

    if feature_values["has_lookalike_chars"] == 1:
        suspicious_features.append(
            "Possible look-alike characters"
        )

    if feature_values["tld_risk"] == 1:
        suspicious_features.append(
            "Risky top-level domain"
        )

    if feature_values["has_suspicious_keyword"] == 1:
        suspicious_features.append(
            "Suspicious keyword detected"
        )

    print("\nSuspicious URL Features:")

    if suspicious_features:
        for feature in suspicious_features:
            print("-", feature)
    else:
        print("- No suspicious binary features detected")


    # CLUSTERING

    # K-Means was trained only on malicious URLs,
    # so it describes malicious patterns rather than
    # classifying URLs as benign or malicious.

    if rf_result == "MALICIOUS" or cnn_result == "MALICIOUS":

        scaler = joblib.load(CLUSTER_SCALER_PATH)
        kmeans = joblib.load(CLUSTER_MODEL_PATH)

        scaled_features = scaler.transform(features)

        cluster = int(
            kmeans.predict(scaled_features)[0]
        ) + 1

        print("\nClosest Malicious URL Pattern:")
        print("Cluster:", cluster)
        print(
            "Pattern:",
            get_cluster_description(cluster)
        )

    else:
        print(
            "\nClustering: Not displayed because "
            "both classification models predicted benign."
        )

    print("\n====================================")


# MAIN MENU

def main():

    while True:

        print("\n====================================")
        print("     PHISHING URL DETECTION PROJECT")
        print("====================================")

        print("1. Run Data Analysis")
        print("2. Run Classification Evaluation")
        print("3. Run Clustering Analysis")
        print("4. Test a URL")
        print("5. Exit")

        choice = input("\nEnter choice (1-5): ").strip()

        if choice == "1":
            run_script("data_analysis.py")

        elif choice == "2":
            run_script("Classification.py")

        elif choice == "3":
            run_script("clustering_processing.py")

        elif choice == "4":
            test_url()

        elif choice == "5":
            print("\nExiting program.")
            break

        else:
            print("\nInvalid choice. Please enter 1-5.")


if __name__ == "__main__":
    main()