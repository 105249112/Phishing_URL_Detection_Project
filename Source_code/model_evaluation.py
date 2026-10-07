import json
import numpy as np
import pandas as pd
import tensorflow as tf
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    ConfusionMatrixDisplay
)


# =========================================================
# SETTINGS


DATASET_PATH = "../Datasets/combined_cleaned.csv"
MODEL_PATH = "../Models/innovation_cnn.keras"
VOCAB_PATH = "../Models/char_to_id.json"

MAX_LENGTH = 200
PAD_ID = 0
UNK_ID = 1


# Make results more reproducible
np.random.seed(42)
tf.keras.utils.set_random_seed(42)


# =========================================================
# ENCODE URLS


def encode_urls(urls, vocab):

    encoded_urls = []

    for url in urls:

        encoded = [
            vocab.get(char, UNK_ID)
            for char in url
        ]

        # Truncate long URLs
        encoded = encoded[:MAX_LENGTH]

        # Pad short URLs
        encoded += (
            [PAD_ID]
            * (MAX_LENGTH - len(encoded))
        )

        encoded_urls.append(encoded)

    return np.array(encoded_urls)


# =========================================================
# EVALUATE MODEL


def evaluate_model(
    model,
    X,
    y,
    urls,
    title
):

    # Predicts malicious probability

    probabilities = (
        model.predict(
            X,
            verbose=0
        )
        .flatten()
    )


    # Convert probability into 0 / 1 prediction

    predictions = (
        probabilities >= 0.5
    ).astype(int)


    # Calculates metrics

    accuracy = accuracy_score(
        y,
        predictions
    )

    precision = precision_score(
        y,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y,
        predictions,
        zero_division=0
    )


    print("\n========================================")
    print(title)


    print(
        "Accuracy:",
        round(accuracy, 4)
    )

    print(
        "Precision:",
        round(precision, 4)
    )

    print(
        "Recall:",
        round(recall, 4)
    )

    print(
        "F1:",
        round(f1, 4)
    )


    # Confusion Matrix

    cm = confusion_matrix(
        y,
        predictions
    )

    print("\nConfusion Matrix:")
    print(cm)


    # Classification Report htat show how well the CNN has classified the benign URL's and malicious URL's separately.

    print("\nClassification Report:")

    print(
        classification_report(
            y,
            predictions,
            target_names=[
                "Benign",
                "Malicious"
            ],
            digits=4,
            zero_division=0
        )
    )


    # =====================================================
    # CONFUSION MATRIX GRAPH


    ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=[
            "Benign",
            "Malicious"
        ]
    ).plot()

    plt.title(
        f"{title} - Confusion Matrix"
    )

    plt.tight_layout()
    plt.show()


    # =====================================================
    # ERROR ANALYSIS


    results = pd.DataFrame({

        "url": list(urls),

        "actual": y,

        "predicted": predictions,

        "probability": probabilities

    })


    false_positives = results[
        (results["actual"] == 0)
        &
        (results["predicted"] == 1)
    ]


    false_negatives = results[
        (results["actual"] == 1)
        &
        (results["predicted"] == 0)
    ]


    print("\nFalse Positives:")
    print(len(false_positives))

    print("\nExample False Positives:")

    print(
        false_positives
        .head(5)
        .to_string(index=False)
    )


    print("\nFalse Negatives:")
    print(len(false_negatives))

    print("\nExample False Negatives:")

    print(
        false_negatives
        .head(5)
        .to_string(index=False)
    )


    # Return results for later comparison

    return {

        "Accuracy": accuracy,

        "Precision": precision,

        "Recall": recall,

        "F1": f1

    }


# =========================================================
# CREATE CNN


def build_cnn(vocab_size):

    model = tf.keras.Sequential([

        tf.keras.Input(
            shape=(MAX_LENGTH,)
        ),

        tf.keras.layers.Embedding(
            input_dim=vocab_size,
            output_dim=32
        ),

        tf.keras.layers.Conv1D(
            filters=64,
            kernel_size=5,
            activation="relu"
        ),

        tf.keras.layers.GlobalMaxPooling1D(),

        tf.keras.layers.Dense(
            64,
            activation="relu"
        ),

        tf.keras.layers.Dropout(
            0.5
        ),

        tf.keras.layers.Dense(
            1,
            activation="sigmoid"
        )

    ])


    model.compile(

        optimizer="adam",

        loss="binary_crossentropy",

        metrics=[
            "accuracy"
        ]

    )

    return model


# =========================================================
# LOAD DATASET
# =========================================================

df = pd.read_csv(
    DATASET_PATH
)


df["label"] = df["type"].map({

    "benign": 0,

    "malicious": 1

})


print("\nDataset shape:")
print(df.shape)

print("\nClass distribution:")
print(
    df["type"]
    .value_counts()
)


# =========================================================
# 1. STANDARD CNN EVALUATION


print("\n========================================")
print("STANDARD CNN TEST")



# Load saved vocabulary

with open(
    VOCAB_PATH,
    "r",
    encoding="utf-8"
) as file:

    vocab = json.load(file)


# Load saved CNN

cnn_model = tf.keras.models.load_model(
    MODEL_PATH
)


# Recreate same 70 / 15 / 15 split

indices = df.index


train_idx, temp_idx = train_test_split(

    indices,

    test_size=0.30,

    random_state=42,

    stratify=df["label"]

)


val_idx, test_idx = train_test_split(

    temp_idx,

    test_size=0.50,

    random_state=42,

    stratify=df.loc[
        temp_idx,
        "label"
    ]

)


test_df = df.loc[
    test_idx
].copy()


X_test = encode_urls(
    test_df["url"],
    vocab
)


y_test = (
    test_df["label"]
    .to_numpy()
)


# Evaluate normal CNN

standard_results = evaluate_model(

    cnn_model,

    X_test,

    y_test,

    test_df["url"].values,

    "STANDARD CNN EVALUATION"

)


# =========================================================
# 2. INNOVATION - SOURCE HOLDOUT EVALUATION


print("\n========================================")
print("SOURCE HOLDOUT EXPERIMENT")


print(
    "\nTraining only on BASE URLs "
    "and testing on QR URLs."
)


# Use base-only URLs for training

base_df = df[
    df["source"] == "base"
].copy()


# Use QR-only URLs for testing

qr_df = df[
    df["source"] == "qr"
].copy()


print("\nBase-only rows:")
print(len(base_df))

print("\nQR-only rows:")
print(len(qr_df))


# Split base data into training + validation

base_train, base_val = train_test_split(

    base_df,

    test_size=0.15,

    random_state=42,

    stratify=base_df["label"]

)


# =========================================================
# CREATE NEW VOCAB FROM BASE TRAINING DATA ONLY


characters = sorted(

    set(

        "".join(
            base_train["url"]
        )

    )

)


source_vocab = {

    char: index + 2

    for index, char

    in enumerate(
        characters
    )

}


# =========================================================
# ENCODE SOURCE HOLDOUT DATA


X_train = encode_urls(

    base_train["url"],

    source_vocab

)


y_train = (
    base_train["label"]
    .to_numpy()
)


X_val = encode_urls(

    base_val["url"],

    source_vocab

)


y_val = (
    base_val["label"]
    .to_numpy()
)


X_qr = encode_urls(

    qr_df["url"],

    source_vocab

)


y_qr = (
    qr_df["label"]
    .to_numpy()
)


# =========================================================
# TRAIN A FRESH CNN


source_model = build_cnn(

    len(source_vocab) + 2

)


early_stopping = (
    tf.keras.callbacks
    .EarlyStopping(

        monitor="val_loss",

        patience=2,

        restore_best_weights=True

    )
)


print(
    "\nTraining source-holdout CNN..."
)


source_model.fit(

    X_train,

    y_train,

    validation_data=(
        X_val,
        y_val
    ),

    epochs=10,

    batch_size=128,

    callbacks=[
        early_stopping
    ],

    verbose=1

)


# =========================================================
# EVALUATE SOURCE HOLDOUT MODEL


holdout_results = evaluate_model(

    source_model,

    X_qr,

    y_qr,

    qr_df["url"].values,

    "SOURCE HOLDOUT EVALUATION"

)


# =========================================================
# 3. COMPARE BOTH EVALUATIONS


comparison = pd.DataFrame(

    [
        standard_results,
        holdout_results
    ],

    index=[
        "Standard Test",
        "Source Holdout"
    ]

)


print("\n========================================")
print("EVALUATION COMPARISON")



print(
    comparison
    .round(4)
    .to_string()
)


# =========================================================
# COMPARISON GRAPH


comparison.plot(

    kind="bar",

    figsize=(9, 5)

)


plt.title(
    "CNN Standard Test vs Source Holdout"
)

plt.ylabel(
    "Score"
)

plt.xlabel(
    "Evaluation Method"
)


# Zoom in because all scores are very high

plt.ylim(
    0.95,
    1.00
)


plt.xticks(
    rotation=0
)

plt.legend(
    title="Metric"
)

plt.tight_layout()

plt.show()


print("\n========================================")
print("MODEL EVALUATION COMPLETE")
print("========================================")