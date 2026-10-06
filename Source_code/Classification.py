import pandas as pd

from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    cross_val_score
)

from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

import os
import joblib


# 1. LOAD DATASET


df = pd.read_csv(
    "../Datasets/feature_dataset.csv"
)

print("\n========== CLASSIFICATION ==========")

print("\nDataset shape:")
print(df.shape)

print("\nClass distribution:")
print(df["type"].value_counts())

print("\nClass percentages:")

print(
    (
        df["type"]
        .value_counts(normalize=True)
        * 100
    ).round(2)
)



# 2. ENCODE TARGET

#encoding the target
# benign = 0
# malicious = 1

df["label"] = df["type"].map({
    "benign": 0,
    "malicious": 1
})


if df["label"].isna().any():

    raise ValueError(
        "Unexpected label found."
    )



# 3. SELECT FEATURES


feature_columns = [

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


X = df[feature_columns] # stores the URL features

y = df["label"]   # 0 or 1



# 4. TRAIN and TEST Split  

# using stratify to keep similar class proportions in training and testing data.

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
    stratify=df.loc[temp_idx, "label"]
)


# Create feature datasets from the same row indices

X_train = X.loc[train_idx]
y_train = y.loc[train_idx]

X_val = X.loc[val_idx]
y_val = y.loc[val_idx]

X_test = X.loc[test_idx]
y_test = y.loc[test_idx]


print("\nTraining rows:")
print(len(X_train))

print("\nValidation rows:")
print(len(X_val))

print("\nTesting rows:")
print(len(X_test))



# 5. CREATE CLASSIFIERS


models = {

    "Logistic Regression":

        LogisticRegression(
            max_iter=1000       # maximum no of iteration allowed to finde the solution 
        ),


    "Random Forest":

        RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            n_jobs=-1
        )

}



# 6. TRAIN AND TEST MODELS


fitted_models = {}

results = []


for name, model in models.items():

    print("\n ==================")
    print(name)

    # Pipeline avoids scaling leakage

    pipeline = Pipeline([

        (
            "scaler",
            StandardScaler()
        ),

        (
            "model",
            model
        )

    ])


    # Training the modls

    pipeline.fit(
        X_train,
        y_train
    )


    fitted_models[name] = pipeline


    # Predict

    predictions = pipeline.predict(
        X_test
    )


    # Metrics

    accuracy = accuracy_score(
        y_test,
        predictions
    )


    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )


    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )


    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )


    results.append({

        "Model": name,

        "Accuracy": accuracy,

        "Precision": precision,

        "Recall": recall,

        "F1": f1

    })


    print("\nAccuracy:")
    print(round(accuracy, 4))

    print("\nPrecision:")
    print(round(precision, 4))

    print("\nRecall:")
    print(round(recall, 4))

    print("\nF1 Score:")
    print(round(f1, 4))


    # Confusion Matrix

    print("\nConfusion Matrix:")


    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )


    # Full classification report

    print("\nClassification Report:")

    print(

        classification_report(

            y_test,

            predictions,

            target_names=[
                "Benign",
                "Malicious"
            ],

            zero_division=0

        )

    )



# 7. MODEL COMPARISON


results_df = pd.DataFrame(
    results
)


print("\n============================")
print("MODEL COMPARISON")



print(

    results_df
    .round(4)
    .to_string(index=False)

)



# 8.CROSS-VALIDATION

# This checks whether the result changes significantly
# depending on which rows are used for training/testing.

cv = StratifiedKFold(

    n_splits=5,

    shuffle=True,

    random_state=42

)


print("\n===============================")
print("CROSS-VALIDATION")



for name, model in models.items():

    pipeline = Pipeline([

        (
            "scaler",
            StandardScaler()
        ),

        (
            "model",
            model
        )

    ])


    scores = cross_val_score(

        pipeline,

        X_train,

        y_train,

        cv=cv,

        scoring="f1",

        n_jobs=-1

    )


    print(f"\n{name}")

    print(
        "Fold F1 scores:",
        scores.round(3)
    )

    print(
        "Mean F1:",
        round(
            scores.mean(),
            3
        )
    )

    print(
        "Standard deviation:",
        round(
            scores.std(),
            3
        )
    )
# 9. Saving the trained model


os.makedirs(
    "../Models",
    exist_ok=True
)

joblib.dump(
    fitted_models["Random Forest"],
    "../Models/phishing_classifier.joblib"
)

print(
    "\nRandom Forest model saved to:"
)

print(
    "../Models/phishing_classifier.joblib"
)



print("\nClassification complete.")


