import pandas as pd
import tensorflow as tf
import json
from tensorflow.keras import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout
import numpy as np
tf.keras.utils.set_random_seed(42)

df = pd.read_csv("../Datasets/combined_cleaned.csv")

print("Dataset shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nClass distribution:")
print(df["type"].value_counts())

print("\nExample URLs:")

print(df[["url", "type"]].head())
df["label"] = df["type"].map({
    "benign": 0,
    "malicious": 1
})

print("\nEncoded labels:")
print(df[["type", "label"]].value_counts())
from sklearn.model_selection import train_test_split

urls = df["url"]
labels = df["label"]

X_train, X_temp, y_train, y_temp = train_test_split(
    urls,
    labels,
    test_size=0.30,
    random_state=42,
    stratify=labels
)

X_val, X_test, y_val, y_test = train_test_split(
    X_temp,
    y_temp,
    test_size=0.50,
    random_state=42,
    stratify=y_temp
)

print("\nTraining set:", len(X_train))
print("Validation set:", len(X_val))
print("Test set:", len(X_test))

print("\nTraining labels:")
print(y_train.value_counts())

print("\nValidation labels:")
print(y_val.value_counts())

print("\nTest labels:")
print(y_test.value_counts())
train_url_lengths = X_train.str.len()

print("\nTraining URL length statistics:")
print(train_url_lengths.describe())

print("\nURL length percentiles:")
print(train_url_lengths.quantile([0.90, 0.95, 0.99]))

print("\nLongest training URL:")
print(train_url_lengths.max())
long_urls = (train_url_lengths > 200).sum()
long_urls_percent = (long_urls / len(train_url_lengths)) * 100

print("\nTraining URLs longer than 200:")
print(long_urls)

print("\nPercentage longer than 200:")
print(f"{long_urls_percent:.2f}%")
characters = sorted(set("".join(X_train)))

print("\nNumber of unique characters:")
print(len(characters))

print("\nCharacters:")
print(characters)
def has_non_ascii(url):
    return any(ord(char) > 127 for char in url)

non_ascii_mask = X_train.apply(has_non_ascii)

print("\nTraining URLs containing non-ASCII characters:")
print(non_ascii_mask.sum())

print("\nPercentage containing non-ASCII characters:")
print(f"{non_ascii_mask.mean() * 100:.2f}%")

print("\nExamples:")
print(X_train[non_ascii_mask].head(10))
char_to_id = {
    char: index + 2
    for index, char in enumerate(characters)
}

PAD_ID = 0
UNK_ID = 1

vocab_size = len(char_to_id) + 2
with open("../Models/char_to_id.json", "w", encoding="utf-8") as file:
    json.dump(char_to_id, file, ensure_ascii=False, indent=2)
    
print("\nCharacter vocabulary saved successfully.")

print("\nVocabulary size including PAD and UNK:")
print(vocab_size)

print("\nExample character IDs:")
for char in ["a", "h", "0", "/", ".", ":"]:
    print(char, "->", char_to_id.get(char, UNK_ID))

max_length = 200

def encode_url(url):
    encoded = [char_to_id.get(char, UNK_ID) for char in url]

    # Cut URLs longer than 200 characters
    encoded = encoded[:max_length]

    # Pad URLs shorter than 200 characters
    encoded += [PAD_ID] * (max_length - len(encoded))

    return encoded


example_url = X_train.iloc[0]
example_encoded = encode_url(example_url)

print("\nExample URL:")
print(example_url)

print("\nOriginal URL length:")
print(len(example_url))

print("\nFirst 30 encoded values:")
print(example_encoded[:30])

print("\nEncoded sequence length:")
print(len(example_encoded))


X_train_encoded = np.array([encode_url(url) for url in X_train])
X_val_encoded = np.array([encode_url(url) for url in X_val])

y_train_array = y_train.to_numpy()
y_val_array = y_val.to_numpy()

print("\nEncoded training shape:")
print(X_train_encoded.shape)

print("\nEncoded validation shape:")
print(X_val_encoded.shape)

print("\nTraining label shape:")
print(y_train_array.shape)

print("\nValidation label shape:")
print(y_val_array.shape)
embedding_dim = 32

model = Sequential([
    tf.keras.Input(shape=(max_length,)),

    Embedding(
        input_dim=vocab_size,
        output_dim=embedding_dim
    ),

    Conv1D(
        filters=64,
        kernel_size=5,
        activation="relu"
    ),

    GlobalMaxPooling1D(),

    Dense(
        64,
        activation="relu"
    ),

    Dropout(0.5),

    Dense(
        1,
        activation="sigmoid"
    )
])

model.summary()
model.compile(
    optimizer="adam",
    loss="binary_crossentropy",
    metrics=[
        "accuracy",
        tf.keras.metrics.Precision(name="precision"),
        tf.keras.metrics.Recall(name="recall")
    ]
)

print("\nModel compiled successfully.")
early_stopping = tf.keras.callbacks.EarlyStopping(
    monitor="val_loss",
    patience=2,
    restore_best_weights=True
)

history = model.fit(
    X_train_encoded,
    y_train_array,
    validation_data=(X_val_encoded, y_val_array),
    epochs=10,
    batch_size=128,
    callbacks=[early_stopping]
)
X_test_encoded = np.array(
    [encode_url(url) for url in X_test]
)

y_test_array = y_test.to_numpy()

print("\nEncoded test shape:")
print(X_test_encoded.shape)

print("\nTest label shape:")
print(y_test_array.shape)
test_results = model.evaluate(
    X_test_encoded,
    y_test_array,
    verbose=1
)

print("\nFinal Test Results:")
print(f"Test Loss: {test_results[0]:.4f}")
print(f"Test Accuracy: {test_results[1]:.4f}")
print(f"Test Precision: {test_results[2]:.4f}")
print(f"Test Recall: {test_results[3]:.4f}")
from sklearn.metrics import confusion_matrix, classification_report

# Get predicted probabilities
y_test_prob = model.predict(X_test_encoded, verbose=0).flatten()

# Convert probabilities to classes using 0.5 threshold
y_test_pred = (y_test_prob >= 0.5).astype(int)

# Confusion matrix
cm = confusion_matrix(y_test_array, y_test_pred)

tn, fp, fn, tp = cm.ravel()

print("\nConfusion Matrix:")
print(cm)

print("\nTrue Negatives:", tn)
print("False Positives:", fp)
print("False Negatives:", fn)
print("True Positives:", tp)

print("\nClassification Report:")
print(classification_report(
    y_test_array,
    y_test_pred,
    target_names=["Benign", "Malicious"],
    digits=4
))
model.save("../Models/innovation_cnn.keras")

print("\nInnovation CNN model saved successfully.")




