import pandas as pd

df = pd.read_csv("../Datasets/URL dataset.csv")

print("First 5 rows:")
print(df.head())

print("\nDataset shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nLabel distribution:")
print(df["type"].value_counts())

print("\nMissing values:")
print(df.isnull().sum())

print("\nExact duplicate rows:")
print(df.duplicated().sum())

blank_urls = df["url"].astype(str).str.strip().eq("").sum()

print("\nBlank URLs:")
print(blank_urls)

print("\nUnique labels:")
print(df["type"].unique())

df["type"] = df["type"].replace({
    "legitimate": "benign",
    "phishing": "malicious"
})

print("\nStandardized label distribution:")
print(df["type"].value_counts())

df["source"] = "base"

print("\nFirst 5 rows after adding source:")
print(df.head())

print("\nFinal columns:")
print(df.columns.tolist())

print("\nFinal dataset validation:")
print(f"Total rows: {len(df)}")
print(f"Missing values: {df.isnull().sum().sum()}")
print(f"Duplicate rows: {df.duplicated().sum()}")
print(f"Blank URLs: {df['url'].astype(str).str.strip().eq('').sum()}")
print(f"Labels: {df['type'].unique().tolist()}")
print(f"Sources: {df['source'].unique().tolist()}")

df.to_csv("base_processed.csv", index=False)

print("\nProcessed base dataset saved successfully.")
print("File: base_processed.csv")