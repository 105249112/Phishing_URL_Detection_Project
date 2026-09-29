import pandas as pd
from urllib.parse import urlparse

df = pd.read_csv("../Datasets/combined_dataset.csv")

print("Combined dataset shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nMissing values:")
print(df.isnull().sum())

print("\nBlank URLs:")
print(df["url"].astype(str).str.strip().eq("").sum())

print("\nLabel distribution:")
print(df["type"].value_counts())

print("\nSource distribution:")
print(df["source"].value_counts())

duplicate_urls = df[
    df.duplicated(subset=["url"], keep=False)
].sort_values("url")

print("\nExact URL duplicate check:")
print(f"Rows involved: {len(duplicate_urls)}")
print(f"Unique duplicated URLs: {duplicate_urls['url'].nunique()}")

print("\nDuplicate URLs by source:")
print(duplicate_urls["source"].value_counts())

print("\nSample duplicate URLs:")
print(
    duplicate_urls[["url", "type", "source"]]
    .head(20)
    .to_string(index=False)
)

label_counts = df.groupby("url")["type"].nunique()
conflicting_urls = label_counts[label_counts > 1]

print("\nExact URLs with conflicting labels:")
print(len(conflicting_urls))

if len(conflicting_urls) > 0:
    conflict_rows = df[
        df["url"].isin(conflicting_urls.index)
    ].sort_values("url")

    print("\nSample conflicting URLs:")
    print(
        conflict_rows[["url", "type", "source"]]
        .head(20)
        .to_string(index=False)
    )

url_source_counts = df.groupby("url")["source"].nunique()
cross_source_urls = url_source_counts[url_source_counts > 1]

base_counts = df[df["source"] == "base"]["url"].value_counts()
qr_counts = df[df["source"] == "qr"]["url"].value_counts()

base_internal_duplicates = base_counts[base_counts > 1]
qr_internal_duplicates = qr_counts[qr_counts > 1]

print("\nDuplicate source investigation:")
print(f"URLs appearing in both base and QR: {len(cross_source_urls)}")
print(f"URLs duplicated within base: {len(base_internal_duplicates)}")
print(f"URLs duplicated within QR: {len(qr_internal_duplicates)}")

base_urls = set(df.loc[df["source"] == "base", "url"])
qr_urls = set(df.loc[df["source"] == "qr", "url"])

both_urls = base_urls & qr_urls
base_only_urls = base_urls - qr_urls
qr_only_urls = qr_urls - base_urls

print("\nUnique URL provenance:")
print(f"Base only: {len(base_only_urls)}")
print(f"QR only: {len(qr_only_urls)}")
print(f"Both sources: {len(both_urls)}")
print(
    f"Total unique URLs: "
    f"{len(base_only_urls) + len(qr_only_urls) + len(both_urls)}"
)

cleaned_df = df.drop_duplicates(
    subset=["url"],
    keep="first"
).copy()

cleaned_df.loc[
    cleaned_df["url"].isin(both_urls),
    "source"
] = "both"

print("\nDeduplication results:")
print(f"Rows before: {len(df)}")
print(f"Rows after: {len(cleaned_df)}")
print(f"Rows removed: {len(df) - len(cleaned_df)}")
print(f"Remaining duplicate URLs: {cleaned_df['url'].duplicated().sum()}")

print("\nLabel distribution after deduplication:")
print(cleaned_df["type"].value_counts())

print("\nSource distribution after deduplication:")
print(cleaned_df["source"].value_counts())

def has_basic_http_structure(url):
    try:
        parsed = urlparse(str(url))
        return (
            parsed.scheme in ["http", "https"]
            and parsed.hostname is not None
        )
    except ValueError:
        return False

structure_check = cleaned_df["url"].apply(has_basic_http_structure)

unusual_urls = cleaned_df[~structure_check].copy()

def get_scheme(url):
    try:
        return urlparse(str(url)).scheme
    except ValueError:
        return "parse_error"

unusual_urls["detected_scheme"] = unusual_urls["url"].apply(get_scheme)

print("\nURL structure investigation:")
print(f"URLs passing basic HTTP/HTTPS structure check: {structure_check.sum()}")
print(f"URLs requiring investigation: {len(unusual_urls)}")

print("\nUnusual URLs by detected scheme:")
print(unusual_urls["detected_scheme"].value_counts(dropna=False))

print("\nSample unusual URLs:")
print(
    unusual_urls[["url", "type", "source", "detected_scheme"]]
    .head(20)
    .to_string(index=False)
)

print("\nUnusual URLs were retained and were not automatically modified.")

print("\nFinal dataset validation:")
print(f"Final rows: {len(cleaned_df)}")
print(f"Duplicate URLs: {cleaned_df['url'].duplicated().sum()}")
print(f"Missing URLs: {cleaned_df['url'].isnull().sum()}")
print(f"Missing labels: {cleaned_df['type'].isnull().sum()}")
print(f"Missing sources: {cleaned_df['source'].isnull().sum()}")
print(f"Blank URLs: {cleaned_df['url'].astype(str).str.strip().eq('').sum()}")

print("\nFinal columns:")
print(cleaned_df.columns.tolist())

cleaned_df.to_csv(
    "../Datasets/combined_cleaned.csv",
    index=False
)

print("\nCleaned dataset saved successfully.")
print("File: ../Datasets/combined_cleaned.csv")