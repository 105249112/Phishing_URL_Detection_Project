import pandas as pd
import matplotlib.pyplot as plt


# =========================================================
# LOAD FEATURE DATASET
# =========================================================

df = pd.read_csv("../Datasets/feature_dataset.csv")



# 1. BASIC DATASET OVERVIEW


print("\n========== DATASET OVERVIEW ==========")

print("\nDataset shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nMissing values:")
print(df.isnull().sum())
print("No missising values")

print("\nDuplicate URLs:")
print(df["url"].duplicated().sum())

print("\nLabel distribution:")
print(df["type"].value_counts())

print("\nSource distribution:")
print(df["source"].value_counts())


# 2. FEATURE COLUMNS


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



# 3. DESCRIPTIVE STATISTICS


print("\n========== DESCRIPTIVE STATISTICS ==========")

print(
    df[feature_columns]
    .describe()
    .round(2)
)


# 4. FEATURE AVERAGES BY CLASS


print("\n========== FEATURE AVERAGES BY CLASS ==========")

class_means = (
    df.groupby("type")[feature_columns]
    .mean()
    .round(3)
)

print(class_means)



# 5. DIFFERENCE BETWEEN MALICIOUS AND BENIGN


difference = (
    class_means.loc["malicious"]
    - class_means.loc["benign"]
)

difference = difference.sort_values(
    key=abs,
    ascending=False
)

print("\n========== DIFFERENCE: MALICIOUS - BENIGN ==========")

print(difference)



# 6. CLASS DISTRIBUTION   - figure 1 


plt.figure()

df["type"].value_counts().plot(
    kind="bar"
)

plt.title("Benign vs Malicious URL Distribution")
plt.xlabel("URL Type")
plt.ylabel("Number of URLs")
plt.xticks(rotation=0)
plt.tight_layout()

plt.show()



# 7. SOURCE DISTRIBUTION - figure 2


plt.figure()

df["source"].value_counts().plot(
    kind="bar"
)

plt.title("Dataset Source Distribution")
plt.xlabel("Source")
plt.ylabel("Number of URLs")
plt.xticks(rotation=0)
plt.tight_layout()

plt.show()



# 8. URL LENGTH BY CLASS - Boxplot, figure 3 


plt.figure()

df.boxplot(
    column="url_length",
    by="type",
    showfliers=False
)

plt.title("URL Length by Class")
plt.suptitle("")
plt.xlabel("URL Type")
plt.ylabel("URL Length")

plt.tight_layout()

plt.show()



# 9. URL LENGTH DISTRIBUTION - Figure 4


benign_lengths = df[
    df["type"] == "benign"
]["url_length"]

malicious_lengths = df[
    df["type"] == "malicious"
]["url_length"]


plt.figure()

plt.hist(
    benign_lengths,
    bins=50,
    alpha=0.5,
    label="Benign"
)

plt.hist(
    malicious_lengths,
    bins=50,
    alpha=0.5,
    label="Malicious"
)

plt.title("URL Length Distribution")
plt.xlabel("URL Length")
plt.ylabel("Frequency")
plt.legend()
plt.tight_layout()

plt.show()



# 10. NUMERIC FEATURE BOXPLOTS - Figure 5,6,7,8


boxplot_features = [
    "hyphen_count",
    "number_count",
    "subdomain_count",
    "path_depth"
]

for feature in boxplot_features:

    plt.figure()

    df.boxplot(
        column=feature,
        by="type"
    )

    plt.title(f"{feature} by Class")
    plt.suptitle("")
    plt.xlabel("URL Type")
    plt.ylabel(feature)
    plt.tight_layout()

    plt.show()



# 11. BINARY FEATURE ANALYSIS  - Figure 9


binary_features = [
    "uses_https",
    "has_ip",
    "has_at_symbol",
    "has_double_slash_redirect",
    "has_lookalike_chars",
    "tld_risk",
    "has_suspicious_keyword"
]


print("\n========== BINARY FEATURE ANALYSIS ==========")

for feature in binary_features:

    print(f"\nFeature: {feature}")

    percentage_table = (
        pd.crosstab(
            df["type"],
            df[feature],
            normalize="index"
        ) * 100
    )

    print(percentage_table.round(2))



# 12. PERCENTAGE OF EACH BINARY FEATURE BY CLASS


binary_summary = (
    df.groupby("type")[binary_features]
    .mean()
    * 100
)

print("\n==== BINARY FEATURE PERCENTAGES =====")

print(binary_summary.round(2))


binary_summary.T.plot(
    kind="bar"
)

plt.title("Binary URL Features by Class")
plt.xlabel("Feature")
plt.ylabel("Percentage of URLs")
plt.xticks(
    rotation=45,
    ha="right"
)
plt.tight_layout()

plt.show()



# 13. CORRELATION MATRIX  - checks how each feature is related with other features


correlation_matrix = (
    df[feature_columns]
    .corr()
)

print("\n=== FEATURE CORRELATION MATRIX =====")

print(
    correlation_matrix
    .round(2)
)






# 14. FEATURE MEDIANS BY CLASS - compares the middle value of each feature for the type


print("\n==== FEATURE MEDIANS BY CLASS ======")

class_medians = (
    df.groupby("type")[feature_columns]
    .median()
    .round(2)
)

print(class_medians)



# 15. DATA SOURCE VS LABEL - htis checks how lables are distributed across the different dataset sources 


print("\n===== SOURCE VS LABEL =====")

source_label_table = pd.crosstab(
    df["source"],
    df["type"]
)

print(source_label_table)


print("\nSource vs label percentages:")

source_label_percent = pd.crosstab(
    df["source"],
    df["type"],
    normalize="index"
) * 100

print(
    source_label_percent.round(2)
)





# FINAL MESSAGE


print("\n======= DATA ANALYSIS COMPLETE ========")
