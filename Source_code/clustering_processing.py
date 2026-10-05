import random

import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score

# Loads the feature dataset
df = pd.read_csv("../Datasets/feature_dataset.csv")

print("Loaded shape:")
print(df.shape)

feature_columns = [
    "url_length", "hyphen_count", "number_count", "uses_https",
    "has_ip", "subdomain_count", "has_at_symbol",
    "has_double_slash_redirect", "path_depth",
    "has_lookalike_chars", "tld_risk", "has_suspicious_keyword",
]

# colours for the graphs 
cluster_colors = {
    1: "#1f77b4",   # blue
    2: "#ff7f0e",   # orange
    3: "#2ca02c",   # green
    4: "#d62728",   # red
    5: "#9467bd",   # purple
}

# Only clustering one class according the the assignment description so i chose malicious 
malicious_df = df[df["type"] == "malicious"].reset_index(drop=True)

print("\nMalicious rows:")
print(malicious_df.shape)

X = malicious_df[feature_columns]

# Standardises features so no single feature dominates for example url_length
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)


# Graph 1: Silhouette score for different values of k

# Trys a range of k values and scores each one, so we can pick the k that produces the better seperated cluster
k_values = [2, 3, 4, 5, 6]
silhouette_scores = []

for k in k_values:

    kmeans_test = KMeans(
        n_clusters=k,
        random_state=42,
        n_init=10
    )

    labels_test = kmeans_test.fit_predict(X_scaled)

     #Scoring all 136,784 rows took far way to long to finish, so a 20,000 row sample had to be used instead
    score = silhouette_score(
        X_scaled,
        labels_test,
        sample_size=20000,
        random_state=42
    )

    silhouette_scores.append(score)

    print(f"k={k}: Silhouette Score = {score:.3f}")


plt.figure(figsize=(7, 4))

plt.plot(
    k_values,
    silhouette_scores,
    marker="o"
)

plt.xlabel("Number of clusters (k)")
plt.ylabel("Silhouette score") #scoring system that measures how well separated the clusters are
plt.title("K-Means Cluster Evaluation by Silhouette Score")
plt.tight_layout()

plt.show()


# Picks whichever k scored highest that's the one that gave the best seperation between clusters
best_k = k_values[silhouette_scores.index(max(silhouette_scores))]

print(f"\nBest k: {best_k}")

# Final K-Means clustering

kmeans = KMeans(
    n_clusters=best_k,
    random_state=42,
    n_init=10
)

# adds 1 so clusters are numbered 1, 2, 3 instead of starting at 0
malicious_df["cluster"] = kmeans.fit_predict(X_scaled) + 1


print("\nCluster sizes:")
print(
    malicious_df["cluster"]
    .value_counts()
    .sort_index()
    .to_string()
)

# Feature averages and differences

# The average feature values across all malicious URLs, used as a baseline to compare each cluster against
overall_avg = malicious_df[feature_columns].mean()

# The average feature values within each individual cluster
cluster_avg = malicious_df.groupby("cluster")[feature_columns].mean()

# How far each cluster's averages are from the overall average this is what actually describes what makes each cluster distinct
cluster_diff = cluster_avg - overall_avg

print("\nOverall malicious averages:") 
print(overall_avg.to_string())


print("\nAverage feature values per cluster:") 
print(cluster_avg.to_string())


print("\nDifference from overall average:") # A negative value means that cluster is below the overall average for that feature and a positive value means it's above average
print(cluster_diff.to_string())


# Graph 2: Scatter plot using two features

plt.figure(figsize=(7, 6))

for c in sorted(malicious_df["cluster"].unique()):

    cluster_points = malicious_df[malicious_df["cluster"] == c]

    plt.scatter(
        cluster_points["url_length"],
        cluster_points["number_count"],
        c=cluster_colors[c],
        s=5,
        alpha=0.5,
        label=f"Cluster {c}"
    )

plt.xlabel("URL Length (characters)")
plt.ylabel("Number of Digits in URL")
plt.title("Malicious URL Clusters by Length and Digit Count")
plt.legend(title="Cluster")
plt.tight_layout()

plt.show()

# Graph 3: Top 5 distinguishing features per cluster

# Finds the 5 features with the biggest swing away from the overall average, across any cluster
top_features = (
    cluster_diff.abs()
    .max()
    .sort_values(ascending=False)
    .head(5)
    .index
)

x = range(len(top_features))

bar_width = 0.15

plt.figure(figsize=(9, 5))

for i, c in enumerate(cluster_diff.index):

    offsets = [
        pos + i * bar_width
        for pos in x
    ]

    plt.bar(
        offsets,
        cluster_diff.loc[c, top_features],
        width=bar_width,
        label=f"Cluster {c}",
        color=cluster_colors[c]
    )

plt.axhline(
    0,
    linewidth=0.8
)

plt.xticks(
    [
        pos + bar_width * 2
        for pos in x
    ],
    top_features,
    rotation=20,
    ha="right"
)

plt.ylabel("Difference from overall average")
plt.title("Top 5 distinguishing features, by cluster")
plt.legend()

plt.tight_layout()

plt.show()


# some real examples to support the cluster descriptions

print("\nExample URLs per cluster:")

for c in sorted(malicious_df["cluster"].unique()):

    print(f"\nCluster {c} examples:")

    example_urls = malicious_df[
        malicious_df["cluster"] == c
    ]["url"].head(5)

    for url in example_urls:
        print(url)

print("\nClustering complete.")
