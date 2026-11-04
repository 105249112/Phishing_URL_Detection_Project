import pandas as pd

# load both datasets
base_df = pd.read_csv("../Datasets/base_processed.csv")
qr_df = pd.read_csv("../Datasets/qr_processed.csv")

# show how many rows and columns each dataset has
print("Base shape:")
print(base_df.shape)

print("\nQR shape:")
print(qr_df.shape)


print("\nBase columns:")
print(base_df.columns.tolist())

print("\nQR columns:")
print(qr_df.columns.tolist())

# stops if the columns don't match   
expected = ["url", "type", "source"]
assert base_df.columns.tolist() == expected, "Base columns do not match"
assert qr_df.columns.tolist() == expected, "QR columns do not match"

# joins the two datasets into one
combined_df = pd.concat([base_df, qr_df], ignore_index=True)

# shows the size of the joined dataset
print("\nCombined shape:")
print(combined_df.shape)

# shows how many benign and malicious rows there are
print("\nType distribution:")
print(combined_df["type"].value_counts())

# shows how many rows came from base and qr
print("\nSource distribution:")
print(combined_df["source"].value_counts())

# saving the combined dataset 
combined_df.to_csv("../Datasets/combined_dataset.csv", index=False)

#confirming the dataset was saved
print("\nCombined dataset saved successfully.")
print("File: ../Datasets/combined_dataset.csv")