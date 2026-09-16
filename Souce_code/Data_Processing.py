import os
import re
import pandas as pd
from PIL import Image
from pyzbar.pyzbar import decode, ZBarSymbol


### Decoding and Cleaning QR Code Files ###

# Folder containing malicious QR code images
folder_path = "  "  #need to give the folder path

# Store decoded information
data = []


# Function to extract only the URL from the decoded QR text
def extract_url(decoded_text):

    # Search for a URL beginning with http:// or https://
    # and stop when whitespace or a new line is reached
    match = re.search(r'https?://[^\s]+', decoded_text)

    if match:
        return match.group(0).strip()

    return None


# Gest all image files from the folder
image_files = [
    filename for filename in os.listdir(folder_path)
    if filename.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".webp"))
]

print(f"Found {len(image_files)} QR code images.\n")


# Process every image file
for count, filename in enumerate(image_files, start=1):

    file_path = os.path.join(folder_path, filename)

    try:
        # Open the QR code image
        image = Image.open(file_path)

        # Decode only QR codes
        decoded_objects = decode(
            image,
            symbols=[ZBarSymbol.QRCODE]
        )

        if decoded_objects:

            for obj in decoded_objects:

                # Get the complete/raw text stored inside the QR code
                decoded_text = obj.data.decode("utf-8")

                # Extract only the URL from the raw text
                url = extract_url(decoded_text)

                if url:

                    # Since the entire dataset is malicious
                    label = "malicious"

                    data.append({
                        "url": url,
                        "label": label
                    })

                else:
                    print(f"No URL found in: {filename}")

        else:
            print(f"Could not decode: {filename}")

    except Exception as e:
        print(f"Error processing {filename}: {e}")


# Convert collected data into a Pandas DataFrame
df = pd.DataFrame(data)

# Remove any leading/trailing whitespace from URLs
df["url"] = df["url"].str.strip()


# Save all decoded and cleaned URLs to CSV
df.to_csv("malicious_qr_urls.csv", index=False)


# Display only the first 5 results
print("\nFirst 5 decoded and cleaned QR URLs:")

if not df.empty:
   
        print(df.head(5))
else:
    print("No URLs were successfully extracted.")


# Display summary
print(f"\nTotal successfully extracted URLs: {len(df)}")
print("CSV saved as: malicious_qr_urls.csv")