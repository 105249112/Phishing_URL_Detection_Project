import os
import re
import pandas as pd
from PIL import Image
from pyzbar.pyzbar import decode, ZBarSymbol


# Function to extract only the URL from QR decoded text

def extract_url(decoded_text):

    match = re.search(r'https?://[^\s]+', decoded_text)

    if match:
        return match.group(0).strip()

    return None


# Function to decode one QR-code folder


def decode_qr_folder(folder_path, label):

    data = []

    failed_files = []

    successful_decodes = 0
    failed_decodes = 0
    no_url_found = 0
    processing_errors = 0


    # Get all image files
    image_files = [
        filename
        for filename in os.listdir(folder_path)
        if filename.lower().endswith(
            (".png", ".jpg", ".jpeg", ".bmp", ".webp")
        )
    ]

    total_images = len(image_files)

    print(f"\nProcessing {label} QR folder")
    print(f"Total images found: {total_images}")


    # Process every image
    for filename in image_files:

        file_path = os.path.join(folder_path, filename)

        try:

            # Open image
            image = Image.open(file_path)

            # Decode only QR codes
            decoded_objects = decode(
                image,
                symbols=[ZBarSymbol.QRCODE]
            )

            if decoded_objects:

                url_found = False

                for obj in decoded_objects:

                    decoded_text = obj.data.decode(
                        "utf-8",
                        errors="ignore"
                    )

                    # Extract clean URL
                    url = extract_url(decoded_text)

                    if url:

                        url_found = True

                        data.append({
                            "url": url,
                            "type": label,
                            "source": "qr"
                        })

                if url_found:
                    successful_decodes += 1

                else:

                    no_url_found += 1

                    failed_files.append({
                        "filename": filename,
                        "label": label,
                        "reason": "QR decoded but no URL found"
                    })

            else:

                failed_decodes += 1

                failed_files.append({
                    "filename": filename,
                    "label": label,
                    "reason": "Could not decode QR code"
                })

        except Exception as e:

            processing_errors += 1

            failed_files.append({
                "filename": filename,
                "label": label,
                "reason": str(e)
            })


    # Calculate success rate
    if total_images > 0:

        success_rate = (
            successful_decodes / total_images
        ) * 100

    else:

        success_rate = 0


    # Show summary
    print(f"\n{label.upper()} QR SUMMARY")

    print(f"Total images: {total_images}")
    print(f"Successfully decoded: {successful_decodes}")
    print(f"Could not decode: {failed_decodes}")
    print(f"Decoded but no URL found: {no_url_found}")
    print(f"Processing errors: {processing_errors}")
    print(f"Success rate: {success_rate:.2f}%")

    return data, failed_files


# Folder paths (Sincce i had two qr folder containg images over 100,000 each, one folder conftains malicious qr images and the other 
# folder had benign qr images)


benign_folder = "/Users/mohamedaarriz/Desktop/swinbunre/Sem4/Computing Innovation Technology/Assignment 2/Phishing URL Detection Project/Datasets/Qr_benign"

malicious_folder = "/Users/mohamedaarriz/Desktop/swinbunre/Sem4/Computing Innovation Technology/Assignment 2/Phishing URL Detection Project/Datasets/Qr_malicious"


# Decode benign QR dataset


benign_data, benign_failures = decode_qr_folder(
    benign_folder,
    "benign"
)


# Decode malicious QR dataset


malicious_data, malicious_failures = decode_qr_folder(
    malicious_folder,
    "malicious"
)



# Combine both decoded QR datasets


all_qr_data = benign_data + malicious_data

df = pd.DataFrame(all_qr_data)


# Remove whitespace just in case
if not df.empty:

    df["url"] = df["url"].str.strip()



# Save combined QR dataset

df.to_csv("../Datasets/qr_processed.csv", index=False)

# Combine failed files


all_failures = benign_failures + malicious_failures

failed_df = pd.DataFrame(all_failures)

failed_df.to_csv(
    "qr_decode_failures.csv",
    index=False
)

# Display first 5 rows


print("\nFirst 5 processed QR URLs:")

print(df.head(5))



# Final summary (after decoding the entire images, this will print the summary of the process)


print("\nFinal QR Dataset Summary")

print(f"Total usable QR URLs: {len(df)}")

print("\nLabel distribution:")

print(df["type"].value_counts())

print("\nFiles created:")
print("qr_processed.csv")