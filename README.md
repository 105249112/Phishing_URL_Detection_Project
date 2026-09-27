# Phishing URL Detection Project

Machine learning project to detect phishing URLs, using URL-based lexical features and a combination of a base dataset, a supplementary URL dataset, and a QR-code-derived dataset.

## 1. Environment Setup

Clone the repo:
```bash
git clone https://github.com/YOUR_USERNAME/Phishing_URL_Detection_Project.git
cd Phishing_URL_Detection_Project
```

Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate      # Mac/Linux
venv\Scripts\activate         # Windows
```

Install required packages:
```bash
pip install -r requirements.txt
```


## 2. Get the Datasets


### Dataset download links 

Qr Codes datasets - https://www.kaggle.com/datasets/samahsadiq/benign-and-malicious-qr-codes/data

Base Dataset - https://data.mendeley.com/datasets/vfszbj9b36/1 (URL dataset.csv) - Base Dataset


After downloading, place the files in this exact structure at the project root:

Phishing_URL_Detection_Project/
└── Datasets/
    ├── benign/ ← benign QR code images
    ├── Qr_malicious/ ← malicious QR code images
    └── URL dataset.csv ← supplementary URL dataset ###(since the base url given in the assignment description has lot of errors in we hve decided to use this URL dataset.csv as our basedataset)



## 3. Run Data Processing      (still needs to be completed once we done with data processing)

```bash
cd Souce_code
python3 Data_Processing.py
```

This script:
- Decodes QR code images into URL text
- Merges the base dataset, supplementary dataset, and decoded QR URLs
- Cleans the combined dataset (removes duplicates, invalid URLs, standardizes labels)
- Outputs the cleaned dataset to `[filename].csv`

## 4. Train the Model        (still needs to be completed once we done with model traning)

*(fill this in once built)*
```bash
python3 train_model.py
```





## Project Structure

Phishing_URL_Detection_Project/
├── Datasets/ (not tracked in Git — see setup above)
├── Souce_code/
│ ├── base_processing.py
| |-- base_processed.csv
| |--Qr_decoding.py
│ └── qr_processed.csv
|
├── requirements.txt
└── README.md


