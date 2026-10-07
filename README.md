# Phishing URL Detection Project  --- #### (To Check a URL whether it is malicious or not - Run main.py and choose option 4 and paste the URL to get the result)

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

### i also haven't uploaded the QR code images to the github beacause since the file is very big and has over 200,000 image so the github won't support. Therefore in Qr_decoding.py file i have manually add the Qr dataset path for decoding, if you need to check the Qr_decoding.py file, u have to download the Qr code images from the above link and use the path where it is installed in the computer. 

Base Dataset - https://data.mendeley.com/datasets/vfszbj9b36/1 (URL dataset.csv) - Base Dataset


Dataset Structure: 




## 3. Project Structure

the below is exact project every teammember followed throughout the project: 


Phishing URL Detection Project/
│
├── Datasets/
│   ├── Qr_benign/
│   │   └── benign QR-code images
│   │
│   ├── Qr_malicious/
│   │   └── malicious QR-code images
│   │
│   ├── base_processed.csv
│   ├── combined_cleaned.csv
│   ├── combined_dataset.csv
│   ├── feature_dataset.csv
│   ├── qr_decode_failures.csv
│   ├── qr_processed.csv
│   └── URL dataset.csv
│
├── Models/
│   ├── char_to_id.json
│   ├── clustering_kmeans.joblib
│   ├── clustering_scaler.joblib
│   ├── innovation_cnn.keras
│   └── phishing_classifier.joblib
│
├── Source_code/
│   ├
│   │
│   ├── base_processing.py
│   ├── Classification.py
│   ├── clustering_processing.py
│   ├── cnn_confusion_matrix.py
│   ├── combined_quality_check.py
│   ├── data_analysis.py
│   ├── feature_extraction.py
│   ├── innovation_model.py
│   ├── main.py
│   ├── merge_processing.py
│   ├── model_comparison_graph.py
│   ├── model_evaluation.py
│   └── Qr_decoding.py
│
├── venv/
│
├── .gitignore
├── README.md
└── requirements.txt

#### (To Check a URL whether it is malicious or not - Run main.py and choose option 4 and paste the URL to get the result)

## 4. Data Processing

Step 1 — Decode the QR images

run the commandd: python3 Qr_decoding.py

This will do: 

- reads images from Qr_benign and Qr_malicious
- decodes QR codes using Pillow and pyzbar
- extracts HTTP/HTTPS URLs
- assigns benign or malicious labels
- records the source as qr
- saves the processed data as: ../Datasets/qr_processed.csv 


Step 2 — Process the base dataset

run the command: python3 base_processing.py

This will do:
- loads URL dataset.csv
- checks missing values, blank URLs and duplicate rows
- standardises labels from legitimate/phishing to benign/malicious
- adds the source value base
- saves: ../Datasets/base_processed.csv

Step 3 — Merge the datasets

run the command: python3 merge_processing.py

This combines the processed base and QR datasets and saves:
../Datasets/combined_dataset.csv


Step 4 — Clean and validate the combined dataset

run the command: python3 combined_quality_check.py

This step checks:
- missing and blank values
- duplicate URLs
- conflicting labels
- overlap between the base and QR sources
- URL structure
Duplicate URLs are removed and URLs appearing in both sources are marked as both.
The cleaned output is:
../Datasets/combined_cleaned.csv

Step 5 — Extract machine-learning features

run the command: python feature_extraction.py

The code creates URL features including:
- URL length
- hyphen count
- digit count
- HTTPS usage
- IP-address usage
- subdomain count
- @ symbol
- double-slash redirect pattern
- path depth
- look-alike characters
- risky top-level domain
- suspicious keywords
The resulting training dataset is saved as:
../Datasets/feature_dataset.csv


 To inspect the prepared feature dataset and produce exploratory graphs/statistics, 
run: python3 data_analysis.py


## 5. Train the Models

## Baseline classifiers
Run: python3 Classification.py

This trains:

- Logistic Regression
- Random Forest

The models use a stratified 70% training, 15% validation and 15% testing split. Performance is measured using accuracy, precision, recall, F1-score, confusion matrices, classification reports and 5-fold stratified cross-validation.

The trained Random Forest pipeline is saved as since it is more effective than logistic regression and choosed it the baseline for now:
../Models/phishing_classifier.joblib

## Character-level CNN

Run: python3 innovation_model.py

The CNN works directly with the raw URL character sequence. URLs are encoded, padded/truncated to 200 characters and processed through an embedding layer and a 1D convolutional neural network.

The code saves:
../Models/innovation_cnn.keras
../Models/char_to_id.json

## K-Means clustering

Run: python3 clustering_processing.py

K-Means is applied to malicious URLs to identify groups of similar malicious URL patterns.
It saves:
../Models/clustering_kmeans.joblib
../Models/clustering_scaler.joblib

## 6. Evaluate the Final CNN

Run: python3 model_evaluation.py

The evaluation includes:
- accuracy
- precision
- recall
- F1-score
- classification report
- confusion matrix
- false-positive analysis
- false-negative analysis

It also performs an additional source-holdout evaluation. A fresh CNN is trained using only base URLs and tested using only qr URLs, while URLs labelled both are excluded. This provides a harder test of how well the model generalises to a different data source.

## 7. Use the Trained Models for Prediction

Before running the application, make sure the required model files have been created by running the training scripts above.
Start the application by running: 
# python3 main.py

The menu provides options for:
1. Run Data Analysis
2. Run Classification Evaluation
3. Run Clustering Analysis
4. Test a URL
5. Exit
Choose:
4
and enter a URL.
The program:
1. extracts the URL features
2. predicts benign/malicious using the saved Random Forest model
3. predicts benign/malicious using the saved CNN
4. displays the malicious probability
5. displays detected suspicious URL features
6. if a model predicts malicious, assigns the URL to the closest malicious K-Means cluster
Example:
Enter choice (1-5): 4
Enter a URL to test: http://example-login-site.com/account

Random Forest:
Prediction: MALICIOUS

Innovation CNN:
Prediction: MALICIOUS


## 8. Recommended Execution Order
For a complete run from the original downloaded datasets:

cd Source_code

python3 Qr_decoding.py
python3 base_processing.py
python3 merge_processing.py
python3 combined_quality_check.py
python3 feature_extraction.py
python3 data_analysis.py
python3 Classification.py
python3 innovation_model.py
python3 clustering_processing.py
python3 model_evaluation.py
python3 main.py

If the prepared datasets and trained models already exist, you can directly run: (make sure it is an right order)
cd Source_code

  python3 main.py


 Thakn you