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








##### Assignment 3 readme sections: ###########


###### 2.6 Threat Model

The Phishing URL Detection application is a web application using React and FastAPI. This application uses a trained Random Forest classifier to detect potentially phishing URLs. The main threat actor is the phisher who will try to avoid detection by changing the characteristics of URLs to be classified as legitimate. The second threat actor is an abusive API user who will try to cause problems with the application or find any vulnerabilities.

Attackers can craft malicious URLs using the React frontend, or can manually issue HTTP requests to /predict FastAPI endpoint. Attackers can also query the model repeatedly, to collect information about the model predictions (labels, confidence scores), inference time, and errors. Attackers are assumed not to have admin access to the server, nor control over the trained model.

Main threats are DoS attacks due to excessive or expensive requests to predict. Other threats are vulnerabilities coming from insecure app configurations, vulnerable dependencies and unsafe model loading via Joblib. Rate limiting is added, but further protection may be needed to prevent expensive requests. SQL injection, file upload attacks and improper access control do not apply since there is no SQL database, file upload functionality or user accounts. Command injection and SSRF are also not an issue as long as the URL feature extraction is not carrying out any system commands or fetching resources from outside.

Denial of service protection was chosen to protect against the threats identified. Misconfiguration and vulnerable dependencies were also chosen from Section 2.7. Section 2.8 looks at how evasion can be prevented by using controlled URL manipulation, and if input normalisation helps to make the model more robust against these types of attacks.


###### Section 2.7 Security Defences

Two security defences were selected based on the threat model in Section 2.6: Misconfiguration and Vulnerable Dependencies (Intermediate) and Denial-of-Service Protection (Advanced). These defences address risks associated with insecure third-party libraries, missing security configurations and excessive requests to the machine-learning prediction endpoint.

#### 2.7.1 Misconfiguration and Vulnerable Dependencies (Intermediate Defence)

Threat and justification

Phishing URL Detection uses a variety of third party dependencies. This includes using React, Vite, FastAPI. Using outdated libraries can leave applications vulnerable to known vulnerabilities. Not having HTTP security headers can leave the application vulnerable to threats such as cross-site scripting (XSS), clickjacking and misinterpretation.This defence was chosen to help find any known vulnerabilities in dependencies and improve the security configuration on the front-end.

Implementation

Dependency audits were performed using "npm audit" for the React frontend and "pip-audit" for the Python backend.
Following an initial audit we found 3 high severity vulnerabilities relating to the dependencies of React Router, React Router DOM, and Vite. All these were updated to a compatible patched version. Following an audit we found there are no known vulnerabilities in the frontend dependencies. We also found no known vulnerabilities in the Python dependencies.

The running web application was examined using OWASP ZAP. The initial scan identified missing security headers, including Content Security Policy (CSP), anti-clickjacking protection and X-Content-Type-Options.

To address these findings, security headers were configured in 'frontend 2/vite.config.js' file for the Vite production-preview server:

1. Content-Security-Policy: Restricts permitted resource sources, including scripts and styles.

2. X-Frame-Options: DENY: Prevents other websites from embedding the application in frames.

3. X-Content-Type-Options: nosniff: Prevents browsers from interpreting responses as an unintended content type.


The CSP was further strengthened by removing the 'unsafe-inline' allowance from style-src.

The testing and results shows that: 

Security assessment                   Before defence                     After defence 

npm dependency audit               3 high vulnerabilities             0 reported vulnerabilities

Python dependency audit          0 known vulnerabilities                  No remediation required

ZAP alert categories                      7                                       3

ZAP medium-risk categories                2                                       0

Frontend security headers       Required headers missing                Configured and verified


The final ZAP scan had zero high and medium risk alerts. There was only 1 low risk alert relating to not having the X-Content-Type-Options header on the FastAPI CORS pre-flight responses. There were also 2 informational alerts.
As the first scan was done against the Vite development server and the last scan was against the production-preview server there will be a difference in the number of alerts shown due to the new headers. The changes made were also checked by looking at the HTTP response headers using curl.
Regression testing was done to confirm that the front-end was still able to submit URLs, get predictions from the Random Forest model and show the visualisation charts. Using a clean chrome profile there were no visible errors in the application console.

Limitations

Auditing dependencies will only identify any vulnerabilities that have been reported within the dependency information available to the tools. It does not guarantee the whole application has no vulnerabilities. Updating dependencies can cause compatibility issues which need to be regression tested. Security headers were tested on the local Vite preview server. In a production environment these protections would also need to be configured on the real hosting server.



###### 2.7.2  Denial-of-Service Protection (Advanced Defence)


Threat & Justification

The /predict endpoint of the application extracts features from the URL and uses a Random Forest algorithm to classify the URL. This endpoint can be misused by an attacker to make many requests at once. This will consume processing power, lowering the availability of the service to real users.
SlowAPI rate limiting has been implemented along with limits on the size of the request body. However, this does not limit the amount of model inferences that can happen concurrently.
Therefore a new method was implemented within the backend/main.py file.

Implementation

A bounded semaphore was implemented in Python to allow for a maximum of 2 model inferences to run at once in one backend process.
Each validated request will attempt to acquire one of the slots before extracting features and predicting with the model.
If there are available slots then the request will run as normal. However if both slots are taken then the backend will return an HTTP 503 (Service Unavailable) response and indicate that they should try again. Finally the slot will be released. The existing synchronous endpoint will still run using the FastAPI thread pool.

Controlled Attack Simulation

To test this defence a temporary testing mode was added to add a 2 second delay into the protected inference function. This simulates a costly process. This is turned off by default.
5 requests were made at once using Python ThreadPoolExecutor. Using the same testing method and simulated costly process the application was tested with and without the semaphore admission control.

The testing and results shows that: 

Measurement                                   Without defence                     With defence

Simultaneous prediction requests                     5                                   5

Successful requests (HTTP 200)                       5                                   2

Rejected requests (HTTP 503)                         0                                   3

Mean successful response time                  Approximately 2.241 s               Approximately 2.163 s

Mean overload rejection time                     Not applicable                    Approximately 0.027 s

Maximum permitted active inferences             No explicit two-slot limit               2




The protected application took 27-28ms to deny the 3 extra requests, while the accepted requests took around 2 seconds to complete. Further testing to ensure availability and recovery:

Responsiveness

The /health endpoint showed a 200 response time of only 17ms while 2 requests were being processed for expensive predictions.

Recovery

Another request was made which gave a 503 response whilst there were still active predictions. Once they had completed however, another request was made and it returned a 200.

Variation Testing

5 valid URLs were requested at the same time. Only 2 of the requests returned a 200, while 3 returned a 503 response. This took around 31ms.

Regression Testing

When not in test mode, the React front end continued to make predictions and show the class-probability and session history charts.
This shows that we can limit concurrent inference, and quickly deny additional work.

Limitations and Trade-Offs

There is a trade-off between availability due to limiting concurrency. If both inference slots are busy, genuine users would get a 503 response. The client should therefore be resilient and attempt to re-request after a reasonable time period.
The semaphore is limited to one Python process. If you had multiple workers or a distributed system, you would need some sort of shared admission control.
Due to this being a controlled environment with a 2 second delay, rather than a large scale DoS attack, it shows that inference is limited to a certain point, but doesn’t fully protect against DoS/DDoS attacks in the real world.


2.7.3 Overall Security Evaluation

The two defences address different aspects of the application's attack surface.

The Intermediate defence reduces exposure to known vulnerable dependencies and unsafe frontend security configurations. The Advanced defence protects machine-learning inference capacity from excessive concurrent processing.

Both defences were evaluated using security tools, controlled experiments and application regression testing. The results demonstrate measurable improvements while preserving the phishing URL checker's main functionality.

Supporting evidence includes the npm and Python dependency audits, OWASP ZAP reports, concurrency-test scripts, response-time measurements and application screenshots. These are retained under security_evidence/section_2.7/.


 ## FastAPI Backend (Assignment 3)


Overview
The FastAPI backend connects the React URL checker to the trained Random Forest classifier from Assignment 2. It validates the submitted URL, extracts the same lexical URL features used during model training, and returns a classification and probability scores in JSON format. Pydantic defines the request and response schemas.

Setup and Run
From the project root, with Python installed, install the backend dependencies:
python3 -m pip install -r backend/requirements.txt

The saved model must be present at Models/phishing_classifier.joblib, and the feature extractor must be available at Source_code/feature_extraction.py. Start the API from the project root:
python3 -m uvicorn backend.main:app --reload

The API is available at http://127.0.0.1:8000, with interactive documentation at http://127.0.0.1:8000/docs. Start the backend before running the React frontend.

API Endpoints
GET /health reports whether the application and saved model are ready. A successful response is:
{
  "status": "ok",
  "model_ready": true,
  "message": "Phishing URL Detection API and model are ready"
}
POST /predict accepts a JSON request containing a URL:
{
  "url": "https://www.example.com"
}
A successful response contains the URL, predicted class (BENIGN or MALICIOUS), prediction confidence, and malicious-class probability:
{
  "url": "https://www.example.com",
  "prediction": "BENIGN",
  "confidence": 0.95,
  "malicious_probability": 0.05
}

The classification and probability values above are illustrative, not recorded model outputs. Probability values are between 0 and 1 and rounded to four decimal places.

## Model Integration
The Random Forest model is loaded from Models/phishing_classifier.joblib once during the FastAPI application lifespan startup. For each valid URL, the backend calls extract_features() from Source_code/feature_extraction.py, creates a Pandas DataFrame with the model's expected feature columns, and calls predict() and predict_proba(). The backend reuses the Assignment 2 model rather than retraining it on each request.
Validation and Error Handling
The request schema requires a URL string of 1–2,048 characters. Additional validation checks the HTTP/HTTPS scheme, hostname, whitespace and port format. Errors are returned in JSON using a detail field, without exposing internal model exceptions.

HTTP status	Meaning
200	Successful request
400	Invalid Content-Length header
413	POST request body exceeds 8,192 bytes
422	Missing, malformed or invalid URL
429	Prediction rate limit exceeded
500	Unexpected model prediction failure
503	Model unavailable or prediction capacity reached


Backend Protections
- Rate limiting: SlowAPI limits /predict to 10 requests per minute per client IP and returns HTTP 429 when exceeded.
- Body-size restriction: Custom ASGI middleware checks both Content-Length and received request bytes, rejecting POST bodies over 8,192 bytes (8 KiB), including streamed bodies.
- CORS: The backend permits the local React development origins http://localhost:5173 and http://127.0.0.1:5173.
- Concurrent inference protection: The version of backend code reviewed includes a bounded semaphore allowing at most two concurrent inferences per backend process. Additional requests receive HTTP 503 and a Retry-After header. Its separate experiment and limitations are documented in Section 2.7.2; final integration into main should be verified after the security branches are merged.
- Controlled DoS test mode: DOS_TEST_MODE is disabled by default and introduces a simulated two-second inference delay only when deliberately enabled for local testing. It must not be enabled in deployment.

Automated Backend Tests
Run the backend test suite from the project root:
python3 -m pytest backend/tests/test_main.py -v
The 13 tests cover the health endpoint, a valid prediction, empty and missing URLs, unsupported schemes, invalid ports, excessively long URLs, URLs containing spaces, rate limiting, unavailable model, model failure, oversized request bodies, and streamed oversized bodies without Content-Length.

Recorded result: 13 passed, 0 failed, 2 dependency-related warnings, in 3.74 seconds (Python 3.13.14). These tests confirm the covered API behaviours; they do not replace live frontend-backend integration testing or Aarriz's separate concurrency experiments.

Limitations
The classifier uses lexical URL features, not the content of the destination website, and may produce false positives or false negatives. The IP-based rate limit and per-process inference semaphore do not provide complete protection against distributed denial-of-service attacks. Successful operation depends on the saved model and feature extraction code being present and compatible.

## Frontend

A React app where the user pastes a URL and sees PHISHING or LEGITIMATE as the most prominent element, with the model's confidence and a caution message. It sends the URL to the backend `POST /predict` endpoint and shows the reply.

To run the frontend (the backend must already be running at http://localhost:8000; it needs Node.js 20 or newer):

```bash
cd "frontend 2"
npm install
npm run dev
```

Then open http://localhost:5173.

- Pinned versions (in `frontend 2/package.json`, with `package-lock.json`): react and react-dom 19.1.0, react-router-dom 7.18.5, recharts 2.15.4, vite 6.4.5, @vitejs/plugin-react 4.5.2.
- Files: `src/Checker.jsx` (form, validation, API call, result and charts), `src/App.jsx` (routes), `src/ErrorBoundary.jsx` (crash fallback), `src/main.jsx` (entry point), `src/index.css` (styles).
- States: idle, loading, success and error. A "Page not found" page covers unknown addresses and an error boundary covers unexpected failures, so the user never sees a blank screen. One `status` value decides which screen is shown, following React's approach of describing each visual state and switching between them (React, n.d.).
- Charts: (1) the class probabilities for the latest check, and (2) the phishing probability of every check this session, with a filter and click-to-view details. Both have titles, labelled axes, legends, tooltips and a text or table alternative.
- Validation: the page checks the scheme, spaces, hostname and length for usability only. The backend repeats these checks and is the security boundary.
- Styling: one colour scheme is defined once as CSS custom properties (MDN Web Docs, n.d.c), and a media query adjusts the layout for narrow screens (MDN Web Docs, n.d.b).
- Accessibility: every input has a label, results and errors are announced to screen readers, everything works by keyboard with a visible `:focus-visible` outline (MDN Web Docs, n.d.a), and the layout works at phone width.
- Limitations: the model only sees the URL text, so it can misjudge some links. The session history is lost on refresh, and there are no automated frontend tests.

### References for frontend

- MDN Web Docs (n.d.a) *:focus-visible CSS pseudo-class*. Available at: https://developer.mozilla.org/docs/Web/CSS/:focus-visible.
- MDN Web Docs (n.d.b) *Media query fundamentals*. Available at: https://developer.mozilla.org/en-US/docs/Learn/CSS/CSS_layout/Media_queries.
- MDN Web Docs (n.d.c) *Using CSS custom properties (variables)*. Available at: https://developer.mozilla.org/en-US/docs/Web/CSS/Using_CSS_Variables.
- React (n.d.) *Reacting to Input with State*. Available at: https://react.dev/learn/reacting-to-input-with-state.
