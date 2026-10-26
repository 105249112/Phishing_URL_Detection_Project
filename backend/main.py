from pydantic import BaseModel, Field
from fastapi import FastAPI
from contextlib import asynccontextmanager
from pathlib import Path
import joblib
from fastapi import FastAPI
import pandas as pd
from urllib.parse import urlsplit
from fastapi import HTTPException
from Source_code.feature_extraction import extract_features

MODEL_PATH = Path(__file__).resolve().parent.parent / "Models" / "phishing_classifier.joblib"

ml_model = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global ml_model
    ml_model = joblib.load(MODEL_PATH)
    print("Random Forest model loaded successfully")
    yield
    ml_model = None
    
app = FastAPI(
    title="Phishing URL Detection API",
    description="Backend API for detecting phishing URLs using our Assignment 2 machine-learning model.",
    version="1.0.0",
    lifespan=lifespan
)
class PredictionRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class PredictionResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    malicious_probability: float

@app.get("/health", tags=["Health"])
def health_check():
    if ml_model is None:
        raise HTTPException(
            status_code=503,
            detail="Machine-learning model is not ready"
        )

    return {
        "status": "ok",
        "model_ready": True,
        "message": "Phishing URL Detection API and model are ready"
    }
    
@app.post("/predict", response_model=PredictionResponse, tags=["Prediction"])
def predict_url(request: PredictionRequest):
    if ml_model is None:
        raise HTTPException(
            status_code=503,
            detail="Prediction model is unavailable"
        )

    url = request.url.strip()
    if not url or any(char.isspace() for char in url):
        raise HTTPException(
            status_code=422,
            detail="Please provide a valid URL without spaces"
        )

    try:
        parsed = urlsplit(url)
        port = parsed.port

    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="Invalid URL format or port number"
    )

    if (
        parsed.scheme.lower() not in ("http", "https")
        or not parsed.hostname
        or "." not in parsed.hostname
    ):
        raise HTTPException(
            status_code=422,
            detail="Please enter a valid HTTP or HTTPS website URL"
        )

    try:
            features = extract_features(url)

            feature_df = pd.DataFrame(
                [features],
                columns=ml_model.feature_names_in_
            )

            predicted_class = int(ml_model.predict(feature_df)[0])
            probabilities = ml_model.predict_proba(feature_df)[0]

            classes = list(ml_model.classes_)
            malicious_probability = float(
                probabilities[classes.index(1)]
            )

            confidence = float(
                probabilities[classes.index(predicted_class)]
            )

            return PredictionResponse(
                url=url,
                prediction="MALICIOUS" if predicted_class == 1 else "BENIGN",
                confidence=round(confidence, 4),
                malicious_probability=round(malicious_probability, 4)
            )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to analyse this URL"
        )
