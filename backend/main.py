
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.types import ASGIApp, Receive, Scope, Send
from Source_code.feature_extraction import extract_features

MODEL_PATH = Path(__file__).resolve().parent.parent / "Models" / "phishing_classifier.joblib"
MAX_REQUEST_BODY_SIZE = 8192
limiter = Limiter(key_func=get_remote_address)
ml_model = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global ml_model
    ml_model = joblib.load(MODEL_PATH)
    print("Random Forest model loaded successfully")
    try:
        yield
    finally:
        ml_model = None

app = FastAPI(
    title="Phishing URL Detection API",
    description="Backend API for detecting phishing URLs using our Assignment 2 machine-learning model.",
    version="1.0.0",
    lifespan=lifespan
)

app.state.limiter = limiter

class RequestBodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_body_size: int):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")

        async def reject(status_code: int, detail: str):
            response = JSONResponse(
                status_code=status_code,
                content={"detail": detail}
            )
            await response(scope, receive, send)

        if content_length is not None:
            try:
                length = int(content_length)
                if length < 0:
                    raise ValueError
            except ValueError:
                await reject(400, "Invalid Content-Length header.")
                return

            if length > self.max_body_size:
                await reject(413, "Request body exceeds the 8 KB limit.")
                return

        chunks = []
        total_size = 0

        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                return

            if message["type"] != "http.request":
                continue

            chunk = message.get("body", b"")
            total_size += len(chunk)

            if total_size > self.max_body_size:
                await reject(413, "Request body exceeds the 8 KB limit.")
                return

            chunks.append(chunk)

            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        body_sent = False

        async def replay_receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False
                }
            return await receive()

        await self.app(scope, replay_receive, send)

app.add_middleware(
    RequestBodySizeLimitMiddleware,
    max_body_size=MAX_REQUEST_BODY_SIZE
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"]
)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."},
        headers={"Retry-After": "60"}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request. Please provide a valid URL."}
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
@limiter.limit("10/minute")
def predict_url(request: Request, payload: PredictionRequest):
    if ml_model is None:
        raise HTTPException(
            status_code=503,
            detail="Prediction model is unavailable"
        )

    url = payload.url.strip()

    if not url or any(char.isspace() for char in url):
        raise HTTPException(
            status_code=422,
            detail="Please provide a valid URL without spaces"
        )

    try:
        parsed = urlsplit(url)
        _ = parsed.port
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
