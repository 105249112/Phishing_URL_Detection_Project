
from fastapi.testclient import TestClient
from backend.main import app
from backend.main import limiter


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["model_ready"] is True


def test_predict_valid_url():
    with TestClient(app) as client:
        response = client.post(
            "/predict",
            json={"url": "https://www.google.com"}
        )

    assert response.status_code == 200

    data = response.json()
    assert data["url"] == "https://www.google.com"
    assert data["prediction"] in ["BENIGN", "MALICIOUS"]
    assert 0 <= data["confidence"] <= 1
    assert 0 <= data["malicious_probability"] <= 1


def test_predict_empty_url():
    with TestClient(app) as client:
        response = client.post(
            "/predict",
            json={"url": ""}
        )

    assert response.status_code == 422


def test_predict_unsafe_scheme():
    with TestClient(app) as client:
        response = client.post(
            "/predict",
            json={"url": "javascript:alert(1)"}
        )

    assert response.status_code == 422


def test_predict_invalid_port():
    with TestClient(app) as client:
        response = client.post(
            "/predict",
            json={"url": "https://example.com:99999"}
        )

    assert response.status_code == 422


def test_predict_missing_url():
    with TestClient(app) as client:
        response = client.post(
            "/predict",
            json={}
        )

    assert response.status_code == 422


def test_predict_url_too_long():
    with TestClient(app) as client:
        response = client.post(
            "/predict",
            json={"url": "https://example.com/" + "a" * 2100}
        )

    assert response.status_code == 422


def test_predict_url_with_spaces():
    with TestClient(app) as client:
        response = client.post(
            "/predict",
            json={"url": "https://example.com/hello world"}
        )

    assert response.status_code == 422


def test_predict_rate_limit():
    from backend.main import limiter
    limiter._storage.reset()
    
    with TestClient(app) as client:
        responses = [
            client.post(
                "/predict",
                json={"url": "https://www.google.com"}
            )
            for _ in range(12)
        ]

    assert any(response.status_code == 429 for response in responses)



def test_predict_model_unavailable(monkeypatch):
    limiter._storage.reset()
    with TestClient(app) as client:
        monkeypatch.setattr("backend.main.ml_model", None)

        response = client.post(
            "/predict",
            json={"url": "https://www.google.com"}
        )
        
    assert response.status_code == 503
    assert response.json()["detail"] == "Prediction model is unavailable"

    
def test_predict_model_failure(monkeypatch):
    limiter._storage.reset()
    with TestClient(app) as client:
        def broken_prediction(features):
            raise RuntimeError("Internal model failure")

        monkeypatch.setattr(
            "backend.main.ml_model.predict",
            broken_prediction
        )

        response = client.post(
            "/predict",
            json={"url": "https://www.google.com"}
        )

    assert response.status_code == 500
    assert response.json()["detail"] == "Unable to analyse this URL"
    assert "Internal model failure" not in response.text
    
