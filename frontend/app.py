import os
import secrets
from urllib.parse import urlsplit

import requests
from flask import Flask, render_template, request, session

API_URL = os.environ.get("API_URL", "http://localhost:8000")
MOCK_API = True # TEMPORARY: demo mode, remove once the real backend works
MAX_LEN = 2048
MAX_HISTORY = 20

app = Flask(__name__)
# Set SECRET_KEY in your environment for anything beyond local demos.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def validate(raw):
    """Usability checks only. The backend repeats validation and is the security boundary."""
    url = (raw or "").strip()
    if not url:
        return None, "Please enter a URL."
    if len(url) > MAX_LEN:
        return None, f"That URL is too long (maximum {MAX_LEN} characters)."
    if any(ch.isspace() for ch in url):
        return None, "A URL cannot contain spaces."
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return None, "Start the URL with http:// or https://"
    if not parts.hostname or "." not in parts.hostname:
        return None, "Enter a full web address, for example https://example.com"
    return url, None


def mock_check_url(url):
    """TEMPORARY MOCK DATA. Not a real prediction. Delete when the backend is connected."""
    risky = any(w in url.lower() for w in ("login", "verify", "secure", "bank", "free", "@", "//ip/")) \
        or urlsplit(url).hostname.replace(".", "").isdigit()
    prob = 0.93 if risky else 0.06
    return {"url": url, "is_phishing": risky,
            "confidence": prob if risky else 1 - prob, "phishing_prob": prob}


def check_url(url):
    """Call the backend. Raises RuntimeError with a user-safe message."""
    if MOCK_API:
        return mock_check_url(url)
    try:
        resp = requests.post(f"{API_URL}/predict", json={"url": url}, timeout=10)
    except requests.RequestException:
        raise RuntimeError("Could not reach the prediction service. Please try again shortly.")
    try:
        data = resp.json()
    except ValueError:
        raise RuntimeError("The prediction service sent an unexpected reply.")
    if resp.status_code != 200:
        detail = data.get("detail") if isinstance(data, dict) else None
        raise RuntimeError(detail if isinstance(detail, str) else "The prediction service could not check that URL.")
    try:
        mal = float(data["malicious_probability"])
        return {
            "url": str(data["url"]),
            "is_phishing": data["prediction"] == "MALICIOUS",
            "confidence": float(data["confidence"]),
            "phishing_prob": mal,
        }
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("The prediction service sent an unexpected reply.")


@app.route("/", methods=["GET", "POST"])
def index():
    status, error, result, value = "idle", None, None, ""
    history = session.get("history", [])
    if request.method == "POST":
        value = request.form.get("url", "")
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
            status, error = "error", "Your form expired. Please try again."
        else:
            url, error = validate(value)
            if error:
                status = "error"
            else:
                try:
                    result = check_url(url)
                    status = "success"
                    history.append({
                        "n": (history[-1]["n"] + 1) if history else 1,
                        "url": url[:80],
                        "label": "Phishing" if result["is_phishing"] else "Legitimate",
                        "phishing_prob": round(result["phishing_prob"], 4),
                    })
                    session["history"] = history[-MAX_HISTORY:]
                except RuntimeError as exc:
                    status, error = "error", str(exc)
    session["csrf"] = secrets.token_hex(16)
    return render_template("index.html", status=status, error=error, result=result,
                           value=value, history=session.get("history", []), csrf=session["csrf"], mock=MOCK_API)


@app.errorhandler(404)
def not_found(_):
    return render_template("message.html", title="Page not found",
                           body="That page doesn't exist."), 404


@app.errorhandler(Exception)
def unexpected(exc):
    app.logger.exception(exc)
    return render_template("message.html", title="Something went wrong",
                           body="The page hit an unexpected problem. Please try again."), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5173, debug=False)
