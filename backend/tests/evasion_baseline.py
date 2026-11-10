
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from Source_code.feature_extraction import extract_features

# Synthetic local test strings
test_urls = {
    "ordinary": "https://example.com/login",
    "unicode_lookalike": "https://example.com/lоgin",
    "zero_width": "https://example.com/log\u200bin",
}

for test_name, url in test_urls.items():
    print(f"\nTest: {test_name}")
    print(f"URL: {ascii(url)}")

    features = extract_features(url)

    print("URL length:", features["url_length"])
    print(
        "Suspicious keyword:",
        features["has_suspicious_keyword"]
    )
    print(
        "Lookalike characters:",
        features["has_lookalike_chars"]
    )
