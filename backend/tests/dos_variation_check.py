
from concurrent.futures import ThreadPoolExecutor
import requests
import time

API_URL = "http://127.0.0.1:8000/predict"

urls = [
    "https://example.com",
    "https://www.wikipedia.org",
    "https://www.python.org",
    "https://www.github.com",
    "https://www.mozilla.org"
]

def check_url(url):
    start = time.perf_counter()

    try:
        response = requests.post(
            API_URL,
            json={"url": url},
            timeout=10
        )

        elapsed = time.perf_counter() - start

        return url, response.status_code, round(elapsed, 3)

    except requests.RequestException as error:
        return url, "ERROR", str(error)

with ThreadPoolExecutor(max_workers=5) as pool:
    results = list(pool.map(check_url, urls))

for url, status, elapsed in results:
    print(f"{url}: HTTP {status}, Time: {elapsed}s")
