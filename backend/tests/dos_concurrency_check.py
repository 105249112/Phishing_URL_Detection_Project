
from concurrent.futures import ThreadPoolExecutor
import requests
import time

API_URL = "http://127.0.0.1:8000/predict"

def send_request(number):
    start = time.perf_counter()

    try:
        response = requests.post(
            API_URL,
            json={"url": "https://example.com"},
            timeout=10
        )

        elapsed = time.perf_counter() - start

        return number, response.status_code, round(elapsed, 3)

    except requests.RequestException as error:
        return number, "ERROR", str(error)

with ThreadPoolExecutor(max_workers=5) as executor:
    results = list(executor.map(send_request, range(1, 6)))

for number, status, elapsed in results:
    print(f"Request {number}: HTTP {status}, Time: {elapsed}")
