import time
import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from .config import settings

class NVDClient:
    def __init__(self) -> None:
        self.base_url = settings.nvd_api_url
        self.timeout = settings.request_timeout_seconds
        self.headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        self._min_interval = 60.0 / max(settings.requests_per_minute, 1)
        self._last_request_ts = 0.0

    def _respect_rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request_ts
        wait_for = self._min_interval - elapsed
        if wait_for > 0:
            time.sleep(wait_for)

    @retry(retry=retry_if_exception_type((requests.RequestException, RuntimeError)),
           stop=stop_after_attempt(5),
           wait=wait_exponential(multiplier=1, min=2, max=30),
           reraise=True)
    def fetch_page(self, *, start_index: int = 0, results_per_page: int | None = None, **extra_params):
        params = {"startIndex": start_index, "resultsPerPage": results_per_page or settings.nvd_results_per_page}
        params.update(extra_params)
        self._respect_rate_limit()
        response = requests.get(self.base_url, headers=self.headers, params=params, timeout=self.timeout)
        self._last_request_ts = time.monotonic()
        if response.status_code in (429, 503):
            raise RuntimeError(f"NVD temporarily unavailable: {response.status_code}")
        response.raise_for_status()
        return response.json()

    def iter_all_cves(self, **extra_params):
        start = 0
        page_size = settings.nvd_results_per_page
        total = None
        while total is None or start < total:
            payload = self.fetch_page(start_index=start, results_per_page=page_size, **extra_params)
            total = payload.get("totalResults", 0)
            vulnerabilities = payload.get("vulnerabilities", []) or []
            if not vulnerabilities:
                break
            for vuln in vulnerabilities:
                yield vuln
            start += page_size
