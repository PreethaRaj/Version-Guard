import os
from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    nvd_api_url: str = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_api_key: str | None = os.getenv("NVD_API_KEY") or None
    open_search_url: str = os.getenv("OPEN_SEARCH_URL", "http://localhost:9200")
    open_search_index: str = os.getenv("OPEN_SEARCH_INDEX", "versionguard-cves")
    nvd_results_per_page: int = int(os.getenv("NVD_RESULTS_PER_PAGE", "2000"))
    rpm_with_key: int = int(os.getenv("NVD_REQUESTS_PER_MINUTE_WITH_KEY", "50"))
    rpm_no_key: int = int(os.getenv("NVD_REQUESTS_PER_MINUTE_NO_KEY", "5"))
    request_timeout_seconds: int = int(os.getenv("NVD_REQUEST_TIMEOUT_SECONDS", "45"))

    @property
    def requests_per_minute(self) -> int:
        return self.rpm_with_key if self.nvd_api_key else self.rpm_no_key

settings = Settings()
