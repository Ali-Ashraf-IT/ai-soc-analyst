import requests


class WazuhClient:

    def __init__(self, base_url, token, timeout=30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self.headers = {
            "Authorization": f"Bearer {token}"
        }

    def health(self):
        response = requests.get(
            f"{self.base_url}/health",
            timeout=self.timeout
        )

        response.raise_for_status()

        return response.json()

    def get_alerts(self, size=20):
        response = requests.get(
            f"{self.base_url}/alerts",
            headers=self.headers,
            params={
                "size": size
            },
            timeout=self.timeout
        )

        response.raise_for_status()

        return response.json()
