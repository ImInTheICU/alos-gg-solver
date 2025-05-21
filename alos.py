"""
Alos PoW solver

Wraps requests.Session to auto solve PoW challenges for alos.gg,
attaching captcha flags to responses and using a dynamic UA generator.

If you have any problems please email me or open a Github issue. Thanks!
"""
__author__ = "Chris <christopher@ropanel.com>"
__version__ = "0.0.1"
__github__ = "https://github.com/ImInTheICU/alos-gg-solver"

import re
import random
import hashlib
import requests

from collections import defaultdict
from typing import Optional, Dict, Tuple, Any

class AlosResponse(requests.Response):
    captcha_present: bool
    captcha_solved: bool

class Alos:
    VERIFY_PATH = "/alosgg/verify"

    _OS_TOKENS: Dict[str, list[str]] = {
        "Windows": ["Windows NT 10.0", "Windows NT 6.3", "Windows NT 6.1"],
        "macOS": [
            "Macintosh; Intel Mac OS X 10_15_7",
            "Macintosh; Intel Mac OS X 11_2_3",
            "Macintosh; Intel Mac OS X 12_0_1",
        ],
        "Linux": ["X11; Linux x86_64"],
        "Android": [
            "Linux; Android 11",
            "Linux; Android 12",
            "Linux; Android 13",
        ],
        "iOS": [
            "iPhone; CPU iPhone OS 14_4 like Mac OS X",
            "iPhone; CPU iPhone OS 15_0 like Mac OS X",
            "iPad; CPU OS 14_7 like Mac OS X",
        ],
    }
    _BROWSERS: Dict[str, float] = {
        "chrome": 50,
        "edge":   15,
        "firefox": 20,
        "safari": 10,
        "opera":  3,
        "samsung": 1,
        "brave": 1,
        "uc":     0.5,
    }

    def __init__(
        self,
        difficulty: int = 4,
        timeout: float = 4.0
    ):
        """
        Initialize Alos solver.

        Args:
            difficulty: Number of leading zeros required by PoW. Shouldn't need to be change has been configured to solve correctly.
            timeout: Request timeout in seconds.
        """
        self.session = requests.Session()
        self.difficulty: int = difficulty
        self.prefix: str = "0" * difficulty
        self.timeout: float = timeout
        self._cached_names: Optional[Tuple[str, str]] = None

    def _gen_user_agent(self) -> str:
        os_family = random.choice(list(self._OS_TOKENS))
        os_token = random.choice(self._OS_TOKENS[os_family])
        names, weights = zip(*self._BROWSERS.items())
        browser = random.choices(names, weights=weights, k=1)[0]
        return getattr(self, f"_ua_{browser}")(os_token)

    def _ua_chrome(self, os_token: str) -> str:
        ma, mi, bu = random.randint(100, 120), random.randint(0, 5999), random.randint(0, 200)
        return f"Mozilla/5.0 ({os_token}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ma}.0.{mi}.{bu} Safari/537.36"

    def _ua_edge(self, os_token: str) -> str:
        ma, mi, bu = random.randint(80, 120), random.randint(0, 5999), random.randint(0, 200)
        return f"Mozilla/5.0 ({os_token}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ma}.0.{mi}.{bu} Edg/{ma}.0.{mi}.{bu}"

    def _ua_firefox(self, os_token: str) -> str:
        ma = random.randint(80, 115)
        yy, mm, dd = random.randint(2019, 2025), random.randint(1, 12), random.randint(1, 28)
        return f"Mozilla/5.0 ({os_token}; rv:{ma}.0) Gecko/{yy:04d}{mm:02d}{dd:02d} Firefox/{ma}.0"

    def _ua_safari(self, os_token: str) -> str:
        if not os_token.startswith(("Macintosh", "iPhone", "iPad")):
            os_token = random.choice(self._OS_TOKENS["macOS"])
        vm, vi, vp = random.randint(13, 16), random.randint(0, 5), random.randint(0, 3)
        return f"Mozilla/5.0 ({os_token}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{vm}.{vi}.{vp} Safari/605.1.15"

    def _ua_opera(self, os_token: str) -> str:
        ma, mi, bu = random.randint(60, 100), random.randint(0, 4999), random.randint(0, 200)
        return f"Mozilla/5.0 ({os_token}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ma}.0.{mi}.{bu} OPR/{ma}.0.{mi}.{bu}"

    def _ua_samsung(self, os_token: str) -> str:
        android_token = random.choice(self._OS_TOKENS["Android"])
        ma, mi, bu = random.randint(80, 115), random.randint(0, 5999), random.randint(0, 200)
        return f"Mozilla/5.0 ({android_token}) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/{ma}.0 Chrome/{ma}.0.{mi}.{bu} Safari/537.36"

    def _ua_brave(self, os_token: str) -> str:
        base = self._ua_chrome(os_token)
        version = base.split("Chrome/")[1].split(" ")[0]
        return base.replace("Safari/537.36", f"Safari/537.36 Brave/{version}")

    def _ua_uc(self, os_token: str) -> str:
        android_token = random.choice(self._OS_TOKENS["Android"])
        ma, mi, bu = random.randint(12, 14), random.randint(0, 5), random.randint(0, 1000)
        return f"Mozilla/5.0 ({android_token}) AppleWebKit/537.36 (KHTML, like Gecko) UCBrowser/{ma}.{mi}.{bu} Mobile Safari/537.36"

    def _discover_vars(self, html: str) -> Tuple[Optional[str], Optional[str]]:
        pairs = re.findall(r'const\s+(\w+)\s*=\s*"([^"\n]+)"', html)
        candidates = [(n, v) for n, v in pairs if len(v) >= 20 and re.fullmatch(r'[A-Za-z0-9+/=]+', v)]
        groups: Dict[int, list[str]] = defaultdict(list)
        for name, val in candidates:
            groups[len(val)].append(name)
        for names in groups.values():
            if len(names) >= 2:
                return names[0], names[1]
        return None, None

    def _solve_proof(self, challenge: str) -> int:
        data = challenge.encode()
        nonce = 0
        while True:
            digest = hashlib.sha256(data + str(nonce).encode()).hexdigest()
            if digest.startswith(self.prefix):
                return nonce
            nonce += 1

    def _solve_challenge(
        self,
        html: str,
        url: str,
        proxies: Optional[Dict[str, str]],
        headers: Dict[str, str]
    ) -> Tuple[bool, bool]:
        domain = re.match(r'^(https?://[^/]+)', url).group(1)
        name1, name2 = self._discover_vars(html)
        if not (name1 and name2):
            return False, False
        if not self._cached_names:
            self._cached_names = (name1, name2)
        else:
            name1, name2 = self._cached_names
        m1 = re.search(rf'{name1}\s*=\s*"([^"\n]+)"', html)
        m2 = re.search(rf'{name2}\s*=\s*"([^"\n]+)"', html)
        if not (m1 and m2):
            return True, False
        r1, r2 = self._solve_proof(m1.group(1)), self._solve_proof(m2.group(1))
        verify_headers = headers.copy()
        verify_headers['Origin'] = domain
        verify_url = f"{domain}{self.VERIFY_PATH}?r1={r1}&r2={r2}"
        try:
            resp = self.session.get(verify_url, headers=verify_headers, proxies=proxies, timeout=self.timeout)
            return True, resp.status_code == 200
        except requests.RequestException:
            return True, False

    def request(
        self,
        method: str,
        url: str,
        proxies: Optional[Dict[str, str]] = None,
        **kwargs: Any
    ) -> AlosResponse:
        """
        Send a HTTP request, auto solving PoW if detected.

        Args:
            method: HTTP method (e.g. 'GET', 'POST').
            url: Target URL.
            proxies: Optional proxy dict.
            **kwargs: Passed to `requests.Session.request`.

        Returns:
            An AlosResponse with `.captcha_present` and `.captcha_solved`.
        """
        headers: Dict[str, str] = kwargs.pop('headers', {})
        domain = re.match(r'^(https?://[^/]+)', url).group(1)

        headers.setdefault('User-Agent', self._gen_user_agent())
        headers.setdefault('Referer', domain)
        kwargs['headers'] = headers
        kwargs.setdefault('timeout', self.timeout)
        if proxies:
            kwargs['proxies'] = proxies

        raw: requests.Response = self.session.request(method, url, **kwargs)
        response = AlosResponse()
        response.__dict__.update(raw.__dict__)
        present, solved = self._solve_challenge(response.text, url, proxies, headers)
        response.captcha_present = present
        response.captcha_solved = solved
        if solved:
            retry = self.session.request(method, url, **kwargs)
            response.__dict__.update(retry.__dict__)
            response.captcha_present = True
            response.captcha_solved = True
        return response
    
    def get(self, url, **kwargs) -> AlosResponse:
        """Alias for `request('GET', ...)`."""
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs) -> AlosResponse:
        """Alias for `request('POST', ...)`."""
        return self.request('POST', url, **kwargs)

    def head(self, url, **kwargs) -> AlosResponse:
        """Alias for `request('HEAD', ...)`."""
        return self.request('HEAD', url, **kwargs)

    def put(self, url, **kwargs) -> AlosResponse:
        """Alias for `request('PUT', ...)`."""
        return self.request('PUT', url, **kwargs)

    def delete(self, url, **kwargs) -> AlosResponse:
        """Alias for `request('DELETE', ...)`."""
        return self.request('DELETE', url, **kwargs)

    def patch(self, url, **kwargs) -> AlosResponse:
        """Alias for `request('PATCH', ...)`."""
        return self.request('PATCH', url, **kwargs)

    def options(self, url, **kwargs) -> AlosResponse:
        """Alias for `request('OPTIONS', ...)`."""
        return self.request('OPTIONS', url, **kwargs)
