> NOTE: Currently patched won't be publicly updated anytime soon. For private queries reach out contact@aris.wtf Thanks :D
## Overview

`alos-gg-solver` is a Python wrapper around `requests.Session` that automatically solves alos.gg Proof-of-Work (PoW) challenges using the `/alosgg/verify` endpoint. After solving the CAPTCHA, alos.gg will temporarily whitelist your IP (including any configured proxy), allowing requests to pass without repeated challenges for a period of time.

> **Note: This works for any site using Alos.gg's protection, I've just defaulted to their site for testing purposes.**

## Features

* Built‑in, dynamic User-Agent generator covering Chrome, Firefox, Safari, Edge, Opera, Samsung Internet, Brave, and UC Browser across desktop and mobile platforms.
* Automatic detection and solving of alos.gg PoW challenges.
* Proxy support-once a PoW is solved, the IP (or proxy) is whitelisted for subsequent requests.
* Typed responses via `AlosResponse`, -> `.captcha_present`, `.captcha_solved` and `.captcha_solve_time` attributes.

## Installation

```bash
pip install -r requirements.txt
```

Dependencies:

* `requests==2.32.3`

> All other modules (`hashlib`, `re`, `random`, `collections`, `typing`, `time`) are part of the Python standard library.

## Usage

### Without Proxy

```python
from alos import Alos

alos = Alos(timeout=5.0)
response = alos.get('https://alos.gg/')

print(f"\nStatus: {response.status_code} \nCaptcha Present: {response.captcha_present} \nSolved: {response.captcha_solved} \nSolve Time: {response.captcha_solve_time / 1e6:.3f} milliseconds \nHTML...: {response.text[:255]}")
```

> **Note:** After the first successful request, your IP is whitelisted by alos.gg. Calls using the same `Alos` instance will skip the PoW challenge until the whitelist expires.

### With Proxy

```python
from alos import Alos

proxy = 'http://123.45.67.89:1234' # IP:PORT
proxies = {
    'http': proxy,
    'https': proxy,
}

alos = Alos(timeout=5.0)
response = alos.get('https://alos.gg/', proxies=proxies)

print(f"\nStatus: {response.status_code} \nCaptcha Present: {response.captcha_present} \nSolved: {response.captcha_solved} \nSolve Time: {response.captcha_solve_time / 1e6:.3f} milliseconds \nHTML...: {response.text[:255]}")
```

> **Note:** Once the PoW is solved, the proxy IP is whitelisted for a period of time. You can make further requests through the same proxy without re-solving the CAPTCHA until the whitelist expires.

## API Reference

See the source code for full details. Key methods:

* `Alos.request(method: str, url: str, proxies: Optional[dict] = None, **kwargs) -> AlosResponse`
* `Alos.get(url: str, **kwargs) -> AlosResponse`
* `Alos.post(url: str, **kwargs) -> AlosResponse`
* *... and other HTTP verbs (`head`, `put`, `delete`, `patch`, `options`)*

`AlosResponse` extends `requests.Response` with:

* `captcha_present: bool` whether a PoW challenge was detected in the response.
* `captcha_solved: bool` whether the PoW was successfully solved (and the request retried).
* `captcha_solve_time: float` the direct time 

## Reporting Issues

If you encounter any issues, please [open a issue](https://github.com/ImInTheICU/alos-gg-solver/issues) or email me at **[contact@aris.wtf](mailto:contact@aris.wtf)**.

## Showcase
<div align="center">
  <video
    src="https://github.com/user-attachments/assets/d37634fd-c968-4e1b-a4d1-76854183579f"
    controls
    width="600"
  >
    Your browser does not support the video tag.
  </video>
</div>

---
