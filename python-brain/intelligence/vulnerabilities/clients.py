"""Clients d'intelligence externe (NVD, OSV, KEV, EPSS).

Le moteur ne les appelle jamais automatiquement : le mode par défaut est hors
ligne. Ces fonctions servent à une recherche explicitement demandée et ne
doivent pas être utilisées dans les tests unitaires.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve}"
OSV_URL = "https://api.osv.dev/v1/query"
USER_AGENT = "NOUR-SENTINEL/0.5.0 (defensive audit; offline by default)"


def build_nvd_url(cve):
    return NVD_URL.format(cve=urllib.parse.quote(str(cve)))


def build_epss_url(cve):
    return EPSS_URL.format(cve=urllib.parse.quote(str(cve)))


def _get_json(url, timeout=10.0):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError, TimeoutError) as error:
        raise RuntimeError(f"External lookup failed: {error}") from error


def fetch_nvd(cve):
    return _get_json(build_nvd_url(cve))


def fetch_epss(cve):
    return _get_json(build_epss_url(cve))


def fetch_kev():
    return _get_json(KEV_URL)


def query_osv(package, version, ecosystem=None):
    query = {"package": {"name": package}, "version": version}

    if ecosystem:
        query["package"]["ecosystem"] = ecosystem

    body = json.dumps(query).encode("utf-8")
    request = urllib.request.Request(
        OSV_URL,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10.0) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError, TimeoutError) as error:
        raise RuntimeError(f"OSV lookup failed: {error}") from error
