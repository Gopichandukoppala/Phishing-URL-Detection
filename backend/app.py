"""Phishing URL prediction API.

Loads the trained Random Forest pickle (a dict: {"model": ..., "features": [...]})
and runs the 30-feature extractor on a submitted URL. The model was trained
with label 1 = phishing, 0 = legitimate, on the feature subset stored in the
pickle (Links_pointing_to_page is dropped).
"""

from __future__ import annotations

import ipaddress
import math
import os
import pickle
import socket
from typing import Any
from urllib.parse import urlparse

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from feature_extraction import FEATURE_NAMES, extract_features

ROOT = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(ROOT, "models", "RandomForest.pickle.dat")
DATASET_PATH = os.path.abspath(os.path.join(ROOT, "..", "ml", "dataset.csv"))

FEATURE_META: dict[str, str] = {
    "having_IPhaving_IP_Address": "Uses an IP address instead of a domain",
    "URLURL_Length": "URL length",
    "Shortining_Service": "Known URL shortener",
    "having_At_Symbol": "Contains an @ symbol",
    "double_slash_redirecting": "Extra // after the scheme",
    "Prefix_Suffix": "Hyphen in the hostname",
    "having_Sub_Domain": "Number of subdomains",
    "SSLfinal_State": "Valid HTTPS certificate",
    "Domain_registeration_length": "Domain registration period",
    "Favicon": "Favicon hosted on the same domain",
    "port": "Non-standard port",
    "HTTPS_token": "The word https inside the hostname",
    "Request_URL": "External images, scripts, and CSS",
    "URL_of_Anchor": "External or empty anchor links",
    "Links_in_tags": "External links in tags",
    "SFH": "Form action points off-site or is blank",
    "Submitting_to_email": "Form submits to an email address",
    "Abnormal_URL": "Hostname does not look like a real domain",
    "Redirect": "HTTP redirect hops",
    "on_mouseover": "onMouseOver status-bar spoofing",
    "RightClick": "Right-click disabled",
    "popUpWidnow": "JavaScript pop-up windows",
    "Iframe": "Invisible or extra iframes",
    "age_of_domain": "Age of the domain",
    "DNSRecord": "DNS record resolves",
    "web_traffic": "Web traffic rank",
    "Page_Rank": "PageRank",
    "Google_Index": "Indexed by Google",
    "Links_pointing_to_page": "Inbound links",
    "Statistical_report": "Appears on a phishing report list",
}

# API contract kept for the frontend: prediction 1 = legitimate, 0 = phishing.
VERDICT = {0: "phishing", 1: "legitimate"}


class PredictRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


class FeatureRow(BaseModel):
    key: str
    label: str
    value: int
    signal: str


class PredictResponse(BaseModel):
    url: str
    normalized_url: str
    prediction: int
    verdict: str
    decision_score: float
    confidence: float
    features: list[FeatureRow]


app = FastAPI(title="Phishing URL Detector", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------- model loading
with open(MODEL_PATH, "rb") as handle:
    _loaded = pickle.load(handle)

if isinstance(_loaded, dict):
    MODEL = _loaded["model"]
    MODEL_FEATURES: list[str] = list(_loaded["features"])
else:  # older pickles that store the bare estimator
    MODEL = _loaded
    MODEL_FEATURES = list(getattr(_loaded, "feature_names_in_", FEATURE_NAMES))

# Same alignment as the notebook (cell 99): a feature value never seen in
# training is replaced by that feature's most common training value.
ALLOWED: dict[str, set] = {}
MODE: dict[str, int] = {}
if os.path.exists(DATASET_PATH):
    _df = pd.read_csv(DATASET_PATH)
    for _col in MODEL_FEATURES:
        if _col in _df.columns:
            ALLOWED[_col] = set(_df[_col].unique())
            MODE[_col] = int(_df[_col].mode()[0])


def align_to_training(values: list[int]) -> dict[str, int]:
    out: dict[str, int] = {}
    for name, v in zip(FEATURE_NAMES, values):
        v = int(v)
        if name in ALLOWED and v not in ALLOWED[name]:
            v = MODE[name]
        out[name] = v
    return out


def signal_name(value: int) -> str:
    if value == 1:
        return "legitimate"
    if value == 0:
        return "suspicious"
    return "phishing"


def scan_error(code: str, title: str, message: str, host: str | None = None) -> None:
    detail: dict[str, str] = {"code": code, "title": title, "message": message}
    if host:
        detail["host"] = host
    raise HTTPException(status_code=400, detail=detail)


def normalize_url(raw: str) -> str:
    url = raw.strip()
    if not url:
        scan_error(
            "empty",
            "No URL entered",
            "Paste a website address first, then run Analyze URL.",
        )
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        scan_error(
            "bad_scheme",
            "This is not a web address",
            "Only http:// and https:// links can be scanned. Other schemes such as ftp:// or file:// are skipped.",
        )
    if not parsed.hostname:
        scan_error(
            "missing_host",
            "The URL has no website name",
            "A usable link looks like example.com or https://example.com. This one has no hostname to look up.",
        )
    host = parsed.hostname.lower()
    if host in {"localhost"} or host.endswith(".localhost"):
        scan_error(
            "localhost",
            "Local addresses are not scanned",
            "localhost points at this computer, not a public website, so it is blocked.",
            host=host,
        )
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            scan_error(
                "private_ip",
                "This is a private address",
                "The scanner only checks public websites. Addresses such as 127.0.0.1 or 192.168.x.x stay on a local network.",
                host=host,
            )
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        scan_error(
            "dns_unresolved",
            "This website name was not found",
            (
                "DNS lookup failed for this domain — there is no public address listed for it. "
                "Check the spelling, or try a site that is actually online (for example wikipedia.org)."
            ),
            host=host,
        )
    for info in infos:
        sockaddr = info[4][0]
        try:
            ip = ipaddress.ip_address(sockaddr)
        except ValueError:
            continue
        if not ip.is_global:
            scan_error(
                "private_resolve",
                "This name points to a private address",
                "The hostname exists, but it resolves to a local or reserved IP, so the scanner will not fetch it.",
                host=host,
            )
    return url


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "model": type(MODEL).__name__,
        "features": len(MODEL_FEATURES),
    }


@app.post("/api/predict", response_model=PredictResponse)
def predict(body: PredictRequest) -> PredictResponse:
    normalized = normalize_url(body.url)
    values = extract_features(normalized)
    if len(values) != len(FEATURE_NAMES):
        raise HTTPException(status_code=500, detail="Feature extractor returned an unexpected vector.")

    aligned = align_to_training(values)
    # Select only the columns the model was trained on, in training order.
    frame = pd.DataFrame([aligned], columns=FEATURE_NAMES)[MODEL_FEATURES]

    # Model label: 1 = phishing, 0 = legitimate
    p_phish = float(MODEL.predict_proba(frame)[0, 1])
    p_legit = 1.0 - p_phish

    prediction = 0 if p_phish >= 0.5 else 1  # API contract: 1 = legitimate
    confidence = max(p_phish, p_legit)

    eps = 1e-6  # avoid log(0)
    pl = min(max(p_legit, eps), 1 - eps)
    score = math.log(pl / (1 - pl))  # positive => legitimate

    features = [
        FeatureRow(
            key=name,
            label=FEATURE_META.get(name, name),
            value=aligned[name],
            signal=signal_name(aligned[name]),
        )
        for name in FEATURE_NAMES
    ]

    return PredictResponse(
        url=body.url.strip(),
        normalized_url=normalized,
        prediction=prediction,
        verdict=VERDICT[prediction],
        decision_score=round(score, 4),
        confidence=round(confidence, 4),
        features=features,
    )


DIST_DIR = os.path.abspath(os.path.join(ROOT, "..", "frontend", "dist"))
if os.path.isdir(DIST_DIR):
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=DIST_DIR, html=True), name="ui")