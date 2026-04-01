"""Spotify Token Proxy — serves user access tokens by reading multi-scrobbler's cached credentials."""

import json
import os
import time

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse

SPOTIFY_CLIENT_ID = os.environ.get("SPOTIFY_CLIENT_ID", "")
SPOTIFY_CLIENT_SECRET = os.environ.get("SPOTIFY_CLIENT_SECRET", "")
SPOTIFY_REDIRECT_URI = os.environ.get("SPOTIFY_REDIRECT_URI", "")
SCROBBLER_CREDS_PATH = os.environ.get("SCROBBLER_CREDS_PATH", "/data/scrobbler/currentCreds-unnamed.json")
TOKEN_CACHE_PATH = os.environ.get("TOKEN_CACHE_PATH", "/data/tokens.json")

SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
SPOTIFY_AUTH_URL = "https://accounts.spotify.com/authorize"

# Scopes needed by user-token consumers (mcp-spotify, etc.)
USER_SCOPES = "user-read-private user-read-email user-read-playback-state user-modify-playback-state user-read-currently-playing user-library-read"

app = FastAPI(title="Spotify Token Proxy")

# In-memory cache of last-known good token
_cached_token: dict | None = None


def _read_scrobbler_creds() -> dict | None:
    """Read multi-scrobbler's cached credentials."""
    try:
        with open(SCROBBLER_CREDS_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _read_token_cache() -> dict | None:
    """Read our own token cache (for tokens we've refreshed ourselves)."""
    try:
        with open(TOKEN_CACHE_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _write_token_cache(data: dict):
    """Write token cache."""
    os.makedirs(os.path.dirname(TOKEN_CACHE_PATH) or ".", exist_ok=True)
    with open(TOKEN_CACHE_PATH, "w") as f:
        json.dump(data, f)


def _refresh_token(refresh_token: str) -> dict:
    """Exchange a refresh token for a new access token."""
    resp = httpx.post(
        SPOTIFY_TOKEN_URL,
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": SPOTIFY_CLIENT_ID,
            "client_secret": SPOTIFY_CLIENT_SECRET,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/token/user")
def get_user_token():
    """Return a valid user access token, refreshing if needed."""
    global _cached_token

    now_ms = int(time.time() * 1000)

    # Try scrobbler creds first (it may have refreshed more recently)
    scrobbler = _read_scrobbler_creds()
    if scrobbler and scrobbler.get("expires", 0) > now_ms + 60_000:
        return {
            "access_token": scrobbler["token"],
            "token_type": "Bearer",
            "expires_in": int((scrobbler["expires"] - now_ms) / 1000),
        }

    # Try our own cache
    if _cached_token and _cached_token.get("expires", 0) > now_ms + 60_000:
        return {
            "access_token": _cached_token["access_token"],
            "token_type": "Bearer",
            "expires_in": int((_cached_token["expires"] - now_ms) / 1000),
        }

    # Need to refresh — get refresh token from scrobbler or our cache
    refresh_tok = None
    if scrobbler:
        refresh_tok = scrobbler.get("refreshToken")
    if not refresh_tok:
        cache = _read_token_cache()
        if cache:
            refresh_tok = cache.get("refresh_token")

    if not refresh_tok:
        raise HTTPException(503, "No refresh token available. Run /authorize to set up OAuth.")

    try:
        result = _refresh_token(refresh_tok)
    except Exception as e:
        raise HTTPException(502, f"Spotify token refresh failed: {e}")

    expires_ms = now_ms + result.get("expires_in", 3600) * 1000
    _cached_token = {
        "access_token": result["access_token"],
        "expires": expires_ms,
    }

    # Persist refresh token if Spotify rotated it
    new_refresh = result.get("refresh_token", refresh_tok)
    _write_token_cache({
        "access_token": result["access_token"],
        "refresh_token": new_refresh,
        "expires": expires_ms,
    })

    return {
        "access_token": result["access_token"],
        "token_type": "Bearer",
        "expires_in": result.get("expires_in", 3600),
    }


@app.get("/authorize")
def authorize():
    """Redirect to Spotify OAuth for initial setup or re-authorization."""
    params = {
        "client_id": SPOTIFY_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": SPOTIFY_REDIRECT_URI,
        "scope": USER_SCOPES,
        "show_dialog": "true",
    }
    url = f"{SPOTIFY_AUTH_URL}?" + "&".join(f"{k}={v}" for k, v in params.items())
    return RedirectResponse(url)


@app.get("/callback")
def callback(code: str = ""):
    """Handle Spotify OAuth callback."""
    if not code:
        raise HTTPException(400, "Missing authorization code")

    resp = httpx.post(
        SPOTIFY_TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": SPOTIFY_REDIRECT_URI,
            "client_id": SPOTIFY_CLIENT_ID,
            "client_secret": SPOTIFY_CLIENT_SECRET,
        },
        timeout=10,
    )
    resp.raise_for_status()
    result = resp.json()

    now_ms = int(time.time() * 1000)
    expires_ms = now_ms + result.get("expires_in", 3600) * 1000

    global _cached_token
    _cached_token = {
        "access_token": result["access_token"],
        "expires": expires_ms,
    }
    _write_token_cache({
        "access_token": result["access_token"],
        "refresh_token": result["refresh_token"],
        "expires": expires_ms,
    })

    return {"status": "ok", "expires_in": result.get("expires_in", 3600)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8095)
