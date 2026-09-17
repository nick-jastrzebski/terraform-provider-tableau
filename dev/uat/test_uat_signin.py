"""Prove a Unified Access Token (UAT) JWT can sign in to the Tableau REST API.

For each site given, this script:
  1. signs a fresh JWT with the UAT private key
  2. signs in to the Tableau REST API with it (credentials.isUat = true)
  3. lists projects on the site using the returned session token
  4. signs out

It exercises the same flow the Terraform provider will use, without any Go,
so failures here point at the UAT setup rather than provider code.

Run from the repo root:

    python dev/uat/test_uat_signin.py --site nj-terraform-1 --site nj-terraform-2
    python dev/uat/test_uat_signin.py --site nj-terraform-1 --scope tableau:content:read --scope tableau:projects:create

Findings from running this against Tableau Cloud (2026-09-17):
  * JWTs over ~8 KB are rejected at sign-in, so a JWT can't carry every scope
    (--all-scopes fails; it's kept to demonstrate the limit).
  * Wildcard scopes (tableau:projects:*) in the JWT are rejected when the UAT
    configuration lists explicit scopes.
  * A missing scope fails the API call with HTTP 401 (code 401002), not 403.

Environment (read from the environment, falling back to the repo-root .env):
    TABLEAU_UAT_USERNAME   Tableau username (email) the JWT signs in as. Must be
                           a site admin on every site tested - scopes cap what a
                           JWT may do, they never grant more than the user has.
    TABLEAU_SERVER_URL     Pod URL, e.g. https://10ax.online.tableau.com
    TABLEAU_TENANT_ID      Optional. If unset, looked up via TCM using
                           TABLEAU_TCM_PAT_NAME / TABLEAU_TCM_PAT_SECRET.

Nothing secret is printed: not the private key, the JWT, or session tokens.
"""

from __future__ import annotations

import argparse
import datetime
import sys
import uuid
from pathlib import Path

import jwt  # PyJWT
import requests

# Share .env loading, the scopes file and the TCM client with uat_config.py.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import uat_config  # noqa: E402

DEFAULT_ISSUER = "https://terraform-provider-tableau.local"
DEFAULT_PRIVATE_KEY = uat_config.DEFAULT_KEY_DIR / "private_key.pem"
MIN_UAT_API_VERSION = (3, 27)  # UAT sign-in was added in Tableau Cloud December 2025
JWT_LIFETIME = datetime.timedelta(minutes=5)
# Measured on Tableau Cloud (2026-09-17): an 8,131-byte JWT signed in, an
# 8,220-byte one got a generic 401 "Signin Error (101002)". Every scope was
# valid on its own, so the cap is size - roughly 180 explicit scopes.
MAX_JWT_BYTES = 8192
TIMEOUT_SECONDS = 30


class SignInTestError(Exception):
    pass


def parse_version(v: str) -> tuple[int, ...]:
    return tuple(int(part) for part in v.split("."))


def detect_api_version(server_url: str) -> str:
    """Ask the pod for its newest REST API version (no authentication needed)."""
    resp = requests.get(
        f"{server_url}/api/3.4/serverinfo",
        headers={"Accept": "application/json"},
        timeout=TIMEOUT_SECONDS,
    )
    if not resp.ok:
        raise SignInTestError(f"serverinfo failed: HTTP {resp.status_code}\n{resp.text}")
    return resp.json()["serverInfo"]["restApiVersion"]


def resolve_tenant_id() -> str:
    tenant_id = uat_config.os.environ.get("TABLEAU_TENANT_ID", "").strip()
    if tenant_id:
        return tenant_id
    if not uat_config.os.environ.get("TABLEAU_TCM_PAT_SECRET"):
        sys.exit(
            "error: TABLEAU_TENANT_ID is not set, and no TCM PAT is available to look it up.\n"
            "Run `python dev/uat/uat_config.py list` to see it, then add TABLEAU_TENANT_ID to .env."
        )
    print("TABLEAU_TENANT_ID not set - looking it up via Tableau Cloud Manager...")
    tenant_id = uat_config.connect().tenant_id
    print(f"Tip: add TABLEAU_TENANT_ID=\"{tenant_id}\" to .env to skip this step.\n")
    return tenant_id


def build_jwt(
    private_key: str,
    issuer: str,
    tenant_id: str,
    username_claim: str,
    username: str,
    scopes: list[str],
    kid: str | None,
) -> tuple[str, dict]:
    now = datetime.datetime.now(datetime.timezone.utc)
    claims = {
        "iss": issuer,  # must exactly match the UAT configuration's issuer
        "iat": int(now.timestamp()),
        "exp": int((now + JWT_LIFETIME).timestamp()),
        "jti": str(uuid.uuid4()),  # unique per token; also what revocation targets
        "https://tableau.com/tenantId": tenant_id,
        username_claim: username,  # claim name must match the config's usernameClaim
        "scp": scopes,
    }
    headers = {"typ": "JWT"}
    if kid:
        headers["kid"] = kid  # only needed for JWKS-based configurations
    # Note: PyJWT's argument is `algorithm`. Tableau's own sample uses `alg=`,
    # which PyJWT doesn't accept.
    token = jwt.encode(claims, private_key, algorithm="RS256", headers=headers)
    return token, claims


def test_site(
    server_url: str, api_version: str, content_url: str, make_jwt, verbose_claims: bool
) -> bool:
    base = f"{server_url}/api/{api_version}"
    http = requests.Session()
    http.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    print(f"\n=== site: {content_url} ===")

    # A fresh JWT per sign-in, as the provider will do: each has a unique jti,
    # so reusing one may be rejected as a replay.
    token, claims = make_jwt()
    if verbose_claims:
        shown = dict(claims)
        if len(shown["scp"]) > 5:
            shown["scp"] = shown["scp"][:3] + [f"... and {len(shown['scp']) - 3} more"]
        print(f"  JWT claims: {shown}")
    print(f"  JWT size:   {len(token)} bytes, {len(claims['scp'])} scope(s)")
    if len(token) > MAX_JWT_BYTES:
        print(f"  [WARN] JWT exceeds ~{MAX_JWT_BYTES} bytes - Tableau rejects these with a generic "
              "401 sign-in error. Request fewer scopes.")

    # 1. Sign in
    body = {"credentials": {"jwt": token, "isUat": True, "site": {"contentUrl": content_url}}}
    resp = http.post(f"{base}/auth/signin", json=body, timeout=TIMEOUT_SECONDS)
    if not resp.ok:
        print(f"  [FAIL] sign-in: HTTP {resp.status_code}\n  {resp.text}")
        return False
    creds = resp.json()["credentials"]
    site_id = creds["site"]["id"]
    http.headers["X-Tableau-Auth"] = creds["token"]
    print("  [ OK ] sign-in")
    print(f"         site ID: {site_id}")
    print(f"         user ID: {creds['user']['id']}")

    ok = True
    try:
        # 2. A real API call with the session (needs tableau:content:read)
        resp = http.get(
            f"{base}/sites/{site_id}/projects", params={"pageSize": 100}, timeout=TIMEOUT_SECONDS
        )
        if resp.ok:
            data = resp.json()
            projects = data.get("projects", {}).get("project", [])
            total = data.get("pagination", {}).get("totalAvailable", len(projects))
            names = ", ".join(p["name"] for p in projects[:10])
            print(f"  [ OK ] list projects: {total} project(s): {names}")
        else:
            ok = False
            print(f"  [FAIL] list projects: HTTP {resp.status_code}\n  {resp.text}")
            if resp.status_code in (401, 403):
                print("         Sign-in worked but this call didn't - the JWT's scp may be "
                      "missing tableau:content:read, or the user lacks access.")
    finally:
        # 3. Always sign out, so test sessions don't linger
        resp = http.post(f"{base}/auth/signout", timeout=TIMEOUT_SECONDS)
        print(f"  [{' OK ' if resp.ok else 'WARN'}] sign-out" + ("" if resp.ok else f": HTTP {resp.status_code}"))

    return ok


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--site", action="append", required=True, metavar="CONTENT_URL",
                        help="site content URL to test (repeatable)")
    parser.add_argument("--issuer", default=DEFAULT_ISSUER, help=f"default: {DEFAULT_ISSUER}")
    parser.add_argument("--private-key-file", type=Path, default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--username-claim", default="email",
                        help="must match the UAT configuration's usernameClaim (default: email)")
    parser.add_argument("--kid", help="key ID header (only for JWKS-based configurations)")
    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument("--scope", action="append", metavar="SCOPE",
                             help="scope to request (repeatable). Default: tableau:content:read")
    scope_group.add_argument("--all-scopes", action="store_true",
                             help="request every scope in scopes_full.txt - exceeds the ~8 KB JWT limit, so expect failure")
    parser.add_argument("--api-version", help="REST API version (default: newest the pod supports)")
    parser.add_argument("--quiet-claims", action="store_true", help="don't print JWT claims")
    args = parser.parse_args()

    uat_config.load_dotenv(uat_config.REPO_ROOT / ".env")
    username = uat_config.require_env("TABLEAU_UAT_USERNAME", "Add the Tableau username (email) to .env.")
    server_url = uat_config.require_env(
        "TABLEAU_SERVER_URL", "Add the pod URL, e.g. https://10ax.online.tableau.com, to .env."
    ).rstrip("/")

    if not args.private_key_file.exists():
        sys.exit(f"error: private key not found: {args.private_key_file}")
    private_key = args.private_key_file.read_text(encoding="utf-8")

    if args.all_scopes:
        scopes = uat_config.read_scopes_file(uat_config.DEFAULT_SCOPES_FILE)
    else:
        scopes = list(dict.fromkeys(args.scope or ["tableau:content:read"]))

    try:
        tenant_id = resolve_tenant_id()
        api_version = args.api_version or detect_api_version(server_url)
        if parse_version(api_version) < MIN_UAT_API_VERSION:
            sys.exit(
                f"error: API {api_version} predates UAT sign-in (needs "
                f"{'.'.join(map(str, MIN_UAT_API_VERSION))}+)."
            )

        print(f"Pod:         {server_url} (REST API {api_version})")
        print(f"Tenant:      {tenant_id}")
        print(f"Signing in:  {username}")
        print(f"Issuer:      {args.issuer}")

        def make_jwt():
            return build_jwt(private_key, args.issuer, tenant_id, args.username_claim,
                             username, scopes, args.kid)

        results = {
            site: test_site(server_url, api_version, site, make_jwt, not args.quiet_claims)
            for site in dict.fromkeys(args.site)
        }
    except (SignInTestError, uat_config.TCMError) as e:
        sys.exit(f"error: {e}")
    except requests.RequestException as e:
        sys.exit(f"error: network problem: {e}")

    print("\n=== summary ===")
    for site, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {site}")
    if not all(results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
