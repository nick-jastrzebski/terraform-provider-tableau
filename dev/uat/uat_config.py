"""Manage Tableau Cloud Manager (TCM) Unified Access Token (UAT) configurations.

Signs in to the TCM REST API with a TCM personal access token, then creates,
lists or deletes UAT configurations. Supports both ways of telling Tableau how
to verify your JWTs:

  * manual keypair - you generate an RSA keypair; the public key is uploaded
                     into the configuration and you sign JWTs with the private key
  * IdP / JWKS URI - your identity provider signs the JWTs and Tableau fetches
                     the verification keys from its JWKS endpoint

Typical manual-keypair flow (run from the repo root):

    python dev/uat/uat_config.py generate-keys
    python dev/uat/uat_config.py list-sites
    python dev/uat/uat_config.py create --name "tf-provider-dev" \
        --issuer "https://terraform-provider-tableau.local" \
        --public-key-file dev/uat/keys/public_key.pem \
        --site my-site-content-url --dry-run
    (then the same command without --dry-run)

IdP flow: swap --public-key-file for --jwks-uri and set --issuer to your IdP's
issuer URL (it must exactly match the `iss` claim your IdP puts in tokens).

Credentials:
    TABLEAU_TCM_PAT_NAME       Name of the TCM personal access token. Create it
                               in Tableau Cloud Manager > My Account Settings.
                               A PAT from a Tableau Cloud *site* will NOT work.
    TABLEAU_TCM_PAT_SECRET     The PAT secret (the "xxxx==:yyyy" value).
    TABLEAU_CLOUD_MANAGER_URL  Optional, defaults to https://cloudmanager.tableau.com
                               (a trailing /api/v1 is accepted and stripped).

All are read from the environment, falling back to the repo-root .env file.
Secrets are never printed.

API reference:
    https://help.tableau.com/current/api/cloud-manager/en-us/reference/index.html
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from pathlib import Path

import requests

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_KEY_DIR = Path(__file__).resolve().parent / "keys"
DEFAULT_BASE_URL = "https://cloudmanager.tableau.com"
TIMEOUT_SECONDS = 30

# The scopes a UAT configuration *allows*. Each JWT then requests a subset of
# these in its `scp` claim - a JWT cannot exceed what the configuration grants.
#
# The default is every scope documented in the Tableau REST API and TCM REST
# API references, because the provider manages content across the whole site.
# Tableau has no catch-all scope: wildcards only replace the action
# (tableau:users:*), never the resource (tableau:* is invalid). Regenerate the
# file with `refresh-scopes` as Tableau adds methods.
DEFAULT_SCOPES_FILE = Path(__file__).resolve().parent / "scopes_full.txt"
REST_REF_BASE = "https://help.tableau.com/current/api/rest_api/en-us/REST/"
TCM_REF_URL = "https://help.tableau.com/current/api/cloud-manager/en-us/reference/index.html"
SCOPE_PATTERN = re.compile(r"tableau:[a-z0-9_]+:[a-z0-9_]+")


# --- configuration -----------------------------------------------------------


def load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=value, optional quotes and `export ` prefix.

    Variables already set in the environment win, so values exported by
    dev/env.ps1 (or set by hand) are never overridden.
    """
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def require_env(name: str, hint: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"error: {name} is not set. {hint}")
    return value


def read_scopes_file(path: Path) -> list[str]:
    """One scope per line; blank lines and # comments ignored."""
    if not path.exists():
        sys.exit(f"error: scopes file not found: {path}\nRun `refresh-scopes` to generate it.")
    scopes = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            scopes.append(line)
    if not scopes:
        sys.exit(f"error: no scopes in {path}")
    return list(dict.fromkeys(scopes))


# --- scope discovery ---------------------------------------------------------


def _scopes_in(html: str) -> set[str]:
    return set(SCOPE_PATTERN.findall(html))


def _drop_truncated(scopes: set[str]) -> set[str]:
    """Remove scraping artefacts where the page wrapped a word mid-action.

    The TCM reference renders e.g. both `tableau:tcm_sites:upd` and
    `tableau:tcm_sites:update`; an action that is a strict prefix of another
    action on the same resource is a fragment, not a real scope.
    """
    actions: dict[str, set[str]] = {}
    for s in scopes:
        _, resource, action = s.split(":")
        actions.setdefault(resource, set()).add(action)
    return {
        s
        for s in scopes
        if not any(
            other != s.split(":")[2] and other.startswith(s.split(":")[2])
            for other in actions[s.split(":")[1]]
        )
    }


def discover_scopes() -> tuple[list[str], list[str]]:
    """Scrape every scope string from the REST API and TCM API references."""
    http = requests.Session()

    def get(url: str, required: bool = True) -> str:
        resp = http.get(url, timeout=TIMEOUT_SECONDS)
        if resp.status_code == 404 and not required:
            # The index still links a few retired pages; skip them.
            print(f"    skipped (404): {url}", file=sys.stderr)
            return ""
        if not resp.ok:
            raise TCMError(f"GET {url} failed: HTTP {resp.status_code}")
        return resp.text

    index = get(REST_REF_BASE + "rest_api_ref.htm")
    pages = sorted(set(re.findall(r"rest_api_ref_[a-z0-9_]+\.htm", index)))
    if not pages:
        raise TCMError("found no method pages in the REST API reference index - has the site changed?")

    rest: set[str] = set()
    for i, page in enumerate(pages, 1):
        print(f"  [{i}/{len(pages)}] {page}", file=sys.stderr)
        rest |= _scopes_in(get(REST_REF_BASE + page, required=False))

    print("  TCM reference", file=sys.stderr)
    tcm = {s for s in _scopes_in(get(TCM_REF_URL)) if s.startswith("tableau:tcm_")}
    if not rest or not tcm:
        raise TCMError(
            f"scrape looks broken ({len(rest)} REST, {len(tcm)} TCM scopes) - "
            "not overwriting the scopes file"
        )

    rest = {s for s in rest if not s.startswith("tableau:tcm_")}
    return sorted(_drop_truncated(rest)), sorted(_drop_truncated(tcm))


# --- TCM client --------------------------------------------------------------


class TCMError(Exception):
    pass


class TCMClient:
    """Tiny wrapper around the handful of TCM REST endpoints this script needs."""

    def __init__(self, base_url: str):
        # Every path below starts with /api/v1, so accept either
        # https://cloudmanager.tableau.com or .../api/v1 as the base.
        base_url = base_url.strip().rstrip("/")
        if base_url.endswith("/api/v1"):
            base_url = base_url[: -len("/api/v1")]
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )
        self.tenant_id: str | None = None

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        resp = self.session.request(method, url, timeout=TIMEOUT_SECONDS, **kwargs)
        if not resp.ok:
            # The body is Tableau's error message; it never echoes credentials.
            raise TCMError(f"{method} {path} failed: HTTP {resp.status_code}\n{resp.text}")
        return resp

    def sign_in_with_pat(self, pat_name: str, pat_secret: str) -> None:
        # POST /api/v1/pat/login  ->  { sessionToken, userId, tenantId, sessionExpiration }
        # The API only takes the secret; the PAT name is a label that identifies
        # the token in the TCM UI, so it's used for messages, not the request.
        try:
            body = self._request("POST", "/api/v1/pat/login", json={"token": pat_secret}).json()
        except TCMError as e:
            if "HTTP 401" in str(e) or "HTTP 403" in str(e):
                raise TCMError(
                    f"{e}\n\nPAT '{pat_name}' was rejected. Check it exists and hasn't expired in "
                    "Tableau Cloud Manager > My Account Settings, that TABLEAU_TCM_PAT_SECRET is "
                    "the full secret, and that it's a TCM PAT (not a site PAT)."
                ) from None
            raise
        self.session.headers["x-tableau-session-token"] = body["sessionToken"]
        self.tenant_id = body["tenantId"]
        print(f"Signed in to TCM with PAT '{pat_name}'. Tenant ID: {self.tenant_id}")
        print(f"Session expires: {body.get('sessionExpiration', 'unknown')}")

    def list_sites(self) -> list[dict]:
        # GET /api/v1/tenants/{tenantId}/sites  (paginated)
        sites: list[dict] = []
        page = 1
        while True:
            body = self._request(
                "GET",
                f"/api/v1/tenants/{self.tenant_id}/sites",
                params={"pageNumber": page, "pageSize": 100},
            ).json()
            batch = _extract_list(body, "sites")
            sites.extend(batch)
            if not batch or not _has_more_pages(body, page, len(sites)):
                return sites
            page += 1

    def list_uat_configs(self) -> list[dict]:
        body = self._request("GET", "/api/v1/uat-configurations").json()
        return _extract_list(body, "uatConfigurations")

    def create_uat_config(self, payload: dict) -> dict:
        return self._request("POST", "/api/v1/uat-configurations", json=payload).json()

    def delete_uat_config(self, config_id: str) -> None:
        self._request("DELETE", f"/api/v1/uat-configurations/{config_id}")


def _extract_list(body, preferred_key: str) -> list[dict]:
    """Pull the item list out of a response.

    The TCM docs don't pin down the exact envelope for every list endpoint, so
    accept a bare list, the expected key, or the first list-valued field.
    """
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        if isinstance(body.get(preferred_key), list):
            return body[preferred_key]
        for value in body.values():
            if isinstance(value, list):
                return value
    raise TCMError(f"Unexpected response shape: {json.dumps(body)[:500]}")


def _has_more_pages(body, page: int, fetched: int) -> bool:
    if not isinstance(body, dict):
        return False
    pagination = body.get("pagination") or body
    total = pagination.get("totalAvailable") or pagination.get("totalCount")
    if total is not None:
        return fetched < int(total)
    total_pages = pagination.get("totalPages") or pagination.get("totalPageCount")
    if total_pages is not None:
        return page < int(total_pages)
    return False


def site_id_of(site: dict) -> str:
    # TCM returns the site's ID as `siteUUID` (confirmed against a live tenant).
    # Don't fall back to `id`: each site also carries a nested `instance.id`,
    # which identifies the pod, not the site.
    return site.get("siteUUID") or site.get("siteId") or ""


# --- commands ----------------------------------------------------------------


def connect() -> TCMClient:
    load_dotenv(REPO_ROOT / ".env")
    hint = (
        "Create a PAT in Tableau Cloud Manager > My Account Settings and add "
        "TABLEAU_TCM_PAT_NAME and TABLEAU_TCM_PAT_SECRET to .env "
        "(site PATs do not work with TCM)."
    )
    pat_name = require_env("TABLEAU_TCM_PAT_NAME", hint)
    pat_secret = require_env("TABLEAU_TCM_PAT_SECRET", hint)
    client = TCMClient(os.environ.get("TABLEAU_CLOUD_MANAGER_URL") or DEFAULT_BASE_URL)
    client.sign_in_with_pat(pat_name, pat_secret)
    return client


def cmd_generate_keys(args: argparse.Namespace) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key_dir: Path = args.out_dir
    private_path = key_dir / "private_key.pem"
    public_path = key_dir / "public_key.pem"
    if not args.force and (private_path.exists() or public_path.exists()):
        sys.exit(
            f"error: keys already exist in {key_dir}. Rotating them breaks any UAT "
            "configuration that uses the old public key. Pass --force to overwrite."
        )

    key_dir.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=args.bits)

    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        private_path.chmod(0o600)  # effective on macOS/Linux; limited on Windows
    except OSError:
        pass

    print(f"Wrote {args.bits}-bit RSA keypair:")
    print(f"  private: {private_path}  (secret - gitignored, never upload or commit)")
    print(f"  public:  {public_path}  (goes into the UAT configuration)")


def cmd_refresh_scopes(args: argparse.Namespace) -> None:
    print("Scraping scopes from the Tableau API references...", file=sys.stderr)
    rest, tcm = discover_scopes()

    old = set(read_scopes_file(args.out)) if args.out.exists() else set()
    new = set(rest) | set(tcm)

    lines = [
        "# Every access scope documented in the Tableau REST API and TCM REST API references.",
        "# Default allow-list for `uat_config.py create`. JWTs may request any subset.",
        "#",
        f"# Generated {datetime.date.today().isoformat()} by: python dev/uat/uat_config.py refresh-scopes",
        f"# Sources: {REST_REF_BASE}rest_api_ref.htm (and its method pages)",
        f"#          {TCM_REF_URL}",
        "",
        f"# --- Tableau REST API ({len(rest)}) ---",
        *rest,
        "",
        f"# --- Tableau Cloud Manager REST API ({len(tcm)}) ---",
        *tcm,
        "",
    ]
    args.out.write_text("\n".join(lines), encoding="utf-8")

    print(f"Wrote {len(new)} scopes ({len(rest)} REST, {len(tcm)} TCM) to {args.out}")
    if old:
        added, removed = sorted(new - old), sorted(old - new)
        print(f"  added:   {len(added)}" + (f"  {', '.join(added)}" if added else ""))
        print(f"  removed: {len(removed)}" + (f"  {', '.join(removed)}" if removed else ""))
        if added or removed:
            print("Existing UAT configurations keep their old scopes until updated.")


def cmd_list_sites(args: argparse.Namespace) -> None:
    client = connect()
    sites = client.list_sites()
    if args.json:
        print(json.dumps(sites, indent=2))
        return
    print(f"\n{len(sites)} site(s):")
    print(f"  {'SITE ID':<38} {'CONTENT URL':<30} NAME")
    for s in sites:
        print(f"  {site_id_of(s):<38} {s.get('contentUrl', ''):<30} {s.get('name', '')}")


def cmd_list(args: argparse.Namespace) -> None:
    client = connect()
    configs = client.list_uat_configs()
    if args.json:
        print(json.dumps(configs, indent=2))
        return
    print(f"\n{len(configs)} UAT configuration(s):")
    for c in configs:
        mode = "jwksUri" if c.get("jwksUri") else "publicKey"
        print(f"\n  {c.get('name')}  (configId: {c.get('configId') or c.get('id')})")
        print(f"    enabled:     {c.get('enabled')}")
        print(f"    issuer:      {c.get('issuer')}")
        print(f"    key source:  {mode}")
        print(f"    resourceIds: {', '.join(c.get('resourceIds') or [])}")
        scopes = c.get("scopes") or []
        print(f"    scopes:      {len(scopes)} (use --json to see them all)")


def cmd_create(args: argparse.Namespace) -> None:
    payload: dict = {
        "name": args.name,
        "issuer": args.issuer,
        "usernameClaim": args.username_claim,
        "scopes": list(dict.fromkeys(args.scope)) if args.scope else read_scopes_file(args.scopes_file),
        "enabled": not args.disabled,
    }

    if args.public_key_file:
        pem = args.public_key_file.read_text(encoding="utf-8").strip()
        if "PRIVATE KEY" in pem:
            sys.exit(
                "error: that file is a PRIVATE key. Pass the public key "
                "(public_key.pem) - the private key must never leave your machine."
            )
        if "BEGIN PUBLIC KEY" not in pem:
            sys.exit("error: public key must be PEM ('-----BEGIN PUBLIC KEY-----').")
        payload["publicKey"] = pem  # json encoding turns newlines into \n as the API expects
    else:
        payload["jwksUri"] = args.jwks_uri

    # In dry-run mode we still sign in and resolve sites, so typos in content
    # URLs surface before anything is created.
    client = connect()

    resource_ids: list[str] = list(args.site_id or [])
    if args.site:
        sites = {s.get("contentUrl"): s for s in client.list_sites()}
        missing = [c for c in args.site if c not in sites]
        if missing:
            known = ", ".join(sorted(k for k in sites if k)) or "(none)"
            sys.exit(f"error: unknown site content URL(s): {', '.join(missing)}\nKnown: {known}")
        for content_url in args.site:
            site_id = site_id_of(sites[content_url])
            if not site_id:
                # Never send an empty ID - TCM rejects it as "Resource ID 'null'".
                sys.exit(
                    f"error: found site '{content_url}' but couldn't read its ID. "
                    f"Fields returned: {', '.join(sorted(sites[content_url]))}"
                )
            resource_ids.append(site_id)
    if args.include_tenant:
        resource_ids.insert(0, client.tenant_id)

    if not resource_ids:
        sys.exit(
            "error: no resources given. Pass --site and/or --site-id for each site the "
            "UAT should work on. Note: the tenant ID alone does NOT enable its sites."
        )
    payload["resourceIds"] = list(dict.fromkeys(resource_ids))  # de-dupe, keep order

    print("\nRequest payload:")
    shown = dict(payload)
    if "publicKey" in shown:
        shown["publicKey"] = shown["publicKey"][:40] + "... (truncated)"
    if len(shown["scopes"]) > 10:
        shown["scopes"] = shown["scopes"][:5] + [f"... and {len(shown['scopes']) - 5} more"]
    print(json.dumps(shown, indent=2))

    if args.dry_run:
        print("\n--dry-run: nothing created.")
        return

    created = client.create_uat_config(payload)
    config_id = created.get("configId") or created.get("id")
    print(f"\nCreated UAT configuration '{created.get('name')}' (configId: {config_id})")
    print("\nFor signing JWTs against this configuration you will need:")
    print(f"  iss                          = {created.get('issuer')}")
    print(f"  https://tableau.com/tenantId = {created.get('tenantId') or client.tenant_id}")
    print(f"  {created.get('usernameClaim') or args.username_claim:<28} = <your Tableau username>")
    print("  scp                          = subset of the scopes above")


def cmd_delete(args: argparse.Namespace) -> None:
    client = connect()
    if not args.yes:
        answer = input(f"Delete UAT configuration {args.config_id}? JWTs using it stop working. [y/N] ")
        if answer.strip().lower() != "y":
            sys.exit("Aborted.")
    client.delete_uat_config(args.config_id)
    print(f"Deleted UAT configuration {args.config_id}")


# --- CLI ---------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("generate-keys", help="generate an RSA keypair for manual-key UATs")
    p.add_argument("--out-dir", type=Path, default=DEFAULT_KEY_DIR)
    p.add_argument("--bits", type=int, default=2048, choices=[2048, 3072, 4096])
    p.add_argument("--force", action="store_true", help="overwrite existing keys")
    p.set_defaults(func=cmd_generate_keys)

    p = sub.add_parser(
        "refresh-scopes", help="regenerate the full scope list from Tableau's API docs (no sign-in)"
    )
    p.add_argument("--out", type=Path, default=DEFAULT_SCOPES_FILE)
    p.set_defaults(func=cmd_refresh_scopes)

    p = sub.add_parser("list-sites", help="list the tenant's sites and their IDs")
    p.add_argument("--json", action="store_true", help="print raw JSON")
    p.set_defaults(func=cmd_list_sites)

    p = sub.add_parser("list", help="list existing UAT configurations")
    p.add_argument("--json", action="store_true", help="print raw JSON")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("create", help="create a UAT configuration")
    p.add_argument("--name", required=True)
    p.add_argument(
        "--issuer",
        required=True,
        help="must exactly match the JWT `iss` claim. Manual keys: any stable URL-like "
        "string you choose. IdP: your IdP's issuer URL.",
    )
    key_source = p.add_mutually_exclusive_group(required=True)
    key_source.add_argument("--public-key-file", type=Path, help="manual keypair: PEM public key")
    key_source.add_argument("--jwks-uri", help="IdP: the IdP's JWKS endpoint URL")
    p.add_argument(
        "--site", action="append", metavar="CONTENT_URL",
        help="site content URL to enable (repeatable); resolved to a site ID",
    )
    p.add_argument("--site-id", action="append", metavar="UUID", help="site ID to enable (repeatable)")
    p.add_argument(
        "--include-tenant", action="store_true",
        help="also add the tenant ID (needed for TCM tenant-level methods)",
    )
    p.add_argument(
        "--scopes-file", type=Path, default=DEFAULT_SCOPES_FILE,
        help="file of allowed scopes, one per line (default: every documented scope)",
    )
    p.add_argument(
        "--scope", action="append", metavar="SCOPE",
        help="allowed scope (repeatable); if given, --scopes-file is ignored",
    )
    p.add_argument("--username-claim", default="email", help="JWT claim holding the username (default: email)")
    p.add_argument("--disabled", action="store_true", help="create the configuration disabled")
    p.add_argument("--dry-run", action="store_true", help="sign in and validate, but don't create")
    p.set_defaults(func=cmd_create)

    p = sub.add_parser("delete", help="delete a UAT configuration")
    p.add_argument("config_id")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p.set_defaults(func=cmd_delete)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        args.func(args)
    except TCMError as e:
        sys.exit(f"error: {e}")
    except requests.RequestException as e:
        sys.exit(f"error: network problem: {e}")


if __name__ == "__main__":
    main()
