"""HA Context Export integration."""

from __future__ import annotations

from http import HTTPStatus
import hmac
from pathlib import Path
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

from aiohttp import web
import voluptuous as vol

from homeassistant.components import persistent_notification
from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.http import (
    KEY_HASS,
    KEY_HASS_USER,
    HomeAssistantView,
    StaticPathConfig,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.network import NoURLAvailableError, get_url

from .const import (
    DATA_LATEST_EXPORT,
    DOMAIN,
    DOWNLOAD_TOKEN_TTL_SECONDS,
    DOWNLOAD_URL,
    EXPORT_DIR_NAME,
    PLATFORMS,
    SERVICE_CREATE,
)
from . import exporter as exporter_module
from .sanitizer import install_export_sanitizers

install_export_sanitizers(exporter_module)
async_create_export = exporter_module.async_create_export

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)
SERVICE_SCHEMA = vol.Schema({})

CREATE_DOWNLOAD_URL = "/api/ha_context_export/create_download"
FRONTEND_URL = "/ha_context_export/frontend/ha-context-export-card.js"


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    """Set up services, frontend resource, and protected download endpoints."""
    hass.data.setdefault(DOMAIN, {})

    if not hass.data[DOMAIN].get("frontend_registered"):
        frontend_file = (
            Path(__file__).parent / "frontend" / "ha-context-export-card.js"
        )
        await hass.http.async_register_static_paths(
            [StaticPathConfig(FRONTEND_URL, str(frontend_file), False)]
        )
        add_extra_js_url(hass, FRONTEND_URL)
        hass.data[DOMAIN]["frontend_registered"] = True

    if not hass.data[DOMAIN].get("http_registered"):
        hass.http.register_view(HAContextExportDownloadView())
        hass.http.register_view(HAContextExportCreateDownloadView())
        hass.data[DOMAIN]["http_registered"] = True

    latest_path = (
        Path(hass.config.config_dir)
        / ".storage"
        / EXPORT_DIR_NAME
        / "latest.zip"
    )
    if latest_path.is_file() and DATA_LATEST_EXPORT not in hass.data[DOMAIN]:
        hass.data[DOMAIN][DATA_LATEST_EXPORT] = {
            "path": str(latest_path),
            "filename": "ha-context-export-latest.zip",
        }

    if not hass.services.has_service(DOMAIN, SERVICE_CREATE):

        async def handle_create(call: ServiceCall) -> None:
            """Create a context export through an action call."""
            await _ensure_admin_or_system(hass, call)
            result = await async_create_export(hass)
            async_notify_export_ready(hass, result["filename"])

        hass.services.async_register(
            DOMAIN,
            SERVICE_CREATE,
            handle_create,
            schema=SERVICE_SCHEMA,
        )

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up HA Context Export from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def _ensure_admin_or_system(
    hass: HomeAssistant, call: ServiceCall
) -> None:
    """Allow system calls and administrator users only."""
    user_id = call.context.user_id
    if user_id is None:
        return

    user = await hass.auth.async_get_user(user_id)
    if user is None or not user.is_admin:
        raise HomeAssistantError(
            "Only Home Assistant administrators may create a context export."
        )


def _absolute_download_url(hass: HomeAssistant, relative_url: str) -> str | None:
    """Build an absolute HA URL suitable for handing off to a browser."""
    try:
        base_url = get_url(hass)
    except NoURLAvailableError:
        return None

    return f"{base_url.rstrip('/')}{relative_url}"


def _android_browser_intent(url: str) -> str | None:
    """Build an Android intent URL that opens the system browser."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    target = f"{parsed.netloc}{parsed.path}"
    if parsed.query:
        target = f"{target}?{parsed.query}"

    return (
        f"intent://{target}#Intent;scheme={parsed.scheme};"
        "action=android.intent.action.VIEW;end"
    )


def _prepare_download(hass: HomeAssistant, filename: str) -> dict[str, str]:
    """Create a fresh short-lived capability URL for the latest export."""
    export_info = hass.data.get(DOMAIN, {}).get(DATA_LATEST_EXPORT)
    if export_info is None:
        raise HomeAssistantError("No context export metadata is available.")

    token = secrets.token_urlsafe(32)
    export_info["download_token"] = token
    export_info["download_token_expires"] = (
        time.monotonic() + DOWNLOAD_TOKEN_TTL_SECONDS
    )

    relative_url = f"{DOWNLOAD_URL}?{urlencode({'token': token})}"
    absolute_url = _absolute_download_url(hass, relative_url)

    return {
        "filename": filename,
        "relative_url": relative_url,
        "absolute_url": absolute_url or relative_url,
    }


def async_notify_export_ready(hass: HomeAssistant, filename: str) -> None:
    """Show fallback download links in a persistent notification."""
    download = _prepare_download(hass, filename)
    absolute_url = download["absolute_url"]
    browser_intent = _android_browser_intent(absolute_url)

    links: list[str] = []
    if browser_intent is not None:
        links.append(f"[Im Browser herunterladen]({browser_intent})")
    links.append(f"[Direkter Download]({absolute_url})")

    message = (
        f"The sanitized context export **{filename}** is ready.\n\n"
        + "  ·  ".join(links)
        + "\n\nFor a reliable one-click download, use the **HA Context Export** "
        "dashboard card. This private fallback link expires after 60 minutes."
    )
    persistent_notification.async_create(
        hass,
        message,
        "HA Context Export",
        "ha_context_export_ready",
    )


class HAContextExportCreateDownloadView(HomeAssistantView):
    """Create an export and return a download URL to the HA frontend."""

    url = CREATE_DOWNLOAD_URL
    name = "api:ha_context_export:create_download"
    requires_auth = True

    async def post(self, request: web.Request) -> web.Response:
        """Create an export for an authenticated administrator."""
        hass: HomeAssistant = request.app[KEY_HASS]
        user = request[KEY_HASS_USER]

        if user is None or not user.is_admin:
            raise web.HTTPForbidden(
                text="Only Home Assistant administrators may create an export."
            )

        result = await async_create_export(hass)
        download = _prepare_download(hass, result["filename"])

        # The frontend deliberately receives a same-origin relative URL. Its
        # JavaScript performs a real window.location navigation so Home
        # Assistant's SPA router cannot swallow the download click.
        return web.json_response(
            {
                "filename": result["filename"],
                "download_url": download["relative_url"],
                "expires_in": DOWNLOAD_TOKEN_TTL_SECONDS,
            }
        )


class HAContextExportDownloadView(HomeAssistantView):
    """Serve the latest context export through a short-lived capability link."""

    url = DOWNLOAD_URL
    name = "api:ha_context_export:download"
    requires_auth = False

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Download the latest generated ZIP when the capability token is valid."""
        hass: HomeAssistant = request.app[KEY_HASS]
        export_info = hass.data.get(DOMAIN, {}).get(DATA_LATEST_EXPORT)

        if not export_info:
            raise web.HTTPNotFound(text="No context export has been generated yet.")

        expected_token = export_info.get("download_token")
        provided_token = request.query.get("token")
        expires_at = export_info.get("download_token_expires")

        if (
            not isinstance(expected_token, str)
            or not isinstance(provided_token, str)
            or not hmac.compare_digest(provided_token, expected_token)
        ):
            raise web.HTTPForbidden(text="Invalid context export download link.")

        if not isinstance(expires_at, (int, float)) or time.monotonic() > expires_at:
            export_info.pop("download_token", None)
            export_info.pop("download_token_expires", None)
            raise web.HTTPGone(
                text="This context export download link has expired. Create a new export."
            )

        path = Path(export_info["path"])
        if not path.is_file():
            raise web.HTTPNotFound(text="The latest context export no longer exists.")

        response = web.FileResponse(path)
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{export_info["filename"]}"'
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.set_status(HTTPStatus.OK)
        return response
