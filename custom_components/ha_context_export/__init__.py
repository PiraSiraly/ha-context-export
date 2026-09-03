"""HA Context Export integration."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path
from typing import Any

from aiohttp import web
import voluptuous as vol

from homeassistant.auth.models import User
from homeassistant.components import persistent_notification
from homeassistant.components.http import KEY_HASS, KEY_HASS_USER, HomeAssistantView
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError

from .const import (
    DATA_LATEST_EXPORT,
    DOMAIN,
    DOWNLOAD_URL,
    EXPORT_DIR_NAME,
    PLATFORMS,
    SERVICE_CREATE,
)
from .exporter import async_create_export

SERVICE_SCHEMA = vol.Schema({})


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    """Set up services and the authenticated download endpoint."""
    hass.data.setdefault(DOMAIN, {})

    if not hass.data[DOMAIN].get("http_registered"):
        hass.http.register_view(HAContextExportDownloadView())
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


def async_notify_export_ready(hass: HomeAssistant, filename: str) -> None:
    """Show a persistent notification with the authenticated download link."""
    message = (
        f"The sanitized context export **{filename}** is ready.\n\n"
        f"[Download context export]({DOWNLOAD_URL})\n\n"
        "The download is available only to signed-in Home Assistant administrators."
    )
    persistent_notification.async_create(
        hass,
        message,
        "HA Context Export",
        "ha_context_export_ready",
    )


class HAContextExportDownloadView(HomeAssistantView):
    """Serve the latest context export to authenticated administrators."""

    url = DOWNLOAD_URL
    name = "api:ha_context_export:download"
    requires_auth = True

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Download the latest generated ZIP."""
        hass: HomeAssistant = request.app[KEY_HASS]
        user: User = request[KEY_HASS_USER]

        if not user.is_admin:
            raise web.HTTPForbidden(
                text="Only Home Assistant administrators may download this export."
            )

        export_info = hass.data.get(DOMAIN, {}).get(DATA_LATEST_EXPORT)
        if not export_info:
            raise web.HTTPNotFound(text="No context export has been generated yet.")

        path = Path(export_info["path"])
        if not path.is_file():
            raise web.HTTPNotFound(text="The latest context export no longer exists.")

        response = web.FileResponse(path)
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{export_info["filename"]}"'
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.set_status(HTTPStatus.OK)
        return response
