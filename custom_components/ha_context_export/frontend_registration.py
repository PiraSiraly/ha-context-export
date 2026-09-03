"""Frontend resource registration for HA Context Export."""

from __future__ import annotations

from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.lovelace.const import LOVELACE_DATA, MODE_STORAGE
from homeassistant.components.lovelace.resources import ResourceStorageCollection
from homeassistant.core import HomeAssistant


async def async_register_frontend_resource(
    hass: HomeAssistant,
    url: str,
    version: str,
) -> None:
    """Register the dashboard card persistently when Lovelace uses storage mode.

    Storage resources are preferred because they are loaded by Lovelace before a
    saved custom card is rendered. YAML resource mode cannot be mutated safely,
    so in that case the frontend extra-JS hook remains the fallback.
    """
    versioned_url = f"{url}?v={version}"
    lovelace_data = hass.data.get(LOVELACE_DATA)

    if lovelace_data is None or getattr(lovelace_data, "resource_mode", None) != MODE_STORAGE:
        add_extra_js_url(hass, versioned_url)
        return

    resources = getattr(lovelace_data, "resources", None)
    if not isinstance(resources, ResourceStorageCollection):
        add_extra_js_url(hass, versioned_url)
        return

    # Force the storage collection to load before async_items/create/update.
    # This avoids replacing an as-yet-unloaded lovelace_resources store.
    await resources.async_get_info()

    for item in resources.async_items():
        existing_url = str(item.get("url", ""))
        if existing_url.split("?", 1)[0] != url:
            continue

        if existing_url != versioned_url:
            await resources.async_update_item(
                item["id"],
                {"res_type": "module", "url": versioned_url},
            )
        return

    await resources.async_create_item(
        {"res_type": "module", "url": versioned_url}
    )
