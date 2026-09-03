"""Button platform for HA Context Export."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import async_notify_export_ready
from .const import DOMAIN
from .exporter import async_create_export


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the export button."""
    async_add_entities([HAContextExportButton(entry)])


class HAContextExportButton(ButtonEntity):
    """Button that creates a sanitized Home Assistant context export."""

    _attr_has_entity_name = True
    _attr_translation_key = "create_export"
    _attr_icon = "mdi:archive-arrow-down-outline"

    def __init__(self, entry: ConfigEntry) -> None:
        """Initialize the button."""
        self._attr_unique_id = f"{entry.entry_id}_create_export"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "HA Context Export",
            "manufacturer": "PiraSiraly",
            "model": "Sanitized Home Assistant context exporter",
        }

    async def async_press(self) -> None:
        """Create the export and show a download notification."""
        result = await async_create_export(self.hass)
        async_notify_export_ready(self.hass, result["filename"])
