class HAContextExportCard extends HTMLElement {
  static getStubConfig() {
    return {};
  }

  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._busy = false;
    this._render();
  }

  setConfig(config) {
    this._config = config || {};
    this._render();
  }

  set hass(hass) {
    this._hass = hass;
  }

  getCardSize() {
    return 2;
  }

  async _createAndDownload() {
    if (this._busy || !this._hass) {
      return;
    }

    this._busy = true;
    this._setState("Export wird erstellt …", true);

    try {
      const result = await this._hass.callApi(
        "POST",
        "ha_context_export/create_download",
        {}
      );

      if (!result || !result.download_url) {
        throw new Error("Home Assistant hat keinen Download-Link zurückgegeben.");
      }

      this._setState("Download wird gestartet …", true);

      // Use a real browser navigation instead of an HA markdown/router link.
      // Content-Disposition: attachment on the backend turns this into a file download.
      const downloadUrl = new URL(result.download_url, window.location.origin).href;
      window.location.assign(downloadUrl);

      window.setTimeout(() => {
        this._busy = false;
        this._setState("Export erstellen & herunterladen", false);
      }, 1500);
    } catch (error) {
      this._busy = false;
      const message = error?.message || String(error);
      this._setState("Download fehlgeschlagen", false);
      this._showError(message);
    }
  }

  _setState(label, busy) {
    const button = this.shadowRoot?.querySelector("button");
    const labelElement = this.shadowRoot?.querySelector(".label");
    const spinner = this.shadowRoot?.querySelector(".spinner");

    if (button) {
      button.disabled = busy;
    }
    if (labelElement) {
      labelElement.textContent = label;
    }
    if (spinner) {
      spinner.hidden = !busy;
    }
  }

  _showError(message) {
    const error = this.shadowRoot?.querySelector(".error");
    if (!error) {
      return;
    }
    error.textContent = message;
    error.hidden = false;
  }

  _render() {
    if (!this.shadowRoot) {
      return;
    }

    this.shadowRoot.innerHTML = `
      <style>
        :host {
          display: block;
        }

        ha-card {
          display: block;
          padding: 16px;
          border-radius: var(--ha-card-border-radius, 12px);
          background: var(--ha-card-background, var(--card-background-color));
          box-shadow: var(--ha-card-box-shadow, none);
          border: var(--ha-card-border-width, 0) solid var(--ha-card-border-color, transparent);
        }

        .title {
          font-size: 16px;
          font-weight: 600;
          margin-bottom: 12px;
          color: var(--primary-text-color);
        }

        button {
          width: 100%;
          min-height: 48px;
          border: 0;
          border-radius: 12px;
          padding: 0 16px;
          background: var(--primary-color);
          color: var(--text-primary-color, white);
          font: inherit;
          font-weight: 600;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
        }

        button:disabled {
          cursor: default;
          opacity: 0.72;
        }

        .spinner {
          width: 16px;
          height: 16px;
          border: 2px solid currentColor;
          border-right-color: transparent;
          border-radius: 50%;
          animation: spin 0.75s linear infinite;
        }

        .error {
          margin-top: 10px;
          color: var(--error-color, #db4437);
          font-size: 13px;
          overflow-wrap: anywhere;
        }

        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      </style>

      <ha-card>
        <div class="title">HA Context Export</div>
        <button type="button">
          <span class="spinner" hidden></span>
          <span class="label">Export erstellen & herunterladen</span>
        </button>
        <div class="error" hidden></div>
      </ha-card>
    `;

    this.shadowRoot
      .querySelector("button")
      ?.addEventListener("click", () => this._createAndDownload());
  }
}

if (!customElements.get("ha-context-export-card")) {
  customElements.define("ha-context-export-card", HAContextExportCard);
}

window.customCards = window.customCards || [];
if (!window.customCards.some((card) => card.type === "ha-context-export-card")) {
  window.customCards.push({
    type: "ha-context-export-card",
    name: "HA Context Export",
    description: "Erstellt einen bereinigten HA-Kontext-Export und lädt ihn direkt herunter.",
    preview: true,
  });
}
