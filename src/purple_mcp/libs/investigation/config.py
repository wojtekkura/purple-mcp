"""Configuration for the investigation orchestrator."""

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource


class _ProgrammaticSettings(BaseSettings):
    """Base class to disable environment variable loading for settings."""

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Disable all settings sources except for programmatic initialization."""
        return (init_settings,)


class InvestigationConfig(_ProgrammaticSettings):
    """Configuration for the InvestigationCollector.

    The investigation library does not own its own transport — it composes
    the alerts, inventory, and SDL libraries. This config carries only the
    minimum credentials and endpoints required to construct those clients.
    """

    auth_token: str = Field(
        ...,
        description="Bearer token used for the alerts GraphQL API, the inventory REST API, "
        "and the SDL PowerQuery API (the same console token).",
    )
    console_base_url: str = Field(
        ...,
        description="Base URL for the SentinelOne console (no trailing slash).",
    )
    alerts_graphql_url: str = Field(
        ...,
        description="Full GraphQL URL for the Unified Alerts Management API.",
    )
    inventory_api_endpoint: str = Field(
        ...,
        description="REST API endpoint path for the Unified Asset Inventory.",
    )
    sdl_base_url: str = Field(
        ...,
        description="Base URL for the SDL API (PowerQuery). Should already include the SDL path.",
    )
    environment: str = Field(
        default="production",
        description="Environment name (development/staging/production) used for SDL "
        "TLS validation policy.",
    )

    @field_validator("console_base_url", "alerts_graphql_url", "sdl_base_url")
    @classmethod
    def validate_https(cls, v: str) -> str:
        """All upstream URLs must use HTTPS."""
        v = v.strip()
        if not v.startswith("https://"):
            raise ValueError("URL must use HTTPS (https://)")
        return v.rstrip("/")

    @field_validator("inventory_api_endpoint")
    @classmethod
    def validate_endpoint(cls, v: str) -> str:
        """Inventory endpoint must start with a slash."""
        v = v.strip()
        if not v.startswith("/"):
            raise ValueError("inventory_api_endpoint must start with '/'")
        return v.rstrip("/")

    @field_validator("auth_token")
    @classmethod
    def validate_auth_token(cls, v: str) -> str:
        """auth_token must be non-empty."""
        if not v.strip():
            raise ValueError("auth_token cannot be empty")
        return v
