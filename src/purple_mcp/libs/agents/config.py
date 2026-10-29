"""Configuration for the SentinelOne agent management client."""

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict


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


class AgentsConfig(_ProgrammaticSettings):
    """Configuration for the SentinelOne Management REST API (agents, packages, activities)."""

    model_config = SettingsConfigDict(validate_assignment=True)

    base_url: str = Field(
        ...,
        description="Console base URL (must use HTTPS).",
    )
    api_prefix: str = Field(
        default="/web/api/v2.1",
        description="Management API path prefix.",
    )
    api_token: str = Field(
        ...,
        description="API token used for authentication.",
    )

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        """Require HTTPS and strip trailing slashes."""
        if not v:
            raise ValueError("base_url cannot be empty")
        if not v.startswith("https://"):
            raise ValueError("base_url must use HTTPS protocol")
        return v.rstrip("/")

    @field_validator("api_prefix")
    @classmethod
    def validate_api_prefix(cls, v: str) -> str:
        """Normalize the prefix to exactly one leading slash and no trailing slash."""
        if not v:
            raise ValueError("api_prefix cannot be empty")
        return "/" + v.strip("/")

    @property
    def api_url(self) -> str:
        """Full URL of the management API root."""
        return f"{self.base_url}{self.api_prefix}"
