"""REST client for the SentinelOne Management API (agents, update packages, activities)."""

import logging
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any

import httpx
from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from purple_mcp.libs.agents.config import AgentsConfig
from purple_mcp.libs.agents.exceptions import (
    AgentsAPIError,
    AgentsAuthenticationError,
    AgentsNetworkError,
    AgentsTransientError,
)
from purple_mcp.user_agent import get_user_agent

logger = logging.getLogger(__name__)

# Raw management API objects are passed through mostly untouched, so they stay loosely typed.
ApiObject = dict[str, Any]


class AgentsClient:
    """Client for SentinelOne agent lookups and the update-software action.

    GET requests are retried on transient failures. The update-software POST is never
    retried automatically, so a flaky network cannot queue the same upgrade twice.
    """

    def __init__(self, config: AgentsConfig):
        """Initialize the agents client.

        Args:
            config: Configuration for the management API
        """
        self.config = config
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "AgentsClient":
        """Enter async context manager."""
        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"ApiToken {self.config.api_token}",
                "Content-Type": "application/json",
                "User-Agent": get_user_agent(),
            },
            timeout=httpx.Timeout(30.0),
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit async context manager."""
        if self._client:
            await self._client.aclose()
            self._client = None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(
            (httpx.TimeoutException, httpx.NetworkError, AgentsTransientError)
        ),
    )
    async def _get_http(self, path: str, params: Mapping[str, str | int]) -> httpx.Response:
        """Execute a GET with automatic retry on transient failures."""
        if not self._client:
            raise AgentsAPIError("Client not initialized. Use async context manager.")

        response = await self._client.get(f"{self.config.api_url}{path}", params=params)
        if response.status_code in (502, 503, 504):
            logger.warning(
                "Transient server error, will retry",
                extra={"status_code": response.status_code, "path": path},
            )
            raise AgentsTransientError(f"Transient server error {response.status_code}")
        return response

    async def _get(self, path: str, params: Mapping[str, str | int]) -> ApiObject:
        """GET a management API path and return the parsed JSON body."""
        try:
            response = await self._get_http(path, params)
        except RetryError as e:
            original = e.last_attempt.exception()
            if isinstance(original, AgentsTransientError):
                raise AgentsAPIError(
                    f"Server returned transient error after multiple retries: {original}"
                ) from original
            raise AgentsNetworkError(f"Network error: {original}") from original
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RequestError) as e:
            raise AgentsNetworkError(f"Network error: {e}") from e
        return self._handle_response(response)

    async def _post(self, path: str, payload: Mapping[str, object]) -> ApiObject:
        """POST to a management API path once, without retries."""
        if not self._client:
            raise AgentsAPIError("Client not initialized. Use async context manager.")
        try:
            response = await self._client.post(f"{self.config.api_url}{path}", json=payload)
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RequestError) as e:
            raise AgentsNetworkError(f"Network error: {e}") from e
        return self._handle_response(response)

    def _handle_response(self, response: httpx.Response) -> ApiObject:
        """Map HTTP errors to typed exceptions and return the JSON body."""
        if response.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
            raise AgentsAuthenticationError(
                "Authentication or authorization failed",
                status_code=response.status_code,
                details="Check that the API token's role allows this operation",
            )
        if response.status_code >= HTTPStatus.BAD_REQUEST:
            try:
                body = response.json()
                errors = body.get("errors") or body.get("message") or body
            except Exception:
                errors = response.text[:500]
            raise AgentsAPIError(
                "Management API error", status_code=response.status_code, details=str(errors)
            )
        try:
            body = response.json()
        except Exception as e:
            raise AgentsAPIError(f"Failed to parse response: {e}") from e
        if not isinstance(body, dict):
            raise AgentsAPIError("Unexpected response shape from management API")
        return body

    async def find_agents(
        self,
        *,
        computer_name: str | None = None,
        uuid: str | None = None,
        agent_id: str | None = None,
        limit: int = 10,
    ) -> list[ApiObject]:
        """Look up agents by exactly one of computer name, agent UUID or numeric agent ID.

        Returns:
            Matching agent objects (possibly empty).
        """
        params: dict[str, str | int] = {"limit": limit}
        if computer_name:
            params["computerName"] = computer_name
        elif uuid:
            params["uuids"] = uuid
        elif agent_id:
            params["ids"] = agent_id
        else:
            raise ValueError("One of computer_name, uuid or agent_id is required")

        body = await self._get("/agents", params)
        data = body.get("data") or []
        return [item for item in data if isinstance(item, dict)]

    async def list_update_packages(self, os_type: str, limit: int = 50) -> list[ApiObject]:
        """List GA agent update packages for an OS type, newest first."""
        body = await self._get(
            "/update/agent/packages",
            {
                "osTypes": os_type,
                "status": "ga",
                "sortBy": "version",
                "sortOrder": "desc",
                "limit": limit,
            },
        )
        data = body.get("data") or []
        return [item for item in data if isinstance(item, dict)]

    async def update_software(self, agent_id: str, package_id: str) -> int:
        """Trigger an immediate agent software update on one agent.

        Returns:
            Number of agents the console reports as affected.
        """
        body = await self._post(
            "/agents/actions/update-software",
            {
                "filter": {"ids": [agent_id]},
                "data": {"packageId": package_id, "isScheduled": False},
            },
        )
        data = body.get("data") or {}
        affected = data.get("affected", 0) if isinstance(data, dict) else 0
        return int(affected)

    async def list_activities(self, agent_id: str, limit: int = 50) -> list[ApiObject]:
        """List the most recent console activities for one agent."""
        body = await self._get(
            "/activities",
            {
                "agentIds": agent_id,
                "sortBy": "createdAt",
                "sortOrder": "desc",
                "limit": limit,
            },
        )
        data = body.get("data") or []
        return [item for item in data if isinstance(item, dict)]
