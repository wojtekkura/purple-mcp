"""Exceptions for SentinelOne agent management operations."""


class AgentsError(Exception):
    """Base exception for all agent management errors."""

    def __init__(self, message: str, details: str | None = None) -> None:
        """Initialize the exception.

        Args:
            message: The main error message.
            details: Optional additional details about the error.
        """
        self.message = message
        self.details = details
        super().__init__(message)

    def __str__(self) -> str:
        """Return a string representation of the error."""
        if self.details:
            return f"{self.message}. Details: {self.details}"
        return self.message


class AgentsClientError(AgentsError):
    """HTTP/network-related errors when communicating with the management API."""

    def __init__(
        self, message: str, status_code: int | None = None, details: str | None = None
    ) -> None:
        """Initialize the client error.

        Args:
            message: The main error message.
            status_code: HTTP status code if applicable.
            details: Optional additional details about the error.
        """
        self.status_code = status_code
        super().__init__(message, details)

    def __str__(self) -> str:
        """Return a string representation of the error."""
        base_message = self.message
        if self.status_code:
            base_message = f"{base_message} (HTTP {self.status_code})"
        if self.details:
            base_message = f"{base_message}. Details: {self.details}"
        return base_message


class AgentsAuthenticationError(AgentsClientError):
    """Exception raised when authentication or authorization fails."""

    pass


class AgentsAPIError(AgentsClientError):
    """Exception raised when the API returns an error."""

    pass


class AgentsNetworkError(AgentsClientError):
    """Exception raised when network/connection errors occur."""

    pass


class AgentsTransientError(AgentsClientError):
    """Exception raised for transient server errors (502/503/504) that should be retried."""

    pass
