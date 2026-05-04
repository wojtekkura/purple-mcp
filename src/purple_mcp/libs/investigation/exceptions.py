"""Exceptions for the investigation library."""


class InvestigationError(Exception):
    """Base exception for investigation orchestration errors."""

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


class PrimaryAlertNotFoundError(InvestigationError):
    """Raised when the primary alert (incident) cannot be located.

    Without the primary alert we cannot derive the asset_id or storyline_id
    needed to fan out the rest of the investigation, so this is fatal.
    """
