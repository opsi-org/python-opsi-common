# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
OPSI Exceptions.
"""

__all__ = (
	"BackendAuthenticationError",
	"BackendBadValueError",
	"BackendConfigurationError",
	"BackendError",
	"BackendIOError",
	"BackendMissingDataError",
	"BackendModuleDisabledError",
	"BackendPermissionDeniedError",
	"BackendReferentialIntegrityError",
	"BackendTemporaryError",
	"BackendUnableToConnectError",
	"BackendUnaccomplishableError",
	"CanceledException",
	"LicenseConfigurationError",
	"LicenseMissingError",
	"OpsiServiceAuthenticationError",
	"OpsiBackupBackendNotFound",
	"OpsiBackupFileError",
	"OpsiBackupFileNotFound",
	"OpsiBadRpcError",
	"OpsiServiceConnectionError",
	"OpsiError",
	"OpsiProductOrderingError",
	"OpsiRpcError",
	"OpsiServiceVerificationError",
	"OpsiServiceTimeoutError",
	"RepositoryError",
)


from typing import Any


class OpsiError(Exception):
	"""Base class for OPSI Backend exceptions."""

	ExceptionShortDescription = "Opsi error"

	def __init__(self, message: str = "") -> None:
		super().__init__(message)
		self.message = str(message)

	def __str__(self) -> str:
		if self.message:
			return f"{self.ExceptionShortDescription}: {self.message}"
		return self.ExceptionShortDescription

	def __repr__(self) -> str:
		if self.message:
			return f'<{self.__class__.__name__}("{self.message}")>'
		return f"<{self.__class__.__name__}>"


class OpsiBackupFileError(OpsiError):
	ExceptionShortDescription = "Opsi backup file error"


class OpsiBackupFileNotFound(OpsiBackupFileError):
	ExceptionShortDescription = "Opsi backup file not found"


class OpsiBackupBackendNotFound(OpsiBackupFileError):
	ExceptionShortDescription = "Opsi backend not found in backup"


class OpsiServiceError(OpsiError):
	ExceptionShortDescription = "Opsi service error"

	def __init__(self, message: str = "", status_code: int | None = None, content: str | None = None) -> None:
		super().__init__(message)
		self.status_code = status_code
		self.content = content


class OpsiServiceAuthenticationError(OpsiServiceError):
	ExceptionShortDescription = "Opsi service authentication error"


BackendAuthenticationError = OpsiServiceAuthenticationError


class OpsiServicePermissionError(OpsiServiceError):
	ExceptionShortDescription = "Opsi service permission error"


BackendPermissionDeniedError = OpsiServicePermissionError


class OpsiServiceConnectionError(OpsiServiceError):
	ExceptionShortDescription = "Opsi service connection error"


class OpsiServiceVerificationError(OpsiServiceConnectionError):
	ExceptionShortDescription = "Opsi service verification error"


class OpsiServiceTimeoutError(OpsiServiceConnectionError):
	ExceptionShortDescription = "Opsi service timeout error"


class OpsiBadRpcError(OpsiError):
	ExceptionShortDescription = "Opsi bad rpc error"


class OpsiRpcError(OpsiError):
	ExceptionShortDescription = "Opsi rpc error"

	def __init__(self, message: str = "", response: dict[str, Any] | None = None) -> None:
		super().__init__(message)
		self.response = response


class OpsiProductOrderingError(OpsiError):
	ExceptionShortDescription = "A condition for ordering cannot be fulfilled"

	def __init__(self, message: str = "", problematicRequirements: list[int] | list[str] | None = None) -> None:
		super().__init__(message)
		self.problematicRequirements: list[int] | list[str] | list = problematicRequirements or []  # pylint: disable=invalid-name

	def __str__(self) -> str:
		if self.message:
			if self.problematicRequirements:
				return f"{self.ExceptionShortDescription}: {self.message} ({self.problematicRequirements})"
			return f"{self.ExceptionShortDescription}: {self.message}"
		return self.ExceptionShortDescription

	def __repr__(self) -> str:
		if self.message:
			if self.problematicRequirements:
				return f'<{self.__class__.__name__}("{self.message}", {self.problematicRequirements})>'
			return f'<{self.__class__.__name__}("{self.message}")>'
		return f"<{self.__class__.__name__}>"


class BackendError(OpsiError):
	"""Exception raised if there is an error in the backend."""

	ExceptionShortDescription = "Backend error"


class BackendIOError(OpsiError):
	"""Exception raised if there is a read or write error in the backend."""

	ExceptionShortDescription = "Backend I/O error"


class BackendUnableToConnectError(BackendIOError):
	"""Exception raised if no connection can be established in the backend."""

	ExceptionShortDescription = "Backend I/O error"


class BackendConfigurationError(OpsiError):
	"""Exception raised if a configuration error occurs in the backend."""

	ExceptionShortDescription = "Backend configuration error"


class BackendReferentialIntegrityError(OpsiError):
	"""
	Exception raised if there is a referential integration
	error occurs in the backend.
	"""

	ExceptionShortDescription = "Backend referential integrity error"


class BackendBadValueError(OpsiError):
	"""Exception raised if an invalid value is found."""

	ExceptionShortDescription = "Backend bad value error"


class BackendMissingDataError(OpsiError):
	"""Exception raised if expected data not found."""

	ExceptionShortDescription = "Backend missing data error"


class BackendTemporaryError(OpsiError):
	"""Exception raised if a temporary error occurs."""

	ExceptionShortDescription = "Backend temporary error"


class BackendUnaccomplishableError(OpsiError):
	"""Exception raised if an unaccomplishable situation appears."""

	ExceptionShortDescription = "Backend unaccomplishable error"


class BackendModuleDisabledError(OpsiError):
	"""Exception raised if a needed module is disabled."""

	ExceptionShortDescription = "Backend module disabled error"


class LicenseConfigurationError(OpsiError):
	"""Exception raised if a configuration error occurs in the license data base."""

	ExceptionShortDescription = "License configuration error"


class LicenseMissingError(OpsiError):
	"""Exception raised if a license is requested but cannot be found."""

	ExceptionShortDescription = "License missing error"


class RepositoryError(OpsiError):
	ExceptionShortDescription = "Repository error"


class CanceledException(Exception):
	ExceptionShortDescription = "CanceledException"
