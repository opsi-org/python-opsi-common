# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
Testing behaviour of exceptions.
"""

import time
from typing import Generator, Type

import pytest
from hypothesis import given, strategies


class FixtureRequest:
	param: str


exception_classes = []
pre_globals = list(globals())
from opsicommon.exceptions import (  # noqa: E402,F401
	BackendAuthenticationError,
	BackendBadValueError,
	BackendConfigurationError,
	BackendError,
	BackendIOError,
	BackendMissingDataError,
	BackendModuleDisabledError,
	BackendPermissionDeniedError,
	BackendReferentialIntegrityError,
	BackendTemporaryError,
	BackendUnableToConnectError,
	BackendUnaccomplishableError,
	LicenseConfigurationError,
	LicenseMissingError,
	OpsiBackupBackendNotFound,
	OpsiBackupFileError,
	OpsiBackupFileNotFound,
	OpsiBadRpcError,
	OpsiError,
	OpsiProductOrderingError,
	OpsiRpcError,
	OpsiServiceAuthenticationError,
	OpsiServiceConnectionError,
	OpsiServiceTimeoutError,
	OpsiServiceVerificationError,
	RepositoryError,
)

exception_classes = [obj for name, obj in dict(globals()).items() if name not in pre_globals and name != "pre_globals"]


@pytest.fixture(
	params=exception_classes,
)
def exception_class(request: FixtureRequest) -> Generator[str, None, None]:
	yield request.param


@pytest.fixture(
	params=[
		"",
		1,
		True,
		time.localtime(),
		"unicode string",
		"utf-8 string: äöüß€".encode(),
		"windows-1258 string: äöüß€".encode("windows-1258"),
		"utf-16 string: äöüß€".encode("utf-16"),
		"latin1 string: äöüß".encode("latin-1"),
	],
	ids=["empty", "int", "bool", "time", "unicode", "utf8-encoded", "windows-1258-encoded", "utf16-encoded", "latin1-encoded"],
)
def exception_parameter(request: FixtureRequest) -> Generator[str, None, None]:
	yield request.param


@pytest.fixture
def exception(exception_class: Type[Exception], exception_parameter: str) -> Generator[Exception, None, None]:
	yield exception_class(exception_parameter)


def test_exception_can_be_printed(exception: Exception) -> None:
	print(exception)


def test_exception_has__repr__(exception: Exception) -> None:
	_repr = repr(exception)
	assert _repr.startswith("<")
	assert exception.__class__.__name__ in _repr
	assert _repr.endswith(">")


@pytest.mark.parametrize(
	"message,problematic_requirements",
	(
		("ordering error", None),
		("ordering error", []),
		("ordering error", ["requirement1", "requirement2"]),
		("", None),
		("", ["requirement1", "requirement2"]),
	),
)
def test_opsi_product_ordering_exception(message: str, problematic_requirements: list[str] | None) -> None:
	exc = OpsiProductOrderingError(message, problematic_requirements)  # type: ignore[arg-type]
	_repr = repr(exc)
	assert _repr.startswith("<")
	assert _repr.endswith(">")
	if message:
		assert ":" in str(exc)


def test_opsi_product_ordering_error_ordering_is_accessible() -> None:
	error = OpsiProductOrderingError("message", [3, 4, 5])
	assert [3, 4, 5] == error.problematicRequirements


def test_exception_is_sub_class_of_opsi_error(exception_class: Type[Exception]) -> None:
	with pytest.raises(OpsiError):
		raise exception_class("message")


@given(strategies.text())
def test_exception_constuctor_hypothesis(message: str) -> None:
	for cls in exception_classes:
		cls(message)
