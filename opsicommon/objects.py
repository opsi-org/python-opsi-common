# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
General classes used in the library.

As an example this contains classes for hosts, products, configurations.
"""

# pylint: disable=too-many-lines

from __future__ import annotations

from datetime import date, datetime
from functools import lru_cache
from inspect import getfullargspec
from types import GeneratorType
from typing import Any, Callable, Generator, Self, Type, TypeVar

import msgspec

from opsicommon.exceptions import BackendBadValueError, BackendConfigurationError
from opsicommon.logging import get_logger
from opsicommon.types import (
	forceActionProgress,
	forceActionRequest,
	forceActionResult,
	forceArchitecture,
	forceAuditState,
	forceBool,
	forceBoolList,
	forceConfigId,
	forceFilename,
	forceFloat,
	forceGroupId,
	forceGroupType,
	forceHardwareAddress,
	forceHardwareDeviceId,
	forceHardwareVendorId,
	forceHostId,
	forceInstallationStatus,
	forceInt,
	forceIPAddress,
	forceLanguageCode,
	forceLicenseContractId,
	forceLicensePoolId,
	forceList,
	forceNetworkAddress,
	forceObjectId,
	forceOpsiHostKey,
	forceOpsiTimestamp,
	forcePackageVersion,
	forceProductId,
	forceProductIdList,
	forceProductPriority,
	forceProductPropertyId,
	forceProductTargetConfiguration,
	forceProductType,
	forceProductVersion,
	forceRequirementType,
	forceSoftwareLicenseId,
	forceString,
	forceStringList,
	forceStringLower,
	forceUnsignedInt,
	forceUrl,
	forceUserId,
	forceUUIDString,
)
from opsicommon.utils import combine_versions, generate_opsi_host_key, timestamp

__all__ = (
	"AuditHardware",
	"AuditHardwareOnHost",
	"AuditSoftware",
	"AuditSoftwareOnClient",
	"AuditSoftwareToLicensePool",
	"BaseObject",
	"BoolConfig",
	"BoolProductProperty",
	"ConcurrentSoftwareLicense",
	"Config",
	"ConfigState",
	"Entity",
	"Group",
	"Host",
	"HostGroup",
	"LicenseContract",
	"LicenseOnClient",
	"LicensePool",
	"LocalbootProduct",
	"NetbootProduct",
	"OEMSoftwareLicense",
	"Object",
	"ObjectToGroup",
	"OpsiClient",
	"OpsiConfigserver",
	"OpsiDepotserver",
	"Product",
	"ProductDependency",
	"ProductGroup",
	"ProductOnClient",
	"ProductOnDepot",
	"ProductProperty",
	"ProductPropertyState",
	"Relationship",
	"RetailSoftwareLicense",
	"SoftwareLicense",
	"SoftwareLicenseToLicensePool",
	"UnicodeConfig",
	"UnicodeProductProperty",
	"VolumeSoftwareLicense",
	"decode_ident",
	"get_backend_method_prefix",
	"get_foreign_id_attributes",
	"get_ident_attributes",
	"get_possible_class_attributes",
	"mandatory_constructor_args",
	"objects_differ",
	"OBJECT_CLASSES",
)


logger = get_logger("opsicommon.general")


BaseObjectT = TypeVar("BaseObjectT", bound="BaseObject")


class classproperty:
	def __init__(self, fget: Callable) -> None:
		self.fget = fget

	def __get__(self, owner_self: Any, owner_cls: Any) -> Any:
		return self.fget(owner_cls)


class BaseObject:
	copy_from_hash = False
	sub_classes: dict[str, type] = {}
	ident_separator = ";"
	foreign_id_attributes: list[str] = []
	backend_method_prefix = ""
	_is_generated_default = False

	@classproperty
	def subClasses(cls) -> dict[str, type]:
		return cls.sub_classes

	@classproperty
	def identSeparator(cls) -> str:
		return cls.ident_separator

	@classproperty
	def foreignIdAttributes(cls) -> list[str]:
		return cls.foreign_id_attributes

	@classproperty
	def backendMethodPrefix(cls) -> str:
		return cls.backend_method_prefix

	def clone(self, identOnly: bool = False) -> Self:
		raise NotImplementedError("Method clone not implemented")

	def getBackendMethodPrefix(self) -> str:
		return self.backend_method_prefix

	def getForeignIdAttributes(self) -> list[str]:
		return self.foreign_id_attributes

	def getIdentAttributes(self) -> tuple[str, ...]:
		return get_ident_attributes(self.__class__)  # type: ignore[arg-type]

	def getIdent(self, returnType: str = "unicode") -> list[str] | tuple[str, ...] | dict[str, str] | str:
		returnType = forceStringLower(returnType)
		ident_attributes = self.getIdentAttributes()

		def get_ident_value(attribute: str) -> str:
			try:
				value = getattr(self, attribute)
				if value is None:
					value = ""

				return value
			except AttributeError:
				return ""

		ident_values = [forceString(get_ident_value(attribute)) for attribute in ident_attributes]

		if returnType == "list":
			return ident_values
		if returnType == "tuple":
			return tuple(ident_values)
		if returnType in ("dict", "hash"):
			return dict(zip(ident_attributes, ident_values))
		return self.ident_separator.join(ident_values)

	def setDefaults(self) -> None:
		pass

	def emptyValues(self, keepAttributes: list[str] | None = None) -> None:
		keep_attributes = set(forceStringList(keepAttributes or []))
		for attribute in self.getIdentAttributes():
			keep_attributes.add(attribute)
		keep_attributes.add("type")

		for attribute in self.__dict__:
			if attribute not in keep_attributes:
				self.__dict__[attribute] = None

	def update(self, updateObject: "BaseObject", updateWithNoneValues: bool = True) -> None:
		if not issubclass(updateObject.__class__, self.__class__):
			raise TypeError(f"Cannot update instance of {self.__class__.__name__} with instance of {updateObject.__class__.__name__}")
		object_hash = updateObject.toHash()

		try:
			del object_hash["type"]
		except KeyError:
			# No key "type", everything fine.
			pass

		if not updateWithNoneValues:
			to_delete = set(key for (key, value) in object_hash.items() if value is None)

			for key in to_delete:
				del object_hash[key]

		self.__dict__.update(object_hash)

	def getType(self) -> str:
		return self.__class__.__name__

	def setGeneratedDefault(self, flag: bool = True) -> None:
		self._is_generated_default = forceBool(flag)

	def isGeneratedDefault(self) -> bool:
		return self._is_generated_default

	@classmethod
	def fromHash(cls: Type[BaseObjectT], _hash: dict[str, Any]) -> BaseObjectT:
		if cls.copy_from_hash:
			_hash = _hash.copy()
		_cls = cls
		try:
			_cls = get_object_type(_hash.pop("type"))  # type: ignore
		except KeyError:
			pass

		possible_attributes = get_possible_class_attributes(_cls)  # type: ignore
		decode_ident(_cls, _hash)
		kwargs = {attr: val for attr, val in _hash.items() if attr in possible_attributes}
		return _cls(**kwargs)

	@classmethod
	def from_json(cls, jsonString: str) -> Any:
		return from_json(jsonString, cls.__name__)

	def to_hash(self) -> dict[str, Any]:
		object_hash = dict(self.__dict__)
		object_hash["type"] = self.getType()
		return object_hash

	toHash = to_hash

	def to_json(self) -> str:
		return to_json(self, deep=False)

	toJson = to_json

	def serialize(self) -> dict[str, Any]:
		_hash = {}
		for key, val in self.toHash().items():
			if isinstance(val, (datetime, date)):
				val = val.isoformat()
			_hash[key] = val
		_hash["ident"] = self.getIdent()
		return _hash

	def __eq__(self, other: object) -> bool:
		if not isinstance(other, self.__class__):
			return False
		if self.isGeneratedDefault() or other.isGeneratedDefault():
			return False
		return self.getIdent() == other.getIdent()

	def __hash__(self) -> int:
		def get_ident_value(attribute: str) -> str:
			try:
				value = getattr(self, attribute)
				if value is None:
					value = ""
				return value
			except AttributeError:
				return ""

		ident_values = tuple(get_ident_value(attribute) for attribute in self.getIdentAttributes())
		return hash(ident_values)

	def __ne__(self, other: object) -> bool:
		return not self.__eq__(other)

	def __str__(self) -> str:
		additional_attributes = []
		for attr in self.getIdentAttributes():
			try:
				value = getattr(self, attr)
				additional_attributes.append(f"{attr}='{value}'")
			except AttributeError:
				pass

		return f"<{self.getType()}({', '.join(additional_attributes)})>"

	def __repr__(self) -> str:
		return self.__str__()


@lru_cache()
def mandatory_constructor_args(_class: Type[BaseObject]) -> list[str]:
	cache_key = _class.__name__  # type: ignore[attr-defined]
	spec = getfullargspec(_class.__init__)  # type: ignore[misc]
	args = spec.args
	defaults = spec.defaults
	mandatory = None
	if defaults is None:
		mandatory = args[1:]
	else:
		last = len(defaults) * -1
		mandatory = args[1:][:last]
	logger.trace("mandatory_constructor_args for %s: %s", cache_key, mandatory)
	return mandatory


@lru_cache()
def get_ident_attributes(_class: Type[BaseObject]) -> tuple[str, ...]:
	ident_attributes = tuple(mandatory_constructor_args(_class))  # type: ignore[arg-type]
	if "hardwareClass" in ident_attributes:
		ident_attributes = tuple([a for a in ident_attributes if a != "hardwareClass"])
	return ident_attributes


@lru_cache()
def get_foreign_id_attributes(_class: Type[BaseObject]) -> Any:
	return _class.foreign_id_attributes


@lru_cache()
def get_possible_class_attributes(_class: Type[BaseObject]) -> set[str]:
	"""
	Returns the possible attributes of a class.
	"""
	attributes = getfullargspec(_class.__init__).args  # type: ignore[misc]
	for sub_class in _class.sub_classes.values():
		attributes.extend(getfullargspec(sub_class.__init__).args)  # type: ignore[misc]

	attributes_set = set(attributes)
	attributes_set.add("type")

	try:
		attributes_set.remove("self")
	except KeyError:
		pass

	return attributes_set


@lru_cache()
def get_backend_method_prefix(_class: Type[BaseObject]) -> Any:
	return _class.backend_method_prefix


def decode_ident(_class: Type[BaseObject], _hash: dict[str, Any]) -> dict[str, Any]:
	if "ident" not in _hash:
		return _hash

	ident = _hash.pop("ident")
	if not isinstance(ident, dict):
		ident_keys = mandatory_constructor_args(_class)  # type: ignore[arg-type]
		ident_values = []
		if isinstance(ident, str):
			ident_values = ident.split(_class.ident_separator)
		elif isinstance(ident, (tuple, list)):
			ident_values = ident  # type: ignore[assignment]

		if len(ident_values) != len(ident_keys):
			raise ValueError(f"Ident {ident} does not match class '{_class}' constructor arguments {ident_keys}")
		ident = dict(zip(ident_keys, ident_values))

	_hash.update(ident)
	return _hash


def objects_differ(obj1: Any, obj2: Any, exclude_attributes: list[str] | None = None) -> bool:
	if exclude_attributes is None:
		exclude_attributes = []
	else:
		exclude_attributes = forceStringList(exclude_attributes)

	if obj1 != obj2:
		return True

	obj2 = obj2.toHash()
	for attribute, value1 in obj1.toHash().items():
		if attribute in exclude_attributes:
			continue

		value2 = obj2.get(attribute)

		if type(value1) is not type(value2):
			return True

		if isinstance(value1, dict):
			if len(value1) != len(value2):
				return True

			for key, value in value1.items():
				if value2.get(key) != value:
					return True
		elif isinstance(value1, list):
			if len(value1) != len(value2):
				return True

			for value in value1:
				if value not in value2:
					return True
		else:
			if value1 != value2:
				return True
	return False


class Entity(BaseObject):
	sub_classes: dict[str, type] = {}

	def setDefaults(self) -> None:
		BaseObject.setDefaults(self)

	def clone(self, identOnly: bool = False) -> Self:
		_hash = {}

		if identOnly:
			ident_attributes = self.getIdentAttributes()
			for attribute, value in self.toHash().items():
				if attribute != "type" and attribute not in ident_attributes:
					continue
				_hash[attribute] = value
		else:
			_hash = self.toHash()

		return self.fromHash(_hash)


BaseObject.sub_classes["Entity"] = Entity


class Relationship(BaseObject):
	sub_classes: dict[str, type] = {}

	def setDefaults(self) -> None:
		BaseObject.setDefaults(self)

	def clone(self, identOnly: bool = False) -> Self:
		_hash = {}
		if identOnly:
			ident_attributes = self.getIdentAttributes()
			for attribute, value in self.toHash().items():
				if attribute != "type" and attribute not in ident_attributes:
					continue
				_hash[attribute] = value
		else:
			_hash = self.toHash()
		return self.fromHash(_hash)

	def serialize(self) -> dict[str, Any]:
		_hash = super().serialize()
		_hash["type"] = self.getType()
		return _hash


BaseObject.sub_classes["Relationship"] = Relationship


class Object(Entity):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Entity.foreign_id_attributes + ["objectId"]

	def __init__(self, id: str, description: str | None = None, notes: str | None = None) -> None:
		self.description: str | None = None
		self.notes: str | None = None
		self.setId(id)
		if description is not None:
			self.setDescription(description)
		if notes is not None:
			self.setNotes(notes)

	def setDefaults(self) -> None:
		Entity.setDefaults(self)
		if self.description is None:
			self.setDescription("")
		if self.notes is None:
			self.setNotes("")

	def getId(self) -> str:
		return self.id

	def setId(self, id: str) -> None:
		self.id = forceObjectId(id)

	def getDescription(self) -> str | None:
		return self.description

	def setDescription(self, description: str) -> None:
		self.description = forceString(description)

	def getNotes(self) -> str | None:
		return self.notes

	def setNotes(self, notes: str) -> None:
		self.notes = forceString(notes)


Entity.sub_classes["Object"] = Object


class User(Entity):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Entity.foreign_id_attributes + ["userId"]
	backend_method_prefix = "user"

	def __init__(
		self,
		id: str,
		created: str | None = None,
		lastLogin: str | None = None,
		mfaState: str | None = None,
		otpSecret: str | None = None,
	) -> None:
		self.created: str | None = None
		self.lastLogin: str | None = None
		self.mfaState: str | None = None
		self.otpSecret: str | None = None

		self.setId(id)
		if created is not None:
			self.setCreated(created)
		if lastLogin is not None:
			self.setLastLogin(lastLogin)
		if mfaState is not None:
			self.setMfaState(mfaState)
		if otpSecret is not None:
			self.setOtpSecret(otpSecret)

	def setDefaults(self) -> None:
		Entity.setDefaults(self)
		if self.created is None:
			self.setCreated(timestamp())
		if self.mfaState is None:
			self.mfaState = "inactive"

	def getId(self) -> str:
		return self.id

	def setId(self, id: str) -> None:
		self.id = forceUserId(id)

	def getLastLogin(self) -> str | None:
		return self.lastLogin

	def setLastLogin(self, lastLogin: str) -> None:
		self.lastLogin = forceOpsiTimestamp(lastLogin)

	def getCreated(self) -> str | None:
		return self.created

	def setCreated(self, created: str) -> None:
		self.created = forceOpsiTimestamp(created)

	def getMfaState(self) -> str | None:
		return self.mfaState

	def setMfaState(self, mfaState: str) -> None:
		self.mfaState = mfaState

	def getOtpSecret(self) -> str | None:
		return self.otpSecret

	def setOtpSecret(self, otpSecret: str) -> None:
		self.otpSecret = otpSecret


Entity.sub_classes["User"] = User


class Host(Object):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Object.foreign_id_attributes + ["hostId"]
	backend_method_prefix = "host"

	def __init__(
		self,
		id: str,
		description: str | None = None,
		notes: str | None = None,
		hardwareAddress: str | None = None,
		ipAddress: str | None = None,
		inventoryNumber: str | None = None,
		systemUUID: str | None = None,
	) -> None:
		Object.__init__(self, id, description, notes)
		self.hardwareAddress: str | None = None
		self.ipAddress: str | None = None
		self.inventoryNumber: str | None = None
		self.systemUUID: str | None = None
		self.setId(id)

		if hardwareAddress is not None:
			self.setHardwareAddress(hardwareAddress)
		if ipAddress is not None:
			self.setIpAddress(ipAddress)
		if inventoryNumber is not None:
			self.setInventoryNumber(inventoryNumber)
		if systemUUID is not None:
			self.setSystemUUID(systemUUID)

	def setDefaults(self) -> None:
		Object.setDefaults(self)
		if self.inventoryNumber is None:
			self.setInventoryNumber("")

	def setId(self, id: str) -> None:
		self.id = forceHostId(id)

	def getHardwareAddress(self) -> str | None:
		return self.hardwareAddress

	def setHardwareAddress(self, hardwareAddress: str) -> None:
		self.hardwareAddress = forceHardwareAddress(forceList(hardwareAddress)[0])

	def getIpAddress(self) -> str | None:
		return self.ipAddress

	def setIpAddress(self, ipAddress: str) -> None:
		try:
			self.ipAddress = forceIPAddress(ipAddress)
		except ValueError as err:
			logger.error("Failed to set ip address '%s' for host %s: %s", ipAddress, self.id, err)
			if ipAddress == "":
				self.ipAddress = ""
			else:
				self.ipAddress = None

	def getInventoryNumber(self) -> str | None:
		return self.inventoryNumber

	def setInventoryNumber(self, inventoryNumber: str) -> None:
		self.inventoryNumber = forceString(inventoryNumber)

	def getSystemUUID(self) -> str | None:
		return self.systemUUID

	def setSystemUUID(self, systemUUID: str) -> None:
		self.systemUUID = forceUUIDString(systemUUID) if systemUUID else ""


Object.sub_classes["Host"] = Host


class OpsiClient(Host):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Host.foreign_id_attributes + ["clientId"]

	def __init__(
		self,
		id: str,
		opsiHostKey: str | None = None,
		description: str | None = None,
		notes: str | None = None,
		hardwareAddress: str | None = None,
		ipAddress: str | None = None,
		inventoryNumber: str | None = None,
		oneTimePassword: str | None = None,
		created: str | None = None,
		lastSeen: str | None = None,
		systemUUID: str | None = None,
	) -> None:
		Host.__init__(self, id, description, notes, hardwareAddress, ipAddress, inventoryNumber, systemUUID)
		self.opsiHostKey: str | None = None
		self.created: str | None = None
		self.lastSeen: str | None = None
		self.oneTimePassword: str | None = None

		if opsiHostKey is not None:
			self.setOpsiHostKey(opsiHostKey)
		if created is not None:
			self.setCreated(created)
		if lastSeen is not None:
			self.setLastSeen(lastSeen)
		if oneTimePassword is not None:
			self.setOneTimePassword(oneTimePassword)

	def setDefaults(self) -> None:
		Host.setDefaults(self)
		if self.opsiHostKey is None:
			self.setOpsiHostKey(generate_opsi_host_key())
		if self.created is None:
			self.setCreated(timestamp())
		if self.lastSeen is None:
			self.setLastSeen(timestamp())

	def getLastSeen(self) -> str | None:
		return self.lastSeen

	def setLastSeen(self, lastSeen: str) -> None:
		self.lastSeen = forceOpsiTimestamp(lastSeen)

	def getCreated(self) -> str | None:
		return self.created

	def setCreated(self, created: str) -> None:
		self.created = forceOpsiTimestamp(created)

	def getOpsiHostKey(self) -> str | None:
		return self.opsiHostKey

	def setOpsiHostKey(self, opsiHostKey: str) -> None:
		self.opsiHostKey = forceOpsiHostKey(opsiHostKey)

	def getOneTimePassword(self) -> str | None:
		return self.oneTimePassword

	def setOneTimePassword(self, oneTimePassword: str) -> None:
		self.oneTimePassword = forceString(oneTimePassword)


Host.sub_classes["OpsiClient"] = OpsiClient


class OpsiDepotserver(Host):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Host.foreign_id_attributes + ["depotId"]

	def __init__(
		self,
		id: str,
		opsiHostKey: str | None = None,
		depotLocalUrl: str | None = None,
		depotRemoteUrl: str | None = None,
		depotWebdavUrl: str | None = None,
		repositoryLocalUrl: str | None = None,
		repositoryRemoteUrl: str | None = None,
		description: str | None = None,
		notes: str | None = None,
		hardwareAddress: str | None = None,
		ipAddress: str | None = None,
		inventoryNumber: str | None = None,
		networkAddress: str | None = None,
		maxBandwidth: int | None = None,
		isMasterDepot: bool | None = None,
		masterDepotId: str | None = None,
		workbenchLocalUrl: str | None = None,
		workbenchRemoteUrl: str | None = None,
		systemUUID: str | None = None,
	) -> None:
		Host.__init__(self, id, description, notes, hardwareAddress, ipAddress, inventoryNumber, systemUUID)

		self.opsiHostKey: str | None = None
		self.depotLocalUrl: str | None = None
		self.depotRemoteUrl: str | None = None
		self.depotWebdavUrl: str | None = None
		self.repositoryLocalUrl: str | None = None
		self.repositoryRemoteUrl: str | None = None
		self.networkAddress: str | None = None
		self.maxBandwidth: int | None = None
		self.isMasterDepot: bool | None = None
		self.masterDepotId: str | None = None
		self.workbenchLocalUrl: str | None = None
		self.workbenchRemoteUrl: str | None = None

		if opsiHostKey is not None:
			self.setOpsiHostKey(opsiHostKey)
		if depotLocalUrl is not None:
			self.setDepotLocalUrl(depotLocalUrl)
		if depotRemoteUrl is not None:
			self.setDepotRemoteUrl(depotRemoteUrl)
		if depotWebdavUrl is not None:
			self.setDepotWebdavUrl(depotWebdavUrl)
		if repositoryLocalUrl is not None:
			self.setRepositoryLocalUrl(repositoryLocalUrl)
		if repositoryRemoteUrl is not None:
			self.setRepositoryRemoteUrl(repositoryRemoteUrl)
		if networkAddress is not None:
			self.setNetworkAddress(networkAddress)
		if maxBandwidth is not None:
			self.setMaxBandwidth(maxBandwidth)
		if isMasterDepot is not None:
			self.setIsMasterDepot(isMasterDepot)
		if masterDepotId is not None:
			self.setMasterDepotId(masterDepotId)
		if workbenchLocalUrl is not None:
			self.setWorkbenchLocalUrl(workbenchLocalUrl)
		if workbenchRemoteUrl is not None:
			self.setWorkbenchRemoteUrl(workbenchRemoteUrl)

	def setDefaults(self) -> None:
		Host.setDefaults(self)
		if self.opsiHostKey is None:
			self.setOpsiHostKey(generate_opsi_host_key())
		if self.isMasterDepot is None:
			self.setIsMasterDepot(True)

	def getOpsiHostKey(self) -> str | None:
		return self.opsiHostKey

	def setOpsiHostKey(self, opsiHostKey: str) -> None:
		self.opsiHostKey = forceOpsiHostKey(opsiHostKey)

	def getDepotLocalUrl(self) -> str | None:
		return self.depotLocalUrl

	def setDepotLocalUrl(self, depotLocalUrl: str) -> None:
		self.depotLocalUrl = forceUrl(depotLocalUrl)

	def getDepotRemoteUrl(self) -> str | None:
		return self.depotRemoteUrl

	def setDepotWebdavUrl(self, depotWebdavUrl: str) -> None:
		self.depotWebdavUrl = forceUrl(depotWebdavUrl)

	def getDepotWebdavUrl(self) -> str | None:
		return self.depotWebdavUrl

	def setDepotRemoteUrl(self, depotRemoteUrl: str) -> None:
		self.depotRemoteUrl = forceUrl(depotRemoteUrl)

	def getRepositoryLocalUrl(self) -> str | None:
		return self.repositoryLocalUrl

	def setRepositoryLocalUrl(self, repositoryLocalUrl: str) -> None:
		self.repositoryLocalUrl = forceUrl(repositoryLocalUrl)

	def getRepositoryRemoteUrl(self) -> str | None:
		return self.repositoryRemoteUrl

	def setRepositoryRemoteUrl(self, repositoryRemoteUrl: str) -> None:
		self.repositoryRemoteUrl = forceUrl(repositoryRemoteUrl)

	def getNetworkAddress(self) -> str | None:
		return self.networkAddress

	def setNetworkAddress(self, networkAddress: str) -> None:
		try:
			self.networkAddress = forceNetworkAddress(networkAddress)
		except ValueError as err:
			logger.error("Failed to set network address '%s' for depot %s: %s", networkAddress, self.id, err)
			self.networkAddress = None

	def getMaxBandwidth(self) -> int | None:
		return self.maxBandwidth

	def setMaxBandwidth(self, maxBandwidth: int) -> None:
		self.maxBandwidth = forceInt(maxBandwidth)

	def setIsMasterDepot(self, isMasterDepot: bool) -> None:
		self.isMasterDepot = forceBool(isMasterDepot)

	def getIsMasterDepot(self) -> bool | None:
		return self.isMasterDepot

	def setMasterDepotId(self, masterDepotId: str) -> None:
		self.masterDepotId = forceHostId(masterDepotId)

	def getMasterDepotId(self) -> str | None:
		return self.masterDepotId

	def setWorkbenchLocalUrl(self, value: str) -> None:
		self.workbenchLocalUrl = forceUrl(value)

	def getWorkbenchLocalUrl(self) -> str | None:
		return self.workbenchLocalUrl

	def setWorkbenchRemoteUrl(self, value: str) -> None:
		self.workbenchRemoteUrl = forceUrl(value)

	def getWorkbenchRemoteUrl(self) -> str | None:
		return self.workbenchRemoteUrl

	def __str__(self) -> str:
		additional_infos = [f"id='{self.id}'"]
		if self.isMasterDepot:
			additional_infos.append(f"isMasterDepot={self.isMasterDepot}")
		if self.masterDepotId:
			additional_infos.append(f"masterDepotId='{self.masterDepotId}'")

		return f"<{self.getType()}({', '.join(additional_infos)})>"


Host.sub_classes["OpsiDepotserver"] = OpsiDepotserver


class OpsiConfigserver(OpsiDepotserver):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = OpsiDepotserver.foreign_id_attributes + ["serverId"]

	def __init__(
		self,
		id: str,
		opsiHostKey: str | None = None,
		depotLocalUrl: str | None = None,
		depotRemoteUrl: str | None = None,
		depotWebdavUrl: str | None = None,
		repositoryLocalUrl: str | None = None,
		repositoryRemoteUrl: str | None = None,
		description: str | None = None,
		notes: str | None = None,
		hardwareAddress: str | None = None,
		ipAddress: str | None = None,
		inventoryNumber: str | None = None,
		networkAddress: str | None = None,
		maxBandwidth: int | None = None,
		isMasterDepot: bool | None = None,
		masterDepotId: str | None = None,
		workbenchLocalUrl: str | None = None,
		workbenchRemoteUrl: str | None = None,
		systemUUID: str | None = None,
	) -> None:
		OpsiDepotserver.__init__(
			self,
			id,
			opsiHostKey,
			depotLocalUrl,
			depotRemoteUrl,
			depotWebdavUrl,
			repositoryLocalUrl,
			repositoryRemoteUrl,
			description,
			notes,
			hardwareAddress,
			ipAddress,
			inventoryNumber,
			networkAddress,
			maxBandwidth,
			isMasterDepot,
			masterDepotId,
			workbenchLocalUrl,
			workbenchRemoteUrl,
			systemUUID,
		)

	def setDefaults(self) -> None:
		if self.isMasterDepot is None:
			self.setIsMasterDepot(True)
		OpsiDepotserver.setDefaults(self)


OpsiDepotserver.sub_classes["OpsiConfigserver"] = OpsiConfigserver
Host.sub_classes["OpsiConfigserver"] = OpsiConfigserver


class Config(Entity):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Entity.foreign_id_attributes + ["configId"]
	backend_method_prefix = "config"

	def __init__(
		self,
		id: str,
		description: str | None = None,
		possibleValues: list[Any] | None = None,
		defaultValues: list[Any] | None = None,
		editable: bool | None = None,
		multiValue: bool | None = None,
	) -> None:
		self.description: str | None = None
		self.possibleValues: list[Any] | None = None
		self.defaultValues: list[Any] | None = None
		self.editable: bool | None = None
		self.multiValue: bool | None = None

		self.setId(id)
		if description is not None:
			self.setDescription(description)
		if possibleValues is not None:
			self.setPossibleValues(possibleValues)
		if defaultValues is not None:
			self.setDefaultValues(defaultValues)
		if editable is not None:
			self.setEditable(editable)
		if multiValue is not None:
			self.setMultiValue(multiValue)

	def setDefaults(self) -> None:
		Entity.setDefaults(self)
		if self.editable is None:
			self.editable = True
		if self.multiValue is None:
			self.multiValue = False
		if self.possibleValues is None:
			self.possibleValues = []
		if self.defaultValues is None:
			self.defaultValues = []

	def getId(self) -> str:
		return self.id

	def setId(self, id: str) -> None:
		self.id = forceConfigId(id)

	def getDescription(self) -> str | None:
		return self.description

	def setDescription(self, description: str) -> None:
		self.description = forceString(description)

	def _updateValues(self) -> None:
		if self.possibleValues is None:
			self.possibleValues = []

		if self.possibleValues and self.defaultValues:
			for default_value in self.defaultValues:
				if default_value not in self.possibleValues:
					self.defaultValues.remove(default_value)
		elif not self.possibleValues and self.defaultValues:
			self.possibleValues = self.defaultValues

		if self.defaultValues and len(self.defaultValues) > 1:
			self.multiValue = True

		if self.possibleValues is not None:
			self.possibleValues.sort()

		if self.defaultValues is not None:
			self.defaultValues.sort()

	def getPossibleValues(self) -> list[Any] | None:
		return self.possibleValues

	def setPossibleValues(self, possibleValues: list[Any]) -> None:
		self.possibleValues = list(set(forceList(possibleValues)))
		self._updateValues()

	def getDefaultValues(self) -> list[Any] | None:
		return self.defaultValues

	def setDefaultValues(self, defaultValues: list[Any]) -> None:
		self.defaultValues = list(set(forceList(defaultValues)))
		self._updateValues()

	def getEditable(self) -> bool | None:
		return self.editable

	def setEditable(self, editable: bool) -> None:
		self.editable = forceBool(editable)

	def getMultiValue(self) -> bool | None:
		return self.multiValue

	def setMultiValue(self, multiValue: bool) -> None:
		self.multiValue = forceBool(multiValue)
		if self.defaultValues is not None and len(self.defaultValues) > 1:
			self.multiValue = True

	def __str__(self) -> str:
		return (
			f"<{self.getType()}(id='{self.id}', description='{self.description}', "
			f"possibleValues={self.possibleValues}, defaultValues={self.defaultValues}, "
			f"editable={self.editable}, multiValue={self.multiValue})>"
		)


Entity.sub_classes["Config"] = Config


class UnicodeConfig(Config):
	sub_classes: dict[str, type] = {}

	def __init__(
		self,
		id: str,
		description: str = "",
		possibleValues: list[Any] | None = None,
		defaultValues: list[Any] | None = None,
		editable: bool | None = None,
		multiValue: bool | None = None,
	) -> None:
		Config.__init__(self, id, description, possibleValues, defaultValues, editable, multiValue)
		if possibleValues is not None:
			self.setPossibleValues(possibleValues)
		if defaultValues is not None:
			self.setDefaultValues(defaultValues)

	def setPossibleValues(self, possibleValues: list[Any]) -> None:
		Config.setPossibleValues(self, forceStringList(possibleValues))

	def setDefaultValues(self, defaultValues: list[Any]) -> None:
		Config.setDefaultValues(self, forceStringList(defaultValues))


Config.sub_classes["UnicodeConfig"] = UnicodeConfig


class BoolConfig(Config):
	sub_classes: dict[str, type] = {}

	def __init__(self, id: str, description: str | None = None, defaultValues: list[bool] | None = None) -> None:
		Config.__init__(self, id, description, [True, False], defaultValues, False, False)

	def setDefaults(self) -> None:
		if self.defaultValues is None:
			self.defaultValues = [False]
		Config.setDefaults(self)

	def setPossibleValues(self, possibleValues: list[bool]) -> None:
		Config.setPossibleValues(self, [True, False])

	def setDefaultValues(self, defaultValues: list[bool]) -> None:
		defaultValues = list(set(forceBoolList(defaultValues)))
		if len(defaultValues) > 1:
			raise BackendBadValueError(f"Bool config cannot have multiple default values: {defaultValues}")
		Config.setDefaultValues(self, defaultValues)

	def __str__(self) -> str:
		return f"<{self.getType()}(id='{self.id}', description='{self.description}', " f"defaultValues={self.defaultValues})>"


Config.sub_classes["BoolConfig"] = BoolConfig


class ConfigState(Relationship):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "configState"

	def __init__(self, configId: str, objectId: str, values: list[Any] | None = None) -> None:
		self.values: list[Any] | None = None
		self.setConfigId(configId)
		self.setObjectId(objectId)

		if values is not None:
			self.setValues(values)

	def setDefaults(self) -> None:
		Relationship.setDefaults(self)
		if self.values is None:
			self.setValues([])

	def getObjectId(self) -> str:
		return self.objectId

	def setObjectId(self, objectId: str) -> None:
		self.objectId = forceObjectId(objectId)

	def getConfigId(self) -> str:
		return self.configId

	def setConfigId(self, configId: str) -> None:
		self.configId = forceConfigId(configId)

	def getValues(self) -> list[Any] | None:
		return self.values

	def setValues(self, values: list[Any]) -> None:
		self.values = sorted(forceList(values), key=lambda x: (x is None, x))

	def __str__(self) -> str:
		return f"<{self.getType()}(configId='{self.configId}', objectId='{self.objectId}', values={self.values})>"


Relationship.sub_classes["ConfigState"] = ConfigState


class Product(Entity):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Entity.foreign_id_attributes + ["productId"]
	backend_method_prefix = "product"

	def __init__(
		self,
		id: str,
		productVersion: str,
		packageVersion: str,
		name: str | None = None,
		licenseRequired: bool | None = None,
		setupScript: str | None = None,
		uninstallScript: str | None = None,
		updateScript: str | None = None,
		alwaysScript: str | None = None,
		onceScript: str | None = None,
		customScript: str | None = None,
		userLoginScript: str | None = None,
		priority: int | None = None,
		description: str | None = None,
		advice: str | None = None,
		changelog: str | None = None,
		productClassIds: list[str] | None = None,
		windowsSoftwareIds: list[str] | None = None,
	):
		self.name: str | None = None
		self.licenseRequired: bool | None = None
		self.setupScript: str | None = None
		self.uninstallScript: str | None = None
		self.updateScript: str | None = None
		self.alwaysScript: str | None = None
		self.onceScript: str | None = None
		self.customScript: str | None = None
		self.userLoginScript: str | None = None
		self.priority: int | None = None
		self.description: str | None = None
		self.advice: str | None = None
		self.changelog: str | None = None
		self.productClassIds: list[str] | None = None
		self.windowsSoftwareIds: list[str] | None = None
		self.setId(id)
		self.setProductVersion(productVersion)
		self.setPackageVersion(packageVersion)

		if name is not None:
			self.setName(name)
		if licenseRequired is not None:
			self.setLicenseRequired(licenseRequired)
		if setupScript is not None:
			self.setSetupScript(setupScript)
		if uninstallScript is not None:
			self.setUninstallScript(uninstallScript)
		if updateScript is not None:
			self.setUpdateScript(updateScript)
		if alwaysScript is not None:
			self.setAlwaysScript(alwaysScript)
		if onceScript is not None:
			self.setOnceScript(onceScript)
		if customScript is not None:
			self.setCustomScript(customScript)
		if userLoginScript is not None:
			self.setUserLoginScript(userLoginScript)
		if priority is not None:
			self.setPriority(priority)
		if description is not None:
			self.setDescription(description)
		if advice is not None:
			self.setAdvice(advice)
		if changelog is not None:
			self.setChangelog(changelog)
		if productClassIds is not None:
			self.setProductClassIds(productClassIds)
		if windowsSoftwareIds is not None:
			self.setWindowsSoftwareIds(windowsSoftwareIds)

	def setDefaults(self) -> None:
		Entity.setDefaults(self)
		if self.name is None:
			self.setName("")
		if self.licenseRequired is None:
			self.setLicenseRequired(False)
		if self.setupScript is None:
			self.setSetupScript("")
		if self.uninstallScript is None:
			self.setUninstallScript("")
		if self.updateScript is None:
			self.setUpdateScript("")
		if self.alwaysScript is None:
			self.setAlwaysScript("")
		if self.onceScript is None:
			self.setOnceScript("")
		if self.customScript is None:
			self.setCustomScript("")
		if self.userLoginScript is None:
			self.setUserLoginScript("")
		if self.priority is None:
			self.setPriority(0)
		if self.description is None:
			self.setDescription("")
		if self.advice is None:
			self.setAdvice("")
		if self.changelog is None:
			self.setChangelog("")
		if self.productClassIds is None:
			self.setProductClassIds([])
		if self.windowsSoftwareIds is None:
			self.setWindowsSoftwareIds([])

	def getId(self) -> str:
		return self.id

	def setId(self, id: str) -> None:
		self.id = forceProductId(id)

	def getProductVersion(self) -> str:
		return self.productVersion

	def setProductVersion(self, productVersion: str) -> None:
		self.productVersion = forceProductVersion(productVersion)

	def getPackageVersion(self) -> str:
		return self.packageVersion

	def setPackageVersion(self, packageVersion: str) -> None:
		self.packageVersion = forcePackageVersion(packageVersion)

	@property
	def version(self) -> str | None:
		return combine_versions(self)

	def getName(self) -> str | None:
		return self.name

	def setName(self, name: str) -> None:
		self.name = forceString(name)

	def getLicenseRequired(self) -> bool | None:
		return self.licenseRequired

	def setLicenseRequired(self, licenseRequired: bool) -> None:
		self.licenseRequired = forceBool(licenseRequired)

	def getSetupScript(self) -> str | None:
		return self.setupScript

	def setSetupScript(self, setupScript: str) -> None:
		self.setupScript = forceFilename(setupScript)

	def getUninstallScript(self) -> str | None:
		return self.uninstallScript

	def setUninstallScript(self, uninstallScript: str) -> None:
		self.uninstallScript = forceFilename(uninstallScript)

	def getUpdateScript(self) -> str | None:
		return self.updateScript

	def setUpdateScript(self, updateScript: str) -> None:
		self.updateScript = forceFilename(updateScript)

	def getAlwaysScript(self) -> str | None:
		return self.alwaysScript

	def setAlwaysScript(self, alwaysScript: str) -> None:
		self.alwaysScript = forceFilename(alwaysScript)

	def getOnceScript(self) -> str | None:
		return self.onceScript

	def setOnceScript(self, onceScript: str) -> None:
		self.onceScript = forceFilename(onceScript)

	def getCustomScript(self) -> str | None:
		return self.customScript

	def setCustomScript(self, customScript: str) -> None:
		self.customScript = forceFilename(customScript)

	def getUserLoginScript(self) -> str | None:
		return self.userLoginScript

	def setUserLoginScript(self, userLoginScript: str) -> None:
		self.userLoginScript = forceFilename(userLoginScript)

	def getPriority(self) -> int | None:
		return self.priority

	def setPriority(self, priority: int) -> None:
		self.priority = forceProductPriority(priority)

	def getDescription(self) -> str | None:
		return self.description

	def setDescription(self, description: str) -> None:
		self.description = forceString(description)

	def getAdvice(self) -> str | None:
		return self.advice

	def setAdvice(self, advice: str) -> None:
		self.advice = forceString(advice)

	def getChangelog(self) -> str | None:
		return self.changelog

	def setChangelog(self, changelog: str) -> None:
		self.changelog = forceString(changelog)

	def getProductClassIds(self) -> list[str] | None:
		return self.productClassIds

	def setProductClassIds(self, productClassIds: list[str]) -> None:
		self.productClassIds = forceStringList(productClassIds)
		self.productClassIds.sort()

	def getWindowsSoftwareIds(self) -> list[str] | None:
		return self.windowsSoftwareIds

	def setWindowsSoftwareIds(self, windowsSoftwareIds: list[str]) -> None:
		self.windowsSoftwareIds = forceStringList(windowsSoftwareIds)
		self.windowsSoftwareIds.sort()

	def __str__(self) -> str:
		return (
			f"<{self.getType()}(id='{self.id}', name='{self.name}', "
			f"productVersion='{self.productVersion}', packageVersion='{self.packageVersion}')>"
		)


Entity.sub_classes["Product"] = Product


class LocalbootProduct(Product):
	sub_classes: dict[str, type] = {}

	def __init__(
		self,
		id: str,
		productVersion: str,
		packageVersion: str,
		name: str | None = None,
		licenseRequired: bool | None = None,
		setupScript: str | None = None,
		uninstallScript: str | None = None,
		updateScript: str | None = None,
		alwaysScript: str | None = None,
		onceScript: str | None = None,
		customScript: str | None = None,
		userLoginScript: str | None = None,
		priority: int | None = None,
		description: str | None = None,
		advice: str | None = None,
		changelog: str | None = None,
		productClassIds: list[str] | None = None,
		windowsSoftwareIds: list[str] | None = None,
	):
		Product.__init__(
			self,
			id,
			productVersion,
			packageVersion,
			name,
			licenseRequired,
			setupScript,
			uninstallScript,
			updateScript,
			alwaysScript,
			onceScript,
			customScript,
			userLoginScript,
			priority,
			description,
			advice,
			changelog,
			productClassIds,
			windowsSoftwareIds,
		)

	def setDefaults(self) -> None:
		Product.setDefaults(self)


Product.sub_classes["LocalbootProduct"] = LocalbootProduct


class NetbootProduct(Product):
	sub_classes: dict[str, type] = {}

	def __init__(
		self,
		id: str,
		productVersion: str,
		packageVersion: str,
		name: str | None = None,
		licenseRequired: bool | None = None,
		setupScript: str | None = None,
		uninstallScript: str | None = None,
		updateScript: str | None = None,
		alwaysScript: str | None = None,
		onceScript: str | None = None,
		customScript: str | None = None,
		priority: int | None = None,
		description: str | None = None,
		advice: str | None = None,
		changelog: str | None = None,
		productClassIds: list[str] | None = None,
		windowsSoftwareIds: list[str] | None = None,
		pxeConfigTemplate: str = "",
	) -> None:
		Product.__init__(
			self,
			id,
			productVersion,
			packageVersion,
			name,
			licenseRequired,
			setupScript,
			uninstallScript,
			updateScript,
			alwaysScript,
			onceScript,
			customScript,
			None,
			priority,
			description,
			advice,
			changelog,
			productClassIds,
			windowsSoftwareIds,
		)
		self.pxeConfigTemplate: str | None = None
		self.setPxeConfigTemplate(pxeConfigTemplate)

	def setDefaults(self) -> None:
		Product.setDefaults(self)

	def getPxeConfigTemplate(self) -> str | None:
		return self.pxeConfigTemplate

	def setPxeConfigTemplate(self, pxeConfigTemplate: str) -> None:
		self.pxeConfigTemplate = None
		if pxeConfigTemplate:
			self.pxeConfigTemplate = forceFilename(pxeConfigTemplate)
		else:
			self.pxeConfigTemplate = None


Product.sub_classes["NetbootProduct"] = NetbootProduct


class ProductProperty(Entity):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "productProperty"

	def __init__(
		self,
		productId: str,
		productVersion: str,
		packageVersion: str,
		propertyId: str,
		description: str | None = None,
		possibleValues: list[Any] | None = None,
		defaultValues: list[Any] | None = None,
		editable: bool | None = None,
		multiValue: bool | None = None,
	):
		self.description: str | None = None
		self.possibleValues: list[Any] | None = None
		self.defaultValues: list[Any] | None = None
		self.editable: bool | None = None
		self.multiValue: bool | None = None
		self.setProductId(productId)
		self.setProductVersion(productVersion)
		self.setPackageVersion(packageVersion)
		self.setPropertyId(propertyId)

		if description is not None:
			self.setDescription(description)
		if possibleValues is not None:
			self.setPossibleValues(possibleValues)
		if defaultValues is not None:
			self.setDefaultValues(defaultValues)
		if editable is not None:
			self.setEditable(editable)
		if multiValue is not None:
			self.setMultiValue(multiValue)

	def setDefaults(self) -> None:
		Entity.setDefaults(self)
		if self.description is None:
			self.setDescription("")
		if self.possibleValues is None:
			self.setPossibleValues([])
		if self.defaultValues is None:
			self.setDefaultValues([])
		if self.editable is None:
			self.setEditable(True)
		if self.multiValue is None:
			self.setMultiValue(False)

	def getProductId(self) -> str:
		return self.productId

	def setProductId(self, productId: str) -> None:
		self.productId = forceProductId(productId)

	def getProductVersion(self) -> str:
		return self.productVersion

	def setProductVersion(self, productVersion: str) -> None:
		self.productVersion = forceProductVersion(productVersion)

	def getPackageVersion(self) -> str:
		return self.packageVersion

	def setPackageVersion(self, packageVersion: str) -> None:
		self.packageVersion = forcePackageVersion(packageVersion)

	def getPropertyId(self) -> str:
		return self.propertyId

	def setPropertyId(self, propertyId: str) -> None:
		self.propertyId = forceProductPropertyId(propertyId)

	def getDescription(self) -> str | None:
		return self.description

	def setDescription(self, description: str) -> None:
		self.description = forceString(description)

	def _updateValues(self) -> None:
		if self.possibleValues is None:
			self.possibleValues = []

		if self.possibleValues and self.defaultValues:
			for default_value in self.defaultValues:
				if default_value not in self.possibleValues:
					self.defaultValues.remove(default_value)
		elif not self.possibleValues and self.defaultValues:
			self.possibleValues = self.defaultValues

		if self.defaultValues and len(self.defaultValues) > 1:
			self.multiValue = True
		if self.possibleValues is not None:
			self.possibleValues.sort()
		if self.defaultValues is not None:
			self.defaultValues.sort()

	def getPossibleValues(self) -> list[Any] | None:
		return self.possibleValues

	def setPossibleValues(self, possibleValues: list[Any]) -> None:
		self.possibleValues = list(set(forceList(possibleValues)))
		self._updateValues()

	def getDefaultValues(self) -> list[Any] | None:
		return self.defaultValues

	def setDefaultValues(self, defaultValues: list[Any]) -> None:
		self.defaultValues = list(set(forceList(defaultValues)))
		self._updateValues()

	def getEditable(self) -> bool | None:
		return self.editable

	def setEditable(self, editable: bool) -> None:
		self.editable = forceBool(editable)

	def getMultiValue(self) -> bool | None:
		return self.multiValue

	def setMultiValue(self, multiValue: bool) -> None:
		self.multiValue = forceBool(multiValue)
		if self.defaultValues is not None and len(self.defaultValues) > 1:
			self.multiValue = True

	def __str__(self) -> str:
		def getAttributes() -> Generator[str, None, None]:
			yield f"productId='{self.productId}'"
			yield f"productVersion='{self.productVersion}'"
			yield f"packageVersion='{self.packageVersion}'"
			yield f"propertyId='{self.propertyId}'"

			for attribute in ("description", "defaultValues", "possibleValues"):
				value = getattr(self, attribute, None)
				if value:
					yield f"{attribute}='{value}'"

			for attribute in ("editable", "multiValue"):
				value = getattr(self, attribute, None)
				if value is not None:
					yield f"{attribute}='{value}'"

		return f"<{self.__class__.__name__}({', '.join(getAttributes())})>"


Entity.sub_classes["ProductProperty"] = ProductProperty


class UnicodeProductProperty(ProductProperty):
	sub_classes: dict[str, type] = {}

	def __init__(
		self,
		productId: str,
		productVersion: str,
		packageVersion: str,
		propertyId: str,
		description: str | None = None,
		possibleValues: list[Any] | None = None,
		defaultValues: list[Any] | None = None,
		editable: bool | None = None,
		multiValue: bool | None = None,
	):
		ProductProperty.__init__(
			self, productId, productVersion, packageVersion, propertyId, description, possibleValues, defaultValues, editable, multiValue
		)

		self.possibleValues = None
		self.defaultValues = None
		if possibleValues is not None:
			self.setPossibleValues(possibleValues)
		if defaultValues is not None:
			self.setDefaultValues(defaultValues)

	def setPossibleValues(self, possibleValues: list[Any]) -> None:
		ProductProperty.setPossibleValues(self, forceStringList(possibleValues))

	def setDefaultValues(self, defaultValues: list[Any]) -> None:
		ProductProperty.setDefaultValues(self, forceStringList(defaultValues))


ProductProperty.sub_classes["UnicodeProductProperty"] = UnicodeProductProperty


class BoolProductProperty(ProductProperty):
	sub_classes: dict[str, type] = {}

	def __init__(
		self,
		productId: str,
		productVersion: str,
		packageVersion: str,
		propertyId: str,
		description: str | None = None,
		defaultValues: list[Any] | None = None,
	) -> None:
		ProductProperty.__init__(
			self, productId, productVersion, packageVersion, propertyId, description, [True, False], defaultValues, False, False
		)

		if self.defaultValues is not None and len(self.defaultValues) > 1:
			raise BackendBadValueError(f"Bool product property cannot have multiple default values: {self.defaultValues}")

	def setDefaults(self) -> None:
		if self.defaultValues is None:
			self.defaultValues = [False]
		ProductProperty.setDefaults(self)

	def setPossibleValues(self, possibleValues: list[Any]) -> None:
		ProductProperty.setPossibleValues(self, [True, False])

	def setDefaultValues(self, defaultValues: list[Any]) -> None:
		defaultValues = forceBoolList(defaultValues)
		if len(defaultValues) > 1:
			raise BackendBadValueError(f"Bool config cannot have multiple default values: {self.defaultValues}")
		ProductProperty.setDefaultValues(self, defaultValues)

	def setEditable(self, editable: bool) -> None:
		self.editable = False

	def __str__(self) -> str:
		def getAttributes() -> Generator[str, None, None]:
			yield f"productId='{self.productId}'"
			yield f"productVersion='{self.productVersion}'"
			yield f"packageVersion='{self.packageVersion}'"
			yield f"propertyId='{self.propertyId}'"

			for attribute in ("description", "defaultValues"):
				value = getattr(self, attribute, None)
				if value:
					yield f"{attribute}='{value}'"

		return f"<{self.__class__.__name__}({', '.join(getAttributes())})>"


ProductProperty.sub_classes["BoolProductProperty"] = BoolProductProperty


class ProductDependency(Relationship):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "productDependency"

	def __init__(
		self,
		productId: str,
		productVersion: str,
		packageVersion: str,
		productAction: str,
		requiredProductId: str,
		requiredProductVersion: str | None = None,
		requiredPackageVersion: str | None = None,
		requiredAction: str | None = None,
		requiredInstallationStatus: str | None = None,
		requirementType: str | None = None,
	):
		self.requiredProductVersion: str | None = None
		self.requiredPackageVersion: str | None = None
		self.requiredAction: str | None = None
		self.requiredInstallationStatus: str | None = None
		self.requirementType: str | None = None

		self.setProductId(productId)
		self.setProductVersion(productVersion)
		self.setPackageVersion(packageVersion)
		self.setProductAction(productAction)
		self.setRequiredProductId(requiredProductId)

		if requiredProductVersion is not None:
			self.setRequiredProductVersion(requiredProductVersion)
		if requiredPackageVersion is not None:
			self.setRequiredPackageVersion(requiredPackageVersion)
		if requiredAction is not None:
			self.setRequiredAction(requiredAction)
		if requiredInstallationStatus is not None:
			self.setRequiredInstallationStatus(requiredInstallationStatus)
		if requirementType is not None:
			self.setRequirementType(requirementType)

	def setDefaults(self) -> None:
		Relationship.setDefaults(self)

	def getProductId(self) -> str:
		return self.productId

	def setProductId(self, productId: str) -> None:
		self.productId = forceProductId(productId)

	def getProductVersion(self) -> str:
		return self.productVersion

	def setProductVersion(self, productVersion: str) -> None:
		self.productVersion = forceProductVersion(productVersion)

	def getPackageVersion(self) -> str:
		return self.packageVersion

	def setPackageVersion(self, packageVersion: str) -> None:
		self.packageVersion = forcePackageVersion(packageVersion)

	def getProductAction(self) -> str:
		return self.productAction

	def setProductAction(self, productAction: str) -> None:
		self.productAction = forceActionRequest(productAction)

	def getRequiredProductId(self) -> str | None:
		return self.requiredProductId

	def setRequiredProductId(self, requiredProductId: str) -> None:
		self.requiredProductId = forceProductId(requiredProductId)

	def getRequiredProductVersion(self) -> str | None:
		return self.requiredProductVersion

	def setRequiredProductVersion(self, requiredProductVersion: str) -> None:
		self.requiredProductVersion = forceProductVersion(requiredProductVersion)

	def getRequiredPackageVersion(self) -> str | None:
		return self.requiredPackageVersion

	def setRequiredPackageVersion(self, requiredPackageVersion: str) -> None:
		self.requiredPackageVersion = forcePackageVersion(requiredPackageVersion)

	def getRequiredAction(self) -> str | None:
		return self.requiredAction

	def setRequiredAction(self, requiredAction: str) -> None:
		self.requiredAction = forceActionRequest(requiredAction)

	def getRequiredInstallationStatus(self) -> str | None:
		return self.requiredInstallationStatus

	def setRequiredInstallationStatus(self, requiredInstallationStatus: str) -> None:
		self.requiredInstallationStatus = forceInstallationStatus(requiredInstallationStatus)

	def getRequirementType(self) -> str | None:
		return self.requirementType

	def setRequirementType(self, requirementType: str) -> None:
		self.requirementType = forceRequirementType(requirementType)

	def __str__(self) -> str:
		return (
			f"<{self.getType()}(productId='{self.productId}', productVersion='{self.productVersion}', "
			f"packageVersion='{self.packageVersion}', productAction='{self.productAction}', "
			f"requiredProductId='{self.requiredProductId}'>"
		)


Relationship.sub_classes["ProductDependency"] = ProductDependency


class ProductOnDepot(Relationship):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "productOnDepot"

	def __init__(
		self,
		productId: str,
		productType: str,
		productVersion: str,
		packageVersion: str,
		depotId: str,
		locked: bool | None = None,
	):
		self.locked: bool | None = None

		self.setProductId(productId)
		self.setProductType(productType)
		self.setProductVersion(productVersion)
		self.setPackageVersion(packageVersion)
		self.setDepotId(depotId)

		if locked is not None:
			self.setLocked(locked)

	def setDefaults(self) -> None:
		Relationship.setDefaults(self)
		if self.locked is None:
			self.setLocked(False)

	def getProductId(self) -> str:
		return self.productId

	def setProductId(self, productId: str) -> None:
		self.productId = forceProductId(productId)

	def getProductType(self) -> str | None:
		return self.productType

	def setProductType(self, productType: str) -> None:
		self.productType = forceProductType(productType)

	def getProductVersion(self) -> str | None:
		return self.productVersion

	def setProductVersion(self, productVersion: str) -> None:
		self.productVersion = forceProductVersion(productVersion)

	def getPackageVersion(self) -> str | None:
		return self.packageVersion

	def setPackageVersion(self, packageVersion: str) -> None:
		self.packageVersion = forcePackageVersion(packageVersion)

	@property
	def version(self) -> str:
		return combine_versions(self)

	def getDepotId(self) -> str:
		return self.depotId

	def setDepotId(self, depotId: str) -> None:
		self.depotId = forceHostId(depotId)

	def getLocked(self) -> bool | None:
		return self.locked

	def setLocked(self, locked: bool) -> None:
		self.locked = forceBool(locked)


Relationship.sub_classes["ProductOnDepot"] = ProductOnDepot


class ProductOnClient(Relationship):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "productOnClient"

	def __init__(
		self,
		productId: str,
		productType: str,
		clientId: str,
		targetConfiguration: str | None = None,
		installationStatus: str | None = None,
		actionRequest: str | None = None,
		lastAction: str | None = None,
		actionProgress: str | None = None,
		actionResult: str | None = None,
		productVersion: str | None = None,
		packageVersion: str | None = None,
		modificationTime: str | None = None,
		actionSequence: int | None = None,
	):
		self.targetConfiguration: str | None = None
		self.installationStatus: str | None = None
		self.actionRequest: str | None = None
		self.lastAction: str | None = None
		self.actionProgress: str | None = None
		self.actionResult: str | None = None
		self.productVersion: str | None = None
		self.packageVersion: str | None = None
		self.modificationTime: str | None = None
		self.actionSequence: int | None = -1

		self.setProductId(productId)
		self.setProductType(productType)
		self.setClientId(clientId)

		if targetConfiguration is not None:
			self.setTargetConfiguration(targetConfiguration)
		if installationStatus is not None:
			self.setInstallationStatus(installationStatus)
		if actionRequest is not None:
			self.setActionRequest(actionRequest)
		if lastAction is not None:
			self.setLastAction(lastAction)
		if actionProgress is not None:
			self.setActionProgress(actionProgress)
		if actionResult is not None:
			self.setActionResult(actionResult)
		if productVersion is not None:
			self.setProductVersion(productVersion)
		if packageVersion is not None:
			self.setPackageVersion(packageVersion)
		if modificationTime is not None:
			self.setModificationTime(modificationTime)
		if actionSequence is not None:
			self.setActionSequence(actionSequence)

	def setDefaults(self) -> None:
		Relationship.setDefaults(self)
		if self.installationStatus is None:
			self.setInstallationStatus("not_installed")
		if self.actionRequest is None:
			self.setActionRequest("none")
		if self.modificationTime is None:
			self.setModificationTime(timestamp())

	def getProductId(self) -> str:
		return self.productId

	def setProductId(self, productId: str) -> None:
		self.productId = forceProductId(productId)

	def getProductType(self) -> str | None:
		return self.productType

	def setProductType(self, productType: str) -> None:
		self.productType = forceProductType(productType)

	def getClientId(self) -> str:
		return self.clientId

	def setClientId(self, clientId: str) -> None:
		self.clientId = forceHostId(clientId)

	def getTargetConfiguration(self) -> str | None:
		return self.targetConfiguration

	def setTargetConfiguration(self, targetConfiguration: str) -> None:
		self.targetConfiguration = forceProductTargetConfiguration(targetConfiguration)

	def getInstallationStatus(self) -> str | None:
		return self.installationStatus

	def setInstallationStatus(self, installationStatus: str) -> None:
		self.installationStatus = forceInstallationStatus(installationStatus)

	def getActionRequest(self) -> str | None:
		return self.actionRequest

	def setActionRequest(self, actionRequest: str) -> None:
		self.actionRequest = forceActionRequest(actionRequest)

	def getActionProgress(self) -> str | None:
		return self.actionProgress

	def setActionProgress(self, actionProgress: str) -> None:
		actionProgress = forceActionProgress(actionProgress)
		if actionProgress and len(actionProgress) > 250:
			logger.warning("Data truncated for actionProgess")
			actionProgress = actionProgress[:250]
		self.actionProgress = forceActionProgress(actionProgress)

	def getLastAction(self) -> str | None:
		return self.lastAction

	def setLastAction(self, lastAction: str) -> None:
		self.lastAction = forceActionRequest(lastAction)

	def getActionResult(self) -> str | None:
		return self.actionResult

	def setActionResult(self, actionResult: str) -> None:
		self.actionResult = forceActionResult(actionResult)

	def getProductVersion(self) -> str | None:
		return self.productVersion

	def setProductVersion(self, productVersion: str) -> None:
		self.productVersion = forceProductVersion(productVersion)

	def getPackageVersion(self) -> str | None:
		return self.packageVersion

	def setPackageVersion(self, packageVersion: str) -> None:
		self.packageVersion = forcePackageVersion(packageVersion)

	@property
	def version(self) -> str:
		return combine_versions(self)

	def getModificationTime(self) -> str | None:
		return self.modificationTime

	def setModificationTime(self, modificationTime: str) -> None:
		self.modificationTime = forceOpsiTimestamp(modificationTime)

	def getActionSequence(self) -> int | None:
		return self.actionSequence

	def setActionSequence(self, actionSequence: int) -> None:
		self.actionSequence = forceInt(actionSequence)

	def __str__(self) -> str:
		return (
			f"<{self.getType()}(clientId='{self.clientId}', productId='{self.productId}', "
			f"installationStatus='{self.installationStatus}', actionRequest='{self.actionRequest}')>"
		)


Relationship.sub_classes["ProductOnClient"] = ProductOnClient


class ProductPropertyState(Relationship):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "productPropertyState"

	def __init__(
		self,
		productId: str,
		propertyId: str,
		objectId: str,
		values: list[Any] | None = None,
	) -> None:
		self.values: list[Any] | None = None

		self.setProductId(productId)
		self.setPropertyId(propertyId)
		self.setObjectId(objectId)

		if values is not None:
			self.setValues(values)

	def setDefaults(self) -> None:
		Relationship.setDefaults(self)
		if self.values is None:
			self.setValues([])

	def getProductId(self) -> str:
		return self.productId

	def setProductId(self, productId: str) -> None:
		self.productId = forceProductId(productId)

	def getObjectId(self) -> str:
		return self.objectId

	def setObjectId(self, objectId: str) -> None:
		self.objectId = forceObjectId(objectId)

	def getPropertyId(self) -> str:
		return self.propertyId

	def setPropertyId(self, propertyId: str) -> None:
		self.propertyId = forceProductPropertyId(propertyId)

	def getValues(self) -> list[Any] | None:
		return self.values

	def setValues(self, values: list[Any]) -> None:
		self.values = forceList(values)
		self.values.sort()

	def __str__(self) -> str:
		def get_attributes() -> Generator[str, None, None]:
			yield f"productId='{self.productId}'"
			yield f"propertyId='{self.propertyId}'"
			yield f"objectId='{self.objectId}'"

			if self.values is not None:
				yield f"values={self.values}"

		return f"<{self.getType()}({', '.join(get_attributes())})>"


Relationship.sub_classes["ProductPropertyState"] = ProductPropertyState


class Group(Object):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Object.foreign_id_attributes + ["groupId"]
	backend_method_prefix = "group"

	def __init__(
		self,
		id: str,
		description: str | None = None,
		notes: str | None = None,
		parentGroupId: str | None = None,
	) -> None:
		Object.__init__(self, id, description, notes)
		self.parentGroupId: str | None = None

		self.setId(id)

		if parentGroupId is not None:
			self.setParentGroupId(parentGroupId)

	def setDefaults(self) -> None:
		Object.setDefaults(self)

	def getId(self) -> str:
		return self.id

	def setId(self, id: str) -> None:
		self.id = forceGroupId(id)

	def getParentGroupId(self) -> str | None:
		return self.parentGroupId

	def setParentGroupId(self, parentGroupId: str) -> None:
		self.parentGroupId = forceGroupId(parentGroupId)

	def __str__(self) -> str:
		return f"<{self.getType()}(id='{self.id}', parentGroupId='{self.parentGroupId}'>"


Object.sub_classes["Group"] = Group


class HostGroup(Group):
	sub_classes: dict[str, type] = {}

	def __init__(
		self,
		id: str,
		description: str | None = None,
		notes: str | None = None,
		parentGroupId: str | None = None,
	) -> None:
		Group.__init__(self, id, description, notes, parentGroupId)

	def setDefaults(self) -> None:
		Group.setDefaults(self)


Group.sub_classes["HostGroup"] = HostGroup


class ProductGroup(Group):
	sub_classes: dict[str, type] = {}

	def __init__(
		self,
		id: str,
		description: str | None = None,
		notes: str | None = None,
		parentGroupId: str | None = None,
	) -> None:
		Group.__init__(self, id, description, notes, parentGroupId)

	def setDefaults(self) -> None:
		Group.setDefaults(self)


Group.sub_classes["ProductGroup"] = ProductGroup


class ObjectToGroup(Relationship):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "objectToGroup"

	def __init__(self, groupType: str, groupId: str, objectId: str) -> None:
		self.setGroupType(groupType)
		self.setGroupId(groupId)
		self.setObjectId(objectId)

	def setDefaults(self) -> None:
		Relationship.setDefaults(self)

	def getGroupType(self) -> str:
		return self.groupType

	def setGroupType(self, groupType: str) -> None:
		self.groupType = forceGroupType(groupType)

	def getGroupId(self) -> str:
		return self.groupId

	def setGroupId(self, groupId: str) -> None:
		self.groupId = forceGroupId(groupId)

	def getObjectId(self) -> str:
		return self.objectId

	def setObjectId(self, objectId: str) -> None:
		self.objectId = forceObjectId(objectId)


Relationship.sub_classes["ObjectToGroup"] = ObjectToGroup


class LicenseContract(Entity):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Entity.foreign_id_attributes + ["licenseContractId"]
	backend_method_prefix = "licenseContract"

	def __init__(
		self,
		id: str,
		description: str | None = None,
		notes: str | None = None,
		partner: str | None = None,
		conclusionDate: str | None = None,
		notificationDate: str | None = None,
		expirationDate: str | None = None,
	):
		self.description: str | None = None
		self.notes: str | None = None
		self.partner: str | None = None
		self.conclusionDate: str | None = None
		self.notificationDate: str | None = None
		self.expirationDate: str | None = None
		self.setId(id)

		if description is not None:
			self.setDescription(description)
		if notes is not None:
			self.setNotes(notes)
		if partner is not None:
			self.setPartner(partner)
		if conclusionDate is not None:
			self.setConclusionDate(conclusionDate)
		if notificationDate is not None:
			self.setNotificationDate(notificationDate)
		if expirationDate is not None:
			self.setExpirationDate(expirationDate)

	def setDefaults(self) -> None:
		Entity.setDefaults(self)
		if self.description is None:
			self.setDescription("")
		if self.notes is None:
			self.setNotes("")
		if self.partner is None:
			self.setPartner("")
		if self.conclusionDate is None:
			self.setConclusionDate(timestamp())
		if self.notificationDate is None:
			self.setNotificationDate("0000-00-00 00:00:00")
		if self.expirationDate is None:
			self.setExpirationDate("0000-00-00 00:00:00")

	def getId(self) -> str:
		return self.id

	def setId(self, id: str) -> None:
		self.id = forceLicenseContractId(id)

	def getDescription(self) -> str | None:
		return self.description

	def setDescription(self, description: str) -> None:
		self.description = forceString(description)

	def getNotes(self) -> str | None:
		return self.notes

	def setNotes(self, notes: str) -> None:
		self.notes = forceString(notes)

	def getPartner(self) -> str | None:
		return self.partner

	def setPartner(self, partner: str) -> None:
		self.partner = forceString(partner)

	def getConclusionDate(self) -> str | None:
		return self.conclusionDate

	def setConclusionDate(self, conclusionDate: str) -> None:
		self.conclusionDate = forceOpsiTimestamp(conclusionDate)

	def getNotificationDate(self) -> str | None:
		return self.notificationDate

	def setNotificationDate(self, notificationDate: str) -> None:
		self.notificationDate = forceOpsiTimestamp(notificationDate)

	def getExpirationDate(self) -> str | None:
		return self.expirationDate

	def setExpirationDate(self, expirationDate: str) -> None:
		self.expirationDate = forceOpsiTimestamp(expirationDate)

	def __str__(self) -> str:
		infos = [f"id='{self.id}'"]

		if self.description:
			infos.append(f"description='{self.description}'")
		if self.partner:
			infos.append(f"partner='{self.partner}'")
		if self.conclusionDate:
			infos.append(f"conclusionDate={self.conclusionDate}")
		if self.notificationDate:
			infos.append(f"notificationDate={self.notificationDate}")
		if self.expirationDate:
			infos.append(f"expirationDate={self.expirationDate}")

		return f"<{self.getType()}({', '.join(infos)})>"


Entity.sub_classes["LicenseContract"] = LicenseContract


class SoftwareLicense(Entity):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Entity.foreign_id_attributes + ["softwareLicenseId"]
	backend_method_prefix = "softwareLicense"

	def __init__(
		self,
		id: str,
		licenseContractId: str,
		maxInstallations: int | None = None,
		boundToHost: str | None = None,
		expirationDate: str | None = None,
	):
		self.maxInstallations: int | None = None
		self.boundToHost: str | None = None
		self.expirationDate: str | None = None
		self.setId(id)
		self.setLicenseContractId(licenseContractId)

		if maxInstallations is not None:
			self.setMaxInstallations(maxInstallations)
		if boundToHost is not None:
			self.setBoundToHost(boundToHost)
		if expirationDate is not None:
			self.setExpirationDate(expirationDate)

	def setDefaults(self) -> None:
		Entity.setDefaults(self)
		if self.maxInstallations is None:
			self.setMaxInstallations(1)
		if self.expirationDate is None:
			self.setExpirationDate("0000-00-00 00:00:00")

	def getId(self) -> str:
		return self.id

	def setId(self, id: str) -> None:
		self.id = forceSoftwareLicenseId(id)

	def getLicenseContractId(self) -> str:
		return self.licenseContractId

	def setLicenseContractId(self, licenseContractId: str) -> None:
		self.licenseContractId = forceLicenseContractId(licenseContractId)

	def getMaxInstallations(self) -> int | None:
		return self.maxInstallations

	def setMaxInstallations(self, maxInstallations: int) -> None:
		self.maxInstallations = forceUnsignedInt(maxInstallations)

	def getBoundToHost(self) -> str | None:
		return self.boundToHost

	def setBoundToHost(self, boundToHost: str) -> None:
		self.boundToHost = forceHostId(boundToHost)

	def getExpirationDate(self) -> str | None:
		return self.expirationDate

	def setExpirationDate(self, expirationDate: str) -> None:
		self.expirationDate = forceOpsiTimestamp(expirationDate)

	def __str__(self) -> str:
		infos = [f"id='{self.id}'", f"licenseContractId='{self.licenseContractId}'"]
		if self.maxInstallations:
			infos.append(f"maxInstallations={self.maxInstallations}")
		if self.boundToHost:
			infos.append(f"boundToHost={self.boundToHost}")
		if self.expirationDate:
			infos.append(f"expirationDate={self.expirationDate}")

		return f"<{self.getType()}({', '.join(infos)})>"


Entity.sub_classes["LicenseContract"] = LicenseContract


class RetailSoftwareLicense(SoftwareLicense):
	sub_classes: dict[str, type] = {}

	def __init__(
		self,
		id: str,
		licenseContractId: str,
		maxInstallations: int | None = None,
		boundToHost: str | None = None,
		expirationDate: str | None = None,
	) -> None:
		SoftwareLicense.__init__(self, id, licenseContractId, maxInstallations, boundToHost, expirationDate)

	def setDefaults(self) -> None:
		SoftwareLicense.setDefaults(self)


SoftwareLicense.sub_classes["RetailSoftwareLicense"] = RetailSoftwareLicense


class OEMSoftwareLicense(SoftwareLicense):
	sub_classes: dict[str, type] = {}

	def __init__(
		self,
		id: str,
		licenseContractId: str,
		maxInstallations: int | None = None,
		boundToHost: str | None = None,
		expirationDate: str | None = None,
	) -> None:
		SoftwareLicense.__init__(self, id, licenseContractId, 1, boundToHost, expirationDate)

	def setDefaults(self) -> None:
		SoftwareLicense.setDefaults(self)

	def setMaxInstallations(self, maxInstallations: int) -> None:
		maxInstallations = forceUnsignedInt(maxInstallations)
		if maxInstallations > 1:
			raise BackendBadValueError("OEM software license max installations can only be set to 1")
		self.maxInstallations = maxInstallations

	def setBoundToHost(self, boundToHost: str) -> None:
		self.boundToHost = forceHostId(boundToHost)
		if not self.boundToHost:
			raise BackendBadValueError("OEM software license requires boundToHost value")


SoftwareLicense.sub_classes["OEMSoftwareLicense"] = OEMSoftwareLicense


class VolumeSoftwareLicense(SoftwareLicense):
	sub_classes: dict[str, type] = {}

	def __init__(
		self,
		id: str,
		licenseContractId: str,
		maxInstallations: int | None = None,
		boundToHost: str | None = None,
		expirationDate: str | None = None,
	) -> None:
		SoftwareLicense.__init__(self, id, licenseContractId, maxInstallations, boundToHost, expirationDate)

	def setDefaults(self) -> None:
		SoftwareLicense.setDefaults(self)
		if self.maxInstallations is None:
			self.setMaxInstallations(1)


SoftwareLicense.sub_classes["VolumeSoftwareLicense"] = VolumeSoftwareLicense


class ConcurrentSoftwareLicense(SoftwareLicense):
	sub_classes: dict[str, type] = {}

	def __init__(
		self,
		id: str,
		licenseContractId: str,
		maxInstallations: int | None = None,
		boundToHost: str | None = None,
		expirationDate: str | None = None,
	) -> None:
		SoftwareLicense.__init__(self, id, licenseContractId, maxInstallations, boundToHost, expirationDate)

	def setDefaults(self) -> None:
		SoftwareLicense.setDefaults(self)


SoftwareLicense.sub_classes["ConcurrentSoftwareLicense"] = ConcurrentSoftwareLicense


class LicensePool(Entity):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Entity.foreign_id_attributes + ["licensePoolId"]
	backend_method_prefix = "licensePool"

	def __init__(self, id: str, description: str | None = None, productIds: list[str] | None = None):
		self.description: str | None = None
		self.productIds: list[str] | None = None
		self.setId(id)

		if description is not None:
			self.setDescription(description)
		if productIds is not None:
			self.setProductIds(productIds)

	def setDefaults(self) -> None:
		Entity.setDefaults(self)
		if self.description is None:
			self.setDescription("")
		if self.productIds is None:
			self.setProductIds([])

	def getId(self) -> str:
		return self.id

	def setId(self, id: str) -> None:
		self.id = forceLicensePoolId(id)

	def getDescription(self) -> str | None:
		return self.description

	def setDescription(self, description: str) -> None:
		self.description = forceString(description)

	def getProductIds(self) -> list[str] | None:
		return self.productIds

	def setProductIds(self, productIds: list[str]) -> None:
		self.productIds = forceProductIdList(productIds)
		self.productIds.sort()

	def __str__(self) -> str:
		infos = [f"id='{self.id}'"]

		if self.description:
			infos.append(f"description='{self.description}'")
		if self.productIds:
			infos.append(f"productIds={self.productIds}")

		return f"<{self.getType()}({', '.join(infos)})>"


Entity.sub_classes["LicensePool"] = LicensePool


class AuditSoftwareToLicensePool(Relationship):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "auditSoftwareToLicensePool"

	def __init__(self, name: str, version: str, subVersion: str, language: str, architecture: str, licensePoolId: str) -> None:
		self.setName(name)
		self.setVersion(version)
		self.setSubVersion(subVersion)
		self.setLanguage(language)
		self.setArchitecture(architecture)
		self.setLicensePoolId(licensePoolId)

	def getLicensePoolId(self) -> str:
		return self.licensePoolId

	def setLicensePoolId(self, licensePoolId: str) -> None:
		self.licensePoolId = forceLicensePoolId(licensePoolId)

	def setName(self, name: str) -> None:
		self.name = forceString(name)

	def getName(self) -> str:
		return self.name

	def setVersion(self, version: str) -> None:
		if not version:
			self.version = ""
		else:
			self.version = forceStringLower(version)

	def getVersion(self) -> str:
		return self.version

	def setSubVersion(self, subVersion: str) -> None:
		if not subVersion:
			self.subVersion = ""
		else:
			self.subVersion = forceStringLower(subVersion)

	def getSubVersion(self) -> str:
		return self.subVersion

	def setLanguage(self, language: str) -> None:
		if not language:
			self.language = ""
		else:
			self.language = forceLanguageCode(language)

	def getLanguage(self) -> str:
		return self.language

	def setArchitecture(self, architecture: str) -> None:
		if not architecture:
			self.architecture = ""
		else:
			self.architecture = forceArchitecture(architecture)

	def getArchitecture(self) -> str:
		return self.architecture

	def __str__(self) -> str:
		infos = [f"name={self.name}"]

		if self.version:
			infos.append(f"version='{self.version}'")
		if self.subVersion:
			infos.append(f"subVersion='{self.subVersion}'")
		if self.language:
			infos.append(f"language='{self.language}'")
		if self.architecture:
			infos.append(f"architecture='{self.architecture}'")
		if self.licensePoolId:
			infos.append(f"licensePoolId='{self.licensePoolId}'")

		return f"<{self.getType()}({', '.join(infos)})>"


Relationship.sub_classes["AuditSoftwareToLicensePool"] = AuditSoftwareToLicensePool


class SoftwareLicenseToLicensePool(Relationship):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "softwareLicenseToLicensePool"

	def __init__(self, softwareLicenseId: str, licensePoolId: str, licenseKey: str | None = None) -> None:
		self.licenseKey: str | None = None
		self.setSoftwareLicenseId(softwareLicenseId)
		self.setLicensePoolId(licensePoolId)

		if licenseKey is not None:
			self.setLicenseKey(licenseKey)

	def setDefaults(self) -> None:
		Relationship.setDefaults(self)

		if self.licenseKey is None:
			self.setLicenseKey("")

	def getSoftwareLicenseId(self) -> str:
		return self.softwareLicenseId

	def setSoftwareLicenseId(self, softwareLicenseId: str) -> None:
		self.softwareLicenseId = forceSoftwareLicenseId(softwareLicenseId)

	def getLicensePoolId(self) -> str:
		return self.licensePoolId

	def setLicensePoolId(self, licensePoolId: str) -> None:
		self.licensePoolId = forceLicensePoolId(licensePoolId)

	def getLicenseKey(self) -> str | None:
		return self.licenseKey

	def setLicenseKey(self, licenseKey: str) -> None:
		self.licenseKey = forceString(licenseKey)


Relationship.sub_classes["SoftwareLicenseToLicensePool"] = SoftwareLicenseToLicensePool


class LicenseOnClient(Relationship):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "licenseOnClient"

	def __init__(
		self,
		softwareLicenseId: str,
		licensePoolId: str,
		clientId: str,
		licenseKey: str | None = None,
		notes: str | None = None,
	):
		self.licenseKey: str | None = None
		self.notes: str | None = None
		self.setSoftwareLicenseId(softwareLicenseId)
		self.setLicensePoolId(licensePoolId)
		self.setClientId(clientId)

		if licenseKey is not None:
			self.setLicenseKey(licenseKey)
		if notes is not None:
			self.setNotes(notes)

	def setDefaults(self) -> None:
		Relationship.setDefaults(self)

		if self.licenseKey is None:
			self.setLicenseKey("")
		if self.notes is None:
			self.setNotes("")

	def getSoftwareLicenseId(self) -> str:
		return self.softwareLicenseId

	def setSoftwareLicenseId(self, softwareLicenseId: str) -> None:
		self.softwareLicenseId = forceSoftwareLicenseId(softwareLicenseId)

	def getLicensePoolId(self) -> str:
		return self.licensePoolId

	def setLicensePoolId(self, licensePoolId: str) -> None:
		self.licensePoolId = forceLicensePoolId(licensePoolId)

	def getClientId(self) -> str:
		return self.clientId

	def setClientId(self, clientId: str) -> None:
		self.clientId = forceHostId(clientId)

	def getLicenseKey(self) -> str | None:
		return self.licenseKey

	def setLicenseKey(self, licenseKey: str) -> None:
		self.licenseKey = forceString(licenseKey)

	def getNotes(self) -> str | None:
		return self.notes

	def setNotes(self, notes: str) -> None:
		self.notes = forceString(notes)


Relationship.sub_classes["LicenseOnClient"] = LicenseOnClient


class AuditSoftware(Entity):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Entity.foreign_id_attributes
	backend_method_prefix = "auditSoftware"

	def __init__(
		self,
		name: str,
		version: str,
		subVersion: str,
		language: str,
		architecture: str,
		windowsSoftwareId: str | None = None,
		windowsDisplayName: str | None = None,
		windowsDisplayVersion: str | None = None,
		installSize: int | None = None,
	):
		self.windowsSoftwareId: str | None = None
		self.windowsDisplayName: str | None = None
		self.windowsDisplayVersion: str | None = None
		self.installSize: int | None = None
		self.setName(name)
		self.setVersion(version)
		self.setSubVersion(subVersion)
		self.setLanguage(language)
		self.setArchitecture(architecture)

		if windowsSoftwareId is not None:
			self.setWindowsSoftwareId(windowsSoftwareId)
		if windowsDisplayName is not None:
			self.setWindowsDisplayName(windowsDisplayName)
		if windowsDisplayVersion is not None:
			self.setWindowsDisplayVersion(windowsDisplayVersion)
		if installSize is not None:
			self.setInstallSize(installSize)

	def setDefaults(self) -> None:
		Entity.setDefaults(self)
		if self.installSize is None:
			self.setInstallSize(0)

	def setName(self, name: str) -> None:
		self.name = forceString(name)

	def getName(self) -> str:
		return self.name

	def setVersion(self, version: str) -> None:
		self.version = forceStringLower(version)

	def getVersion(self) -> str:
		return self.version

	def setSubVersion(self, subVersion: str) -> None:
		self.subVersion = forceStringLower(subVersion)

	def getSubVersion(self) -> str:
		return self.subVersion

	def setLanguage(self, language: str) -> None:
		if not language:
			self.language = ""
		else:
			self.language = forceLanguageCode(language)

	def getLanguage(self) -> str:
		return self.language

	def setArchitecture(self, architecture: str) -> None:
		if not architecture:
			self.architecture = ""
		else:
			self.architecture = forceArchitecture(architecture)

	def getArchitecture(self) -> str:
		return self.architecture

	def getWindowsSoftwareId(self) -> str | None:
		return self.windowsSoftwareId

	def setWindowsSoftwareId(self, windowsSoftwareId: str) -> None:
		self.windowsSoftwareId = forceStringLower(windowsSoftwareId)

	def getWindowsDisplayName(self) -> str | None:
		return self.windowsDisplayName

	def setWindowsDisplayName(self, windowsDisplayName: str) -> None:
		self.windowsDisplayName = forceString(windowsDisplayName)

	def getWindowsDisplayVersion(self) -> str | None:
		return self.windowsDisplayVersion

	def setWindowsDisplayVersion(self, windowsDisplayVersion: str) -> None:
		self.windowsDisplayVersion = forceString(windowsDisplayVersion)

	def getInstallSize(self) -> int | None:
		return self.installSize

	def setInstallSize(self, installSize: int) -> None:
		self.installSize = forceInt(installSize)


Entity.sub_classes["AuditSoftware"] = AuditSoftware


class AuditSoftwareOnClient(Relationship):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "auditSoftwareOnClient"

	def __init__(
		self,
		name: str,
		version: str,
		subVersion: str,
		language: str,
		architecture: str,
		clientId: str,
		uninstallString: str | None = None,
		binaryName: str | None = None,
		firstseen: str | None = None,
		lastseen: str | None = None,
		state: int | None = None,
		usageFrequency: int | None = None,
		lastUsed: str | None = None,
		licenseKey: str | None = None,
	):
		self.uninstallString: str | None = None
		self.binaryName: str | None = None
		self.firstseen: str | None = None
		self.lastseen: str | None = None
		self.state: int | None = None
		self.usageFrequency: int | None = None
		self.lastUsed: str | None = None
		self.licenseKey: str | None = None
		self.setName(name)
		self.setVersion(version)
		self.setSubVersion(subVersion)
		self.setLanguage(language)
		self.setArchitecture(architecture)
		self.setClientId(clientId)

		if uninstallString is not None:
			self.setUninstallString(uninstallString)
		if binaryName is not None:
			self.setBinaryName(binaryName)
		if firstseen is not None:
			self.setFirstseen(firstseen)
		if lastseen is not None:
			self.setLastseen(lastseen)
		if state is not None:
			self.setState(state)
		if usageFrequency is not None:
			self.setUsageFrequency(usageFrequency)
		if lastUsed is not None:
			self.setLastUsed(lastUsed)
		if licenseKey is not None:
			self.setLicenseKey(licenseKey)

	def setDefaults(self) -> None:
		Relationship.setDefaults(self)

		if self.uninstallString is None:
			self.setUninstallString("")
		if self.binaryName is None:
			self.setBinaryName("")
		if self.firstseen is None:
			self.setFirstseen(timestamp())
		if self.lastseen is None:
			self.setLastseen(timestamp())
		if self.state is None:
			self.setState(1)
		if self.usageFrequency is None:
			self.setUsageFrequency(-1)
		if self.lastUsed is None:
			self.setLastUsed("0000-00-00 00:00:00")

	def setName(self, name: str) -> None:
		self.name = forceString(name)

	def getName(self) -> str:
		return self.name

	def setVersion(self, version: str) -> None:
		self.version = forceStringLower(version)

	def getVersion(self) -> str:
		return self.version

	def setSubVersion(self, subVersion: str) -> None:
		self.subVersion = forceStringLower(subVersion)

	def getSubVersion(self) -> str:
		return self.subVersion

	def setLanguage(self, language: str) -> None:
		if not language:
			self.language = ""
		else:
			self.language = forceLanguageCode(language)

	def getLanguage(self) -> str:
		return self.language

	def setArchitecture(self, architecture: str) -> None:
		if not architecture:
			self.architecture = ""
		else:
			self.architecture = forceArchitecture(architecture)

	def getArchitecture(self) -> str:
		return self.architecture

	def getClientId(self) -> str:
		return self.clientId

	def setClientId(self, clientId: str) -> None:
		self.clientId = forceHostId(clientId)

	def getUninstallString(self) -> str | None:
		return self.uninstallString

	def setUninstallString(self, uninstallString: str) -> None:
		self.uninstallString = forceString(uninstallString)

	def getBinaryName(self) -> str | None:
		return self.binaryName

	def setBinaryName(self, binaryName: str) -> None:
		self.binaryName = forceString(binaryName)

	def getFirstseen(self) -> str | None:
		return self.firstseen

	def setFirstseen(self, firstseen: str) -> None:
		self.firstseen = forceOpsiTimestamp(firstseen)

	def getLastseen(self) -> str | None:
		return self.lastseen

	def setLastseen(self, lastseen: str) -> None:
		self.lastseen = forceOpsiTimestamp(lastseen)

	def getState(self) -> int | None:
		return self.state

	def setState(self, state: int) -> None:
		self.state = forceAuditState(state)

	def getUsageFrequency(self) -> int | None:
		return self.usageFrequency

	def setUsageFrequency(self, usageFrequency: int) -> None:
		self.usageFrequency = forceInt(usageFrequency)

	def getLastUsed(self) -> str | None:
		return self.lastUsed

	def setLastUsed(self, lastUsed: str) -> None:
		self.lastUsed = forceOpsiTimestamp(lastUsed)

	def getLicenseKey(self) -> str | None:
		return self.licenseKey

	def setLicenseKey(self, licenseKey: str) -> None:
		self.licenseKey = forceString(licenseKey)


Relationship.sub_classes["AuditSoftwareOnClient"] = AuditSoftwareOnClient


class AuditHardware(Entity):
	sub_classes: dict[str, type] = {}
	foreign_id_attributes = Entity.foreign_id_attributes
	backend_method_prefix = "auditHardware"
	hardware_attributes: dict[str, dict[str, Any]] = {}

	def __init__(self, hardwareClass: str, **kwargs: Any) -> None:
		self.setHardwareClass(hardwareClass)
		attributes = self.hardware_attributes.get(hardwareClass, {})
		for attribute in attributes:
			if attribute not in kwargs:
				low_attr = attribute.lower()
				if low_attr in kwargs:
					kwargs[attribute] = kwargs[low_attr]
					del kwargs[low_attr]
				else:
					kwargs[attribute] = None

		if attributes:
			attribute_to_delete = set()
			for attribute, value in kwargs.items():
				attr_type = attributes.get(attribute)
				if not attr_type:
					attribute_to_delete.add(attribute)
					continue
				if value is None:
					continue

				if attr_type.startswith("varchar"):
					kwargs[attribute] = forceString(value).strip()
					try:
						size = int(attr_type.split("(")[1].split(")")[0].strip())

						if len(kwargs[attribute]) > size:
							logger.warning(
								"Truncating value of attribute %s of hardware class %s to length %d", attribute, hardwareClass, size
							)
							kwargs[attribute] = kwargs[attribute][:size].strip()
					except (ValueError, IndexError):
						pass
				elif "int" in attr_type:
					try:
						kwargs[attribute] = forceInt(value)
					except Exception as err:
						logger.trace(err)
						kwargs[attribute] = None
				elif attr_type == "double":
					try:
						kwargs[attribute] = forceFloat(value)
					except Exception as err:
						logger.trace(err)
						kwargs[attribute] = None
				else:
					raise BackendConfigurationError(
						f"Attribute '{attribute}' of hardware class '{hardwareClass}' has unknown type '{type}'"
					)

			for attribute in attribute_to_delete:
				del kwargs[attribute]
		else:
			new_kwargs = {}
			for attribute, value in kwargs.items():
				if isinstance(value, str):
					new_kwargs[attribute] = forceString(value).strip()
				else:
					new_kwargs[attribute] = value

			kwargs = new_kwargs
			del new_kwargs

		self.__dict__.update(kwargs)

		try:
			if getattr(self, "vendorId", None):
				self.vendorId = forceHardwareVendorId(self.vendorId)  # type: ignore[has-type]
		except AttributeError:
			pass

		try:
			if getattr(self, "subsystemVendorId", None):
				self.subsystemVendorId = forceHardwareVendorId(self.subsystemVendorId)  # type: ignore[has-type]
		except AttributeError:
			pass

		try:
			if getattr(self, "deviceId", None):
				self.deviceId = forceHardwareDeviceId(self.deviceId)  # type: ignore[has-type]
		except AttributeError:
			pass

		try:
			if getattr(self, "subsystemDeviceId", None):
				self.subsystemDeviceId = forceHardwareDeviceId(self.subsystemDeviceId)  # type: ignore[has-type]
		except AttributeError:
			pass

	@staticmethod
	def setHardwareConfig(hardwareConfig: list[dict[str, Any]]) -> None:
		hardware_attributes: dict[str, dict[str, Any]] = {}
		for config in hardwareConfig:
			hw_class = config["Class"]["Opsi"]
			hardware_attributes[hw_class] = {}
			for value in config["Values"]:
				if value["Scope"] == "g":
					hardware_attributes[hw_class][value["Opsi"]] = value["Type"]
		AuditHardware.hardware_attributes = hardware_attributes

	def setDefaults(self) -> None:
		Entity.setDefaults(self)

	def setHardwareClass(self, hardwareClass: str) -> None:
		self.hardwareClass = forceString(hardwareClass)

	def getHardwareClass(self) -> str:
		return self.hardwareClass

	def getIdentAttributes(self) -> tuple[str, ...]:
		return ("hardwareClass",) + tuple(sorted(self.hardware_attributes.get(self.hardwareClass, {})))

	@classmethod
	def fromHash(cls, _hash: dict[str, Any]) -> AuditHardware:
		if cls.copy_from_hash:
			_hash = _hash.copy()
		_hash.pop("type", None)
		return AuditHardware(**_hash)

	def __str__(self) -> str:
		infos = []
		hardware_class = self.getHardwareClass()
		if hardware_class:
			infos.append(f"hardwareClass={hardware_class}")

		try:
			infos.append(f"name='{self.name}'")  # type: ignore[attr-defined]
		except AttributeError:
			pass

		try:
			if self.vendorId:
				infos.append(f"vendorId='{self.vendorId}'")
		except AttributeError:
			pass

		try:
			if self.subsystemVendorId:
				infos.append(f"subsystemVendorId='{self.subsystemVendorId}'")
		except AttributeError:
			pass

		try:
			if self.deviceId:
				infos.append(f"deviceId='{self.deviceId}'")
		except AttributeError:
			pass

		try:
			if self.subsystemDeviceId:
				infos.append(f"subsystemDeviceId='{self.subsystemDeviceId}'")
		except AttributeError:
			pass

		return f"<{self.__class__.__name__}({', '.join(infos)})>"


Entity.sub_classes["AuditHardware"] = AuditHardware


class AuditHardwareOnHost(Relationship):
	sub_classes: dict[str, type] = {}
	backend_method_prefix = "auditHardwareOnHost"
	hardware_attributes: dict[str, dict[str, Any]] = {}

	def __init__(
		self,
		hardwareClass: str,
		hostId: str,
		firstseen: str | None = None,
		lastseen: str | None = None,
		state: int | None = None,
		**kwargs: Any,
	) -> None:
		self.firstseen: str | None = None
		self.lastseen: str | None = None
		self.state: int | None = None
		self.setHostId(hostId)
		self.setHardwareClass(hardwareClass)

		for attribute in self.hardware_attributes.get(hardwareClass, {}):
			if attribute not in kwargs:
				lower_attribute = attribute.lower()
				if lower_attribute in kwargs:
					kwargs[attribute] = kwargs[lower_attribute]
					del kwargs[lower_attribute]
				else:
					kwargs[attribute] = None

		if self.hardware_attributes.get(hardwareClass):
			for attribute, value in list(kwargs.items()):
				attr_type = self.hardware_attributes[hardwareClass].get(attribute)
				if not attr_type:
					del kwargs[attribute]
					continue
				if value is None:
					continue

				if attr_type.startswith("varchar"):
					kwargs[attribute] = forceString(value).strip()
					try:
						size = int(attr_type.split("(")[1].split(")")[0].strip())

						if len(kwargs[attribute]) > size:
							logger.warning(
								"Truncating value of attribute %s of hardware class %s to length %d", attribute, hardwareClass, size
							)
							kwargs[attribute] = kwargs[attribute][:size].strip()
					except (ValueError, IndexError):
						pass
				elif "int" in attr_type:
					try:
						kwargs[attribute] = forceInt(value)
					except Exception as err:
						logger.trace(err)
						kwargs[attribute] = None
				elif attr_type == "double":
					try:
						kwargs[attribute] = forceFloat(value)
					except Exception as err:
						logger.trace(err)
						kwargs[attribute] = None
				else:
					raise BackendConfigurationError(
						f"Attribute '{attribute}' of hardware class '{hardwareClass}' has unknown type '{type}'"
					)
		else:
			for attribute, value in kwargs.items():
				if isinstance(value, str):
					kwargs[attribute] = forceString(value).strip()

		self.__dict__.update(kwargs)
		if firstseen is not None:
			self.setFirstseen(firstseen)
		if lastseen is not None:
			self.setLastseen(lastseen)
		if state is not None:
			self.setState(state)

		try:
			if getattr(self, "vendorId", None):
				self.vendorId = forceHardwareVendorId(self.vendorId)  # type: ignore[has-type]
		except AttributeError:
			pass

		try:
			if getattr(self, "subsystemVendorId", None):
				self.subsystemVendorId = forceHardwareVendorId(self.subsystemVendorId)  # type: ignore[has-type]
		except AttributeError:
			pass

		try:
			if getattr(self, "deviceId", None):
				self.deviceId = forceHardwareDeviceId(self.deviceId)  # type: ignore[has-type]
		except AttributeError:
			pass

		try:
			if getattr(self, "subsystemDeviceId", None):
				self.subsystemDeviceId = forceHardwareDeviceId(self.subsystemDeviceId)  # type: ignore[has-type]
		except AttributeError:
			pass

	@staticmethod
	def setHardwareConfig(hardwareConfig: list[dict[str, Any]]) -> None:
		hardware_attributes: dict[str, dict[str, Any]] = {}
		for config in hardwareConfig:
			hw_class = config["Class"]["Opsi"]
			hardware_attributes[hw_class] = {}
			for value in config["Values"]:
				hardware_attributes[hw_class][value["Opsi"]] = value["Type"]
		AuditHardwareOnHost.hardware_attributes = hardware_attributes

	def setDefaults(self) -> None:
		Relationship.setDefaults(self)
		if self.firstseen is None:
			self.setFirstseen(timestamp())
		if self.lastseen is None:
			self.setLastseen(timestamp())
		if self.state is None:
			self.setState(1)

	def getHostId(self) -> str:
		return self.hostId

	def setHostId(self, hostId: str) -> None:
		self.hostId = forceHostId(hostId)

	def setHardwareClass(self, hardwareClass: str) -> None:
		self.hardwareClass = forceString(hardwareClass)

	def getHardwareClass(self) -> str:
		return self.hardwareClass

	def getFirstseen(self) -> str | None:
		return self.firstseen

	def setFirstseen(self, firstseen: str) -> None:
		self.firstseen = forceOpsiTimestamp(firstseen)

	def getLastseen(self) -> str | None:
		return self.firstseen

	def setLastseen(self, lastseen: str) -> None:
		self.lastseen = forceOpsiTimestamp(lastseen)

	def getState(self) -> int | None:
		return self.state

	def setState(self, state: int) -> None:
		self.state = forceAuditState(state)

	def toAuditHardware(self) -> AuditHardware:
		audit_hardware_hash = {"type": "AuditHardware"}
		attributes = set(AuditHardware.hardware_attributes.get(self.getHardwareClass(), {}).keys())

		for attribute, value in self.toHash().items():
			if attribute == "type":
				continue

			if attribute == "hardwareClass":
				audit_hardware_hash[attribute] = value
				continue

			if attribute in attributes:
				audit_hardware_hash[attribute] = value

		return AuditHardware.fromHash(audit_hardware_hash)

	def getIdentAttributes(self) -> tuple[str, ...]:
		return ("hostId", "hardwareClass") + tuple(sorted(self.hardware_attributes.get(self.hardwareClass, {})))

	@classmethod
	def fromHash(cls, _hash: dict[str, Any]) -> AuditHardwareOnHost:
		if cls.copy_from_hash:
			_hash = _hash.copy()
		_hash.pop("type", None)
		return AuditHardwareOnHost(**_hash)

	def __str__(self) -> str:
		additional = [f"hostId='{self.hostId}'"]
		hardware_class = self.getHardwareClass()
		if hardware_class:
			additional.append(f"hardwareClass={hardware_class}")

		try:
			additional.append(f"name='{self.name}'")  # type: ignore[attr-defined]
		except AttributeError:
			pass

		return f"<{self.getType()}({', '.join(additional)})>"


Relationship.sub_classes["AuditHardwareOnHost"] = AuditHardwareOnHost

OBJECT_CLASSES = {name: cls for (name, cls) in globals().items() if isinstance(cls, type) and issubclass(cls, BaseObject)}


@lru_cache()
def get_object_type(object_type: str) -> Type[BaseObject]:
	return OBJECT_CLASSES[object_type]


def serialize(obj: Any, deep: bool = False) -> Any:
	# This is performance critical!
	if isinstance(obj, (list, set, GeneratorType)):
		return [serialize(o, deep) for o in obj]
	if isinstance(obj, BaseObject):
		return obj.serialize()
	if not deep:
		return obj
	if isinstance(obj, dict):
		return {k: serialize(v, deep) for k, v in obj.items()}
	return obj


def deserialize(obj: Any, deep: bool = False, prevent_object_creation: bool = False) -> Any:
	# This is performance critical!
	if isinstance(obj, list):
		return [deserialize(o, deep=deep, prevent_object_creation=prevent_object_creation) for o in obj]
	if isinstance(obj, dict):
		if not prevent_object_creation:
			try:
				obj_type = get_object_type(obj["type"])
				return obj_type.fromHash(obj)  # type: ignore[union-attr]
			except KeyError:
				pass
			except Exception as err:
				logger.error(err, exc_info=True)
				raise ValueError(f"Failed to create object from dict {obj}: {err}") from err
		if deep:
			return {k: deserialize(v, deep=deep, prevent_object_creation=prevent_object_creation) for k, v in obj.items()}
	return obj


json_decoder = msgspec.json.Decoder()
json_encoder = msgspec.json.Encoder()


def from_json(obj: str | bytes, object_type: str | None = None, prevent_object_creation: bool = False) -> Any:
	if isinstance(obj, str):
		obj = obj.encode("utf-8")
	obj = json_decoder.decode(obj)
	if isinstance(obj, dict) and object_type:
		obj["type"] = object_type
	return deserialize(obj, prevent_object_creation=prevent_object_creation)


def to_json(obj: Any, deep: bool = False) -> str:
	return json_encoder.encode(serialize(obj, deep=deep)).decode("utf-8")
