# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
General classes used in the library.

As an example this contains classes for hosts, products, configurations.
"""

# pylint: disable=too-many-lines

import inspect

from opsicommon.logging import logger
from opsicommon.exceptions import BackendBadValueError, BackendConfigurationError
from opsicommon.types import (
	forceActionProgress, forceActionRequest,
	forceActionResult, forceArchitecture, forceAuditState, forceBool,
	forceBoolList, forceConfigId, forceFilename, forceFloat, forceGroupId,
	forceGroupType, forceHardwareAddress, forceHardwareDeviceId,
	forceHardwareVendorId, forceHostId, forceInstallationStatus, forceInt,
	forceIPAddress, forceLanguageCode, forceLicenseContractId,
	forceLicensePoolId, forceList, forceNetworkAddress, forceObjectId,
	forceOpsiHostKey, forceOpsiTimestamp, forcePackageVersion, forceProductId,
	forceProductIdList, forceProductPriority, forceProductPropertyId,
	forceProductTargetConfiguration, forceProductType, forceProductVersion,
	forceRequirementType, forceSoftwareLicenseId, forceUnicode,
	forceUnicodeList, forceUnicodeLower, forceUnsignedInt, forceUrl
)
from opsicommon.utils import (
	combine_versions, from_json, to_json, generate_opsi_host_key, timestamp
)

__all__ = (
	"AuditHardware", "AuditHardwareOnHost", "AuditSoftware",
	"AuditSoftwareOnClient", "AuditSoftwareToLicensePool", "BaseObject",
	"BoolConfig", "BoolProductProperty", "ConcurrentSoftwareLicense",
	"Config", "ConfigState", "Entity", "Group", "Host", "HostGroup",
	"LicenseContract", "LicenseOnClient", "LicensePool", "LocalbootProduct",
	"NetbootProduct", "OEMSoftwareLicense", "Object", "ObjectToGroup",
	"OpsiClient", "OpsiConfigserver", "OpsiDepotserver", "Product",
	"ProductDependency", "ProductGroup", "ProductOnClient", "ProductOnDepot",
	"ProductProperty", "ProductPropertyState", "Relationship",
	"RetailSoftwareLicense", "SoftwareLicense", "SoftwareLicenseToLicensePool",
	"UnicodeConfig", "UnicodeProductProperty", "VolumeSoftwareLicense",
	"decode_ident", "get_backend_method_prefix", "get_foreign_id_attributes",
	"get_ident_attributes", "get_possible_class_attributes",
	"mandatory_constructor_args", "objects_differ",
	"OBJECT_CLASSES"
)

_MANDATORY_CONSTRUCTOR_ARGS_CACHE = {}


def mandatory_constructor_args(_class):
	cache_key = _class.__name__
	if not cache_key in _MANDATORY_CONSTRUCTOR_ARGS_CACHE:
		spec = inspect.getfullargspec(_class.__init__)
		args = spec.args
		defaults = spec.defaults
		mandatory = None
		if defaults is None:
			mandatory = args[1:]
		else:
			last = len(defaults) * -1
			mandatory = args[1:][:last]
		logger.trace("mandatory_constructor_args for %s: %s", cache_key, mandatory)
		_MANDATORY_CONSTRUCTOR_ARGS_CACHE[cache_key] = mandatory
	return _MANDATORY_CONSTRUCTOR_ARGS_CACHE[cache_key]


def get_ident_attributes(_class):
	return tuple(mandatory_constructor_args(_class))


def get_foreign_id_attributes(_class):
	return _class.foreign_id_attributes


def get_possible_class_attributes(_class):
	"""
	Returns the possible attributes of a class.

	:rtype: set of strings
	"""
	attributes = inspect.getfullargspec(_class.__init__).args
	for sub_class in _class.sub_classes.values():
		attributes.extend(inspect.getfullargspec(sub_class.__init__).args)

	attributes = set(attributes)
	attributes.add('type')

	try:
		attributes.remove('self')
	except KeyError:
		pass

	return attributes


def get_backend_method_prefix(_class):
	return _class.backend_method_prefix


def decode_ident(_class, _hash):
	if not "ident" in _hash:
		return _hash

	ident = _hash.pop('ident')
	if not isinstance(ident, dict):
		ident_keys = mandatory_constructor_args(_class)
		ident_values = []
		if isinstance(ident, str):
			ident_values = ident.split(_class.ident_separator)
		elif isinstance(ident, (tuple, list)):
			ident_values = ident

		if len(ident_values) != len(ident_keys):
			raise ValueError(
				f"Ident {ident} does not match class '{_class}' constructor arguments {ident_keys}"
			)
		ident = dict(zip(ident_keys, ident_values))

	_hash.update(ident)
	return _hash


def objects_differ(obj1, obj2, exclude_attributes=None):  # pylint: disable=too-many-return-statements,too-many-branches
	if exclude_attributes is None:
		exclude_attributes = []
	else:
		exclude_attributes = forceUnicodeList(exclude_attributes)

	if obj1 != obj2:
		return True

	obj2 = obj2.toHash()
	for (attribute, value1) in obj1.toHash().items():
		if attribute in exclude_attributes:
			continue

		value2 = obj2.get(attribute)

		if type(value1) is not type(value2):
			return True

		if isinstance(value1, dict):
			if len(value1) != len(value2):
				return True

			for (key, value) in value1.items():
				if value2.get(key) != value:
					return True
		elif isinstance(value1, list):
			if len(value1) != len(value2):
				return True

			for value in value1:
				if value not in value2:
					return True

			for value in value2:
				if value not in value1:
					return True
		else:
			if value1 != value2:
				return True
	return False


class classproperty:  # pylint: disable=invalid-name,too-few-public-methods
	def __init__(self, fget):
		self.fget = fget

	def __get__(self, owner_self, owner_cls):  # pylint: disable=unused-argument
		return self.fget(owner_cls)

class BaseObject:
	sub_classes = {}
	ident_separator = ';'
	foreign_id_attributes = []
	backend_method_prefix = ''
	_is_generated_default = False

	@classproperty
	def subClasses(cls):  # pylint: disable=invalid-name,no-self-argument
		return cls.sub_classes

	@classproperty
	def identSeparator(cls):  # pylint: disable=invalid-name,no-self-argument
		return cls.ident_separator

	@classproperty
	def foreignIdAttributes(cls):  # pylint: disable=invalid-name,no-self-argument
		return cls.foreign_id_attributes

	@classproperty
	def backendMethodPrefix(cls):  # pylint: disable=invalid-name,no-self-argument
		return cls.backend_method_prefix

	def getBackendMethodPrefix(self):  # pylint: disable=invalid-name
		return self.backend_method_prefix

	def getForeignIdAttributes(self):  # pylint: disable=invalid-name
		return self.foreign_id_attributes

	def getIdentAttributes(self):  # pylint: disable=invalid-name
		return get_ident_attributes(self.__class__)

	def getIdent(self, returnType='unicode'):  # pylint: disable=invalid-name
		returnType = forceUnicodeLower(returnType)
		ident_attributes = self.getIdentAttributes()

		def get_ident_value(attribute):
			try:
				value = getattr(self, attribute)
				if value is None:
					value = ''

				return value
			except AttributeError:
				return ''

		ident_values = [forceUnicode(get_ident_value(attribute)) for attribute in ident_attributes]

		if returnType == 'list':
			return ident_values
		if returnType == 'tuple':
			return tuple(ident_values)
		if returnType in ('dict', 'hash'):
			return dict(zip(ident_attributes, ident_values))
		return self.ident_separator.join(ident_values)

	def setDefaults(self):  # pylint: disable=invalid-name
		pass

	def emptyValues(self, keepAttributes=None):  # pylint: disable=invalid-name
		keepAttributes = set(forceUnicodeList(keepAttributes or []))
		for attribute in self.getIdentAttributes():
			keepAttributes.add(attribute)
		keepAttributes.add('type')

		for attribute in self.__dict__:
			if attribute not in keepAttributes:
				self.__dict__[attribute] = None

	def update(self, updateObject, updateWithNoneValues=True):  # pylint: disable=invalid-name
		if not issubclass(updateObject.__class__, self.__class__):
			raise TypeError(
				f"Cannot update instance of {self.__class__.__name__} with instance of {updateObject.__class__.__name__}"
			)
		object_hash = updateObject.toHash()

		try:
			del object_hash['type']
		except KeyError:
			# No key "type", everything fine.
			pass

		if not updateWithNoneValues:
			to_delete = set(
				key for (key, value)
				in object_hash.items()
				if value is None
			)

			for key in to_delete:
				del object_hash[key]

		self.__dict__.update(object_hash)

	def getType(self):  # pylint: disable=invalid-name
		return self.__class__.__name__

	def setGeneratedDefault(self, flag=True):  # pylint: disable=invalid-name
		self._is_generated_default = forceBool(flag)

	def isGeneratedDefault(self):  # pylint: disable=invalid-name
		return self._is_generated_default

	def toHash(self):  # pylint: disable=invalid-name
		object_hash = dict(self.__dict__)
		object_hash['type'] = self.getType()
		return object_hash

	def to_json(self):
		return to_json(self)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return False
		if self.isGeneratedDefault() or other.isGeneratedDefault():
			return False
		return self.getIdent() == other.getIdent()

	def __hash__(self):
		def get_ident_value(attribute):
			try:
				value = getattr(self, attribute)
				if value is None:
					value = ''
				return value
			except AttributeError:
				return ''

		ident_values = tuple(get_ident_value(attribute) for attribute in self.getIdentAttributes())
		return hash(ident_values)

	def __ne__(self, other):
		return not self.__eq__(other)

	def __str__(self):
		additional_attributes = []
		for attr in self.getIdentAttributes():
			try:
				value = getattr(self, attr)
				additional_attributes.append(f"{attr}='{value}'")
			except AttributeError:
				pass

		return f"<{self.getType()}({', '.join(additional_attributes)})>"

	def __repr__(self):
		return self.__str__()


class Entity(BaseObject):
	sub_classes = {}

	def setDefaults(self):
		BaseObject.setDefaults(self)

	@staticmethod
	def fromHash(_hash):  # pylint: disable=invalid-name
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'Entity'

		cls = eval(_hash['type'])  # pylint: disable=eval-used
		kwargs = {}
		decode_ident(cls, _hash)
		for varname in cls.__init__.__code__.co_varnames[1:]:
			try:
				kwargs[varname] = _hash[varname]
			except KeyError:
				pass

		try:
			return cls(**kwargs)
		except TypeError as err:
			if '__init__() takes at least' in forceUnicode(err):
				try:
					args = mandatory_constructor_args(cls)
					missing_args = [arg for arg in args if arg not in kwargs]
					if missing_args:
						raise TypeError(
							f"Missing required argument(s): {', '.join(repr(a) for a in missing_args)}"
						 ) from err
				except NameError:
					pass

			raise err

	def clone(self, identOnly=False):  # pylint: disable=invalid-name
		_hash = {}

		if identOnly:
			ident_attributes = self.getIdentAttributes()
			for (attribute, value) in self.toHash().items():
				if attribute != 'type' and attribute not in ident_attributes:
					continue
				_hash[attribute] = value
		else:
			_hash = self.toHash()

		return self.fromHash(_hash)

	def serialize(self):
		_hash = self.toHash()
		_hash['ident'] = self.getIdent()
		return _hash

	@staticmethod
	def from_json(jsonString):  # pylint: disable=invalid-name
		return from_json(jsonString, 'Entity')


BaseObject.sub_classes['Entity'] = Entity


class Relationship(BaseObject):
	sub_classes = {}

	def setDefaults(self):
		BaseObject.setDefaults(self)

	@staticmethod
	def fromHash(_hash):  # pylint: disable=invalid-name
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'Relationship'

		cls = eval(_hash['type'])  # pylint: disable=eval-used
		kwargs = {}
		decode_ident(cls, _hash)
		for varname in cls.__init__.__code__.co_varnames[1:]:
			try:
				kwargs[varname] = _hash[varname]
			except KeyError:
				pass

		try:
			return cls(**kwargs)
		except TypeError as err:
			if '__init__() takes at least' in str(err):
				try:
					args = mandatory_constructor_args(cls)
					missing_args = [arg for arg in args if arg not in kwargs]
					if missing_args:
						raise TypeError(
							f"Missing required argument(s): {', '.join(repr(a) for a in missing_args)}"
						) from err
				except NameError:
					pass

			raise err

	def clone(self, identOnly=False):  # pylint: disable=invalid-name
		_hash = {}
		if identOnly:
			ident_attributes = self.getIdentAttributes()
			for (attribute, value) in self.toHash().items():
				if attribute != 'type' and attribute not in ident_attributes:
					continue
				_hash[attribute] = value
		else:
			_hash = self.toHash()
		return self.fromHash(_hash)

	def serialize(self):
		_hash = self.toHash()
		_hash['type'] = self.getType()
		_hash['ident'] = self.getIdent()
		return _hash

	@staticmethod
	def from_json(jsonString):  # pylint: disable=invalid-name
		return from_json(jsonString, 'Relationship')


BaseObject.sub_classes['Relationship'] = Relationship


class Object(Entity):
	sub_classes = {}
	foreign_id_attributes = Entity.foreign_id_attributes + ['objectId']

	def __init__(self, id, description=None, notes=None):  # pylint: disable=redefined-builtin,invalid-name
		self.description = None
		self.notes = None
		self.setId(id)
		if description is not None:
			self.setDescription(description)
		if notes is not None:
			self.setNotes(notes)

	def setDefaults(self):
		Entity.setDefaults(self)
		if self.description is None:
			self.setDescription("")
		if self.notes is None:
			self.setNotes("")

	def getId(self):  # pylint: disable=invalid-name
		return self.id

	def setId(self, id):  # pylint: disable=redefined-builtin,invalid-name
		self.id = forceObjectId(id)  # pylint: disable=invalid-name

	def getDescription(self):  # pylint: disable=invalid-name
		return self.description

	def setDescription(self, description):  # pylint: disable=invalid-name
		self.description = forceUnicode(description)

	def getNotes(self):  # pylint: disable=invalid-name
		return self.notes

	def setNotes(self, notes):  # pylint: disable=invalid-name
		self.notes = forceUnicode(notes)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'Object'

		return Entity.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'Object')


Entity.sub_classes['Object'] = Object


class Host(Object):
	sub_classes = {}
	foreign_id_attributes = Object.foreign_id_attributes + ['hostId']
	backend_method_prefix = 'host'

	def __init__(  # pylint: disable=too-many-arguments
		self, id, description=None, notes=None, hardwareAddress=None,  # pylint: disable=redefined-builtin
		ipAddress=None, inventoryNumber=None
	):
		Object.__init__(self, id, description, notes)
		self.hardwareAddress = None  # pylint: disable=invalid-name
		self.ipAddress = None  # pylint: disable=invalid-name
		self.inventoryNumber = None  # pylint: disable=invalid-name
		self.setId(id)

		if hardwareAddress is not None:
			self.setHardwareAddress(hardwareAddress)
		if ipAddress is not None:
			self.setIpAddress(ipAddress)
		if inventoryNumber is not None:
			self.setInventoryNumber(inventoryNumber)

	def setDefaults(self):
		Object.setDefaults(self)
		if self.inventoryNumber is None:
			self.setInventoryNumber("")

	def setId(self, id):  # pylint: disable=redefined-builtin
		self.id = forceHostId(id)

	def getHardwareAddress(self):  # pylint: disable=invalid-name
		return self.hardwareAddress

	def setHardwareAddress(self, hardwareAddress):  # pylint: disable=invalid-name
		self.hardwareAddress = forceHardwareAddress(forceList(hardwareAddress)[0])

	def getIpAddress(self):  # pylint: disable=invalid-name
		return self.ipAddress

	def setIpAddress(self, ipAddress):  # pylint: disable=invalid-name
		try:
			self.ipAddress = forceIPAddress(ipAddress)
		except ValueError as err:
			logger.error(
				"Failed to set ip address '%s' for host %s: %s",
				ipAddress, self.id, err
			)
			self.ipAddress = None

	def getInventoryNumber(self):  # pylint: disable=invalid-name
		return self.inventoryNumber

	def setInventoryNumber(self, inventoryNumber):  # pylint: disable=invalid-name
		self.inventoryNumber = forceUnicode(inventoryNumber)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'Host'

		return Object.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'Host')


Object.sub_classes['Host'] = Host


class OpsiClient(Host):
	sub_classes = {}
	foreign_id_attributes = Host.foreign_id_attributes + ['clientId']

	def __init__(  # pylint: disable=too-many-arguments
		self, id, opsiHostKey=None, description=None, notes=None,  # pylint: disable=redefined-builtin
		hardwareAddress=None, ipAddress=None, inventoryNumber=None,
		oneTimePassword=None, created=None, lastSeen=None
	):

		Host.__init__(self, id, description, notes, hardwareAddress, ipAddress,
			inventoryNumber)
		self.opsiHostKey = None  # pylint: disable=invalid-name
		self.created = None  # pylint: disable=invalid-name
		self.lastSeen = None  # pylint: disable=invalid-name
		self.oneTimePassword = None  # pylint: disable=invalid-name

		if opsiHostKey is not None:
			self.setOpsiHostKey(opsiHostKey)
		if created is not None:
			self.setCreated(created)
		if lastSeen is not None:
			self.setLastSeen(lastSeen)
		if oneTimePassword is not None:
			self.setOneTimePassword(oneTimePassword)

	def setDefaults(self):
		Host.setDefaults(self)
		if self.opsiHostKey is None:
			self.setOpsiHostKey(generate_opsi_host_key())
		if self.created is None:
			self.setCreated(timestamp())
		if self.lastSeen is None:
			self.setLastSeen(timestamp())

	def getLastSeen(self):  # pylint: disable=invalid-name
		return self.lastSeen

	def setLastSeen(self, lastSeen):  # pylint: disable=invalid-name
		self.lastSeen = forceOpsiTimestamp(lastSeen)

	def getCreated(self):  # pylint: disable=invalid-name
		return self.created

	def setCreated(self, created):  # pylint: disable=invalid-name
		self.created = forceOpsiTimestamp(created)

	def getOpsiHostKey(self):  # pylint: disable=invalid-name
		return self.opsiHostKey

	def setOpsiHostKey(self, opsiHostKey):  # pylint: disable=invalid-name
		self.opsiHostKey = forceOpsiHostKey(opsiHostKey)

	def getOneTimePassword(self):  # pylint: disable=invalid-name
		return self.oneTimePassword

	def setOneTimePassword(self, oneTimePassword):  # pylint: disable=invalid-name
		self.oneTimePassword = forceUnicode(oneTimePassword)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'OpsiClient'

		return Host.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'OpsiClient')


Host.sub_classes['OpsiClient'] = OpsiClient


class OpsiDepotserver(Host):  # pylint: disable=too-many-instance-attributes,too-many-public-methods
	sub_classes = {}
	foreign_id_attributes = Host.foreign_id_attributes + ['depotId']

	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self, id, opsiHostKey=None, depotLocalUrl=None,  # pylint: disable=redefined-builtin
		depotRemoteUrl=None, depotWebdavUrl=None,
		repositoryLocalUrl=None, repositoryRemoteUrl=None,
		description=None, notes=None, hardwareAddress=None,
		ipAddress=None, inventoryNumber=None, networkAddress=None,
		maxBandwidth=None, isMasterDepot=None, masterDepotId=None,
		workbenchLocalUrl=None, workbenchRemoteUrl=None
	):

		Host.__init__(
			self, id, description, notes, hardwareAddress, ipAddress,
			inventoryNumber)

		self.opsiHostKey = None  # pylint: disable=invalid-name
		self.depotLocalUrl = None  # pylint: disable=invalid-name
		self.depotRemoteUrl = None  # pylint: disable=invalid-name
		self.depotWebdavUrl = None  # pylint: disable=invalid-name
		self.repositoryLocalUrl = None  # pylint: disable=invalid-name
		self.repositoryRemoteUrl = None  # pylint: disable=invalid-name
		self.networkAddress = None  # pylint: disable=invalid-name
		self.maxBandwidth = None  # pylint: disable=invalid-name
		self.isMasterDepot = None  # pylint: disable=invalid-name
		self.masterDepotId = None  # pylint: disable=invalid-name
		self.workbenchLocalUrl = None  # pylint: disable=invalid-name
		self.workbenchRemoteUrl = None  # pylint: disable=invalid-name

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

	def setDefaults(self):
		Host.setDefaults(self)
		if self.opsiHostKey is None:
			self.setOpsiHostKey(generate_opsi_host_key())
		if self.isMasterDepot is None:
			self.setIsMasterDepot(True)

	def getOpsiHostKey(self):  # pylint: disable=invalid-name
		return self.opsiHostKey

	def setOpsiHostKey(self, opsiHostKey):  # pylint: disable=invalid-name
		self.opsiHostKey = forceOpsiHostKey(opsiHostKey)

	def getDepotLocalUrl(self):  # pylint: disable=invalid-name
		return self.depotLocalUrl

	def setDepotLocalUrl(self, depotLocalUrl):  # pylint: disable=invalid-name
		self.depotLocalUrl = forceUrl(depotLocalUrl)

	def getDepotRemoteUrl(self):  # pylint: disable=invalid-name
		return self.depotRemoteUrl

	def setDepotWebdavUrl(self, depotWebdavUrl):  # pylint: disable=invalid-name
		self.depotWebdavUrl = forceUrl(depotWebdavUrl)

	def getDepotWebdavUrl(self):  # pylint: disable=invalid-name
		return self.depotWebdavUrl

	def setDepotRemoteUrl(self, depotRemoteUrl):  # pylint: disable=invalid-name
		self.depotRemoteUrl = forceUrl(depotRemoteUrl)

	def getRepositoryLocalUrl(self):  # pylint: disable=invalid-name
		return self.repositoryLocalUrl

	def setRepositoryLocalUrl(self, repositoryLocalUrl):  # pylint: disable=invalid-name
		self.repositoryLocalUrl = forceUrl(repositoryLocalUrl)

	def getRepositoryRemoteUrl(self):  # pylint: disable=invalid-name
		return self.repositoryRemoteUrl

	def setRepositoryRemoteUrl(self, repositoryRemoteUrl):  # pylint: disable=invalid-name
		self.repositoryRemoteUrl = forceUrl(repositoryRemoteUrl)

	def getNetworkAddress(self):  # pylint: disable=invalid-name
		return self.networkAddress

	def setNetworkAddress(self, networkAddress):  # pylint: disable=invalid-name
		try:
			self.networkAddress = forceNetworkAddress(networkAddress)
		except ValueError as err:
			logger.error(
				"Failed to set network address '%s' for depot %s: %s",
				networkAddress, self.id, err
			)
			self.networkAddress = None

	def getMaxBandwidth(self):  # pylint: disable=invalid-name
		return self.maxBandwidth

	def setMaxBandwidth(self, maxBandwidth):  # pylint: disable=invalid-name
		self.maxBandwidth = forceInt(maxBandwidth)

	def setIsMasterDepot(self, isMasterDepot):  # pylint: disable=invalid-name
		self.isMasterDepot = forceBool(isMasterDepot)

	def getIsMasterDepot(self):  # pylint: disable=invalid-name
		return self.isMasterDepot

	def setMasterDepotId(self, masterDepotId):  # pylint: disable=invalid-name
		self.masterDepotId = forceHostId(masterDepotId)

	def getMasterDepotId(self):  # pylint: disable=invalid-name
		return self.masterDepotId

	def setWorkbenchLocalUrl(self, value):  # pylint: disable=invalid-name
		self.workbenchLocalUrl = forceUrl(value)

	def getWorkbenchLocalUrl(self):  # pylint: disable=invalid-name
		return self.workbenchLocalUrl

	def setWorkbenchRemoteUrl(self, value):  # pylint: disable=invalid-name
		self.workbenchRemoteUrl = forceUrl(value)

	def getWorkbenchRemoteUrl(self):  # pylint: disable=invalid-name
		return self.workbenchRemoteUrl

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'OpsiDepotserver'
		return Host.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'OpsiDepotserver')

	def __str__(self):
		additional_infos = [f"id='{self.id}'"]
		if self.isMasterDepot:
			additional_infos.append(f"isMasterDepot={self.isMasterDepot}")
		if self.masterDepotId:
			additional_infos.append(f"masterDepotId='{self.masterDepotId}'")

		return f"<{self.getType()}({', '.join(additional_infos)})>"


Host.sub_classes['OpsiDepotserver'] = OpsiDepotserver


class OpsiConfigserver(OpsiDepotserver):
	sub_classes = {}
	foreign_id_attributes = OpsiDepotserver.foreign_id_attributes + ['serverId']

	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self, id, opsiHostKey=None, depotLocalUrl=None,  # pylint: disable=redefined-builtin
		depotRemoteUrl=None, depotWebdavUrl=None,
		repositoryLocalUrl=None, repositoryRemoteUrl=None,
		description=None, notes=None, hardwareAddress=None,
		ipAddress=None, inventoryNumber=None, networkAddress=None,
		maxBandwidth=None, isMasterDepot=None, masterDepotId=None,
		workbenchLocalUrl=None, workbenchRemoteUrl=None
	):
		OpsiDepotserver.__init__(
			self, id, opsiHostKey, depotLocalUrl,
			depotRemoteUrl, depotWebdavUrl, repositoryLocalUrl,
			repositoryRemoteUrl, description, notes, hardwareAddress,
			ipAddress, inventoryNumber, networkAddress, maxBandwidth,
			isMasterDepot, masterDepotId,
			workbenchLocalUrl, workbenchRemoteUrl)

	def setDefaults(self):
		if self.isMasterDepot is None:
			self.setIsMasterDepot(True)
		OpsiDepotserver.setDefaults(self)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'OpsiConfigserver'

		return OpsiDepotserver.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'OpsiConfigserver')


OpsiDepotserver.sub_classes['OpsiConfigserver'] = OpsiConfigserver
Host.sub_classes['OpsiConfigserver'] = OpsiConfigserver


class Config(Entity):
	sub_classes = {}
	foreign_id_attributes = Object.foreign_id_attributes + ['configId']
	backend_method_prefix = 'config'

	def __init__(  # pylint: disable=too-many-arguments
		self, id, description=None, possibleValues=None,  # pylint: disable=redefined-builtin,invalid-name
		defaultValues=None, editable=None, multiValue=None  # pylint: disable=invalid-name
	):
		self.description = None
		self.possibleValues = None  # pylint: disable=invalid-name
		self.defaultValues = None  # pylint: disable=invalid-name
		self.editable = None
		self.multiValue = None  # pylint: disable=invalid-name

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

	def setDefaults(self):
		Entity.setDefaults(self)
		if self.editable is None:
			self.editable = True
		if self.multiValue is None:
			self.multiValue = False
		if self.possibleValues is None:
			self.possibleValues = []
		if self.defaultValues is None:
			self.defaultValues = []

	def getId(self):  # pylint: disable=invalid-name
		return self.id

	def setId(self, id):  # pylint: disable=redefined-builtin,invalid-name
		self.id = forceConfigId(id)  # pylint: disable=invalid-name

	def getDescription(self):  # pylint: disable=invalid-name
		return self.description

	def setDescription(self, description):  # pylint: disable=invalid-name
		self.description = forceUnicode(description)

	def _updateValues(self):  # pylint: disable=invalid-name
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

	def getPossibleValues(self):  # pylint: disable=invalid-name
		return self.possibleValues

	def setPossibleValues(self, possibleValues):  # pylint: disable=invalid-name
		self.possibleValues = list(set(forceList(possibleValues)))
		self._updateValues()

	def getDefaultValues(self):  # pylint: disable=invalid-name
		return self.defaultValues

	def setDefaultValues(self, defaultValues):  # pylint: disable=invalid-name
		self.defaultValues = list(set(forceList(defaultValues)))
		self._updateValues()

	def getEditable(self):  # pylint: disable=invalid-name
		return self.editable

	def setEditable(self, editable):  # pylint: disable=invalid-name
		self.editable = forceBool(editable)

	def getMultiValue(self):  # pylint: disable=invalid-name
		return self.multiValue

	def setMultiValue(self, multiValue):  # pylint: disable=invalid-name
		self.multiValue = forceBool(multiValue)
		if self.defaultValues is not None and len(self.defaultValues) > 1:
			self.multiValue = True

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'Config'

		return Entity.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'Config')

	def __str__(self):
		return (
			f"<{self.getType()}(id='{self.id}', description='{self.description}', "
			f"possibleValues={self.possibleValues}, defaultValues={self.defaultValues}, "
			f"editable={self.editable}, multiValue={self.multiValue})>"
		)


Entity.sub_classes['Config'] = Config


class UnicodeConfig(Config):
	sub_classes = {}

	def __init__(  # pylint: disable=too-many-arguments
		self, id, description='', possibleValues=None,  # pylint: disable=redefined-builtin
		defaultValues=None, editable=None, multiValue=None
	):

		Config.__init__(self, id, description, possibleValues, defaultValues,
			editable, multiValue)

		if possibleValues is not None:
			self.setPossibleValues(possibleValues)
		if defaultValues is not None:
			self.setDefaultValues(defaultValues)

	def setDefaults(self):
		if self.possibleValues is None:
			self.possibleValues = ['']
		if self.defaultValues is None:
			self.defaultValues = ['']
		Config.setDefaults(self)

	def setPossibleValues(self, possibleValues):
		Config.setPossibleValues(self, forceUnicodeList(possibleValues))

	def setDefaultValues(self, defaultValues):
		Config.setDefaultValues(self, forceUnicodeList(defaultValues))

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'UnicodeConfig'

		return Config.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'UnicodeConfig')


Config.sub_classes['UnicodeConfig'] = UnicodeConfig


class BoolConfig(Config):
	sub_classes = {}

	def __init__(
		self, id, description=None, defaultValues=None  # pylint: disable=redefined-builtin
	):
		Config.__init__(
			self, id, description, [True, False], defaultValues, False, False
		)

	def setDefaults(self):
		if self.defaultValues is None:
			self.defaultValues = [False]
		Config.setDefaults(self)

	def setPossibleValues(self, possibleValues):
		Config.setPossibleValues(self, [True, False])

	def setDefaultValues(self, defaultValues):
		defaultValues = list(set(forceBoolList(defaultValues)))
		if len(defaultValues) > 1:
			raise BackendBadValueError(f"Bool config cannot have multiple default values: {defaultValues}")
		Config.setDefaultValues(self, defaultValues)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'BoolConfig'

		return Config.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'BoolConfig')

	def __str__(self):
		return (
			f"<{self.getType()}(id='{self.id}', description='{self.description}', "
			f"defaultValues={self.defaultValues})>"
		)


Config.sub_classes['BoolConfig'] = BoolConfig


class ConfigState(Relationship):
	sub_classes = {}
	backend_method_prefix = 'configState'

	def __init__(self, configId, objectId, values=None):  # pylint: disable=invalid-name
		self.values = None
		self.setConfigId(configId)
		self.setObjectId(objectId)

		if values is not None:
			self.setValues(values)

	def setDefaults(self):
		Relationship.setDefaults(self)
		if self.values is None:
			self.setValues([])

	def getObjectId(self):  # pylint: disable=invalid-name
		return self.objectId

	def setObjectId(self, objectId):  # pylint: disable=invalid-name
		self.objectId = forceObjectId(objectId)  # pylint: disable=invalid-name

	def getConfigId(self):  # pylint: disable=invalid-name
		return self.configId

	def setConfigId(self, configId):  # pylint: disable=invalid-name
		self.configId = forceConfigId(configId)  # pylint: disable=invalid-name

	def getValues(self):  # pylint: disable=invalid-name
		return self.values

	def setValues(self, values):  # pylint: disable=invalid-name
		self.values = sorted(
			forceList(values),
			key=lambda x: (x is None, x)
		)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'ConfigState'

		return Relationship.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'ConfigState')

	def __str__(self):
		return f"<{self.getType()}(configId='{self.configId}', objectId='{self.objectId}', values={self.values})>"


Relationship.sub_classes['ConfigState'] = ConfigState


class Product(Entity):  # pylint: disable=too-many-instance-attributes,too-many-public-methods
	sub_classes = {}
	foreign_id_attributes = Object.foreign_id_attributes + ['productId']
	backend_method_prefix = 'product'

	def __init__(  # pylint: disable=too-many-arguments,too-many-instance-attributes,too-many-public-methods,too-many-locals,too-many-branches
		self, id, productVersion, packageVersion, name=None,  # pylint: disable=redefined-builtin,invalid-name
		licenseRequired=None, setupScript=None, uninstallScript=None,  # pylint: disable=invalid-name
		updateScript=None, alwaysScript=None, onceScript=None,  # pylint: disable=invalid-name
		customScript=None, userLoginScript=None, priority=None,  # pylint: disable=invalid-name
		description=None, advice=None, changelog=None,  # pylint: disable=invalid-name
		productClassIds=None, windowsSoftwareIds=None  # pylint: disable=invalid-name
	):
		self.name = None
		self.licenseRequired = None  # pylint: disable=invalid-name
		self.setupScript = None  # pylint: disable=invalid-name
		self.uninstallScript = None  # pylint: disable=invalid-name
		self.updateScript = None  # pylint: disable=invalid-name
		self.alwaysScript = None  # pylint: disable=invalid-name
		self.onceScript = None  # pylint: disable=invalid-name
		self.customScript = None  # pylint: disable=invalid-name
		self.userLoginScript = None  # pylint: disable=invalid-name
		self.priority = None
		self.description = None
		self.advice = None
		self.changelog = None
		self.productClassIds = None  # pylint: disable=invalid-name
		self.windowsSoftwareIds = None  # pylint: disable=invalid-name
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

	def setDefaults(self):  # pylint: disable=too-many-branches
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

	def getId(self):  # pylint: disable=invalid-name
		return self.id

	def setId(self, id):  # pylint: disable=redefined-builtin,invalid-name
		self.id = forceProductId(id)  # pylint: disable=invalid-name

	def getProductVersion(self):  # pylint: disable=invalid-name
		return self.productVersion

	def setProductVersion(self, productVersion):  # pylint: disable=invalid-name
		self.productVersion = forceProductVersion(productVersion)  # pylint: disable=invalid-name

	def getPackageVersion(self):  # pylint: disable=invalid-name
		return self.packageVersion

	def setPackageVersion(self, packageVersion):  # pylint: disable=invalid-name
		self.packageVersion = forcePackageVersion(packageVersion)  # pylint: disable=invalid-name

	@property
	def version(self):
		return combine_versions(self)

	def getName(self):  # pylint: disable=invalid-name
		return self.name

	def setName(self, name):  # pylint: disable=invalid-name
		self.name = forceUnicode(name)

	def getLicenseRequired(self):  # pylint: disable=invalid-name
		return self.licenseRequired

	def setLicenseRequired(self, licenseRequired):  # pylint: disable=invalid-name
		self.licenseRequired = forceBool(licenseRequired)

	def getSetupScript(self):  # pylint: disable=invalid-name
		return self.setupScript

	def setSetupScript(self, setupScript):  # pylint: disable=invalid-name
		self.setupScript = forceFilename(setupScript)

	def getUninstallScript(self):  # pylint: disable=invalid-name
		return self.uninstallScript

	def setUninstallScript(self, uninstallScript):  # pylint: disable=invalid-name
		self.uninstallScript = forceFilename(uninstallScript)

	def getUpdateScript(self):  # pylint: disable=invalid-name
		return self.updateScript

	def setUpdateScript(self, updateScript):  # pylint: disable=invalid-name
		self.updateScript = forceFilename(updateScript)

	def getAlwaysScript(self):  # pylint: disable=invalid-name
		return self.alwaysScript

	def setAlwaysScript(self, alwaysScript):  # pylint: disable=invalid-name
		self.alwaysScript = forceFilename(alwaysScript)

	def getOnceScript(self):  # pylint: disable=invalid-name
		return self.onceScript

	def setOnceScript(self, onceScript):  # pylint: disable=invalid-name
		self.onceScript = forceFilename(onceScript)

	def getCustomScript(self):  # pylint: disable=invalid-name
		return self.customScript

	def setCustomScript(self, customScript):  # pylint: disable=invalid-name
		self.customScript = forceFilename(customScript)

	def getUserLoginScript(self):  # pylint: disable=invalid-name
		return self.userLoginScript

	def setUserLoginScript(self, userLoginScript):  # pylint: disable=invalid-name
		self.userLoginScript = forceFilename(userLoginScript)

	def getPriority(self):  # pylint: disable=invalid-name
		return self.priority

	def setPriority(self, priority):  # pylint: disable=invalid-name
		self.priority = forceProductPriority(priority)

	def getDescription(self):  # pylint: disable=invalid-name
		return self.description

	def setDescription(self, description):  # pylint: disable=invalid-name
		self.description = forceUnicode(description)

	def getAdvice(self):  # pylint: disable=invalid-name
		return self.advice

	def setAdvice(self, advice):  # pylint: disable=invalid-name
		self.advice = forceUnicode(advice)

	def getChangelog(self):  # pylint: disable=invalid-name
		return self.changelog

	def setChangelog(self, changelog):  # pylint: disable=invalid-name
		self.changelog = forceUnicode(changelog)

	def getProductClassIds(self):  # pylint: disable=invalid-name
		return self.productClassIds

	def setProductClassIds(self, productClassIds):  # pylint: disable=invalid-name
		self.productClassIds = forceUnicodeList(productClassIds)
		self.productClassIds.sort()

	def getWindowsSoftwareIds(self):  # pylint: disable=invalid-name
		return self.windowsSoftwareIds

	def setWindowsSoftwareIds(self, windowsSoftwareIds):  # pylint: disable=invalid-name
		self.windowsSoftwareIds = forceUnicodeList(windowsSoftwareIds)
		self.windowsSoftwareIds.sort()

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'Product'

		return Entity.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'Product')

	def __str__(self):
		return (
			f"<{self.getType()}(id='{self.id}', name='{self.name}', "
			f"productVersion='{self.productVersion}', packageVersion='{self.packageVersion}')>"
		)


Entity.sub_classes['Product'] = Product


class LocalbootProduct(Product):
	sub_classes = {}

	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self, id, productVersion, packageVersion, name=None,  # pylint: disable=redefined-builtin
		licenseRequired=None, setupScript=None, uninstallScript=None,
		updateScript=None, alwaysScript=None, onceScript=None,
		customScript=None, userLoginScript=None, priority=None,
		description=None, advice=None, changelog=None,
		productClassIds=None, windowsSoftwareIds=None
	):

		Product.__init__(self, id, productVersion, packageVersion, name,
			licenseRequired, setupScript, uninstallScript, updateScript,
			alwaysScript, onceScript, customScript, userLoginScript, priority,
			description, advice, changelog, productClassIds, windowsSoftwareIds)

	def setDefaults(self):
		Product.setDefaults(self)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'LocalbootProduct'

		return Product.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'LocalbootProduct')


Product.sub_classes['LocalbootProduct'] = LocalbootProduct


class NetbootProduct(Product):
	sub_classes = {}

	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self, id, productVersion, packageVersion, name=None,  # pylint: disable=redefined-builtin
		licenseRequired=None, setupScript=None, uninstallScript=None,
		updateScript=None, alwaysScript=None, onceScript=None,
		customScript=None, priority=None, description=None,
		advice=None, changelog=None, productClassIds=None,
		windowsSoftwareIds=None, pxeConfigTemplate=''
	):

		Product.__init__(self, id, productVersion, packageVersion, name,
			licenseRequired, setupScript, uninstallScript, updateScript,
			alwaysScript, onceScript, customScript, None, priority,
			description, advice, changelog, productClassIds, windowsSoftwareIds)
		self.setPxeConfigTemplate(pxeConfigTemplate)

	def setDefaults(self):
		Product.setDefaults(self)

	def getPxeConfigTemplate(self):  # pylint: disable=invalid-name
		return self.pxeConfigTemplate

	def setPxeConfigTemplate(self, pxeConfigTemplate):  # pylint: disable=invalid-name
		if pxeConfigTemplate:
			self.pxeConfigTemplate = forceFilename(pxeConfigTemplate)  # pylint: disable=invalid-name
		else:
			self.pxeConfigTemplate = None

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'NetbootProduct'

		return Product.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'NetbootProduct')


Product.sub_classes['NetbootProduct'] = NetbootProduct


class ProductProperty(Entity):  # pylint: disable=too-many-instance-attributes,too-many-public-methods
	sub_classes = {}
	backend_method_prefix = 'productProperty'

	def __init__(  # pylint: disable=too-many-arguments
		self, productId, productVersion, packageVersion, propertyId,  # pylint: disable=invalid-name
		description=None, possibleValues=None, defaultValues=None,  # pylint: disable=invalid-name
		editable=None, multiValue=None  # pylint: disable=invalid-name
	):
		self.description = None
		self.possibleValues = None  # pylint: disable=invalid-name
		self.defaultValues = None  # pylint: disable=invalid-name
		self.editable = None
		self.multiValue = None  # pylint: disable=invalid-name
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

	def setDefaults(self):
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

	def getProductId(self):  # pylint: disable=invalid-name
		return self.productId

	def setProductId(self, productId):  # pylint: disable=invalid-name
		self.productId = forceProductId(productId)  # pylint: disable=invalid-name

	def getProductVersion(self):  # pylint: disable=invalid-name
		return self.productVersion

	def setProductVersion(self, productVersion):  # pylint: disable=invalid-name
		self.productVersion = forceProductVersion(productVersion)  # pylint: disable=invalid-name

	def getPackageVersion(self):  # pylint: disable=invalid-name
		return self.packageVersion

	def setPackageVersion(self, packageVersion):  # pylint: disable=invalid-name
		self.packageVersion = forcePackageVersion(packageVersion)  # pylint: disable=invalid-name

	def getPropertyId(self):  # pylint: disable=invalid-name
		return self.propertyId

	def setPropertyId(self, propertyId):  # pylint: disable=invalid-name
		self.propertyId = forceProductPropertyId(propertyId)  # pylint: disable=invalid-name

	def getDescription(self):  # pylint: disable=invalid-name
		return self.description

	def setDescription(self, description):  # pylint: disable=invalid-name
		self.description = forceUnicode(description)

	def _updateValues(self):  # pylint: disable=invalid-name
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

	def getPossibleValues(self):  # pylint: disable=invalid-name
		return self.possibleValues

	def setPossibleValues(self, possibleValues):  # pylint: disable=invalid-name
		self.possibleValues = list(set(forceList(possibleValues)))
		self._updateValues()

	def getDefaultValues(self):  # pylint: disable=invalid-name
		return self.defaultValues

	def setDefaultValues(self, defaultValues):  # pylint: disable=invalid-name
		self.defaultValues = list(set(forceList(defaultValues)))
		self._updateValues()

	def getEditable(self):  # pylint: disable=invalid-name
		return self.editable

	def setEditable(self, editable):  # pylint: disable=invalid-name
		self.editable = forceBool(editable)

	def getMultiValue(self):  # pylint: disable=invalid-name
		return self.multiValue

	def setMultiValue(self, multiValue):  # pylint: disable=invalid-name
		self.multiValue = forceBool(multiValue)
		if self.defaultValues is not None and len(self.defaultValues) > 1:
			self.multiValue = True

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'ProductProperty'

		return Entity.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'ProductProperty')

	def __str__(self):
		def getAttributes():  # pylint: disable=invalid-name
			yield f"productId='{self.productId}'"
			yield f"productVersion='{self.productVersion}'"
			yield f"packageVersion='{self.packageVersion}'"
			yield f"propertyId='{self.propertyId}'"

			for attribute in ('description', 'defaultValues', 'possibleValues'):
				try:
					value = getattr(self, attribute)
					if value:
						yield f"{attribute}='{value}'"
				except AttributeError:
					pass

			for attribute in ('editable', 'multiValue'):
				try:
					value = getattr(self, attribute)
					if value is not None:
						yield f"{attribute}='{value}'"
				except AttributeError:
					pass

		return f"<{self.__class__.__name__}({', '.join(getAttributes())})>"


Entity.sub_classes['ProductProperty'] = ProductProperty


class UnicodeProductProperty(ProductProperty):
	sub_classes = {}

	def __init__(  # pylint: disable=too-many-arguments
		self, productId, productVersion, packageVersion, propertyId,
		description=None, possibleValues=None, defaultValues=None,
		editable=None, multiValue=None
	):

		ProductProperty.__init__(self, productId, productVersion,
			packageVersion, propertyId, description, possibleValues,
			defaultValues, editable, multiValue)

		self.possibleValues = None
		self.defaultValues = None
		if possibleValues is not None:
			self.setPossibleValues(possibleValues)
		if defaultValues is not None:
			self.setDefaultValues(defaultValues)

	def setDefaults(self):
		if self.possibleValues is None:
			self.possibleValues = ['']
		if self.defaultValues is None:
			self.defaultValues = ['']
		ProductProperty.setDefaults(self)

	def setPossibleValues(self, possibleValues):
		ProductProperty.setPossibleValues(self, forceUnicodeList(possibleValues))

	def setDefaultValues(self, defaultValues):
		ProductProperty.setDefaultValues(self, forceUnicodeList(defaultValues))

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'UnicodeProductProperty'

		return ProductProperty.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'UnicodeProductProperty')


ProductProperty.sub_classes['UnicodeProductProperty'] = UnicodeProductProperty


class BoolProductProperty(ProductProperty):
	sub_classes = {}

	def __init__(  # pylint: disable=too-many-arguments
		self, productId, productVersion, packageVersion, propertyId,
		description=None, defaultValues=None
	):

		ProductProperty.__init__(self, productId, productVersion,
			packageVersion, propertyId, description, [True, False],
			defaultValues, False, False)

		if self.defaultValues is not None and len(self.defaultValues) > 1:
			raise BackendBadValueError(f"Bool product property cannot have multiple default values: {self.defaultValues}")

	def setDefaults(self):
		if self.defaultValues is None:
			self.defaultValues = [False]
		ProductProperty.setDefaults(self)

	def setPossibleValues(self, possibleValues):
		ProductProperty.setPossibleValues(self, [True, False])

	def setDefaultValues(self, defaultValues):
		defaultValues = forceBoolList(defaultValues)
		if len(defaultValues) > 1:
			raise BackendBadValueError(f"Bool config cannot have multiple default values: {self.defaultValues}")
		ProductProperty.setDefaultValues(self, defaultValues)

	def setEditable(self, editable):
		self.editable = False

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'BoolProductProperty'

		return ProductProperty.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'BoolProductProperty')

	def __str__(self):
		def getAttributes():  # pylint: disable=invalid-name
			yield f"productId='{self.productId}'"
			yield f"productVersion='{self.productVersion}'"
			yield f"packageVersion='{self.packageVersion}'"
			yield f"propertyId='{self.propertyId}'"

			for attribute in ('description', 'defaultValues'):
				try:
					value = getattr(self, attribute)
					if value:
						yield f"{attribute}='{value}'"
				except AttributeError:
					pass

		return f"<{self.__class__.__name__}({', '.join(getAttributes())})>"


ProductProperty.sub_classes['BoolProductProperty'] = BoolProductProperty


class ProductDependency(Relationship):  # pylint: disable=too-many-instance-attributes,too-many-public-methods
	sub_classes = {}
	backend_method_prefix = 'productDependency'

	def __init__(  # pylint: disable=too-many-arguments
		self, productId, productVersion, packageVersion,  # pylint: disable=invalid-name
		productAction, requiredProductId, requiredProductVersion=None,  # pylint: disable=invalid-name
		requiredPackageVersion=None, requiredAction=None,  # pylint: disable=invalid-name
		requiredInstallationStatus=None, requirementType=None  # pylint: disable=invalid-name
	):
		self.requiredProductVersion = None  # pylint: disable=invalid-name
		self.requiredPackageVersion = None  # pylint: disable=invalid-name
		self.requiredAction = None  # pylint: disable=invalid-name
		self.requiredInstallationStatus = None  # pylint: disable=invalid-name
		self.requirementType = None  # pylint: disable=invalid-name
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

	def setDefaults(self):
		Relationship.setDefaults(self)

	def getProductId(self):  # pylint: disable=invalid-name
		return self.productId

	def setProductId(self, productId):  # pylint: disable=invalid-name
		self.productId = forceProductId(productId)  # pylint: disable=invalid-name

	def getProductVersion(self):  # pylint: disable=invalid-name
		return self.productVersion

	def setProductVersion(self, productVersion):  # pylint: disable=invalid-name
		self.productVersion = forceProductVersion(productVersion)  # pylint: disable=invalid-name

	def getPackageVersion(self):  # pylint: disable=invalid-name
		return self.packageVersion

	def setPackageVersion(self, packageVersion):  # pylint: disable=invalid-name
		self.packageVersion = forcePackageVersion(packageVersion)  # pylint: disable=invalid-name

	def getProductAction(self):  # pylint: disable=invalid-name
		return self.productAction

	def setProductAction(self, productAction):  # pylint: disable=invalid-name
		self.productAction = forceActionRequest(productAction)  # pylint: disable=invalid-name

	def getRequiredProductId(self):  # pylint: disable=invalid-name
		return self.requiredProductId

	def setRequiredProductId(self, requiredProductId):  # pylint: disable=invalid-name
		self.requiredProductId = forceProductId(requiredProductId)  # pylint: disable=invalid-name

	def getRequiredProductVersion(self):  # pylint: disable=invalid-name
		return self.requiredProductVersion

	def setRequiredProductVersion(self, requiredProductVersion):  # pylint: disable=invalid-name
		self.requiredProductVersion = forceProductVersion(requiredProductVersion)

	def getRequiredPackageVersion(self):  # pylint: disable=invalid-name
		return self.requiredPackageVersion

	def setRequiredPackageVersion(self, requiredPackageVersion):  # pylint: disable=invalid-name
		self.requiredPackageVersion = forcePackageVersion(requiredPackageVersion)

	def getRequiredAction(self):  # pylint: disable=invalid-name
		return self.requiredAction

	def setRequiredAction(self, requiredAction):  # pylint: disable=invalid-name
		self.requiredAction = forceActionRequest(requiredAction)

	def getRequiredInstallationStatus(self):  # pylint: disable=invalid-name
		return self.requiredInstallationStatus

	def setRequiredInstallationStatus(self, requiredInstallationStatus):  # pylint: disable=invalid-name
		self.requiredInstallationStatus = forceInstallationStatus(requiredInstallationStatus)

	def getRequirementType(self):  # pylint: disable=invalid-name
		return self.requirementType

	def setRequirementType(self, requirementType):  # pylint: disable=invalid-name
		self.requirementType = forceRequirementType(requirementType)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'ProductDependency'

		return Relationship.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'ProductDependency')

	def __str__(self):
		return (
			f"<{self.getType()}(productId='{self.productId}', productVersion='{self.productVersion}', "
			f"packageVersion='{self.packageVersion}', productAction='{self.productAction}', "
			f"requiredProductId='{self.requiredProductId}'>"
		)

Relationship.sub_classes['ProductDependency'] = ProductDependency


class ProductOnDepot(Relationship):
	sub_classes = {}
	backend_method_prefix = 'productOnDepot'

	def __init__(  # pylint: disable=too-many-arguments
		self, productId, productType, productVersion, packageVersion,  # pylint: disable=invalid-name
		depotId, locked=None  # pylint: disable=invalid-name
	):
		self.locked = None
		self.setProductId(productId)
		self.setProductType(productType)
		self.setProductVersion(productVersion)
		self.setPackageVersion(packageVersion)
		self.setDepotId(depotId)
		if locked is not None:
			self.setLocked(locked)

	def setDefaults(self):
		Relationship.setDefaults(self)
		if self.locked is None:
			self.setLocked(False)

	def getProductId(self):  # pylint: disable=invalid-name
		return self.productId

	def setProductId(self, productId):  # pylint: disable=invalid-name
		self.productId = forceProductId(productId)  # pylint: disable=invalid-name

	def getProductType(self):  # pylint: disable=invalid-name
		return self.productType

	def setProductType(self, productType):  # pylint: disable=invalid-name
		self.productType = forceProductType(productType)  # pylint: disable=invalid-name

	def getProductVersion(self):  # pylint: disable=invalid-name
		return self.productVersion

	def setProductVersion(self, productVersion):  # pylint: disable=invalid-name
		self.productVersion = forceProductVersion(productVersion)  # pylint: disable=invalid-name

	def getPackageVersion(self):  # pylint: disable=invalid-name
		return self.packageVersion

	def setPackageVersion(self, packageVersion):  # pylint: disable=invalid-name
		self.packageVersion = forcePackageVersion(packageVersion)  # pylint: disable=invalid-name

	@property
	def version(self):
		return combine_versions(self)

	def getDepotId(self):  # pylint: disable=invalid-name
		return self.depotId

	def setDepotId(self, depotId):  # pylint: disable=invalid-name
		self.depotId = forceHostId(depotId)  # pylint: disable=invalid-name

	def getLocked(self):  # pylint: disable=invalid-name
		return self.locked

	def setLocked(self, locked):  # pylint: disable=invalid-name
		self.locked = forceBool(locked)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'ProductOnDepot'

		return Relationship.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'ProductOnDepot')


Relationship.sub_classes['ProductOnDepot'] = ProductOnDepot


class ProductOnClient(Relationship):  # pylint: disable=too-many-instance-attributes,too-many-public-methods
	sub_classes = {}
	backend_method_prefix = 'productOnClient'

	def __init__(  # pylint: disable=too-many-arguments
		self, productId, productType, clientId,  # pylint: disable=invalid-name
		targetConfiguration=None, installationStatus=None,  # pylint: disable=invalid-name
		actionRequest=None, lastAction=None, actionProgress=None,  # pylint: disable=invalid-name
		actionResult=None, productVersion=None, packageVersion=None,  # pylint: disable=invalid-name
		modificationTime=None, actionSequence=None  # pylint: disable=invalid-name
	):
		self.targetConfiguration = None  # pylint: disable=invalid-name
		self.installationStatus = None  # pylint: disable=invalid-name
		self.actionRequest = None  # pylint: disable=invalid-name
		self.lastAction = None  # pylint: disable=invalid-name
		self.actionProgress = None  # pylint: disable=invalid-name
		self.actionResult = None  # pylint: disable=invalid-name
		self.productVersion = None  # pylint: disable=invalid-name
		self.packageVersion = None  # pylint: disable=invalid-name
		self.modificationTime = None  # pylint: disable=invalid-name
		self.actionSequence = -1  # pylint: disable=invalid-name
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

	def setDefaults(self):
		Relationship.setDefaults(self)
		if self.installationStatus is None:
			self.setInstallationStatus('not_installed')
		if self.actionRequest is None:
			self.setActionRequest('none')
		if self.modificationTime is None:
			self.setModificationTime(timestamp())

	def getProductId(self):  # pylint: disable=invalid-name
		return self.productId

	def setProductId(self, productId):  # pylint: disable=invalid-name
		self.productId = forceProductId(productId)  # pylint: disable=invalid-name

	def getProductType(self):  # pylint: disable=invalid-name
		return self.productType

	def setProductType(self, productType):  # pylint: disable=invalid-name
		self.productType = forceProductType(productType)  # pylint: disable=invalid-name

	def getClientId(self):  # pylint: disable=invalid-name
		return self.clientId

	def setClientId(self, clientId):  # pylint: disable=invalid-name
		self.clientId = forceHostId(clientId)  # pylint: disable=invalid-name

	def getTargetConfiguration(self):  # pylint: disable=invalid-name
		return self.targetConfiguration

	def setTargetConfiguration(self, targetConfiguration):  # pylint: disable=invalid-name
		self.targetConfiguration = forceProductTargetConfiguration(targetConfiguration)

	def getInstallationStatus(self):  # pylint: disable=invalid-name
		return self.installationStatus

	def setInstallationStatus(self, installationStatus):  # pylint: disable=invalid-name
		self.installationStatus = forceInstallationStatus(installationStatus)

	def getActionRequest(self):  # pylint: disable=invalid-name
		return self.actionRequest

	def setActionRequest(self, actionRequest):  # pylint: disable=invalid-name
		self.actionRequest = forceActionRequest(actionRequest)

	def getActionProgress(self):  # pylint: disable=invalid-name
		return self.actionProgress

	def setActionProgress(self, actionProgress):  # pylint: disable=invalid-name
		actionProgress = forceActionProgress(actionProgress)
		if actionProgress and len(actionProgress) > 250:
			logger.warning("Data truncated for actionProgess")
			actionProgress = actionProgress[:250]
		self.actionProgress = forceActionProgress(actionProgress)

	def getLastAction(self):  # pylint: disable=invalid-name
		return self.lastAction

	def setLastAction(self, lastAction):  # pylint: disable=invalid-name
		self.lastAction = forceActionRequest(lastAction)

	def getActionResult(self):  # pylint: disable=invalid-name
		return self.actionResult

	def setActionResult(self, actionResult):  # pylint: disable=invalid-name
		self.actionResult = forceActionResult(actionResult)

	def getProductVersion(self):  # pylint: disable=invalid-name
		return self.productVersion

	def setProductVersion(self, productVersion):  # pylint: disable=invalid-name
		self.productVersion = forceProductVersion(productVersion)

	def getPackageVersion(self):  # pylint: disable=invalid-name
		return self.packageVersion

	def setPackageVersion(self, packageVersion):  # pylint: disable=invalid-name
		self.packageVersion = forcePackageVersion(packageVersion)

	@property
	def version(self):
		return combine_versions(self)

	def getModificationTime(self):  # pylint: disable=invalid-name
		return self.modificationTime

	def setModificationTime(self, modificationTime):  # pylint: disable=invalid-name
		self.modificationTime = forceOpsiTimestamp(modificationTime)

	def getActionSequence(self):  # pylint: disable=invalid-name
		return self.actionSequence

	def setActionSequence(self, actionSequence):  # pylint: disable=invalid-name
		self.actionSequence = forceInt(actionSequence)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'ProductOnClient'

		return Relationship.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'ProductOnClient')

	def __str__(self):
		return (
			f"<{self.getType()}(clientId='{self.clientId}', productId='{self.productId}', "
			f"installationStatus='{self.installationStatus}', actionRequest='{self.actionRequest}')>"
		)

Relationship.sub_classes['ProductOnClient'] = ProductOnClient


class ProductPropertyState(Relationship):
	sub_classes = {}
	backend_method_prefix = 'productPropertyState'

	def __init__(self, productId, propertyId, objectId, values=None):  # pylint: disable=invalid-name
		self.values = None
		self.setProductId(productId)
		self.setPropertyId(propertyId)
		self.setObjectId(objectId)

		if values is not None:
			self.setValues(values)

	def setDefaults(self):
		Relationship.setDefaults(self)
		if self.values is None:
			self.setValues([])

	def getProductId(self):  # pylint: disable=invalid-name
		return self.productId

	def setProductId(self, productId):  # pylint: disable=invalid-name
		self.productId = forceProductId(productId)  # pylint: disable=invalid-name

	def getObjectId(self):  # pylint: disable=invalid-name
		return self.objectId

	def setObjectId(self, objectId):  # pylint: disable=invalid-name
		self.objectId = forceObjectId(objectId)  # pylint: disable=invalid-name

	def getPropertyId(self):  # pylint: disable=invalid-name
		return self.propertyId

	def setPropertyId(self, propertyId):  # pylint: disable=invalid-name
		self.propertyId = forceProductPropertyId(propertyId)  # pylint: disable=invalid-name

	def getValues(self):  # pylint: disable=invalid-name
		return self.values

	def setValues(self, values):  # pylint: disable=invalid-name
		self.values = forceList(values)
		self.values.sort()

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'ProductPropertyState'

		return Relationship.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'ProductPropertyState')

	def __str__(self):
		def get_attributes():
			yield f"productId='{self.productId}'"
			yield f"propertyId='{self.propertyId}'"
			yield f"objectId='{self.objectId}'"

			if self.values is not None:
				yield f"values={self.values}"

		return f"<{self.getType()}({', '.join(get_attributes())})>"


Relationship.sub_classes['ProductPropertyState'] = ProductPropertyState


class Group(Object):
	sub_classes = {}
	foreign_id_attributes = Object.foreign_id_attributes + ['groupId']
	backend_method_prefix = 'group'

	def __init__(
		self, id, description=None, notes=None, parentGroupId=None  # pylint: disable=redefined-builtin
	):
		Object.__init__(self, id, description, notes)
		self.parentGroupId = None  # pylint: disable=invalid-name
		self.setId(id)

		if parentGroupId is not None:
			self.setParentGroupId(parentGroupId)

	def setDefaults(self):
		Object.setDefaults(self)

	def getId(self):
		return self.id

	def setId(self, id):  # pylint: disable=redefined-builtin
		self.id = forceGroupId(id)

	def getParentGroupId(self):  # pylint: disable=invalid-name
		return self.parentGroupId

	def setParentGroupId(self, parentGroupId):  # pylint: disable=invalid-name
		self.parentGroupId = forceGroupId(parentGroupId)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'Group'

		return Object.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'Group')

	def __str__(self):
		return f"<{self.getType()}(id='{self.id}', parentGroupId='{self.parentGroupId}'>"


Object.sub_classes['Group'] = Group


class HostGroup(Group):
	sub_classes = {}

	def __init__(
		self, id, description=None, notes=None, parentGroupId=None  # pylint: disable=redefined-builtin
	):
		Group.__init__(self, id, description, notes, parentGroupId)

	def setDefaults(self):
		Group.setDefaults(self)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'HostGroup'

		return Group.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'HostGroup')


Group.sub_classes['HostGroup'] = HostGroup


class ProductGroup(Group):
	sub_classes = {}

	def __init__(
		self, id, description=None, notes=None, parentGroupId=None  # pylint: disable=redefined-builtin
	):
		Group.__init__(self, id, description, notes, parentGroupId)

	def setDefaults(self):
		Group.setDefaults(self)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'ProductGroup'

		return Group.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'ProductGroup')


Group.sub_classes['ProductGroup'] = ProductGroup


class ObjectToGroup(Relationship):
	sub_classes = {}
	backend_method_prefix = 'objectToGroup'

	def __init__(self, groupType, groupId, objectId):  # pylint: disable=invalid-name
		self.setGroupType(groupType)
		self.setGroupId(groupId)
		self.setObjectId(objectId)

	def setDefaults(self):
		Relationship.setDefaults(self)

	def getGroupType(self):  # pylint: disable=invalid-name
		return self.groupType

	def setGroupType(self, groupType):  # pylint: disable=invalid-name
		self.groupType = forceGroupType(groupType)  # pylint: disable=invalid-name

	def getGroupId(self):  # pylint: disable=invalid-name
		return self.groupId

	def setGroupId(self, groupId):  # pylint: disable=invalid-name
		self.groupId = forceGroupId(groupId)  # pylint: disable=invalid-name

	def getObjectId(self):  # pylint: disable=invalid-name
		return self.objectId

	def setObjectId(self, objectId):  # pylint: disable=invalid-name
		self.objectId = forceObjectId(objectId)  # pylint: disable=invalid-name

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'ObjectToGroup'

		return Relationship.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'ObjectToGroup')


Relationship.sub_classes['ObjectToGroup'] = ObjectToGroup


class LicenseContract(Entity):
	sub_classes = {}
	foreign_id_attributes = Entity.foreign_id_attributes + ['licenseContractId']
	backend_method_prefix = 'licenseContract'

	def __init__(  # pylint: disable=too-many-arguments
		self, id, description=None, notes=None, partner=None,  # pylint: disable=redefined-builtin,invalid-name
		conclusionDate=None, notificationDate=None,  # pylint: disable=invalid-name
		expirationDate=None  # pylint: disable=invalid-name
	):
		self.description = None
		self.notes = None
		self.partner = None
		self.conclusionDate = None  # pylint: disable=invalid-name
		self.notificationDate = None  # pylint: disable=invalid-name
		self.expirationDate = None  # pylint: disable=invalid-name
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
		if conclusionDate is not None:
			self.setExpirationDate(expirationDate)

	def setDefaults(self):
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
			self.setNotificationDate('0000-00-00 00:00:00')
		if self.expirationDate is None:
			self.setExpirationDate('0000-00-00 00:00:00')

	def getId(self):  # pylint: disable=invalid-name
		return self.id

	def setId(self, id):  # pylint: disable=redefined-builtin,invalid-name
		self.id = forceLicenseContractId(id)  # pylint: disable=invalid-name

	def getDescription(self):  # pylint: disable=invalid-name
		return self.description

	def setDescription(self, description):  # pylint: disable=invalid-name
		self.description = forceUnicode(description)

	def getNotes(self):  # pylint: disable=invalid-name
		return self.notes

	def setNotes(self, notes):  # pylint: disable=invalid-name
		self.notes = forceUnicode(notes)

	def getPartner(self):  # pylint: disable=invalid-name
		return self.partner

	def setPartner(self, partner):  # pylint: disable=invalid-name
		self.partner = forceUnicode(partner)

	def getConclusionDate(self):  # pylint: disable=invalid-name
		return self.conclusionDate

	def setConclusionDate(self, conclusionDate):  # pylint: disable=invalid-name
		self.conclusionDate = forceOpsiTimestamp(conclusionDate)

	def getNotificationDate(self):  # pylint: disable=invalid-name
		return self.notificationDate

	def setNotificationDate(self, notificationDate):  # pylint: disable=invalid-name
		self.notificationDate = forceOpsiTimestamp(notificationDate)

	def getExpirationDate(self):  # pylint: disable=invalid-name
		return self.expirationDate

	def setExpirationDate(self, expirationDate):  # pylint: disable=invalid-name
		self.expirationDate = forceOpsiTimestamp(expirationDate)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'LicenseContract'

		return Entity.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'LicenseContract')

	def __str__(self):
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


Entity.sub_classes['LicenseContract'] = LicenseContract


class SoftwareLicense(Entity):
	sub_classes = {}
	foreign_id_attributes = Entity.foreign_id_attributes + ['softwareLicenseId']
	backend_method_prefix = 'softwareLicense'

	def __init__(  # pylint: disable=too-many-arguments
		self, id, licenseContractId, maxInstallations=None,  # pylint: disable=redefined-builtin,invalid-name
		boundToHost=None, expirationDate=None  # pylint: disable=invalid-name
	):
		self.maxInstallations = None  # pylint: disable=invalid-name
		self.boundToHost = None  # pylint: disable=invalid-name
		self.expirationDate = None  # pylint: disable=invalid-name
		self.setId(id)
		self.setLicenseContractId(licenseContractId)

		if maxInstallations is not None:
			self.setMaxInstallations(maxInstallations)
		if boundToHost is not None:
			self.setBoundToHost(boundToHost)
		if expirationDate is not None:
			self.setExpirationDate(expirationDate)

	def setDefaults(self):
		Entity.setDefaults(self)
		if self.maxInstallations is None:
			self.setMaxInstallations(1)
		if self.expirationDate is None:
			self.setExpirationDate('0000-00-00 00:00:00')

	def getId(self):  # pylint: disable=invalid-name
		return self.id

	def setId(self, id):  # pylint: disable=redefined-builtin,invalid-name
		self.id = forceSoftwareLicenseId(id)  # pylint: disable=invalid-name

	def getLicenseContractId(self):  # pylint: disable=invalid-name
		return self.licenseContractId

	def setLicenseContractId(self, licenseContractId):  # pylint: disable=invalid-name
		self.licenseContractId = forceLicenseContractId(licenseContractId)  # pylint: disable=invalid-name

	def getMaxInstallations(self):  # pylint: disable=invalid-name
		return self.maxInstallations

	def setMaxInstallations(self, maxInstallations):  # pylint: disable=invalid-name
		self.maxInstallations = forceUnsignedInt(maxInstallations)

	def getBoundToHost(self):  # pylint: disable=invalid-name
		return self.boundToHost

	def setBoundToHost(self, boundToHost):  # pylint: disable=invalid-name
		self.boundToHost = forceHostId(boundToHost)

	def getExpirationDate(self):  # pylint: disable=invalid-name
		return self.expirationDate

	def setExpirationDate(self, expirationDate):  # pylint: disable=invalid-name
		self.expirationDate = forceOpsiTimestamp(expirationDate)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'SoftwareLicense'

		return Entity.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'SoftwareLicense')

	def __str__(self):
		infos = [
			f"id='{self.id}'",
			f"licenseContractId='{self.licenseContractId}'"
		]
		if self.maxInstallations:
			infos.append(f"maxInstallations={self.maxInstallations}")
		if self.boundToHost:
			infos.append(f"boundToHost={self.boundToHost}")
		if self.expirationDate:
			infos.append(f"expirationDate={self.expirationDate}")

		return f"<{self.getType()}({', '.join(infos)})>"


Entity.sub_classes['LicenseContract'] = LicenseContract


class RetailSoftwareLicense(SoftwareLicense):
	sub_classes = {}

	def __init__(  # pylint: disable=too-many-arguments
		self, id, licenseContractId, maxInstallations=None,  # pylint: disable=redefined-builtin
		boundToHost=None, expirationDate=None
	):

		SoftwareLicense.__init__(self, id, licenseContractId, maxInstallations,
			boundToHost, expirationDate)

	def setDefaults(self):
		SoftwareLicense.setDefaults(self)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'RetailSoftwareLicense'

		return SoftwareLicense.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'RetailSoftwareLicense')


SoftwareLicense.sub_classes['RetailSoftwareLicense'] = RetailSoftwareLicense


class OEMSoftwareLicense(SoftwareLicense):
	sub_classes = {}

	def __init__(  # pylint: disable=too-many-arguments
		self, id, licenseContractId, maxInstallations=None,  # pylint: disable=redefined-builtin
		boundToHost=None, expirationDate=None
	):
		SoftwareLicense.__init__(self, id, licenseContractId, 1, boundToHost,
			expirationDate)

	def setDefaults(self):
		SoftwareLicense.setDefaults(self)

	def setMaxInstallations(self, maxInstallations):
		maxInstallations = forceUnsignedInt(maxInstallations)
		if maxInstallations > 1:
			raise BackendBadValueError("OEM software license max installations can only be set to 1")
		self.maxInstallations = maxInstallations

	def setBoundToHost(self, boundToHost):
		self.boundToHost = forceHostId(boundToHost)
		if not self.boundToHost:
			raise BackendBadValueError("OEM software license requires boundToHost value")

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'OEMSoftwareLicense'

		return SoftwareLicense.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'OEMSoftwareLicense')


SoftwareLicense.sub_classes['OEMSoftwareLicense'] = OEMSoftwareLicense


class VolumeSoftwareLicense(SoftwareLicense):
	sub_classes = {}

	def __init__(  # pylint: disable=too-many-arguments
		self, id, licenseContractId, maxInstallations=None,  # pylint: disable=redefined-builtin
		boundToHost=None, expirationDate=None
	):
		SoftwareLicense.__init__(self, id, licenseContractId, maxInstallations,
			boundToHost, expirationDate)

	def setDefaults(self):
		SoftwareLicense.setDefaults(self)
		if self.maxInstallations is None:
			self.setMaxInstallations(1)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'VolumeSoftwareLicense'

		return SoftwareLicense.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'VolumeSoftwareLicense')


SoftwareLicense.sub_classes['VolumeSoftwareLicense'] = VolumeSoftwareLicense


class ConcurrentSoftwareLicense(SoftwareLicense):
	sub_classes = {}

	def __init__(  # pylint: disable=too-many-arguments
		self, id, licenseContractId, maxInstallations=None,  # pylint: disable=redefined-builtin
		boundToHost=None, expirationDate=None
	):
		SoftwareLicense.__init__(self, id, licenseContractId, maxInstallations,
			boundToHost, expirationDate)

	def setDefaults(self):
		SoftwareLicense.setDefaults(self)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'ConcurrentSoftwareLicense'

		return SoftwareLicense.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'ConcurrentSoftwareLicense')


SoftwareLicense.sub_classes['ConcurrentSoftwareLicense'] = ConcurrentSoftwareLicense


class LicensePool(Entity):
	sub_classes = {}
	foreign_id_attributes = Entity.foreign_id_attributes + ['licensePoolId']
	backend_method_prefix = 'licensePool'

	def __init__(
		self, id, description=None, productIds=None  # pylint: disable=redefined-builtin,invalid-name
	):
		self.description = None
		self.productIds = None  # pylint: disable=invalid-name
		self.setId(id)

		if description is not None:
			self.setDescription(description)
		if productIds is not None:
			self.setProductIds(productIds)

	def setDefaults(self):
		Entity.setDefaults(self)
		if self.description is None:
			self.setDescription("")
		if self.productIds is None:
			self.setProductIds([])

	def getId(self):  # pylint: disable=invalid-name
		return self.id

	def setId(self, id):  # pylint: disable=redefined-builtin,invalid-name
		self.id = forceLicensePoolId(id)  # pylint: disable=invalid-name

	def getDescription(self):  # pylint: disable=invalid-name
		return self.description

	def setDescription(self, description):  # pylint: disable=invalid-name
		self.description = forceUnicode(description)

	def getProductIds(self):  # pylint: disable=invalid-name
		return self.productIds

	def setProductIds(self, productIds):  # pylint: disable=invalid-name
		self.productIds = forceProductIdList(productIds)
		self.productIds.sort()

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'LicensePool'

		return Entity.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'LicensePool')

	def __str__(self):
		infos = [f"id='{self.id}'"]

		if self.description:
			infos.append(f"description='{self.description}'")
		if self.productIds:
			infos.append(f"productIds={self.productIds}")

		return f"<{self.getType()}({', '.join(infos)})>"


Entity.sub_classes['LicensePool'] = LicensePool


class AuditSoftwareToLicensePool(Relationship):
	sub_classes = {}
	backend_method_prefix = 'auditSoftwareToLicensePool'

	def __init__(  # pylint: disable=too-many-arguments
		self, name, version, subVersion, language, architecture, licensePoolId  # pylint: disable=invalid-name
	):
		self.setName(name)
		self.setVersion(version)
		self.setSubVersion(subVersion)
		self.setLanguage(language)
		self.setArchitecture(architecture)
		self.setLicensePoolId(licensePoolId)

	def getLicensePoolId(self):  # pylint: disable=invalid-name
		return self.licensePoolId

	def setLicensePoolId(self, licensePoolId):  # pylint: disable=invalid-name
		self.licensePoolId = forceLicensePoolId(licensePoolId)  # pylint: disable=invalid-name

	def setName(self, name):  # pylint: disable=invalid-name
		self.name = forceUnicode(name)

	def getName(self):  # pylint: disable=invalid-name
		return self.name

	def setVersion(self, version):  # pylint: disable=invalid-name
		if not version:
			self.version = ''
		else:
			self.version = forceUnicodeLower(version)

	def getVersion(self):  # pylint: disable=invalid-name
		return self.version

	def setSubVersion(self, subVersion):  # pylint: disable=invalid-name
		if not subVersion:
			self.subVersion = ''  # pylint: disable=invalid-name
		else:
			self.subVersion = forceUnicodeLower(subVersion)

	def getSubVersion(self):  # pylint: disable=invalid-name
		return self.subVersion

	def setLanguage(self, language):  # pylint: disable=invalid-name
		if not language:
			self.language = ''
		else:
			self.language = forceLanguageCode(language)

	def getLanguage(self):  # pylint: disable=invalid-name
		return self.language

	def setArchitecture(self, architecture):  # pylint: disable=invalid-name
		if not architecture:
			self.architecture = ''
		else:
			self.architecture = forceArchitecture(architecture)

	def getArchitecture(self):  # pylint: disable=invalid-name
		return self.architecture

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'AuditSoftwareToLicensePool'

		return Relationship.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'AuditSoftwareToLicensePool')

	def __str__(self):
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


Relationship.sub_classes['AuditSoftwareToLicensePool'] = AuditSoftwareToLicensePool


class SoftwareLicenseToLicensePool(Relationship):
	sub_classes = {}
	backend_method_prefix = 'softwareLicenseToLicensePool'

	def __init__(self, softwareLicenseId, licensePoolId, licenseKey=None):  # pylint: disable=invalid-name
		self.licenseKey = None  # pylint: disable=invalid-name
		self.setSoftwareLicenseId(softwareLicenseId)
		self.setLicensePoolId(licensePoolId)

		if licenseKey is not None:
			self.setLicenseKey(licenseKey)

	def setDefaults(self):
		Relationship.setDefaults(self)

		if self.licenseKey is None:
			self.setLicenseKey('')

	def getSoftwareLicenseId(self):  # pylint: disable=invalid-name
		return self.softwareLicenseId

	def setSoftwareLicenseId(self, softwareLicenseId):  # pylint: disable=invalid-name
		self.softwareLicenseId = forceSoftwareLicenseId(softwareLicenseId)  # pylint: disable=invalid-name

	def getLicensePoolId(self):  # pylint: disable=invalid-name
		return self.licensePoolId

	def setLicensePoolId(self, licensePoolId):  # pylint: disable=invalid-name
		self.licensePoolId = forceLicensePoolId(licensePoolId)  # pylint: disable=invalid-name

	def getLicenseKey(self):  # pylint: disable=invalid-name
		return self.licenseKey

	def setLicenseKey(self, licenseKey):  # pylint: disable=invalid-name
		self.licenseKey = forceUnicode(licenseKey)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'SoftwareLicenseToLicensePool'

		return Relationship.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'SoftwareLicenseToLicensePool')


Relationship.sub_classes['SoftwareLicenseToLicensePool'] = SoftwareLicenseToLicensePool


class LicenseOnClient(Relationship):
	sub_classes = {}
	backend_method_prefix = 'licenseOnClient'

	def __init__(  # pylint: disable=too-many-arguments
		self, softwareLicenseId, licensePoolId, clientId,  # pylint: disable=invalid-name
		licenseKey=None, notes=None  # pylint: disable=invalid-name
	):
		self.licenseKey = None  # pylint: disable=invalid-name
		self.notes = None
		self.setSoftwareLicenseId(softwareLicenseId)
		self.setLicensePoolId(licensePoolId)
		self.setClientId(clientId)

		if licenseKey is not None:
			self.setLicenseKey(licenseKey)
		if notes is not None:
			self.setNotes(notes)

	def setDefaults(self):
		Relationship.setDefaults(self)

		if self.licenseKey is None:
			self.setLicenseKey('')
		if self.notes is None:
			self.setNotes('')

	def getSoftwareLicenseId(self):  # pylint: disable=invalid-name
		return self.softwareLicenseId

	def setSoftwareLicenseId(self, softwareLicenseId):  # pylint: disable=invalid-name
		self.softwareLicenseId = forceSoftwareLicenseId(softwareLicenseId)  # pylint: disable=invalid-name

	def getLicensePoolId(self):  # pylint: disable=invalid-name
		return self.licensePoolId

	def setLicensePoolId(self, licensePoolId):  # pylint: disable=invalid-name
		self.licensePoolId = forceLicensePoolId(licensePoolId)  # pylint: disable=invalid-name

	def getClientId(self):  # pylint: disable=invalid-name
		return self.clientId

	def setClientId(self, clientId):  # pylint: disable=invalid-name
		self.clientId = forceHostId(clientId)  # pylint: disable=invalid-name

	def getLicenseKey(self):  # pylint: disable=invalid-name
		return self.licenseKey

	def setLicenseKey(self, licenseKey):  # pylint: disable=invalid-name
		self.licenseKey = forceUnicode(licenseKey)

	def getNotes(self):  # pylint: disable=invalid-name
		return self.notes

	def setNotes(self, notes):  # pylint: disable=invalid-name
		self.notes = forceUnicode(notes)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'LicenseOnClient'

		return Relationship.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'LicenseOnClient')


Relationship.sub_classes['LicenseOnClient'] = LicenseOnClient


class AuditSoftware(Entity):  # pylint: disable=too-many-instance-attributes,too-many-public-methods
	sub_classes = {}
	foreign_id_attributes = Entity.foreign_id_attributes
	backend_method_prefix = 'auditSoftware'

	def __init__(  # pylint: disable=too-many-arguments
		self, name, version, subVersion, language, architecture,  # pylint: disable=invalid-name
		windowsSoftwareId=None, windowsDisplayName=None,  # pylint: disable=invalid-name
		windowsDisplayVersion=None, installSize=None  # pylint: disable=invalid-name
	):
		self.windowsSoftwareId = None  # pylint: disable=invalid-name
		self.windowsDisplayName = None  # pylint: disable=invalid-name
		self.windowsDisplayVersion = None  # pylint: disable=invalid-name
		self.installSize = None  # pylint: disable=invalid-name
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

	def setDefaults(self):
		Entity.setDefaults(self)
		if self.installSize is None:
			self.setInstallSize(0)

	def setName(self, name):  # pylint: disable=invalid-name
		self.name = forceUnicode(name)

	def getName(self):  # pylint: disable=invalid-name
		return self.name

	def setVersion(self, version):  # pylint: disable=invalid-name
		self.version = forceUnicodeLower(version)

	def getVersion(self):  # pylint: disable=invalid-name
		return self.version

	def setSubVersion(self, subVersion):  # pylint: disable=invalid-name
		self.subVersion = forceUnicodeLower(subVersion)  # pylint: disable=invalid-name

	def getSubVersion(self):  # pylint: disable=invalid-name
		return self.subVersion

	def setLanguage(self, language):  # pylint: disable=invalid-name
		if not language:
			self.language = ''
		else:
			self.language = forceLanguageCode(language)

	def getLanguage(self):  # pylint: disable=invalid-name
		return self.language

	def setArchitecture(self, architecture):  # pylint: disable=invalid-name
		if not architecture:
			self.architecture = ''
		else:
			self.architecture = forceArchitecture(architecture)

	def getArchitecture(self):  # pylint: disable=invalid-name
		return self.architecture

	def getWindowsSoftwareId(self):  # pylint: disable=invalid-name
		return self.windowsSoftwareId

	def setWindowsSoftwareId(self, windowsSoftwareId):  # pylint: disable=invalid-name
		self.windowsSoftwareId = forceUnicodeLower(windowsSoftwareId)

	def getWindowsDisplayName(self):  # pylint: disable=invalid-name
		return self.windowsDisplayName

	def setWindowsDisplayName(self, windowsDisplayName):  # pylint: disable=invalid-name
		self.windowsDisplayName = forceUnicode(windowsDisplayName)

	def getWindowsDisplayVersion(self):  # pylint: disable=invalid-name
		return self.windowsDisplayVersion

	def setWindowsDisplayVersion(self, windowsDisplayVersion):  # pylint: disable=invalid-name
		self.windowsDisplayVersion = forceUnicode(windowsDisplayVersion)

	def getInstallSize(self):  # pylint: disable=invalid-name
		return self.installSize

	def setInstallSize(self, installSize):  # pylint: disable=invalid-name
		self.installSize = forceInt(installSize)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'AuditSoftware'

		return Entity.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'AuditSoftware')


Entity.sub_classes['AuditSoftware'] = AuditSoftware


class AuditSoftwareOnClient(Relationship):  # pylint: disable=too-many-instance-attributes,too-many-public-methods
	sub_classes = {}
	backend_method_prefix = 'auditSoftwareOnClient'

	def __init__(  # pylint: disable=too-many-arguments
		self, name, version, subVersion, language, architecture,  # pylint: disable=invalid-name
		clientId, uninstallString=None, binaryName=None,  # pylint: disable=invalid-name
		firstseen=None, lastseen=None, state=None,  # pylint: disable=invalid-name
		usageFrequency=None, lastUsed=None, licenseKey=None  # pylint: disable=invalid-name
	):
		self.uninstallString = None  # pylint: disable=invalid-name
		self.binaryName = None  # pylint: disable=invalid-name
		self.firstseen = None
		self.lastseen = None
		self.state = None
		self.usageFrequency = None  # pylint: disable=invalid-name
		self.lastUsed = None  # pylint: disable=invalid-name
		self.licenseKey = None  # pylint: disable=invalid-name
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

	def setDefaults(self):
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
			self.setLastUsed('0000-00-00 00:00:00')

	def setName(self, name):  # pylint: disable=invalid-name
		self.name = forceUnicode(name)

	def getName(self):  # pylint: disable=invalid-name
		return self.name

	def setVersion(self, version):  # pylint: disable=invalid-name
		self.version = forceUnicodeLower(version)

	def getVersion(self):  # pylint: disable=invalid-name
		return self.version

	def setSubVersion(self, subVersion):  # pylint: disable=invalid-name
		self.subVersion = forceUnicodeLower(subVersion)  # pylint: disable=invalid-name

	def getSubVersion(self):  # pylint: disable=invalid-name
		return self.subVersion

	def setLanguage(self, language):  # pylint: disable=invalid-name
		if not language:
			self.language = ''
		else:
			self.language = forceLanguageCode(language)

	def getLanguage(self):  # pylint: disable=invalid-name
		return self.language

	def setArchitecture(self, architecture):  # pylint: disable=invalid-name
		if not architecture:
			self.architecture = ''
		else:
			self.architecture = forceArchitecture(architecture)

	def getArchitecture(self):  # pylint: disable=invalid-name
		return self.architecture

	def getClientId(self):  # pylint: disable=invalid-name
		return self.clientId

	def setClientId(self, clientId):  # pylint: disable=invalid-name
		self.clientId = forceHostId(clientId)  # pylint: disable=invalid-name

	def getUninstallString(self):  # pylint: disable=invalid-name
		return self.uninstallString

	def setUninstallString(self, uninstallString):  # pylint: disable=invalid-name
		self.uninstallString = forceUnicode(uninstallString)

	def getBinaryName(self):  # pylint: disable=invalid-name
		return self.binaryName

	def setBinaryName(self, binaryName):  # pylint: disable=invalid-name
		self.binaryName = forceUnicode(binaryName)

	def getFirstseen(self):  # pylint: disable=invalid-name
		return self.firstseen

	def setFirstseen(self, firstseen):  # pylint: disable=invalid-name
		self.firstseen = forceOpsiTimestamp(firstseen)

	def getLastseen(self):  # pylint: disable=invalid-name
		return self.firstseen

	def setLastseen(self, lastseen):  # pylint: disable=invalid-name
		self.lastseen = forceOpsiTimestamp(lastseen)

	def getState(self):  # pylint: disable=invalid-name
		return self.state

	def setState(self, state):  # pylint: disable=invalid-name
		self.state = forceAuditState(state)

	def getUsageFrequency(self):  # pylint: disable=invalid-name
		return self.usageFrequency

	def setUsageFrequency(self, usageFrequency):  # pylint: disable=invalid-name
		self.usageFrequency = forceInt(usageFrequency)

	def getLastUsed(self):  # pylint: disable=invalid-name
		return self.lastUsed

	def setLastUsed(self, lastUsed):  # pylint: disable=invalid-name
		self.lastUsed = forceOpsiTimestamp(lastUsed)

	def getLicenseKey(self):  # pylint: disable=invalid-name
		return self.licenseKey

	def setLicenseKey(self, licenseKey):  # pylint: disable=invalid-name
		self.licenseKey = forceUnicode(licenseKey)

	@staticmethod
	def fromHash(_hash):
		try:
			_hash['type']
		except KeyError:
			_hash['type'] = 'AuditSoftwareOnClient'

		return Relationship.fromHash(_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'AuditSoftwareOnClient')


Relationship.sub_classes['AuditSoftwareOnClient'] = AuditSoftwareOnClient


class AuditHardware(Entity):
	sub_classes = {}
	foreign_id_attributes = Entity.foreign_id_attributes
	backend_method_prefix = 'auditHardware'
	hardware_attributes = {}

	def __init__(self, hardwareClass, **kwargs):  # pylint: disable=too-many-branches,too-many-statements,invalid-name
		self.setHardwareClass(hardwareClass)
		attributes = self.hardware_attributes.get(hardwareClass, {})
		for attribute in attributes:
			if attribute not in kwargs:
				low_attr = attribute.lower()
				try:
					kwargs[attribute] = kwargs[low_attr]
					del kwargs[low_attr]
				except KeyError:
					kwargs[attribute] = None

		if attributes:
			attribute_to_delete = set()
			for (attribute, value) in kwargs.items():
				attr_type = attributes.get(attribute)
				if not attr_type:
					attribute_to_delete.add(attribute)
					continue
				if value is None:
					continue

				if attr_type.startswith('varchar'):
					kwargs[attribute] = forceUnicode(value).strip()
					try:
						size = int(attr_type.split('(')[1].split(')')[0].strip())

						if len(kwargs[attribute]) > size:
							logger.warning(
								"Truncating value of attribute %s of hardware class %s to length %d",
								attribute, hardwareClass, size
							)
							kwargs[attribute] = kwargs[attribute][:size].strip()
					except (ValueError, IndexError):
						pass
				elif 'int' in attr_type:
					try:
						kwargs[attribute] = forceInt(value)
					except Exception as err:  # pylint: disable=broad-except
						logger.trace(err)
						kwargs[attribute] = None
				elif attr_type == 'double':
					try:
						kwargs[attribute] = forceFloat(value)
					except Exception as err:  # pylint: disable=broad-except
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
			for (attribute, value) in kwargs.items():
				if isinstance(value, str):
					new_kwargs[attribute] = forceUnicode(value).strip()
				else:
					new_kwargs[attribute] = value

			kwargs = new_kwargs
			del new_kwargs

		self.__dict__.update(kwargs)

		try:
			if getattr(self, "vendorId", None):
				self.vendorId = forceHardwareVendorId(self.vendorId)  # pylint: disable=invalid-name
		except AttributeError:
			pass

		try:
			if getattr(self, "subsystemVendorId", None):
				self.subsystemVendorId = forceHardwareVendorId(self.subsystemVendorId)  # pylint: disable=invalid-name
		except AttributeError:
			pass

		try:
			if getattr(self, "deviceId", None):
				self.deviceId = forceHardwareDeviceId(self.deviceId)  # pylint: disable=invalid-name
		except AttributeError:
			pass

		try:
			if getattr(self, "subsystemDeviceId", None):
				self.subsystemDeviceId = forceHardwareDeviceId(self.subsystemDeviceId)  # pylint: disable=invalid-name
		except AttributeError:
			pass

	@staticmethod
	def setHardwareConfig(hardwareConfig):  # pylint: disable=invalid-name
		hardware_attributes = {}
		for config in hardwareConfig:
			hw_class = config['Class']['Opsi']
			hardware_attributes[hw_class] = {}
			for value in config['Values']:
				if value["Scope"] == 'g':
					hardware_attributes[hw_class][value['Opsi']] = value["Type"]
		AuditHardware.hardware_attributes = hardware_attributes

	def setDefaults(self):
		Entity.setDefaults(self)

	def setHardwareClass(self, hardwareClass):  # pylint: disable=invalid-name
		self.hardwareClass = forceUnicode(hardwareClass)  # pylint: disable=invalid-name

	def getHardwareClass(self):  # pylint: disable=invalid-name
		return self.hardwareClass

	def getIdentAttributes(self):
		attributes = list(self.hardware_attributes.get(self.hardwareClass, {}).keys())
		attributes.sort()
		attributes.insert(0, 'hardwareClass')
		return tuple(attributes)

	def serialize(self):
		return self.toHash()

	@staticmethod
	def fromHash(_hash):
		init_hash = {
			key: value
			for key, value in _hash.items()
			if key != 'type'
		}

		return AuditHardware(**init_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'AuditHardware')

	def __str__(self):
		infos = []
		hardware_class = self.getHardwareClass()
		if hardware_class:
			infos.append(f"hardwareClass={hardware_class}")

		try:
			infos.append(f"name='{self.name}'")
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


Entity.sub_classes['AuditHardware'] = AuditHardware


class AuditHardwareOnHost(Relationship):  # pylint: disable=too-many-instance-attributes
	sub_classes = {}
	backend_method_prefix = 'auditHardwareOnHost'
	hardware_attributes = {}

	def __init__(  # pylint: disable=too-many-arguments,too-many-branches,too-many-statements
		self, hardwareClass, hostId, firstseen=None, lastseen=None,  # pylint: disable=invalid-name
		state=None, **kwargs
	):
		self.firstseen = None
		self.lastseen = None
		self.state = None
		self.setHostId(hostId)
		self.setHardwareClass(hardwareClass)

		for attribute in self.hardware_attributes.get(hardwareClass, {}):
			if attribute not in kwargs:
				lower_attribute = attribute.lower()
				try:
					kwargs[attribute] = kwargs[lower_attribute]
					del kwargs[lower_attribute]
				except KeyError:
					kwargs[attribute] = None

		if self.hardware_attributes.get(hardwareClass):
			for (attribute, value) in kwargs.items():
				attr_type = self.hardware_attributes[hardwareClass].get(attribute)
				if not attr_type:
					del kwargs[attribute]  # pylint: disable=unnecessary-dict-index-lookup
					continue
				if value is None:
					continue

				if attr_type.startswith('varchar'):
					kwargs[attribute] = forceUnicode(value).strip()
					try:
						size = int(attr_type.split('(')[1].split(')')[0].strip())

						if len(kwargs[attribute]) > size:
							logger.warning('Truncating value of attribute %s of hardware class %s to length %d', attribute, hardwareClass, size)
							kwargs[attribute] = kwargs[attribute][:size].strip()
					except (ValueError, IndexError):
						pass
				elif 'int' in attr_type:
					try:
						kwargs[attribute] = forceInt(value)
					except Exception as err:  # pylint: disable=broad-except
						logger.trace(err)
						kwargs[attribute] = None
				elif attr_type == 'double':
					try:
						kwargs[attribute] = forceFloat(value)
					except Exception as err:  # pylint: disable=broad-except
						logger.trace(err)
						kwargs[attribute] = None
				else:
					raise BackendConfigurationError(
						f"Attribute '{attribute}' of hardware class '{hardwareClass}' has unknown type '{type}'"
					)
		else:
			for (attribute, value) in kwargs.items():
				if isinstance(value, str):
					kwargs[attribute] = forceUnicode(value).strip()

		self.__dict__.update(kwargs)
		if firstseen is not None:
			self.setFirstseen(firstseen)
		if lastseen is not None:
			self.setLastseen(lastseen)
		if state is not None:
			self.setState(state)

		try:
			if getattr(self, "vendorId", None):
				self.vendorId = forceHardwareVendorId(self.vendorId)  # pylint: disable=invalid-name
		except AttributeError:
			pass

		try:
			if getattr(self, "subsystemVendorId", None):
				self.subsystemVendorId = forceHardwareVendorId(self.subsystemVendorId)  # pylint: disable=invalid-name
		except AttributeError:
			pass

		try:
			if getattr(self, "deviceId", None):
				self.deviceId = forceHardwareDeviceId(self.deviceId)  # pylint: disable=invalid-name
		except AttributeError:
			pass

		try:
			if getattr(self, "subsystemDeviceId", None):
				self.subsystemDeviceId = forceHardwareDeviceId(self.subsystemDeviceId)  # pylint: disable=invalid-name
		except AttributeError:
			pass

	@staticmethod
	def setHardwareConfig(hardwareConfig):  # pylint: disable=invalid-name
		hardware_attributes = {}
		for config in hardwareConfig:
			hw_class = config['Class']['Opsi']
			hardware_attributes[hw_class] = {}
			for value in config['Values']:
				hardware_attributes[hw_class][value['Opsi']] = value["Type"]
		AuditHardwareOnHost.hardware_attributes = hardware_attributes

	def setDefaults(self):
		Relationship.setDefaults(self)
		if self.firstseen is None:
			self.setFirstseen(timestamp())
		if self.lastseen is None:
			self.setLastseen(timestamp())
		if self.state is None:
			self.setState(1)

	def getHostId(self):  # pylint: disable=invalid-name
		return self.hostId

	def setHostId(self, hostId):  # pylint: disable=invalid-name
		self.hostId = forceHostId(hostId)  # pylint: disable=invalid-name

	def setHardwareClass(self, hardwareClass):  # pylint: disable=invalid-name
		self.hardwareClass = forceUnicode(hardwareClass)  # pylint: disable=invalid-name

	def getHardwareClass(self):  # pylint: disable=invalid-name
		return self.hardwareClass

	def getFirstseen(self):  # pylint: disable=invalid-name
		return self.firstseen

	def setFirstseen(self, firstseen):  # pylint: disable=invalid-name
		self.firstseen = forceOpsiTimestamp(firstseen)

	def getLastseen(self):  # pylint: disable=invalid-name
		return self.firstseen

	def setLastseen(self, lastseen):  # pylint: disable=invalid-name
		self.lastseen = forceOpsiTimestamp(lastseen)

	def getState(self):  # pylint: disable=invalid-name
		return self.state

	def setState(self, state):  # pylint: disable=invalid-name
		self.state = forceAuditState(state)

	def toAuditHardware(self):  # pylint: disable=invalid-name
		audit_hardware_hash = {'type': 'AuditHardware'}
		attributes = set(AuditHardware.hardware_attributes.get(self.getHardwareClass(), {}).keys())

		for (attribute, value) in self.toHash():
			if attribute == 'type':
				continue

			if attribute == 'hardwareClass':
				audit_hardware_hash[attribute] = value
				continue

			if attribute in attributes:
				audit_hardware_hash[attribute] = value

		return AuditHardware.fromHash(audit_hardware_hash)

	def getIdentAttributes(self):
		attributes = list(self.hardware_attributes.get(self.hardwareClass, {}).keys())
		attributes.sort()
		attributes.insert(0, 'hostId')
		attributes.insert(0, 'hardwareClass')
		return tuple(attributes)

	def serialize(self):
		return self.toHash()

	@staticmethod
	def fromHash(_hash):
		init_hash = {
			key: value
			for key, value in _hash.items()
			if key != 'type'
		}

		return AuditHardwareOnHost(**init_hash)

	@staticmethod
	def from_json(jsonString):
		return from_json(jsonString, 'AuditHardwareOnHost')

	def __str__(self):
		additional = [f"hostId='{self.hostId}'"]
		hardware_class = self.getHardwareClass()
		if hardware_class:
			additional.append(f"hardwareClass={hardware_class}")

		try:
			additional.append(f"name='{self.name}'")
		except AttributeError:
			pass

		return f"<{self.getType()}({', '.join(additional)})>"


Relationship.sub_classes['AuditHardwareOnHost'] = AuditHardwareOnHost

OBJECT_CLASSES  = {
	name: cls for (name, cls) in globals().items() if isinstance(cls, type) and issubclass(cls, BaseObject)
}
