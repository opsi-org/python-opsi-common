# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
test_objects
"""

import json
from contextlib import contextmanager
from typing import Any, Dict, Generator, Optional, Type
from unittest import mock

import pytest

from opsicommon.objects import (
	Entity,
	decode_ident,
	get_backend_method_prefix,
	get_foreign_id_attributes,
	get_possible_class_attributes,
	mandatory_constructor_args,
	objects_differ,
)

object_classes = []  # pylint: disable=use-tuple-over-list
pre_globals = list(globals())
from opsicommon.objects import (  # pylint: disable=wrong-import-position,unused-import
	AuditHardware,
	AuditHardwareOnHost,
	AuditSoftware,
	AuditSoftwareOnClient,
	AuditSoftwareToLicensePool,
	BaseObject,
	BoolConfig,
	BoolProductProperty,
	ConcurrentSoftwareLicense,
	Config,
	ConfigState,
	Group,
	Host,
	HostGroup,
	LicenseContract,
	LicenseOnClient,
	LicensePool,
	LocalbootProduct,
	NetbootProduct,
	ObjectToGroup,
	OEMSoftwareLicense,
	OpsiClient,
	OpsiConfigserver,
	OpsiDepotserver,
	Product,
	ProductDependency,
	ProductGroup,
	ProductOnClient,
	ProductOnDepot,
	ProductProperty,
	ProductPropertyState,
	RetailSoftwareLicense,
	SoftwareLicense,
	SoftwareLicenseToLicensePool,
	UnicodeConfig,
	UnicodeProductProperty,
	VolumeSoftwareLicense,
)

object_classes = [
	_obj for _name, _obj in dict(globals()).items() if _name not in pre_globals and _name != "pre_globals"
]


@contextmanager
def empty_mandatory_constructor_args_cache() -> Generator[None, None, None]:
	with mock.patch('opsicommon.objects._MANDATORY_CONSTRUCTOR_ARGS_CACHE', {}):
		yield


def test_object_classes() -> None:
	objs = (
		Host(
			"test.dom.tld", "desc", "notes", "00:01:02:03:04:05", "172.16.1.1", "inv001"
		),
		OpsiClient(
			"client.dom.tld", "12345678901234567890123456789011", "desc", "notes", "00:01:02:03:04:05",
			"172.16.1.1", "inv001", "password", "2021-01-01", "2021-01-02"
		),
		OpsiDepotserver(
			"depot.dom.tld", "12345678901234567890123456789022", "file:///depot", "smb://depot/share",
			"webdavs://depot:4447/depot", "file:///repo", "webdavs://depot:4447/repository", "desc", "notes",
			"00:01:02:03:04:06", "192.168.1.1", "inv_asdf", "10.10.0.0/16", 10000, False, "master.dom.tld",
			"file:///workbench", "webdavs://depot:4447/workbench"
		),
		OpsiConfigserver(
			"opsi.dom.tld", "12345678901234567890123456789033", "file:///depot", "smb://depot/share",
			"webdavs://opsi:4447/depot", "file:///repo", "webdavs://opsi:4447/repository", "desc", "notes",
			"00:01:02:03:04:07", "192.168.2.1", "xyz", "10.10.0.0/16", 10000, True, None,
			"file:///workbench", "webdavs://opsi:4447/workbench"
		),
		Config(
			"config.id", "description", ["1", "2", "3"], ["1", "2"], True, True
		),
		UnicodeConfig(
			"unicodeconfig.id", "description", ["x", "y"], ["y"], False, False
		),
		BoolConfig(
			"boolconfig.id", "desc"
		),
		ConfigState(
			"config.id", "depot.dom.tld", ["1"]
		),
		Product(
			"product1", "1.0", "1", "Product 1", True, "setup", "uninst", "update", "always", "once",
			"custom", "login", 100, "desc", "advice", "changelog", ["cls1", "cls2"], ["swid1", "swid2"]
		),
		LocalbootProduct(
			"locproduct1", "1.1k", "2", "Loc Product 1", True, "setup", "uninst", "update", "always", "once",
			"custom", "login", 0, "---", "advice", "changelog", ["cls11", "cls12"], ["swid11", "swid12"]
		),
		NetbootProduct(
			"netproduct1", "21H1", "3", "Net Product 1", True, "setup", "uninst", "update", "always", "once",
			"custom", 0, "---", "advice", "changelog", ["cls11", "cls12"], ["swid11", "swid12"], "pxetempl1"
		),
		ProductProperty(
			"product1", "1.0", "1", "prop_id", "desc", ["a", "b"], ["a"], True, True
		),
		UnicodeProductProperty(
			"product1", "1.0", "1", "unicode_prop_id", "desc", ["a2", "b2"], ["a2"], True, True
		),
		BoolProductProperty(
			"product1", "1.0", "1", "bool_prop_id", "desc", [True]
		),
		ProductDependency(
			"product1", "1.0", "1", "setup", "product2", "2.0", "2", "setup", None, "after"
		),
		ProductOnDepot(
			"product1", "LocalbootProduct", "1.0", "1", "depot.dom.tld", False
		),
		ProductOnClient(
			"product1", "LocalbootProduct", "client.dom.tld", "installed", "installed", "setup", "setup",
			"installing 10%", "failed", "1.0", "1", "2021-01-01", 2
		),
		ProductPropertyState(
			"product1", "prop1", "client.dom.tld", ["x"]
		),
		Group(
			"group1", "desc", "notes", "parentgroup"
		),
		HostGroup(
			"hgroup", "description", "notes", "parentg"
		),
		ProductGroup(
			"pgroup", "p desc", "p note", "pparent"
		),
		ObjectToGroup(
			"HostGroup", "hgroup", "client.dom.tld"
		),
		LicenseContract(
			"licontract1", "desc", "notes", "partner", "2020-01-01", "2021-12-01", "2025-01-01"
		),
		SoftwareLicense(
			"lic1", "licontract1", 1, "client.dom.tld", "2021-12-01"
		),
		RetailSoftwareLicense(
			"retlic1", "licontract1", 1, "client.dom.tld", "2023-12-01"
		),
		OEMSoftwareLicense(
			"oemlic1", "licontract1", 1, "client.dom.tld", "2025-12-01"
		),
		VolumeSoftwareLicense(
			"collic1", "licontract1", 100, "client.dom.tld", "2029-12-01"
		),
		ConcurrentSoftwareLicense(
			"conlic1", "licontract1", 1, "client.dom.tld", "2020-12-01"
		),
		LicensePool(
			"licpool1", "desc", ["prod1", "prod2"]
		),
		AuditSoftwareToLicensePool(
			"sname", "1.0", "sub", "en", "x64", "licpool1"
		),
		SoftwareLicenseToLicensePool(
			"lic1", "licpool1", "123123213"
		),
		LicenseOnClient(
			"lic1", "licpool1", "client.dom.tld", "123", "notes"
		),
		AuditSoftware(
			"sname", "1.0", "sub", "en", "x64", "sw1", "disp1", "1.0", 10000
		),
		AuditSoftwareOnClient(
			"sname", "1.0", "sub", "en", "x64", "client.dom.tld", "uninst", "binname", "2020-01-01",
			"2021-01-01", 1, 100, "2020-01-01", "123123"
		),
		AuditHardware(
			"BASE_BOARD"
		),
		AuditHardwareOnHost(
			"BASE_BOARD", "client.dom.tld"
		)
	)
	for obj in objs:
		assert str(obj)
		assert obj.sub_classes is not None
		assert obj.foreign_id_attributes is not None
		assert obj.backend_method_prefix is not None
		assert obj.foreign_id_attributes is not None
		assert obj.getIdentAttributes()
		assert obj.getIdent()
		assert obj.getType()
		assert obj.to_json()

		_dict = obj.to_hash()
		for attr, value in _dict.items():
			if attr == "type":
				continue
			getter = getattr(obj, f"get{attr[0].upper()}{attr[1:]}")
			assert getter() == value
			setter = getattr(obj, f"set{attr[0].upper()}{attr[1:]}")
			if value is not None:
				setter(value)

		# type: ignore[assignment]
		if not isinstance(obj, Entity):
			raise ValueError("wrong type")  # pylint: disable=loop-invariant-statement

		_class = obj.__class__

		for key in dir(_class):
			if isinstance(getattr(_class, key), property):
				assert getattr(obj, key)

		_class.fromHash(_dict)
		del _dict["type"]
		assert isinstance(_class.fromHash(_dict), _class)
		assert isinstance(_class.from_json(json.dumps(_dict)), _class)  # pylint: disable=dotted-import-in-loop

		obj.update(obj.clone())
		obj.emptyValues()
		obj.setDefaults()


def test_get_possible_class_attributes() -> None:
	assert get_possible_class_attributes(Host) == set([
		'masterDepotId', 'depotLocalUrl', 'repositoryRemoteUrl',
		'description', 'created', 'inventoryNumber', 'notes',
		'oneTimePassword', 'isMasterDepot', 'id', 'lastSeen',
		'maxBandwidth', 'hardwareAddress', 'networkAddress',
		'repositoryLocalUrl', 'opsiHostKey', 'ipAddress',
		'depotWebdavUrl', 'depotRemoteUrl', 'type',
		'workbenchRemoteUrl', 'workbenchLocalUrl'
	])

	class Test(Entity):  # pylint: disable=too-few-public-methods
		sub_classes: Dict[str, type] = {}

		def __init__(no_self: Any, arg: Any) -> None:  # pylint: disable=unused-argument,no-self-argument
			pass

	assert get_possible_class_attributes(Test) == set(["no_self", "arg", "type"])


def test_get_foreign_id_attributes() -> None:
	assert get_foreign_id_attributes(Host) == ['objectId', 'hostId']


def test_get_backend_method_prefix() -> None:
	assert get_backend_method_prefix(Host) == 'host'


@pytest.mark.parametrize("cls, value, expected, exc", (
	(
		ProductOnClient,
		{"ident": ["product", "LocalbootProduct", "client1.dom.tld"]},
		{"productId": "product", "productType": "LocalbootProduct", "clientId": "client1.dom.tld"},
		None
	),
	(
		ProductOnClient,
		{"ident": ("product", "LocalbootProduct", "client1.dom.tld")},
		{"productId": "product", "productType": "LocalbootProduct", "clientId": "client1.dom.tld"},
		None
	),
	(
		ProductOnClient,
		{"ident": "product;LocalbootProduct;client1.dom.tld"},
		{"productId": "product", "productType": "LocalbootProduct", "clientId": "client1.dom.tld"},
		None
	),
	(
		ProductOnClient,
		{"ident": "product;LocalbootProduct;client1.dom.tld;invalid"},
		None,
		ValueError
	)
))
def test_decode_ident(cls: Type, value: dict, expected: Optional[dict], exc: Optional[Type[Exception]]) -> None:
	if exc:
		with pytest.raises(exc):
			decode_ident(cls, value)
	else:
		result = decode_ident(cls, value)
		# print(result)
		assert result == expected


CONFIG_SERVER1 = vars(OpsiConfigserver(
	id='configserver1.test.invalid',
	opsiHostKey='71234545689056789012123678901234',
	depotLocalUrl='file:///var/lib/opsi/depot',
	depotRemoteUrl='smb://configserver1/opsi_depot',
	repositoryLocalUrl='file:///var/lib/opsi/repository',
	repositoryRemoteUrl='webdavs://configserver1:4447/repository',
	description='The configserver',
	notes='Config 1',
	hardwareAddress=None,
	ipAddress=None,
	inventoryNumber='00000000001',
	networkAddress='192.168.1.0/24',
	maxBandwidth=10000
))


def test_object_hash() -> None:
	config_server1 = OpsiConfigserver(**CONFIG_SERVER1)
	config_server2 = OpsiConfigserver(**CONFIG_SERVER1)
	assert hash(config_server1) == hash(config_server2)


def test_object_to_str() -> None:
	config_server1 = OpsiConfigserver(**CONFIG_SERVER1)
	_str = str(config_server1)
	assert _str.startswith("<OpsiConfigserver")


def test_objects_differ() -> None:
	config_server1 = OpsiConfigserver(**CONFIG_SERVER1)
	config_server2 = OpsiConfigserver(**CONFIG_SERVER1)
	assert not objects_differ(config_server1, config_server2)

	assert objects_differ(config_server1, None)

	config_server2.setDescription("123")
	assert objects_differ(config_server1, config_server2)
	assert not objects_differ(config_server1, config_server2, exclude_attributes=["description"])

	config_server2.description = 123  # type: ignore[assignment]
	assert objects_differ(config_server1, config_server2)

	config_server1.description = {"test": 1}  # type: ignore[assignment]
	config_server2.description = {"test": 1, "test2": 2}  # type: ignore[assignment]
	assert objects_differ(config_server1, config_server2)

	config_server1.description = {"test": 1}  # type: ignore[assignment]
	config_server2.description = {"test": 2}  # type: ignore[assignment]
	assert objects_differ(config_server1, config_server2)

	config_server1.description = ["test"]  # type: ignore[assignment]
	config_server2.description = ["test", "test2"]  # type: ignore[assignment]
	assert objects_differ(config_server1, config_server2)

	config_server1.description = ["test", "test1"]  # type: ignore[assignment]
	config_server2.description = ["test", "test2"]  # type: ignore[assignment]
	assert objects_differ(config_server1, config_server2)

	config_server1.description = ["test", "test2"]  # type: ignore[assignment]
	config_server2.description = ["test", "test2", "test3"]  # type: ignore[assignment]
	assert objects_differ(config_server1, config_server2)


def test_comparing_config_server_to_other_object_with_same_settings() -> None:
	config_server1 = OpsiConfigserver(**CONFIG_SERVER1)
	config_server2 = OpsiConfigserver(**CONFIG_SERVER1)
	assert config_server1 == config_server2


def test_comparing_configserver_to_depotserver_fails() -> None:
	assert OpsiConfigserver(**CONFIG_SERVER1) != OpsiDepotserver(**CONFIG_SERVER1)


def test_comparing_config_server_to_some_dict_fails() -> None:
	assert OpsiConfigserver(**CONFIG_SERVER1) != {"test": 123}


PRODUCT2 = vars(LocalbootProduct(
	id='product2',
	name='Product 2',
	productVersion='2.0',
	packageVersion='test',
	licenseRequired=False,
	setupScript="setup.ins",
	uninstallScript="uninstall.ins",
	updateScript="update.ins",
	alwaysScript=None,
	onceScript=None,
	priority=0,
	description=None,
	advice="",
	productClassIds=['localboot-products'],
	windowsSoftwareIds=['{98723-7898adf2-287aab}', 'xxxxxxxx']
))


def test_comparing_two_localboot_products_with_same_settings() -> None:
	assert LocalbootProduct(**PRODUCT2) == LocalbootProduct(**PRODUCT2)


def test_object_empty_values() -> None:
	product = LocalbootProduct(**PRODUCT2)
	product.emptyValues()
	mand = mandatory_constructor_args(LocalbootProduct)
	mand.append("type")
	for attr, val in product.to_hash().items():
		if attr not in mand:
			assert val is None


def test_object_update() -> None:
	product1 = LocalbootProduct(**PRODUCT2)
	product2 = LocalbootProduct(**PRODUCT2)
	product2.setDescription("NEW DESCRIPTION")
	product2.setAdvice("NEW ADVICE")

	product1.update(product2)
	assert product1.description == product2.description
	assert product1.advice == product2.advice
	assert not objects_differ(product1, product2)

	product2.description = None
	product1.update(product2, updateWithNoneValues=False)
	assert product2.description is None
	assert product1.description == "NEW DESCRIPTION"

	product1.update(product2, updateWithNoneValues=True)
	assert product2.description is None
	assert product1.description is None


def test_from_hash() -> None:
	product1 = LocalbootProduct(**PRODUCT2)
	_hash = PRODUCT2.copy()
	product2 = LocalbootProduct.fromHash(_hash)
	assert not objects_differ(product1, product2)

	del _hash["productVersion"]
	with pytest.raises(TypeError):
		LocalbootProduct.fromHash(_hash)

	with pytest.raises(TypeError) as err:
		LocalbootProduct.fromHash({"id": "p1"})
	assert "Missing required argument(s): 'productVersion', 'packageVersion'" in str(err.value)


def test_clone() -> None:
	product1 = LocalbootProduct(**PRODUCT2)
	product2 = product1.clone(identOnly=False)
	assert not objects_differ(product1, product2)

	product2 = product1.clone(identOnly=True)
	assert objects_differ(product1, product2)
	for attr in product1.getIdentAttributes():
		if attr != "type":
			assert getattr(product1, attr) == getattr(product2, attr)


def test_serialize() -> None:
	product1 = LocalbootProduct(**PRODUCT2)
	_hash = product1.to_hash()
	res = product1.serialize()
	_hash["ident"] = product1.getIdent("str")
	assert _hash == res


def test_set_defaults() -> None:
	product1 = LocalbootProduct(**PRODUCT2)
	product1.emptyValues()
	product1.setDefaults()
	assert product1.customScript == ""
	assert product1.priority == 0


def test_multivalue_unicode_config_with_unicode() -> None:
	config = UnicodeConfig(
		id='python-opsi.test',
		description="Something from the OPSI forums.",
		possibleValues=["Neutron Gerätetechnik GmbH", "Neutron Mikroelektronik GmbH"],
		defaultValues=["Neutron Mikroelektronik GmbH"]
	)

	assert config.possibleValues and "Neutron Gerätetechnik GmbH" in config.possibleValues
	assert config.possibleValues and "Neutron Mikroelektronik GmbH" in config.possibleValues


AUDIT_HARDWARE_ON_HOST1 = vars(AuditHardwareOnHost(
	hostId="client.test.local",
	hardwareClass='COMPUTER_SYSTEM',
	description="Description for auditHardware",
	vendor="Vendor for auditHardware",
	model="Model for auditHardware",
	serialNumber='843391034-2192',
	systemType='Desktop',
	totalPhysicalMemory=1073741824
))


def test_audit_hardware_on_host_unicode() -> None:
	audit_hardware_on_host = AuditHardwareOnHost(**AUDIT_HARDWARE_ON_HOST1)
	assert str(audit_hardware_on_host)


def test_audit_hardware_on_host_unicode_with_additionals() -> None:
	audit_hardware_on_host = AuditHardwareOnHost(**AUDIT_HARDWARE_ON_HOST1)
	setattr(audit_hardware_on_host, "name", "Ünicöde name.")
	assert str(audit_hardware_on_host)


def test_getting_helpful_error_message_with_baseclass_relationship() -> None:
	"""
	Error messages for object.fromHash should be helpful.

	If the creation of a new object from a hash fails the resulting error
	message should show what required attributes are missing.
	"""
	with pytest.raises(TypeError) as err:
		ProductDependency.fromHash({
			"productAction": "setup",
			"requirementType": "after",
			"requiredInstallationStatus": "installed",
			"requiredProductId": "mshotfix",
			"product_id": "msservicepack"
			# The following attributes are missing:
			# * productVersion
			# * packageVersion
		})

	# print(err)
	assert '__init__() takes at least 6 arguments (6 given)' not in str(err)
	assert 'productVersion' in str(err)
	assert 'packageVersion' in str(err)


def test_getting_helpful_error_message_with_baseclass_entity() -> None:
	"""
	Error messages for Product.fromHash should be helpful.

	If the creation of a new object from a hash fails the resulting error
	message should show what required attributes are missing.
	"""
	with pytest.raises(TypeError) as err:
		Product.fromHash({
			"id": "newProduct",
			# The following attributes are missing:
			# * productVersion
			# * packageVersion
		})
	# print(err)
	assert '__init__() takes at least 6 arguments (6 given)' not in str(err)
	assert 'productVersion' in str(err)
	assert 'packageVersion' in str(err)


def test_get_mandatory_constructor_args_from_constructor_with_no_arguments() -> None:
	class NoArgs(BaseObject):  # pylint: disable=too-few-public-methods
		def __init__(self) -> None:
			pass

	obj = NoArgs()
	with empty_mandatory_constructor_args_cache():
		assert mandatory_constructor_args(obj.__class__) == []


def test_get_mandatory_constructor_args_from_constructor_with_only_mandatory_arguments() -> None:
	class OnlyMandatory(BaseObject):  # pylint: disable=too-few-public-methods
		def __init__(self, arg1: Any, arg2: Any, arg3: Any) -> None:  # pylint: disable=unused-argument
			pass

	obj = OnlyMandatory(1, 1, 1)
	with empty_mandatory_constructor_args_cache():
		assert mandatory_constructor_args(obj.__class__) == ['arg1', 'arg2', 'arg3']


def test_get_mandatory_constructor_args_from_constructor_with_only_optional_arguments() -> None:
	class OnlyOptional(BaseObject):  # pylint: disable=too-few-public-methods
		def __init__(self, only: int = 1, optional: int = 2, arguments: Any = None) -> None:  # pylint: disable=unused-argument
			pass

	obj = OnlyOptional()
	with empty_mandatory_constructor_args_cache():
		assert mandatory_constructor_args(obj.__class__) == []


def test_get_mandatory_constructor_args_from_constructor_with_mixed_arguments() -> None:
	class MixedArgs(BaseObject):  # pylint: disable=too-few-public-methods
		def __init__(self, arg1: bool, arg2: bool, kwarg1: int = 0, kwarg2: int = 0) -> None:  # pylint: disable=unused-argument
			pass

	obj = MixedArgs(True, True)
	with empty_mandatory_constructor_args_cache():
		assert mandatory_constructor_args(obj.__class__) == ["arg1", "arg2"]


def test_get_mandatory_constructor_args_from_constructor_with_wildcard_arguments() -> None:
	class WildcardOnly(BaseObject):  # pylint: disable=too-few-public-methods
		def __init__(self, *only: Any) -> None:  # pylint: disable=unused-argument
			pass

	obj = WildcardOnly("yeah", "great", "thing")
	with empty_mandatory_constructor_args_cache():
		assert mandatory_constructor_args(obj.__class__) == []


def test_get_mandatory_constructor_args_from_constructor_with_keyword_arguments() -> None:
	class Kwargz(BaseObject):  # pylint: disable=too-few-public-methods
		def __init__(self, **kwargs: Any) -> None:  # pylint: disable=unused-argument
			pass

	obj = Kwargz(goand=1, get="asdf", them=[], girl=True)
	with empty_mandatory_constructor_args_cache():
		assert mandatory_constructor_args(obj.__class__) == []


def test_get_mandatory_constructor_args_from_constructor_with_mixed_with_args_and_kwargs() -> None:
	class KwargzAndMore(BaseObject):  # pylint: disable=too-few-public-methods
		def __init__(self, crosseyed: bool, heart: bool, *more: Any, **kwargs: Any) -> None:  # pylint: disable=unused-argument
			pass

	obj = KwargzAndMore(False, True, "some", "more", things="here")
	with empty_mandatory_constructor_args_cache():
		assert mandatory_constructor_args(obj.__class__) == ["crosseyed", "heart"]


def test_product_name_can_be_very_long() -> None:
	"""
	Namens with a length of more than 128 characters can are supported.
	"""
	product = Product(
		id='new_prod',
		name='New Product for Tests',
		productVersion='1.0',
		packageVersion='1.0'
	)

	new_name = (
		'This is a very long name with 128 characters to test the '
		'creation of long product names that should work now but '
		'were limited b4'
	)

	product.setName(new_name)
	name_from_prod = product.getName()
	assert new_name == name_from_prod
	assert 128 == len(name_from_prod)


@pytest.mark.parametrize("property_class", [ProductProperty, BoolProductProperty, UnicodeProductProperty])
@pytest.mark.parametrize("required_attribute", ["description", "defaultValues"])
def test_product_property_shows_optional_arguments_in_repr(property_class: Type, required_attribute: str) -> None:
	additional_param = {required_attribute: [True]}
	prod_prop = property_class('testprod', '1.0', '2', 'myproperty', **additional_param)
	rep = repr(prod_prop)
	assert required_attribute in rep
	assert rep.startswith('<')
	assert rep.endswith('>')


@pytest.mark.parametrize("property_class", [ProductProperty, BoolProductProperty, UnicodeProductProperty])
@pytest.mark.parametrize("attribute_name", ['description'])
@pytest.mark.parametrize("attribute_value", [
	'someText',
	'',
	None
])
def test_product_property_representation_shows_value_if_filled(
	property_class: Type, attribute_name: str, attribute_value: Optional[str]
) -> None:
	attrs = {attribute_name: attribute_value}
	prod_prop = property_class('testprod', '1.0', '2', 'myproperty', **attrs)

	rep = repr(prod_prop)
	if attribute_value:
		assert f'{attribute_name}=' in rep
		assert repr(attribute_value) in rep
	else:
		assert f'{attribute_name}=' not in rep
		assert repr(attribute_value) not in rep


@pytest.mark.parametrize("property_class", [ProductProperty, UnicodeProductProperty])
@pytest.mark.parametrize("required_attribute", ["multiValue", "editable", "possibleValues"])
def test_product_property_shows_optional_arguments_in_repr2(property_class: Type, required_attribute: str) -> None:
	additional_param = {required_attribute: [True]}
	prod_prop = property_class('testprod', '1.0', '2', 'myproperty', **additional_param)
	rep = repr(prod_prop)
	assert required_attribute in rep
	assert rep.startswith('<')
	assert rep.endswith('>')


@pytest.mark.parametrize("test_values", [
	[1, 2, 3],
	[False],
	False,
	[True],
	True,
])
def test_product_property_state_show_selected_values(test_values: Any) -> None:
	product_id = 'testprod'
	property_id = 'myproperty'
	object_id = 'testobject.foo.bar'
	state = ProductPropertyState(product_id, property_id, object_id, values=test_values)

	rep = repr(state)
	assert state.__class__.__name__ in rep
	assert product_id in rep
	assert property_id in rep
	assert object_id in rep
	assert 'values=' in rep
	assert repr(test_values) in rep
	assert rep.startswith('<')
	assert rep.endswith('>')
