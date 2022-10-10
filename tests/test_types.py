# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""


import time
import datetime

import pytest

from opsicommon.objects import OpsiClient, Host, ProductOnClient
from opsicommon.types import (
	args, forceActionRequest, forceActionRequestList, forceActionProgress, forceActionResult,
	forceRequirementType,
	forceArchitecture, forceBool, forceDict, forceBoolList, forceEmailAddress,
	forceFilename, forceFloat, forceFqdn, forceGroupType, forceHardwareAddress,
	forceHostId, forceInstallationStatus, forceInt, forceUnsignedInt, forceIntList,
	forceIPAddress, forceHostAddress, forceNetmask,
	forceNetworkAddress, forceLanguageCode, forceList, forceObjectClass,
	forceOct, forceOpsiHostKey, forceOpsiTimestamp, forcePackageVersion, forcePackageVersionList,
	forceProductId, forceProductIdList, forcePackageCustomName, forceProductType,
	forceProductVersion, forceProductVersionList, forceProductPropertyId, forceConfigId,
	forceProductPropertyType, forceProductPriority, forceProductTargetConfiguration,
	forceTime, forceHardwareVendorId, forceHardwareDeviceId,
	forceUnicode, forceUnicodeList, forceUnicodeLowerList, forceUniqueList,
	forceUrl
)


@pytest.fixture
def opsi_client():
	return OpsiClient(
		id='test1.test.invalid',
		description='Test client 1',
		notes='Notes ...',
		hardwareAddress='00:01:02:03:04:05',
		ipAddress='192.168.1.100',
		lastSeen='2009-01-01 00:00:00',
		opsiHostKey='45656789789012789012345612340123'
	)


@pytest.mark.parametrize("cls", [Host, OpsiClient])
def test_force_object_class_to_host_from_json(opsi_client, cls):  # pylint: disable=redefined-outer-name
	assert isinstance(forceObjectClass(opsi_client.toJson(), cls), cls)


def test_forcing_object_class_from_product_on_client_json():
	json = {
		"clientId": "dolly.janus.vater",
		"action_request": "setup",
		"productType": "LocalbootProduct",
		"type": "ProductOnClient",
		"productId": "hoer_auf_deinen_vater"
	}

	poc = forceObjectClass(json, ProductOnClient)

	assert isinstance(poc, ProductOnClient)


def test_forcing_object_class_from_json_has_good_error_description():
	incomplete_json = {
		"clientId": "Nellie*",
		"action_request": "setup",
		"productType": "LocalbootProduct",
		"type": "ProductOnClient"
	}

	try:
		forceObjectClass(incomplete_json, ProductOnClient)
		pytest.fail("No error from incomplete json.")
	except ValueError as error:
		assert "missing 1 required positional argument: 'productId'" in str(error)

	incomplete_json['type'] = "NotValid"
	try:
		forceObjectClass(incomplete_json, ProductOnClient)
		pytest.fail("No error from invalid type.")
	except ValueError as error:
		assert "Invalid object type: NotValid" in str(error)


def test_forcing_object_class_from_invalid_json():
	with pytest.raises(ValueError):
		forceObjectClass('{"id":"x"', ProductOnClient)


@pytest.mark.parametrize("cls", [Host, OpsiClient])
def test_force_object_class_from_hash(opsi_client, cls):  # pylint: disable=redefined-outer-name
	assert isinstance(forceObjectClass(opsi_client.toHash(), cls), cls)


def funky_generator():
	yield "y"
	yield "u"
	yield "so"
	yield "funky"


@pytest.mark.parametrize("inp,expected", [
	("x", ['x']),
	("xy", ['xy']),
	(None, [None]),
	((0, 1), [0, 1]),
	(('x', 'a'), ['x', 'a']),
	(['x', 'a'], ['x', 'a']),
	(funky_generator(), ['y', 'u', 'so', 'funky']),
])
def test_force_list(inp, expected):
	result = forceList(inp)
	assert isinstance(result, list)
	assert expected == result


def test_force_list_converting_set():
	inputset = set('abc')
	result_list = forceList(inputset)

	assert len(inputset) == len(result_list)

	for element in inputset:
		assert element in result_list


@pytest.mark.parametrize("value, expected", [
	('x', 'x'),
	(b'bff69c0d457adb884dafbe8b55a56258', 'bff69c0d457adb884dafbe8b55a56258')
])
def test_force_unicode_results_in_unicode(value, expected):
	result = forceUnicode(value)
	assert isinstance(result, str)
	assert result == expected


def test_force_unicode_list_results_in_list_of_unicode():
	returned = forceUnicodeList([None, 1, 'x', 'y'])
	assert isinstance(returned, list)

	for i in returned:
		assert isinstance(i, str)


def test_force_unicode_lower_list_results_in_lowercase():
	assert forceUnicodeLowerList(['X', 'YES']) == ['x', 'yes']


def test_force_unicode_lower_list_results_in_unicode():
	for i in forceUnicodeLowerList([None, 1, 'X', 'y']):
		assert isinstance(i, str)


@pytest.mark.parametrize("value", ("on", "oN", 'YeS', 1, '1', 'x', True, 'true', 'TRUE'))
def test_force_bool_with_true_values(value):
	assert forceBool(value) is True


@pytest.mark.parametrize("value", ("off", "oFF", 'no', 0, '0', False, 'false', 'FALSE'))
def test_force_bool_with_falsy_values(value):
	assert forceBool(value) is False


def test_force_bool_with_positive_list():
	for i in forceBoolList([1, 'yes', 'on', '1', True]):
		assert i is True


def test_force_bool_with_negative_list():
	for i in forceBoolList([None, 'no', 'false', '0', False]):
		assert i is False


@pytest.mark.parametrize("value, expected", (
	('100', 100),
	('-100', -100),
	(int(1000000000000000), 1000000000000000)
))
def test_force_int(value, expected):
	assert expected == forceInt(value)


@pytest.mark.parametrize("value, expected", (
	('100', 100),
	('-100', 100)
))
def test_force_unsigned_int(value, expected):
	assert expected == forceUnsignedInt(value)


@pytest.mark.parametrize("value", ("abc", ))
def test_force_int_raises_value_error_if_no_conversion_possible(value):
	with pytest.raises(ValueError):
		forceInt(value)


def test_force_int_list():
	assert [100, 1, 2] == forceIntList(['100', 1, '2'])


@pytest.mark.parametrize("value, expected", (
	(0o750, 0o750),
	(0o666, 0o666),
	('666', 0o666),
	('0666', 0o666),
))
def test_force_oct(value, expected):
	assert expected == forceOct(value)


@pytest.mark.parametrize("value", ('abc', '8'))
def test_force_oct_raising_errors_on_invalid_value(value):
	with pytest.raises(ValueError):
		forceOct(value)


@pytest.mark.parametrize("value, expected", (
	('20000202111213', '2000-02-02 11:12:13'),
	(None, '0000-00-00 00:00:00'),
	(0, '0000-00-00 00:00:00'),
	('', '0000-00-00 00:00:00'),
	('2020-01-01', '2020-01-01 00:00:00'),
	(datetime.datetime(2013, 9, 11, 10, 54, 23), '2013-09-11 10:54:23'),
	(datetime.datetime(2013, 9, 11, 10, 54, 23, 123123), '2013-09-11 10:54:23'),
))
def test_force_opsi_timestamp(value, expected):
	result = forceOpsiTimestamp(value)
	assert expected == result
	assert isinstance(result, str)


@pytest.mark.parametrize("value", ('abc', '8'))
def test_force_opsi_timestamp_raises_errors_on_wrong_input(value):
	with pytest.raises(ValueError):
		forceOpsiTimestamp(value)


@pytest.mark.parametrize("host_id, expected", (
	('client.test.invalid', 'client.test.invalid'),
	('CLIENT.test.invalid', 'client.test.invalid')
))
def test_force_host_id(host_id, expected):
	assert expected == forceHostId(host_id)


@pytest.mark.parametrize("host_id", ('abc', '8', 'abc.def', '.test.invalid', 'abc.uib.x'))
def test_force_host_id_raises_exception_if_invalid(host_id):
	with pytest.raises(ValueError):
		forceHostId(host_id)


@pytest.mark.parametrize("address, expected", (
	('12345678ABCD', '12:34:56:78:ab:cd'),
	('12:34:56:78:ab:cd', '12:34:56:78:ab:cd'),
	('12-34-56-78-Ab-cD', '12:34:56:78:ab:cd'),
	('12-34-56:78AB-CD', '12:34:56:78:ab:cd'),
	('', ''),
))
def test_forcing_returns_address_seperated_by_colons(address, expected):
	result = forceHardwareAddress(address)
	assert expected == result
	assert isinstance(result, str)


@pytest.mark.parametrize("address", (
	'12345678abc',
	'12345678abcdef',
	'1-2-3-4-5-6-7',
	None,
	True,
))
def test_forcing_invalid_addresses_raise_exceptions(address):
	with pytest.raises(ValueError):
		forceHardwareAddress(address)


@pytest.mark.parametrize("inp, expected", [
	('1.1.1.1', '1.1.1.1'),
	('192.168.101.1', '192.168.101.1'),
	('192.168.101.1', '192.168.101.1'),
	('2001:0db8:85a3::8a2e:0370:7334', '2001:db8:85a3::8a2e:370:7334'),
	('2001:db8:85a3:0000:0000:8a2e:0370:7334', '2001:db8:85a3::8a2e:370:7334'),
	('::FFFF:129.144.52.38', '129.144.52.38')
])
def test_force_ip_address(inp, expected):
	output = forceIPAddress(inp)
	assert expected == output
	assert isinstance(output, str)


@pytest.mark.parametrize("malformed_input", [
	'1922.1.1.1',
	None,
	True,
	'1.1.1.1.',
	'2.2.2.2.2',
	'a.2.3.4',
])
def test_force_ip_address_fails_on_invalid_input(malformed_input):
	with pytest.raises(ValueError):
		forceIPAddress(malformed_input)


@pytest.mark.parametrize("value, expected, exc", (
	('2001:db8:85a3::8a2e:0370:7334', '2001:db8:85a3::8a2e:370:7334', None),
	('192.168.1.1', '192.168.1.1', None),
	('host.DOM.tld', 'host.dom.tld', None),
	('hostName', 'hostname', None),
	('192.168.1.1.2', None, ValueError),
))
def test_force_host_address(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceHostAddress(value)
	else:
		assert forceHostAddress(value) == expected


@pytest.mark.parametrize("value, expected, exc", (
	('255.255.255.0', '255.255.255.0', None),
	('255.255.255.256', None, ValueError),
	('24', None, ValueError),
))
def test_force_netmask(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceNetmask(value)
	else:
		assert forceNetmask(value) == expected


@pytest.mark.parametrize("address, expected", (
	('192.168.0.0/16', '192.168.0.0/16'),
	('10.10.10.10/32', '10.10.10.10/32'),
))
def test_force_network_address(address, expected):
	result = forceNetworkAddress(address)
	assert expected == result
	assert isinstance(result, str)


@pytest.mark.parametrize("address", (
	'192.168.101',
	'192.1.1.1/40',
	None,
	True,
	'10.10.1/24',
	'a.2.3.4/0',
))
def test_force_network_address_with_invalid_addresses_raises_exceptions(address):
	with pytest.raises(ValueError):
		forceNetworkAddress(address)


@pytest.mark.parametrize("url, expected", (
	('file:///', 'file:///'),
	('file:///path/to/file', 'file:///path/to/file'),
	('smb://server/path', 'smb://server/path'),
	('https://x:y@server.domain.tld:4447/resource', 'https://x:y@server.domain.tld:4447/resource'),
))
def test_force_url(url, expected):
	result = forceUrl(url)
	assert expected == result
	assert isinstance(result, str)


@pytest.mark.parametrize("url, expected", (
	('https://X:YY12ZZ@SERVER.DOMAIN.TLD:4447/resource', 'https://X:YY12ZZ@SERVER.DOMAIN.TLD:4447/resource'),
	('https://X:Y@server.domain.tld:4447/resource', 'https://X:Y@server.domain.tld:4447/resource'),
))
def test_force_url_does_not_force_lowercase(url, expected):
	"""
	Complete URLs must not be forced to lowercase because they could \
	include an username / password combination for an proxy.
	"""
	assert expected == forceUrl(url)


@pytest.mark.parametrize("url", (
	'abc',
	'/abc',
	'http//server',
	1,
	True,
	None,
))
def test_force_url_with_invalid_urls_raises_exceptions(url):
	with pytest.raises(ValueError):
		forceUrl(url)


@pytest.mark.parametrize("host_key", (
	'abcdef78901234567890123456789012',
))
def test_force_opsi_host_key(host_key):
	result = forceOpsiHostKey(host_key)
	assert host_key.lower() == result
	assert isinstance(result, str)


@pytest.mark.parametrize("host_key", (
	'abCdeF7890123456789012345678901',  # too short
	'abCdeF78901234567890123456789012b',  # too long
	'GbCdeF78901234567890123456789012',
))
def test_force_opsi_host_key_with_invalid_host_keys_raises_exceptions(host_key):
	with pytest.raises(ValueError):
		forceOpsiHostKey(host_key)


@pytest.mark.parametrize("version, expected, exc", (
	('1.0', '1.0', None),
	('2 3 4', None, ValueError),
))
def test_force_product_version(version, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceProductVersion(version)
	else:
		result = forceProductVersion(version)
		assert expected == result
		assert isinstance(result, str)


@pytest.mark.parametrize("version, expected, exc", (
	(['2.0', '2.1'], ['2.0', '2.1'], None),
	('3.1k', ['3.1k'], None),
	(['1 1 1'], None, ValueError)
))
def test_force_product_version_list(version, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceProductVersionList(version)
	else:
		assert forceProductVersionList(version) == expected


@pytest.mark.parametrize("version, expected, exc", (
	(1, '1', None),
	(8, '8', None),
	('x_3_f', None, ValueError),
))
def test_force_package_version(version, expected, exc):
	if exc:
		with pytest.raises(exc):
			forcePackageVersion(version)
	else:
		result = forcePackageVersion(version)
		assert expected == result
		assert isinstance(result, str)


@pytest.mark.parametrize("version, expected, exc", (
	([2, '2.1'], ['2', '2.1'], None),
	('ver1', ['ver1'], None),
	('___', None, ValueError)
))
def test_force_package_version_list(version, expected, exc):
	if exc:
		with pytest.raises(exc):
			forcePackageVersionList(version)
	else:
		assert forcePackageVersionList(version) == expected


@pytest.mark.parametrize("product_id, expected_product_id", (
	('testProduct1', 'testproduct1'),
))
def test_force_product_id(product_id, expected_product_id):
	result = forceProductId(product_id)
	assert expected_product_id == result
	assert isinstance(result, str)


@pytest.mark.parametrize("product_id", ('äöü', 'product test'))
def test_force_product_id_with_invalid_product_id_raises_exceptions(product_id):
	with pytest.raises(ValueError):
		forceProductId(product_id)


@pytest.mark.parametrize("value, expected, exc", (
	('testProduct1', ['testproduct1'], None),
	(['testproduct1', 'testproduct2'], ['testproduct1', 'testproduct2'], None),
	('ööö', None, ValueError),
))
def test_force_product_id_list(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceProductIdList(value)
	else:
		assert forceProductIdList(value) == expected


@pytest.mark.parametrize("value, expected, exc", (
	('cust', 'cust', None),
	('xy-', None, ValueError),
))
def test_force_package_custom_name(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forcePackageCustomName(value)
	else:
		assert forcePackageCustomName(value) == expected


@pytest.mark.parametrize("path, expected", (
	('c:\\tmp\\test.txt', 'c:\\tmp\\test.txt'),
))
def testforce_filename(path, expected):
	result = forceFilename(path)
	assert expected == result
	assert isinstance(expected, str)


@pytest.mark.parametrize("status", ('installed', 'not_installed', 'unknown'))
def test_force_installation_status(status):
	result = forceInstallationStatus(status)
	assert result == status
	assert isinstance(result, str)


@pytest.mark.parametrize("status", ('none', 'abc'))
def testforce_installation_status_with_invalid_status_raises_exceptions(status):
	with pytest.raises(ValueError):
		forceInstallationStatus(status)


def test_force_unicode_with_invalid_status_raises_exceptions():
	with pytest.raises(ValueError):
		forceActionRequest('installed')


@pytest.mark.parametrize("action_request", (
	'setup',
	'uninstall',
	'update',
	'once',
	'always',
	'none',
	None
))
def test_force_action_request(action_request):
	returned = forceActionRequest(action_request)
	assert returned == str(action_request).lower()
	assert isinstance(returned, str)


def test_force_action_request_returns_none_on_undefined():
	assert forceActionRequest("undefined") is None


@pytest.mark.parametrize("value, expected, exc", (
	("setup", ["setup"], None),
	(["setup", "Always"], ["setup", "always"], None),
	(["invalid"], None, ValueError),
	("INVALID", None, ValueError)
))
def test_force_action_request_list(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceActionRequestList(value)
	else:
		assert forceActionRequestList(value) == expected


@pytest.mark.parametrize("value, expected, exc", (
	("failed", "failed", None),
	("successful", "successful", None),
	("none", "none", None),
	(None, "none", None),
	("", None, None),
	("x", None, ValueError),
	("-", None, ValueError)
))
def test_force_action_result(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceActionResult(value)
	else:
		assert forceActionResult(value) == expected


@pytest.mark.parametrize("value, expected, exc", (
	("Before", "before", None),
	("after", "after", None),
	("", None, None),
	("-", None, ValueError)
))
def test_force_requirement_type(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceRequirementType(value)
	else:
		assert forceRequirementType(value) == expected


def test_force_action_progress():
	returned = forceActionProgress('installing 50%')
	assert returned == 'installing 50%'
	assert isinstance(returned, str)


@pytest.mark.parametrize("code, expected", (
	('xx-xxxx-xx', 'xx-Xxxx-XX'),
	('yy_yy', 'yy-YY'),
	('zz_ZZZZ', 'zz-Zzzz'),
))
def test_force_language_code_normalises_casing(code, expected):
	assert expected == forceLanguageCode(code)


@pytest.mark.parametrize("code, expected", (
	('dE', 'de'),
	('en-us', 'en-US')
))
def test_force_language_code(code, expected):
	assert forceLanguageCode(code) == expected


def test_force_language_code_raises_exception_on_invalid_code():
	with pytest.raises(ValueError):
		forceLanguageCode('de-DEU')


@pytest.mark.parametrize("architecture, expected", (
	('X86', 'x86'),
	('X64', 'x64'),
))
def test_forcing_returns_lowercase(architecture, expected):
	assert expected == forceArchitecture(architecture)


def test_force_time_fails_if_no_time_given():
	with pytest.raises(ValueError):
		forceTime('Hello World!')


@pytest.mark.parametrize("time_info", (
	time.time(),
	time.localtime(),
	datetime.datetime.now(),
))
def test_force_time_returns_time_struct(time_info):
	assert isinstance(forceTime(time_info), time.struct_time)


@pytest.mark.parametrize("value, expected, exc", (
	("0adf", "0ADF", None),
	("012F", "012F", None),
	("invalid", None, ValueError),
	("INVA", None, ValueError)
))
def test_force_hardware_vendor_id(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceHardwareVendorId(value)
	else:
		assert forceHardwareVendorId(value) == expected


@pytest.mark.parametrize("value, expected, exc", (
	("0adE", "0ADE", None),
	("01aa", "01AA", None),
	("----", None, ValueError),
	("", None, ValueError)
))
def test_force_hardware_device_id(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceHardwareDeviceId(value)
	else:
		assert forceHardwareDeviceId(value) == expected


@pytest.mark.parametrize("invalid_mail_address", ('infouib.de',))
def test_force_email_address_raises_an_exception_on_invalid_mail_address(invalid_mail_address):
	with pytest.raises(ValueError):
		forceEmailAddress(invalid_mail_address)


@pytest.mark.parametrize("address, expected", (
	('info@uib.de', 'info@uib.de'),
	('webmaster@somelongname.passenger-association.aero', 'webmaster@somelongname.passenger-association.aero'),
	('bla@name.posts-and-telecommunications.museum', 'bla@name.posts-and-telecommunications.museum'),
	('webmaster@bike.equipment', 'webmaster@bike.equipment'),
	('some.name@company.travelersinsurance', 'some.name@company.travelersinsurance'),
))
# A large list of TLDs can be found at https://publicsuffix.org/
def test_force_email_address(address, expected):
	assert expected == forceEmailAddress(address)


@pytest.mark.parametrize("invalid_type", ('TrolololoProduct', None))
def testforce_product_type_raises_exception_on_unknown_type(invalid_type):
	with pytest.raises(ValueError):
		forceProductType(invalid_type)


@pytest.mark.parametrize("inp", ('LocalBootProduct', 'LOCALBOOT'))
def testforce_product_type_to_localboot_product(inp):
	assert 'LocalbootProduct' == forceProductType(inp)


@pytest.mark.parametrize("inp", ('NetbOOtProduct', 'nETbOOT'))
def testforce_product_type_to_netboot_product(inp):
	assert 'NetbootProduct' == forceProductType(inp)


@pytest.mark.parametrize("value, expected, exc", (
	("prop1", "prop1", None),
	("PROP2", "prop2", None),
	("inv alid", None, ValueError)
))
def test_force_product_property_id(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceProductPropertyId(value)
	else:
		assert forceProductPropertyId(value) == expected


@pytest.mark.parametrize("value, expected, exc", (
	("config.name", "config.name", None),
	("CONF.NAme", "conf.name", None),
	("not valid", None, ValueError)
))
def test_force_config_id(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceConfigId(value)
	else:
		assert forceConfigId(value) == expected


@pytest.mark.parametrize("value, expected, exc", (
	("UnicodeProductProperty", "UnicodeProductProperty", None),
	("Unicodeproductproperty", "UnicodeProductProperty", None),
	("BoolProductProperty", "BoolProductProperty", None),
	("ProductProperty", None, ValueError)
))
def test_force_product_property_type(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceProductPropertyType(value)
	else:
		assert forceProductPropertyType(value) == expected


@pytest.mark.parametrize("value, expected, exc", (
	("100", 100, None),
	(-101, -100, None),
	(1000, 100, None),
	(0.0, 0, None),
	("high", None, ValueError)
))
def test_force_product_priority(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceProductPriority(value)
	else:
		assert forceProductPriority(value) == expected


@pytest.mark.parametrize("value, expected, exc", (
	("Installed", "installed", None),
	("always", "always", None),
	("forbidden", "forbidden", None),
	("undefineD", "undefined", None),
	("other", None, ValueError)
))
def test_force_product_target_configuration(value, expected, exc):
	if exc:
		with pytest.raises(exc):
			forceProductTargetConfiguration(value)
	else:
		assert forceProductTargetConfiguration(value) == expected


@pytest.mark.parametrize("inp, expected", [
	(None, {}),
	({'a': 1}, {'a': 1}),
])
def test_force_dict_returns_dict(inp, expected):
	assert forceDict(inp) == expected


@pytest.mark.parametrize("inp", ['asdg', ['asdfg', 'asd']])
def test_force_dict_fails_if_conversion_impossible(inp):
	with pytest.raises(ValueError):
		forceDict(inp)


@pytest.mark.parametrize("expected, before", (
	([1], [1, 1]),
	([1, 2, 3], (1, 2, 2, 3)),
))
def test_after_forcing_items_in_list_are_unique(before, expected):
	assert expected == forceUniqueList(before)


def test_force_unique_list_does_not_change_order():
	assert [2, 1, 3, 5, 4] == forceUniqueList([2, 2, 1, 3, 5, 4, 1])


def test_args_decorator_arguments_default_to_none():
	@args("somearg", "someOtherArg")
	class SomeClass:  # pylint: disable=too-few-public-methods
		def __init__(self, **kwargs):
			pass

	some_obj = SomeClass()
	assert some_obj.somearg is None  # pylint: disable=no-member
	assert some_obj.someOtherArg is None  # pylint: disable=no-member


def test_args_decorator_takes_keyword_arguments():

	@args("somearg", someOtherArg=forceInt)
	class SomeOtherClass:  # pylint: disable=too-few-public-methods
		def __init__(self, **kwargs):
			pass

	some_other_obj = SomeOtherClass(someOtherArg="5")

	assert some_other_obj.somearg is None  # pylint: disable=no-member
	assert 5 == some_other_obj.someOtherArg  # pylint: disable=no-member


def test_args_decorator_creates_private_args():

	@args("_somearg", "_someOtherArg")
	class SomeClass:  # pylint: disable=too-few-public-methods
		def __init__(self, **kwargs):
			pass

	some_obj = SomeClass(somearg=5)

	assert 5 == some_obj._somearg  # pylint: disable=no-member,protected-access
	assert some_obj._someOtherArg is None  # pylint: disable=no-member,protected-access


def test_force_fqdn_removes_trailing_dot():
	assert 'abc.example.local' == forceFqdn('abc.example.local.')


@pytest.mark.parametrize("hostname", [
	'hostname.rootzone.tld',  # complete hostname
	pytest.param('host_name.rootzone.tld', marks=pytest.mark.xfail),  # underscore
	pytest.param('hostname.tld', marks=pytest.mark.xfail),  # only domain
])
def test_force_fqdn_requires_hostname_root_zone_and_top_level_domain(hostname):
	forceFqdn(hostname)


@pytest.mark.parametrize("domain", [
	'BLA.domain.invalid',
	'bla.doMAIN.invalid',
	'bla.domain.iNVAlid'])
def test_force_fqdn_always_returns_lowercase(domain):
	assert 'bla.domain.invalid' == forceFqdn(domain)


@pytest.mark.parametrize("inp", ['asdf', None])
def test_force_group_fails_on_invalid_input(inp):
	with pytest.raises(ValueError):
		forceGroupType(inp)


@pytest.mark.parametrize("inp, expected", [
	('hostGROUP', 'HostGroup'),
	('HostgROUp', 'HostGroup'),
	('PrOdUcTgRoUp', 'ProductGroup'),
])
def test_force_group_type_standardises_case(inp, expected):
	assert forceGroupType(inp) == expected


@pytest.mark.parametrize("inp, expected", [
	(1, 1.0),
	(1.3, 1.3),
	("1", 1.0),
	("1.3", 1.3),
	("	1.4   ", 1.4),
])
def test_force_float(inp, expected):
	assert expected == forceFloat(inp)


@pytest.mark.parametrize("invalid_input", [
	{"abc": 123},
	['a', 'b'],
	"No float",
	"text",
])
def test_force_float_fails_with_invalid_input(invalid_input):
	with pytest.raises(ValueError):
		forceFloat(invalid_input)
