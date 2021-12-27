# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import pytest

from opsicommon.utils import compareVersions


@pytest.mark.parametrize("first, operator, second", [
	('1.0', '<', '2.0'),
	pytest.param('1.0', '>', '2.0', marks=pytest.mark.xfail),
	pytest.param('1.0', '>', '1.0', marks=pytest.mark.xfail),
	pytest.param('1.2.3.5', '>', '2.2.3.5', marks=pytest.mark.xfail),
])
def testComparingVersionsOfSameSize(first, operator, second):
	assert compareVersions(first, operator, second)


@pytest.mark.parametrize("v1, operator, v2", [
	('1.0', '', '1.0'),
	pytest.param('1', '', '2', marks=pytest.mark.xfail),
])
def testComparingWithoutGivingOperatorDefaultsToEqual(v1, operator, v2):
	assert compareVersions(v1, operator, v2)


def testComparingWithOnlyOneEqualitySign():
	assert compareVersions('1.0', '=', '1.0')

@pytest.mark.parametrize("first, operator, second", [
	('1.0or2.0', '<', '1.0or2.1'),
	('1.0or2.0', '<', '1.1or2.0'),
	('1.0or2.1', '<', '1.1or2.0')
])
def testComparingOrVersions(first, operator, second):
	assert compareVersions(first, operator, second)

@pytest.mark.parametrize("first, operator, second", [
	('20.09', '<', '21.h1'),
	('1.0.2s', '<', '1.0.2u'),
	('1.blubb.bla', '<', '1.foo'),
	('1.0.a', '<', '1.0.b'),
	('a.b', '>', 'a.a'),
])
def testComparingLetterVersions(first, operator, second):
	assert compareVersions(first, operator, second)


@pytest.mark.parametrize("operator", ['asdf', '+-', '<>', '!='])
def testUsingUnknownOperatorFails(operator):
	with pytest.raises(ValueError):
		compareVersions('1', operator, '2')


@pytest.mark.parametrize("v1, operator, v2", [
	('1.0~20131212', '<', '2.0~20120101'),
	('1.0~20131212', '==', '1.0~20120101'),
])
def testIgnoringVersionsWithWaveInThem(v1, operator, v2):
	assert compareVersions(v1, operator, v2)


@pytest.mark.parametrize("v1, operator, v2", [
	('abc-1.2.3-4', '==', '1.2.3-4'),
	('1.2.3-4', '==', 'abc-1.2.3-4')
])
def testUsingInvalidVersionStringsFails(v1, operator, v2):
	with pytest.raises(ValueError):
		compareVersions(v1, operator, v2)


@pytest.mark.parametrize("v1, operator, v2", [
	('1.1.0.1', '>', '1.1'),
	('1.1', '<', '1.1.0.1'),
	('1.1', '==', '1.1.0.0'),
])
def testComparisonsWithDifferntDepthsAreMadeTheSameDepth(v1, operator, v2):
	assert compareVersions(v1, operator, v2)


@pytest.mark.parametrize("v1, operator, v2", [
	('1-2', '<', '1-3'),
	('1-2.0', '<', '1-2.1')
])
def testPackageVersionsAreComparedAswell(v1, operator, v2):
	assert compareVersions(v1, operator, v2)

