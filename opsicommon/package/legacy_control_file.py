# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
handling for old control file format
"""

import re
from pathlib import Path

from opsicommon.logging import get_logger
from opsicommon.objects import (
	BoolProductProperty,
	LocalbootProduct,
	NetbootProduct,
	ProductDependency,
	ProductProperty,
	UnicodeProductProperty,
	from_json,
	to_json,
)
from opsicommon.types import (
	forceActionRequest,
	forceBool,
	forceFilename,
	forceInstallationStatus,
	forceList,
	forcePackageVersion,
	forceProductId,
	forceProductPriority,
	forceProductPropertyType,
	forceProductType,
	forceProductVersion,
	forceRequirementType,
	forceUnicode,
	forceUnicodeLower,
	forceUniqueList,
)

logger = get_logger("opsicommon.package")


class LegacyControlFile:
	sectionRegex = re.compile(r"^\s*\[([^\]]+)\]\s*$")
	valueContinuationRegex = re.compile(r"^\s(.*)$")
	optionRegex = re.compile(r"^([^\:]+)\s*\:\s*(.*)$")

	def __init__(self, control_file: Path | None = None) -> None:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
		self._sections: dict[str, str | list[dict[str, str]]] = {}
		self.product = None
		self.productDependencies = []  # pylint: disable=invalid-name
		self.productProperties: list[ProductProperty] = []  # pylint: disable=invalid-name
		self.packageDependencies: list[dict[str, str | None]] = []  # pylint: disable=invalid-name

		if not control_file:
			return

		productAttributes = set(  # pylint: disable=invalid-name
			[
				"id",
				"type",
				"name",
				"description",
				"advice",
				"version",
				"packageversion",
				"priority",
				"licenserequired",
				"productclasses",
				"pxeconfigtemplate",
				"setupscript",
				"uninstallscript",
				"updatescript",
				"alwaysscript",
				"oncescript",
				"customscript",
				"userloginscript",
			]
		)
		dependencyAttributes = set(  # pylint: disable=invalid-name
			[
				"action",
				"requiredproduct",
				"requiredproductversion",
				"requiredpackageversion",
				"requiredclass",
				"requiredstatus",
				"requiredaction",
				"requirementtype",
			]
		)
		propertyAttributes = set(  # pylint: disable=invalid-name
			["type", "name", "default", "values", "description", "editable", "multivalue"]
		)

		sectionType = None  # pylint: disable=invalid-name
		option = None
		for lineNum, line in enumerate(control_file.read_text().splitlines(), start=1):  # pylint: disable=invalid-name
			if line and line.startswith((";", "#")):
				# Comment
				continue

			line = line.replace("\r", "")

			match = self.sectionRegex.search(line)
			if match:
				sectionType = match.group(1).strip().lower()  # pylint: disable=invalid-name
				if sectionType not in ("package", "product", "windows", "productdependency", "productproperty", "changelog"):
					raise ValueError(f"Parse error in line {lineNum}: unknown section '{sectionType}'")
				if sectionType == "changelog":
					self._sections[sectionType] = ""
				else:
					if sectionType in self._sections:
						self._sections[sectionType].append({})  # type: ignore
					else:
						self._sections[sectionType] = [{}]
				continue

			if not sectionType and line:
				raise ValueError(f"Parse error in line {lineNum}: not in a section")

			if sectionType == "changelog":
				if self._sections[sectionType]:
					self._sections[sectionType] += "\n"  # type: ignore
				self._sections[sectionType] += line.rstrip()  # type: ignore
				continue

			key = None
			value = None
			match = self.valueContinuationRegex.search(line)
			if match:
				value = match.group(1)
			else:
				match = self.optionRegex.search(line)

				if match:
					key = match.group(1).lower()
					value = match.group(2).strip()

			if sectionType == "package":
				option = key
				if key == "version":
					value = forceUnicodeLower(value)
				elif key == "depends":
					value = forceUnicodeLower(value)
				else:  # Unsupported key
					continue

			elif sectionType == "product" and key in productAttributes:
				option = key
				if key == "id":
					value = forceProductId(value)
				elif key == "type":
					value = forceProductType(value)
				elif key == "name":
					value = forceUnicode(value)
				elif key == "description":
					value = forceUnicode(value)
				elif key == "advice":
					value = forceUnicode(value)
				elif key == "version":
					value = forceProductVersion(value)
				elif key == "packageversion":
					value = forcePackageVersion(value)
				elif key == "priority":
					value = forceProductPriority(value)
				elif key == "licenserequired":
					value = forceBool(value)
				elif key == "productclasses":
					value = forceUnicodeLower(value)
				elif key == "pxeconfigtemplate":
					value = forceFilename(value)
				elif key == "setupscript":
					value = forceFilename(value)
				elif key == "uninstallscript":
					value = forceFilename(value)
				elif key == "updatescript":
					value = forceFilename(value)
				elif key == "alwaysscript":
					value = forceFilename(value)
				elif key == "oncescript":
					value = forceFilename(value)
				elif key == "customscript":
					value = forceFilename(value)
				elif key == "userloginscript":
					value = forceFilename(value)

			elif sectionType == "windows" and key in ("softwareids",):
				option = key
				value = forceUnicodeLower(value)

			elif sectionType == "productdependency" and key in dependencyAttributes:
				option = key
				if key == "action":
					value = forceActionRequest(value)
				elif key == "requiredproduct":
					value = forceProductId(value)
				elif key == "requiredproductversion":
					value = forceProductVersion(value)
				elif key == "requiredpackageversion":
					value = forcePackageVersion(value)
				elif key == "requiredclass":
					value = forceUnicodeLower(value)
				elif key == "requiredstatus":
					value = forceInstallationStatus(value)
				elif key == "requiredaction":
					value = forceActionRequest(value)
				elif key == "requirementtype":
					value = forceRequirementType(value)

			elif sectionType == "productproperty" and key in propertyAttributes:
				option = key
				if key == "type":
					value = forceProductPropertyType(value)
				elif key == "name":
					value = forceUnicodeLower(value)
				elif key == "default":
					value = forceUnicode(value)
				elif key == "values":
					value = forceUnicode(value)
				elif key == "description":
					value = forceUnicode(value)
				elif key == "editable":
					value = forceBool(value)
				elif key == "multivalue":
					value = forceBool(value)

			else:
				value = forceUnicode(line)

			if not option:
				raise ValueError(f"Parse error in line '{lineNum}': no option / bad option defined")

			if option not in self._sections[sectionType][-1]:  # type: ignore
				self._sections[sectionType][-1][option] = value  # type: ignore
			else:
				if isinstance(self._sections[sectionType][-1][option], str):  # type: ignore
					if not self._sections[sectionType][-1][option].endswith("\n"):  # type: ignore
						self._sections[sectionType][-1][option] += "\n"  # type: ignore
					self._sections[sectionType][-1][option] += value.lstrip()  # type: ignore

		for (sectionType, secs) in self._sections.items():  # pylint: disable=too-many-nested-blocks,invalid-name
			if sectionType == "changelog":
				continue

			for i, currentSection in enumerate(secs):  # pylint: disable=invalid-name
				for (option, value) in currentSection.items():  # type: ignore
					if (  # pylint: disable=too-many-boolean-expressions
						(sectionType == "product" and option == "productclasses")
						or (sectionType == "package" and option == "depends")
						or (sectionType == "productproperty" and option in ("default", "values"))
						or (sectionType == "windows" and option == "softwareids")
					):
						try:
							if not value.strip().startswith(("{", "[")):
								raise ValueError("Not trying to read json string because value does not start with { or [")
							value = from_json(value.strip())
							# Remove duplicates
							value = forceUniqueList(value)
						except Exception as err:  # pylint: disable=broad-except
							logger.trace("Failed to read json string '%s': %s", value.strip(), err)  # type: ignore
							value = value.replace("\n", "")
							value = value.replace("\t", "")
							if not (sectionType == "productproperty" and option == "default"):
								value = [v.strip() for v in value.split(",")]

							# Remove duplicates
							value = [v for v in forceList(value) if v not in ("", None)]
							value = forceUniqueList(value)

					if isinstance(value, str):
						value = value.rstrip()

					self._sections[sectionType][i][option] = value  # type: ignore  # pylint: disable=unnecessary-dict-index-lookup

		if not self._sections.get("product"):
			raise ValueError(f"Error in control file '{control_file}': 'product' section not found")

		# Get package info
		for (option, value) in self._sections.get("package", [{}])[0].items():  # type: ignore
			if option == "depends":
				for dep in value:
					match = re.search(r"^\s*([^\(]+)\s*\(*\s*([^\)]*)\s*\)*", dep)
					if not match or not match.group(1):
						raise ValueError(f"Bad package dependency '{dep}' in control file")

					package = match.group(1).strip()
					version = match.group(2)
					condition = None
					if version:
						match = re.search(r"^\s*([<>]?=?)\s*([\w\.]+-*[\w\.]*)\s*$", version)
						if not match:
							raise ValueError(f"Bad version string '{version}' in package dependency")

						condition = match.group(1)
						if not condition:
							condition = "="
						if not isinstance(condition, str) or condition not in ("=", "<", "<=", ">", ">="):
							raise ValueError(f"Bad condition string '{condition}' in package dependency")
						version = match.group(2)
					else:
						version = None
					self.packageDependencies.append({"package": package, "condition": condition, "version": version})

		# Create Product object
		product = self._sections["product"][0]  # type: ignore
		Class: type  # pylint: disable=invalid-name
		if product.get("type") == "NetbootProduct":  # type: ignore
			Class = NetbootProduct
		elif product.get("type") == "LocalbootProduct":  # type: ignore
			Class = LocalbootProduct
		else:
			raise ValueError(f"Error in control file '{control_file}': unknown product type '{product.get('type')}'")  # type: ignore

		productVersion = product.get("version")  # type: ignore  # pylint: disable=invalid-name
		if not productVersion:
			logger.warning("No product version given! Assuming 1.0.")
			productVersion = 1.0  # pylint: disable=invalid-name
		# type: ignore  # pylint: disable=invalid-name
		packageVersion = self._sections.get("package", [{}])[0].get("version") or product.get(
			"packageversion"
		)  # pylint: disable=invalid-name
		if not packageVersion:
			logger.warning("No package version given! Assuming 1.")
			packageVersion = 1  # pylint: disable=invalid-name

		self.product = Class(
			id=product.get("id"),  # type: ignore
			name=product.get("name"),  # type: ignore
			productVersion=productVersion,
			packageVersion=packageVersion,
			licenseRequired=product.get("licenserequired"),  # type: ignore
			setupScript=product.get("setupscript"),  # type: ignore
			uninstallScript=product.get("uninstallscript"),  # type: ignore
			updateScript=product.get("updatescript"),  # type: ignore
			alwaysScript=product.get("alwaysscript"),  # type: ignore
			onceScript=product.get("oncescript"),  # type: ignore
			customScript=product.get("customscript"),  # type: ignore
			priority=product.get("priority"),  # type: ignore
			description=product.get("description"),  # type: ignore
			advice=product.get("advice"),  # type: ignore
			productClassIds=product.get("productclasses"),  # type: ignore
			windowsSoftwareIds=self._sections.get("windows", [{}])[0].get("softwareids", []),  # type: ignore
			changelog=self._sections.get("changelog"),
		)
		if isinstance(self.product, NetbootProduct) and product.get("pxeconfigtemplate") is not None:  # type: ignore
			self.product.setPxeConfigTemplate(product.get("pxeconfigtemplate"))  # type: ignore

		if isinstance(self.product, LocalbootProduct) and product.get("userloginscript") is not None:  # type: ignore
			self.product.setUserLoginScript(product.get("userloginscript"))  # type: ignore
		self.product.setDefaults()

		# Create ProductDependency objects
		for productDependency in self._sections.get("productdependency", []):  # pylint: disable=invalid-name
			self.productDependencies.append(
				ProductDependency(
					productId=self.product.getId(),
					productVersion=self.product.getProductVersion(),
					packageVersion=self.product.getPackageVersion(),
					productAction=productDependency.get("action"),  # type: ignore
					requiredProductId=productDependency.get("requiredproduct"),  # type: ignore
					requiredProductVersion=productDependency.get("requiredproductversion"),  # type: ignore
					requiredPackageVersion=productDependency.get("requiredpackageversion"),  # type: ignore
					requiredAction=productDependency.get("requiredaction"),  # type: ignore
					requiredInstallationStatus=productDependency.get("requiredstatus"),  # type: ignore
					requirementType=productDependency.get("requirementtype"),  # type: ignore
				)
			)
			self.productDependencies[-1].setDefaults()

		# Create ProductProperty objects
		for productProperty in self._sections.get("productproperty", []):  # pylint: disable=invalid-name
			self.parse_product_property(productProperty)  # type: ignore

	def parse_product_property(self, productProperty: dict[str, str]) -> None:  # pylint: disable=invalid-name
		Class: type  # pylint: disable=invalid-name
		if productProperty.get("type", "").lower() in ("unicodeproductproperty", "unicode", ""):
			Class = UnicodeProductProperty
		elif productProperty.get("type", "").lower() in ("boolproductproperty", "bool"):
			Class = BoolProductProperty
		else:
			raise ValueError(f"Error in control file: unknown product property type '{productProperty.get('type')}'")
		self.productProperties.append(
			Class(
				productId=self.product.getId(),  # type: ignore
				productVersion=self.product.getProductVersion(),  # type: ignore
				packageVersion=self.product.getPackageVersion(),  # type: ignore
				propertyId=productProperty.get("name", ""),
				description=productProperty.get("description", ""),
				defaultValues=productProperty.get("default", []),
			)
		)
		if isinstance(self.productProperties[-1], UnicodeProductProperty):
			if productProperty.get("values") is not None:
				self.productProperties[-1].setPossibleValues(productProperty.get("values"))  # type: ignore
			else:
				self.productProperties[-1].possibleValues = []

			if productProperty.get("editable") is not None:
				self.productProperties[-1].setEditable(productProperty["editable"])  # type: ignore
			else:
				if productProperty.get("values") not in (None, []):
					self.productProperties[-1].setEditable(False)
				else:
					self.productProperties[-1].setEditable(True)

			if productProperty.get("multivalue") is not None:
				self.productProperties[-1].setMultiValue(productProperty["multivalue"])  # type: ignore

		self.productProperties[-1].setDefaults()

	def generate_control_file(self, control_file: Path) -> None:  # pylint: disable=too-many-branches,too-many-statements
		if not self.product:
			raise RuntimeError("No product to generate control file for.")
		lines = ["[Package]"]
		lines.append(f"version: {self.product.getPackageVersion()}")
		depends = ""
		for package_dependency in self.packageDependencies:
			if depends:
				depends += ", "

			depends += package_dependency["package"]  # type: ignore
			if package_dependency["version"]:
				depends += f" ({package_dependency['condition']} {package_dependency['version']})"

		lines.append(f"depends: {depends}")
		lines.append("")

		lines.append("[Product]")
		productType = self.product.getType()  # pylint: disable=invalid-name
		if productType == "LocalbootProduct":
			productType = "localboot"  # pylint: disable=invalid-name
		elif productType == "NetbootProduct":
			productType = "netboot"  # pylint: disable=invalid-name
		else:
			raise ValueError(f"Unhandled product type '{productType}'")

		lines.append(f"type: {productType}")
		lines.append(f"id: {self.product.getId()}")
		lines.append(f"name: {self.product.getName()}")
		lines.append("description: ")
		descLines = (self.product.getDescription() or "").split("\n")  # pylint: disable=invalid-name
		if len(descLines) > 0:
			lines[-1] += descLines[0]
			if len(descLines) > 1:
				for line in descLines[1:]:
					lines.append(f" {line}")
		lines.append(f"advice: {self.product.getAdvice()}")
		lines.append(f"version: {self.product.getProductVersion()}")
		lines.append(f"priority: {self.product.getPriority()}")
		lines.append(f"licenseRequired: {self.product.getLicenseRequired()}")
		if self.product.getProductClassIds() is not None:
			lines.append(f'productClasses: {", ".join(self.product.getProductClassIds())}')
		lines.append(f"setupScript: {self.product.getSetupScript()}")
		lines.append(f"uninstallScript: {self.product.getUninstallScript()}")
		lines.append(f"updateScript: {self.product.getUpdateScript()}")
		lines.append(f"alwaysScript: {self.product.getAlwaysScript()}")
		lines.append(f"onceScript: {self.product.getOnceScript()}")
		lines.append(f"customScript: {self.product.getCustomScript()}")
		if isinstance(self.product, LocalbootProduct):
			lines.append(f"userLoginScript: {self.product.getUserLoginScript()}")
		if isinstance(self.product, NetbootProduct):
			pxeConfigTemplate = self.product.getPxeConfigTemplate() or ""  # pylint: disable=invalid-name
			lines.append(f"pxeConfigTemplate: {pxeConfigTemplate}")
		lines.append("")

		if self.product.getWindowsSoftwareIds():
			lines.append("[Windows]")
			lines.append(f'softwareIds: {", ".join(self.product.getWindowsSoftwareIds())}')
			lines.append("")

		for dependency in self.productDependencies:
			lines.append("[ProductDependency]")
			lines.append(f"action: {dependency.getProductAction()}")
			if dependency.getRequiredProductId():
				lines.append(f"requiredProduct: {dependency.getRequiredProductId()}")
			if dependency.getRequiredProductVersion():
				lines.append(f"requiredProductVersion: {dependency.getRequiredProductVersion()}")
			if dependency.getRequiredPackageVersion():
				lines.append(f"requiredPackageVersion: {dependency.getRequiredPackageVersion()}")
			if dependency.getRequiredAction():
				lines.append(f"requiredAction: {dependency.getRequiredAction()}")
			if dependency.getRequiredInstallationStatus():
				lines.append(f"requiredStatus: {dependency.getRequiredInstallationStatus()}")
			if dependency.getRequirementType():
				lines.append(f"requirementType: {dependency.getRequirementType()}")
			lines.append("")

		for productProperty in self.productProperties:  # pylint: disable=invalid-name
			lines.append("[ProductProperty]")
			productPropertyType = "unicode"  # pylint: disable=invalid-name
			if isinstance(productProperty, BoolProductProperty):
				productPropertyType = "bool"  # pylint: disable=invalid-name
			lines.append(f"type: {productPropertyType}")
			lines.append(f"name: {productProperty.getPropertyId()}")
			if not isinstance(productProperty, BoolProductProperty):
				lines.append(f"multivalue: {productProperty.getMultiValue()}")
				lines.append(f"editable: {productProperty.getEditable()}")
			if productProperty.getDescription():
				lines.append("description: ")
				descLines = (productProperty.getDescription() or "").split("\n")  # type: ignore  # pylint: disable=invalid-name
				if len(descLines) > 0:
					lines[-1] += descLines[0]
					if len(descLines) > 1:
						for line in descLines[1:]:
							lines.append(f" {line}")

			if not isinstance(productProperty, BoolProductProperty) and productProperty.getPossibleValues() is not None:
				lines.append(f"values: {to_json(productProperty.getPossibleValues())}")
			if productProperty.getDefaultValues() is not None:
				if isinstance(productProperty, BoolProductProperty):
					lines.append(f"default: {productProperty.getDefaultValues()[0]}")  # type: ignore
				else:
					lines.append(f"default: {to_json(productProperty.getDefaultValues())}")
			lines.append("")

		if self.product.getChangelog():
			lines.append("[Changelog]")
			lines.extend((self.product.getChangelog() or "").split("\n"))

		control_file.write_text("\n".join(lines))
