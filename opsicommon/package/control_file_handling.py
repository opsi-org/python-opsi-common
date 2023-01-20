"""
handling for opsi control files
"""

from typing import Any

import tomlkit

from opsicommon.objects import (
	BoolProductProperty,
	LocalbootProduct,
	NetbootProduct,
	Product,
	ProductDependency,
	ProductProperty,
	UnicodeProductProperty,
)
from opsicommon.types import forceDictList


def multiline_string(value: str) -> tomlkit.items.String:
	return tomlkit.items.String(tomlkit.items.StringType.MLB, value, value, tomlkit.items.Trivia())


def create_package_dependencies(pdeps: list[dict[str, str | None]]) -> list[dict[str, str | None]]:
	result = []
	for pdep in forceDictList(pdeps):
		if not pdep.get('package'):
			raise ValueError(f"No package given: {pdep}")
		if not pdep.get('version'):
			pdep['version'] = None
			pdep['condition'] = None
		else:
			if not pdep.get('condition'):
				pdep['condition'] = '='
			if pdep['condition'] not in ('=', '<', '<=', '>', '>='):
				raise ValueError(f"Bad condition string '{pdep['condition']}' in package dependency")
		result.append(pdep)
	return result


def create_product_dependencies(pid: str, prod_v: str, pack_v: str, pdeps: list[dict[str, str]]) -> list[ProductDependency]:
	result = []
	for dep in pdeps:
		dependency = ProductDependency(
			pid,
			prod_v,
			pack_v,
			dep["action"],
			dep["requiredProduct"],
			requiredProductVersion=dep.get("requiredProductVersion"),
			requiredPackageVersion=dep.get("requiredPackageVersion"),
			requiredAction=dep.get("requiredAction", "setup"),
			requiredInstallationStatus=dep.get("requiredStatus", "installed"),
			requirementType=dep.get("requirementType", "before"),
		)
		result.append(dependency)
	return result


def create_product_properties(pid: str, prod_v: str, pack_v: str, props: list[dict[str, Any]]) -> list[ProductProperty]:
	result = []
	kwargs: dict[str, Any]
	for prop in props:
		pp_class: type = UnicodeProductProperty
		p_type = str(prop.get("type", "")).lower()
		kwargs = {
			"productId": pid,
			"productVersion": prod_v,
			"packageVersion": pack_v,
			"propertyId": prop.get("name", ""),
			"description": prop.get("description", ""),
			"defaultValues": prop.get("default", []),
		}
		if p_type in ("boolproductproperty", "bool"):
			pp_class = BoolProductProperty
		elif p_type in ("unicodeproductproperty", "unicode", ""):
			kwargs.update({
				"possibleValues": prop.get("values", []),
				"editable": [prop.get("editable", not prop.get("values", []))],
				"multiValue": prop.get("multivalue"),
			})
		else:
			raise ValueError(f"Error in control file: unknown product property type '{prop.get('type')}'")
		result.append(pp_class(**kwargs))
		result[-1].setDefaults()
	return result


def create_product(data_dict: dict[str, Any]) -> Product:
	kwargs: dict[str, Any] = data_dict["Product"].copy()
	if data_dict.get("windows"):
		kwargs["windowsSoftwareIds"] = data_dict.get("windows", {}).get("softwareids", [])
	kwargs["productClassIds"] = data_dict["Product"].get("productClasses")  # But WHY??
	kwargs["changelog"] = data_dict.get("changelog", {}).get("changelog")
	for key in ("id", "version", "type", "productClasses"):
		if key in kwargs:
			kwargs.pop(key)
	print(kwargs)
	if data_dict["Product"]["type"] in ("netboot", "NetbootProduct"):
		return NetbootProduct(data_dict["Product"]["id"], data_dict["Product"]["version"], data_dict["Package"]["version"], **kwargs)
	if data_dict["Product"]["type"] in ("localboot", "LocalbootProduct"):
		return LocalbootProduct(data_dict["Product"]["id"], data_dict["Product"]["version"], data_dict["Package"]["version"], **kwargs)
	raise RuntimeError(f"Unknown opsi package type {data_dict['Product']['type']}")


def dictify_product(product: Product) -> dict[str, Any]:
	product_dict = {
		"type": product.getType(),
		"id": product.getId(),
		"name": product.getName(),
		"description": multiline_string(product.getDescription() or "") or None,
		"advice": multiline_string(product.getAdvice() or "") or None,
		"version": product.getProductVersion(),
		"priority": product.getPriority(),
		"licenseRequired": product.getLicenseRequired(),
		"productClasses": product.getProductClassIds(),
		"setupScript": product.getSetupScript() or None,
		"uninstallScript": product.getUninstallScript() or None,
		"updateScript": product.getUpdateScript() or None,
		"alwaysScript": product.getAlwaysScript() or None,
		"onceScript": product.getOnceScript() or None,
		"customScript": product.getCustomScript() or None,
		"userLoginScript": product.getUserLoginScript() or None,
		"windowsSoftwareIds": product.getWindowsSoftwareIds(),
	}
	if isinstance(product, NetbootProduct):
		product_dict["pxeConfigTemplate"] = product.getPxeConfigTemplate()
	return {key: value for key, value in product_dict.items() if value is not None}


def dictify_product_properties(product_properties: list[ProductProperty]) -> list[dict[str, Any]]:
	properties_list = []
	for prop in product_properties:
		property_dict = {
			"type": prop.getType(),
			"name": prop.getPropertyId(),
			"multivalue": prop.getMultiValue(),
			"editable": prop.getEditable(),
			"description": prop.getDescription(),
			"values": prop.getPossibleValues(),
			"default": prop.getDefaultValues(),
		}
		properties_list.append({key: value for key, value in property_dict.items() if value is not None})  # pylint: disable=loop-invariant-statement
	return properties_list


def dictify_product_dependencies(product_dependencies: list[ProductDependency]) -> list[dict[str, Any]]:
	dependencies_list = []
	for dep in product_dependencies:
		dependency_dict = {
			"requiredProduct": dep.getRequiredProductId(),
			"requiredProductVersion": dep.getRequiredProductVersion(),
			"requiredPackageVersion": dep.getRequiredPackageVersion(),
			"action": dep.getProductAction(),
			"requirementType": dep.getRequirementType(),
			"requiredAction": dep.getRequiredAction(),
			"requiredStatus": dep.getRequiredInstallationStatus(),
		}
		dependencies_list.append({key: value for key, value in dependency_dict.items() if value is not None})  # pylint: disable=loop-invariant-statement
	return dependencies_list
