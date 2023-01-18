"""
handling for opsi control files
"""

from typing import Any

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
	for prop in props:
		pp_class: type = UnicodeProductProperty
		p_type = str(prop.get("type", "")).lower()
		kwargs: dict[str, Any] = {
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
