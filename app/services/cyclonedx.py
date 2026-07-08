from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CycloneDXParseError(ValueError):
    """Raised when a CycloneDX document cannot be parsed."""


class CycloneDXComponent(BaseModel):
    """Normalized software component details from a CycloneDX SBOM."""

    software_name: str | None = Field(None, description="Component or application name")
    version: str | None = Field(None, description="Component version")
    supplier: str | None = Field(None, description="Component supplier")
    package_url: str | None = Field(None, description="Package URL")
    component_type: str | None = Field(None, description="CycloneDX component type")

    model_config = ConfigDict(extra="ignore")


def parse_cyclonedx_file(path: str | Path) -> list[CycloneDXComponent]:
    """Parse a CycloneDX JSON or XML file from disk."""
    file_path = Path(path)
    return parse_cyclonedx(file_path.read_text(encoding="utf-8"))


def parse_cyclonedx(payload: str | bytes | dict[str, Any]) -> list[CycloneDXComponent]:
    """Parse CycloneDX JSON or XML content into normalized component records."""
    if isinstance(payload, dict):
        return _parse_json_bom(payload)

    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")

    content = payload.strip()
    if not content:
        raise CycloneDXParseError("CycloneDX payload is empty.")

    if content.startswith("{"):
        try:
            return _parse_json_bom(json.loads(content))
        except json.JSONDecodeError as error:
            raise CycloneDXParseError("Invalid CycloneDX JSON payload.") from error

    if content.startswith("<"):
        return _parse_xml_bom(content)

    raise CycloneDXParseError("CycloneDX payload must be JSON or XML.")


def _parse_json_bom(payload: dict[str, Any]) -> list[CycloneDXComponent]:
    components = payload.get("components")
    if components is None:
        return []
    if not isinstance(components, list):
        raise CycloneDXParseError("CycloneDX JSON components must be a list.")

    return [
        CycloneDXComponent(
            software_name=_as_string(component.get("name")),
            version=_as_string(component.get("version")),
            supplier=_parse_json_supplier(component.get("supplier")),
            package_url=_as_string(component.get("purl")),
            component_type=_as_string(component.get("type")),
        )
        for component in components
        if isinstance(component, dict)
    ]


def _parse_json_supplier(value: Any) -> str | None:
    if isinstance(value, dict):
        return _as_string(value.get("name"))
    return _as_string(value)


def _parse_xml_bom(content: str) -> list[CycloneDXComponent]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as error:
        raise CycloneDXParseError("Invalid CycloneDX XML payload.") from error

    components_element = _find_child(root, "components")
    if components_element is None:
        return []

    return [
        CycloneDXComponent(
            software_name=_child_text(component, "name"),
            version=_child_text(component, "version"),
            supplier=_xml_supplier(component),
            package_url=_child_text(component, "purl"),
            component_type=_as_string(component.attrib.get("type")),
        )
        for component in _find_children(components_element, "component")
    ]


def _xml_supplier(component: ET.Element) -> str | None:
    supplier = _find_child(component, "supplier")
    if supplier is None:
        return None

    name = _child_text(supplier, "name")
    if name:
        return name
    return _clean_text(supplier.text)


def _find_child(element: ET.Element, local_name: str) -> ET.Element | None:
    for child in element:
        if _local_name(child.tag) == local_name:
            return child
    return None


def _find_children(element: ET.Element, local_name: str) -> list[ET.Element]:
    return [child for child in element if _local_name(child.tag) == local_name]


def _child_text(element: ET.Element, local_name: str) -> str | None:
    child = _find_child(element, local_name)
    if child is None:
        return None
    return _clean_text(child.text)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _as_string(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return _clean_text(value)
    return str(value)
