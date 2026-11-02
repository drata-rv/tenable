from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator, Optional, Union

from lxml import etree

from nessus_drata.models import ComplianceItem, HostKeyCandidates, HostResult

logger = logging.getLogger("nessus_drata.parse")

_ROOT_TAG = "NessusClientData_v2"

_NAMESPACE_NOISE = frozenset({"NS_ERR_UNDEFINED_NAMESPACE"})

_TRUNCATION_TYPES = frozenset({"ERR_TAG_NOT_FINISHED"})


class ExportParseError(Exception):
    pass


def local_name(tag: str) -> str:
    if "}" in tag:
        tag = tag.rsplit("}", 1)[1]
    if ":" in tag:
        tag = tag.rsplit(":", 1)[1]
    return tag


def _find_child(elem, name: str):
    for child in elem:
        if not isinstance(child.tag, str):
            continue
        if local_name(child.tag) == name:
            return child
    return None


def _find_children(elem, name: str) -> list:
    return [
        child
        for child in elem
        if isinstance(child.tag, str) and local_name(child.tag) == name
    ]


def _text_or_none(elem) -> Optional[str]:
    if elem is None:
        return None
    text = elem.text
    if text is None:
        return None
    return text


def _is_compliance_item(report_item) -> bool:
    compliance_elem = _find_child(report_item, "compliance")
    if compliance_elem is not None and compliance_elem.text is not None:
        if compliance_elem.text.strip().lower() == "true":
            return True
    if _find_child(report_item, "compliance-check-name") is not None:
        return True
    return False


def _build_compliance_item(report_item) -> Optional[ComplianceItem]:
    check_name_elem = _find_child(report_item, "compliance-check-name")
    check_name = _text_or_none(check_name_elem)
    if not check_name:
        return None

    raw_result = _text_or_none(_find_child(report_item, "compliance-result"))
    result = raw_result if raw_result else "ERROR"

    return ComplianceItem(
        check_name=check_name,
        result=result,
        actual_value=_text_or_none(_find_child(report_item, "compliance-actual-value")),
        policy_value=_text_or_none(_find_child(report_item, "compliance-policy-value")),
        audit_file=_text_or_none(_find_child(report_item, "compliance-audit-file")),
        reference=_text_or_none(_find_child(report_item, "compliance-reference")),
    )


def _build_host_properties(report_host) -> dict[str, str]:
    host_properties: dict[str, str] = {}
    host_properties_elem = _find_child(report_host, "HostProperties")
    if host_properties_elem is None:
        return host_properties
    for tag_elem in _find_children(host_properties_elem, "tag"):
        name = tag_elem.get("name")
        if name is None:
            continue
        host_properties[name] = tag_elem.text if tag_elem.text is not None else ""
    return host_properties


def _clear_element(elem) -> None:
    elem.clear()
    parent = elem.getparent()
    if parent is not None:
        while elem.getprevious() is not None:
            del parent[0]


def _size_of(path: Union[str, Path]) -> int:
    try:
        return Path(path).stat().st_size
    except OSError:
        return -1


def _check_parser_health(context, path: Union[str, Path], saw_root: bool) -> None:
    if not saw_root:
        raise ExportParseError(
            f"{path}: no <{_ROOT_TAG}> document found (file is {_size_of(path)} bytes). "
            f"Not a .nessus export; an error page or empty download is the usual cause."
        )
    real_errors = [e for e in context.error_log if e.type_name not in _NAMESPACE_NOISE]
    if any(e.type_name in _TRUNCATION_TYPES for e in real_errors):
        raise ExportParseError(
            f"{path}: export is truncated (an element was never closed; file is "
            f"{_size_of(path)} bytes). Re-run to fetch a fresh export."
        )
    if real_errors:
        first = real_errors[0]
        logger.warning(
            "%s: %d XML error(s) recovered while parsing (first: %s at line %s: %s). "
            "Content near the damage may be missing; check manifest coverage.",
            path,
            len(real_errors),
            first.type_name,
            first.line,
            first.message.strip(),
        )


def parse_nessus_xml(path: Union[str, Path]) -> Iterator[HostResult]:
    context = etree.iterparse(
        str(path),
        events=("end",),
        recover=True,
        huge_tree=True,
    )

    saw_root = False
    try:
        for _event, elem in context:
            if not isinstance(elem.tag, str):
                continue
            tag = local_name(elem.tag)
            if tag == _ROOT_TAG:
                saw_root = True
                continue
            if tag != "ReportHost":
                continue

            host_properties = _build_host_properties(elem)
            host_key_candidates = HostKeyCandidates(
                netbios_name=host_properties.get("netbios-name"),
                host_fqdn=host_properties.get("host-fqdn"),
                host_ip=host_properties.get("host-ip"),
            )

            items: list[ComplianceItem] = []
            for report_item in _find_children(elem, "ReportItem"):
                if not _is_compliance_item(report_item):
                    continue
                compliance_item = _build_compliance_item(report_item)
                if compliance_item is not None:
                    items.append(compliance_item)

            yield HostResult(
                host_key_candidates=host_key_candidates,
                host_properties=host_properties,
                compliance_items=tuple(items),
                source_fidelity="full",
            )

            _clear_element(elem)
    except etree.XMLSyntaxError as exc:
        raise ExportParseError(
            f"{path}: not parseable as XML ({exc}); file is {_size_of(path)} bytes"
        ) from exc

    _check_parser_health(context, path, saw_root)
