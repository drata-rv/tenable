"""Primary .nessus XML parser.

Per spec Section 3.7 / 8, .nessus files use the `cm:` prefix on compliance
elements but frequently do not declare `xmlns:cm` on the root element. Strict
XML parsers raise `unbound prefix` and abort on that shape. Two mitigations,
both mandatory and both applied here:

1. Parse with `lxml.etree.iterparse(..., recover=True, huge_tree=True)`.
2. Match every element by local name only (strip any `{uri}` or `prefix:`
   component) — never match on qualified tag or namespace map.

Iterates on `ReportHost` end events and clears processed elements so a
hundred-host export does not sit fully in memory. Pure I/O + parsing module;
no transform logic lives here — that is transform.py's job in a later phase.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional, Union

from lxml import etree

from nessus_drata.models import ComplianceItem, HostKeyCandidates, HostResult


def local_name(tag: str) -> str:
    """Strip any `{uri}` or `prefix:` component from an element tag, leaving
    the bare local name for comparison. This is the only tag-matching path
    permitted by the spec (Section 3.7) — never match on qualified tag or
    namespace map, since `.nessus` files often leave `cm:` undeclared.
    """
    # lxml gives Clark-notation tags for namespaced elements: "{uri}local".
    if "}" in tag:
        tag = tag.rsplit("}", 1)[1]
    # Undeclared-prefix elements under recover=True keep the literal
    # "prefix:local" text as the tag instead of raising, so also strip that.
    if ":" in tag:
        tag = tag.rsplit(":", 1)[1]
    return tag


def _find_child(elem, name: str):
    for child in elem:
        # Comments and processing instructions are real children in lxml's
        # tree but carry a callable (not str) .tag — never real elements,
        # so they can never match a local-name lookup. Skip them rather
        # than let local_name() raise on a non-string tag.
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
        # Malformed edge case: gated in as compliance but no usable check
        # name. Skip rather than yield a ComplianceItem with an empty name.
        return None

    return ComplianceItem(
        check_name=check_name,
        result=_text_or_none(_find_child(report_item, "compliance-result")),
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
    """Bound memory on large exports: clear the processed element and drop
    now-empty preceding siblings, per the standard iterparse pattern.
    """
    elem.clear()
    parent = elem.getparent()
    if parent is not None:
        while elem.getprevious() is not None:
            del parent[0]


def parse_nessus_xml(path: Union[str, Path]) -> Iterator[HostResult]:
    """Parse a .nessus XML export into one HostResult per ReportHost.

    Yields HostResult objects lazily via iterparse on ReportHost end events.
    Plain vulnerability ReportItem elements (no <compliance>true</compliance>
    and no compliance-check-name child) are skipped silently and never
    counted. A ReportHost with zero compliance items still yields a
    HostResult with an empty compliance_items tuple.
    """
    context = etree.iterparse(
        str(path),
        events=("end",),
        recover=True,
        huge_tree=True,
    )

    for _event, elem in context:
        if not isinstance(elem.tag, str):
            # Comment / processing-instruction node; never a ReportHost.
            continue
        if local_name(elem.tag) != "ReportHost":
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
