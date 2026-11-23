"""Read-only interpretation of an explicit, bounded SROS2 policy XML subset.

This module evaluates source-policy intent, not installed DDS permissions or
runtime enforcement.  In particular, request/reply mean service client/server
roles, not individual DDS request/reply directions.  See docs/policy_adapter.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any
from xml.parsers import expat


REFERENCE_COMMIT = "bb2505b58b44ab18d1b2005bb22b70c611c58acc"
MAX_XML_BYTES = 2 * 1024 * 1024
MAX_XML_ELEMENTS = 20_000
MAX_XML_DEPTH = 32
MAX_ROS_NAME_LENGTH = 255
OPERATIONS = frozenset({"publish", "subscribe", "request", "reply"})
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)
_ENCLAVE_TOKEN = re.compile(r"[A-Za-z0-9_.-]+\Z", re.ASCII)
_GROUPS = {
    "topics": ("topic", ("publish", "subscribe")),
    "services": ("service", ("request", "reply")),
    "actions": ("action", ("call", "execute")),
}
_ACTION_SERVICES = ("cancel_goal", "get_result", "send_goal")
_ACTION_TOPICS = ("feedback", "status")


@dataclass(frozen=True)
class _Issue:
    code: str
    detail: str
    source: str
    enclave: str | None = None

    def describe(self) -> str:
        return f"{self.code}: {self.detail} [{self.source}]"


@dataclass(frozen=True)
class _Rule:
    allowed: bool
    source: str
    origin: str


@dataclass
class _Node:
    tag: str
    attributes: dict[str, str]
    line: int
    children: list[_Node] = field(default_factory=list)
    text: str = ""


class _RejectedXML(ValueError):
    pass


def _valid_enclave(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 1024:
        return False
    if value == "/":
        return True
    return value.startswith("/") and all(
        part not in {"", ".", ".."} and _ENCLAVE_TOKEN.fullmatch(part)
        for part in value[1:].split("/")
    )


def _valid_absolute_name(value: Any, *, namespace: bool = False) -> bool:
    if not isinstance(value, str) or len(value) > MAX_ROS_NAME_LENGTH:
        return False
    if namespace and value == "/":
        return True
    if namespace and value.endswith("/"):
        value = value[:-1]
    return value.startswith("/") and bool(value[1:]) and all(
        _TOKEN.fullmatch(part) for part in value[1:].split("/")
    )


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


class Policy:
    """A frozen source-policy snapshot with conservative, scoped uncertainty.

    ``issues`` and query return values are defensive copies.  A malformed or
    unsupported enclave cannot yield a definite result, including an ALLOW
    from a separately understood rule in that same enclave.
    """

    def __init__(
        self,
        *,
        path: Path,
        sha256: str | None,
        rules: dict[tuple[str, str, str], list[_Rule]],
        enclave_sources: dict[str, str],
        issues: list[_Issue],
    ) -> None:
        self._path = str(path)
        self._sha256 = sha256
        self._rules = MappingProxyType({key: tuple(value) for key, value in rules.items()})
        self._enclave_sources = MappingProxyType(dict(enclave_sources))
        self._issues = tuple(issues)

    @property
    def sha256(self) -> str | None:
        return self._sha256

    @property
    def issues(self) -> list[str]:
        return [issue.describe() for issue in self._issues]

    @property
    def enclaves(self) -> tuple[str, ...]:
        return tuple(sorted(self._enclave_sources))

    def check(self, enclave: str, resource: str, operation: str) -> dict[str, Any]:
        """Return ``value`` (True/False/None), ``reasons`` and XML ``sources``.

        ``resource`` is an already resolved absolute ROS topic/service name.
        Missing enclaves are UNKNOWN; only a fully supported, present enclave
        can produce a default-DENY result for a missing exact permission.
        """
        bad_query: list[str] = []
        if not _valid_enclave(enclave):
            bad_query.append("INVALID_QUERY_ENCLAVE: expected a canonical absolute enclave path")
        if not _valid_absolute_name(resource):
            bad_query.append("INVALID_QUERY_RESOURCE: expected a supported final absolute ROS name")
        if not isinstance(operation, str) or operation not in OPERATIONS:
            bad_query.append("INVALID_QUERY_OPERATION: use publish, subscribe, request or reply")
        if bad_query:
            return {"value": None, "reasons": bad_query, "sources": []}

        relevant = [
            issue for issue in self._issues if issue.enclave is None or issue.enclave == enclave
        ]
        if relevant:
            return {
                "value": None,
                "reasons": [issue.describe() for issue in relevant],
                "sources": _unique([issue.source for issue in relevant]),
            }
        if enclave not in self._enclave_sources:
            return {
                "value": None,
                "reasons": [f"UNKNOWN_ENCLAVE: {enclave!r} has no complete profile in this snapshot"],
                "sources": [self._path],
            }
        matching = self._rules.get((enclave, resource, operation), ())
        denied = [rule for rule in matching if not rule.allowed]
        if denied:
            return {
                "value": False,
                "reasons": ["EXPLICIT_DENY: an exact DENY overrides ALLOW across this enclave's profiles"],
                "sources": _unique([rule.source for rule in matching]),
            }
        if matching:
            return {
                "value": True,
                "reasons": [
                    "EXPLICIT_ALLOW: exact source-policy permission; runtime DDS enforcement is not checked",
                    *_unique([rule.origin for rule in matching]),
                ],
                "sources": _unique([rule.source for rule in matching]),
            }
        return {
            "value": False,
            "reasons": ["DEFAULT_DENY: no exact grant in this complete supported enclave"],
            "sources": [self._enclave_sources[enclave]],
        }


def _parse_xml(data: bytes) -> _Node:
    """Parse bounded UTF-8 XML without DTDs, entities, includes or execution."""
    # Restrict encodings so byte-level provenance and accepted input are simple.
    data.decode("utf-8-sig", errors="strict")
    parser = expat.ParserCreate(encoding="UTF-8", namespace_separator="}")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    stack: list[_Node] = []
    root: _Node | None = None
    count = 0

    def reject_declaration(*_args: Any) -> None:
        raise _RejectedXML("DTD and entity declarations/references are not supported")

    def declaration(version: str, encoding: str | None, _standalone: int) -> None:
        if version != "1.0" or (encoding is not None and encoding.upper() != "UTF-8"):
            raise _RejectedXML("only XML 1.0 encoded as UTF-8 is supported")

    def start(tag: str, attributes: dict[str, str]) -> None:
        nonlocal count, root
        count += 1
        if count > MAX_XML_ELEMENTS or len(stack) >= MAX_XML_DEPTH:
            raise _RejectedXML("XML element/depth limit exceeded")
        node = _Node(tag, dict(attributes), parser.CurrentLineNumber)
        if stack:
            stack[-1].children.append(node)
        else:
            root = node
        stack.append(node)

    def text(value: str) -> None:
        if stack:
            stack[-1].text += value

    parser.XmlDeclHandler = declaration
    parser.StartElementHandler = start
    parser.EndElementHandler = lambda _tag: stack.pop()
    parser.CharacterDataHandler = text
    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = reject_declaration
    parser.SkippedEntityHandler = reject_declaration
    parser.ProcessingInstructionHandler = reject_declaration
    parser.Parse(data, True)
    if root is None:
        raise _RejectedXML("XML document has no root element")
    return root


class _Loader:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.source_name = str(path)
        self.rules: dict[tuple[str, str, str], list[_Rule]] = {}
        self.enclave_sources: dict[str, str] = {}
        self.issues: list[_Issue] = []
        self.sha256: str | None = None

    def source(self, node: _Node | None = None) -> str:
        return f"{self.source_name}#L{node.line}" if node else self.source_name

    def issue(self, code: str, detail: str, node: _Node | None, enclave: str | None) -> None:
        self.issues.append(_Issue(code, detail, self.source(node), enclave))

    def result(self) -> Policy:
        return Policy(
            path=self.source_name,
            sha256=self.sha256,
            rules=self.rules,
            enclave_sources=self.enclave_sources,
            issues=self.issues,
        )

    def attributes(self, node: _Node, allowed: set[str], enclave: str | None) -> None:
        for name in node.attributes:
            if name not in allowed:
                self.issue("UNSUPPORTED_ATTRIBUTE", f"{node.tag}: {name}", node, enclave)

    def container(self, node: _Node, enclave: str | None) -> None:
        if node.text.strip():
            self.issue("INVALID_MIXED_CONTENT", f"unexpected text inside {node.tag}", node, enclave)

    def parse(self, root: _Node) -> None:
        if root.tag != "policy":
            self.issue("INVALID_ROOT", "expected unqualified <policy>", root, None)
            return
        self.attributes(root, {"version"}, None)
        self.container(root, None)
        if root.attributes.get("version") != "0.2.0":
            self.issue("UNSUPPORTED_POLICY_VERSION", "expected version='0.2.0'", root, None)
        if len(root.children) != 1 or root.children[0].tag != "enclaves":
            self.issue("INVALID_STRUCTURE", "policy must contain exactly one enclaves element", root, None)
            return
        enclaves = root.children[0]
        self.attributes(enclaves, set(), None)
        self.container(enclaves, None)
        if not enclaves.children:
            self.issue("INVALID_STRUCTURE", "enclaves requires at least one enclave", enclaves, None)
        for node in enclaves.children:
            if node.tag != "enclave":
                self.issue("UNSUPPORTED_ELEMENT", f"unexpected {node.tag} inside enclaves", node, None)
                continue
            self.parse_enclave(node)

    def parse_enclave(self, node: _Node) -> None:
        enclave = node.attributes.get("path")
        if not _valid_enclave(enclave):
            self.issue("INVALID_ENCLAVE_PATH", "expected a canonical absolute enclave path", node, None)
            return
        assert isinstance(enclave, str)
        if enclave in self.enclave_sources:
            self.issue("DUPLICATE_ENCLAVE", f"duplicate enclave path {enclave!r}", node, enclave)
        else:
            self.enclave_sources[enclave] = self.source(node)
        self.attributes(node, {"path"}, enclave)
        self.container(node, enclave)
        # Several profiles blocks can produce several DDS grants.  Their
        # cross-grant meaning is deliberately outside this policy subset.
        if len(node.children) != 1 or node.children[0].tag != "profiles":
            self.issue("UNSUPPORTED_PROFILES_LAYOUT", "one profiles block per enclave is required", node, enclave)
            return
        profiles = node.children[0]
        self.attributes(profiles, set(), enclave)
        self.container(profiles, enclave)
        if not profiles.children:
            self.issue("INVALID_STRUCTURE", "profiles requires at least one profile", profiles, enclave)
        seen: set[tuple[str, str]] = set()
        for profile in profiles.children:
            if profile.tag != "profile":
                self.issue("UNSUPPORTED_ELEMENT", f"unexpected {profile.tag} inside profiles", profile, enclave)
                continue
            self.parse_profile(profile, enclave, seen)

    def parse_profile(self, node: _Node, enclave: str, seen: set[tuple[str, str]]) -> None:
        self.attributes(node, {"ns", "node"}, enclave)
        self.container(node, enclave)
        ns = node.attributes.get("ns")
        node_name = node.attributes.get("node")
        if not _valid_absolute_name(ns, namespace=True):
            self.issue("INVALID_PROFILE_NAMESPACE", "profile ns must be a supported absolute namespace", node, enclave)
            return
        if not isinstance(node_name, str) or not _TOKEN.fullmatch(node_name):
            self.issue("INVALID_PROFILE_NODE", "profile node must be one valid name token", node, enclave)
            return
        assert isinstance(ns, str)
        ns = ns.rstrip("/") or "/"
        if len((ns.rstrip("/") + "/" + node_name)) > MAX_ROS_NAME_LENGTH:
            self.issue("INVALID_PROFILE_NODE", "expanded node name is too long", node, enclave)
            return
        identity = (ns, node_name)
        if identity in seen:
            self.issue("DUPLICATE_PROFILE", f"duplicate (ns,node) definition {identity!r}", node, enclave)
        seen.add(identity)
        for group in node.children:
            if group.tag not in _GROUPS:
                self.issue("UNSUPPORTED_ELEMENT", f"unexpected {group.tag} inside profile", group, enclave)
                continue
            self.parse_group(group, enclave, ns, node_name)

    def expand(self, name: str, ns: str, node_name: str, node: _Node, enclave: str) -> str | None:
        if any(char in name for char in "*?[]{}"):
            self.issue("UNSUPPORTED_NAME_PATTERN", "wildcards and substitutions are not interpreted", node, enclave)
            return None
        if name.startswith("~/"):
            expanded = ns.rstrip("/") + "/" + node_name + name[1:]
        elif name.startswith("/"):
            expanded = name
        else:
            expanded = ns.rstrip("/") + "/" + name
        # Do not strip whitespace: the referenced SROS2 transform uses the
        # literal expression value, so silently trimming could invent a grant.
        if not _valid_absolute_name(expanded):
            self.issue("INVALID_RESOURCE_NAME", f"unsupported resource expression {name!r}", node, enclave)
            return None
        return expanded

    def add(self, enclave: str, resource: str, operation: str, qualifier: str, node: _Node, origin: str) -> None:
        if not _valid_absolute_name(resource):
            self.issue("INVALID_EXPANDED_NAME", "derived Action resource exceeds supported name limits", node, enclave)
            return
        key = (enclave, resource, operation)
        self.rules.setdefault(key, []).append(_Rule(qualifier == "ALLOW", self.source(node), origin))

    def parse_group(self, group: _Node, enclave: str, ns: str, node_name: str) -> None:
        child_tag, operations = _GROUPS[group.tag]
        self.attributes(group, set(operations), enclave)
        self.container(group, enclave)
        qualifiers: dict[str, str] = {}
        for operation in operations:
            qualifier = group.attributes.get(operation)
            if qualifier is None:
                continue
            if qualifier not in {"ALLOW", "DENY"}:
                self.issue("INVALID_QUALIFIER", f"{operation} requires ALLOW or DENY", group, enclave)
                continue
            qualifiers[operation] = qualifier
        if not group.children:
            self.issue("INVALID_STRUCTURE", f"{group.tag} requires at least one {child_tag}", group, enclave)
        for expression in group.children:
            if expression.tag != child_tag:
                self.issue("UNSUPPORTED_ELEMENT", f"expected {child_tag}, got {expression.tag}", expression, enclave)
                continue
            self.attributes(expression, set(), enclave)
            if expression.children:
                self.issue("INVALID_RESOURCE_STRUCTURE", "resource expressions must contain only text", expression, enclave)
                continue
            name = self.expand(expression.text, ns, node_name, expression, enclave)
            if name is None:
                continue
            for operation, qualifier in qualifiers.items():
                if group.tag != "actions":
                    self.add(enclave, name, operation, qualifier, expression, f"{group.tag}.{operation}")
                    continue
                service_op, topic_op = ("request", "subscribe") if operation == "call" else ("reply", "publish")
                for suffix in _ACTION_SERVICES:
                    self.add(enclave, name + "/_action/" + suffix, service_op, qualifier, expression, f"actions.{operation} -> services.{service_op}")
                for suffix in _ACTION_TOPICS:
                    self.add(enclave, name + "/_action/" + suffix, topic_op, qualifier, expression, f"actions.{operation} -> topics.{topic_op}")


def load_policy(path: Path, *, source_name: str | None = None) -> Policy:
    """Load a bounded local SROS2 XML file; file/parser failures become UNKNOWN.

    The SHA-256 is over the complete original bytes.  It is None if the file
    cannot be read or exceeds the input cap; partial input is never hashed as
    though it were a complete policy.  No XML includes or network are followed.
    """
    loader = _Loader(Path(path).absolute())
    if source_name is not None:
        loader.source_name = source_name
    try:
        with loader.path.open("rb") as stream:
            data = stream.read(MAX_XML_BYTES + 1)
    except (OSError, ValueError) as error:
        loader.issue("POLICY_READ_ERROR", str(error), None, None)
        return loader.result()
    if len(data) > MAX_XML_BYTES:
        loader.issue("POLICY_SIZE_LIMIT", f"policy exceeds {MAX_XML_BYTES} bytes", None, None)
        return loader.result()
    loader.sha256 = hashlib.sha256(data).hexdigest()
    try:
        root = _parse_xml(data)
    except (expat.ExpatError, UnicodeError, _RejectedXML) as error:
        loader.issue("POLICY_XML_ERROR", str(error), None, None)
        return loader.result()
    loader.parse(root)
    return loader.result()
