#!/usr/bin/env python3
"""
PastelParse
===========

A small, interactive tool for identifying JSON parser inconsistencies during
authorized web application penetration tests.

The program:

1. Reads a raw HTTP/1.x request from a file.
2. Detects and parses a JSON request body.
3. Lists the JSON fields and asks which field should be tested.
4. Generates mutations such as:
   - Duplicate JSON keys
   - Reversed object key order
   - Different key capitalisations
   - JSON type changes
   - Scalar-versus-vector changes
5. Sends the original request and each mutated request.
6. Compares response status codes and response bodies.
7. Optionally sends verification and reset requests.
8. Writes exact request payloads and captured responses to a JSON report.

Safety defaults:

- Only localhost/loopback targets are allowed unless --allow-remote is used.
- Requests are sent sequentially.
- A delay is added between tests.
- The user must explicitly confirm authorization before requests are sent.
- --dry-run can be used to generate payloads without sending anything.

Python requirement: Python 3.10 or later.
External dependencies: None.
"""

from __future__ import annotations

import argparse
import base64
import copy
import difflib
import gzip
import hashlib
import http.client
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import zlib

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


# Type alias used throughout the program for HTTP header collections.
Headers = list[tuple[str, str]]


@dataclass
class RawHTTPRequest:
    """A parsed HTTP/1.x request."""

    method: str
    target: str
    version: str
    headers: Headers
    body: bytes


@dataclass(frozen=True)
class Destination:
    """The network destination derived from a raw HTTP request."""

    scheme: str
    host: str
    port: int
    request_target: str


@dataclass(frozen=True)
class FieldReference:
    """
    A reference to an object member inside a JSON document.

    Path tokens are strings for object keys and integers for array indices.
    The final token is always an object key because the tool tests JSON fields.
    """

    path: tuple[str | int, ...]
    value: Any


@dataclass
class Mutation:
    """One generated JSON mutation."""

    name: str
    category: str
    description: str
    body: bytes
    probe_values: list[Any]


@dataclass
class ResponseRecord:
    """The important parts of a captured HTTP response."""

    status: int | None
    reason: str
    version: str
    headers: Headers
    body: bytes
    elapsed_ms: float
    truncated: bool
    error: str | None = None


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    """Return a hexadecimal SHA-256 digest."""

    return hashlib.sha256(value).hexdigest()


def get_header(
    headers: Sequence[tuple[str, str]],
    name: str,
    default: str | None = None,
) -> str | None:
    """
    Return the final occurrence of a header.

    Using the final occurrence is useful because some HTTP implementations
    treat later duplicate headers as authoritative.
    """

    wanted = name.lower()

    for header_name, header_value in reversed(headers):
        if header_name.lower() == wanted:
            return header_value

    return default


def split_http_message(raw: bytes) -> tuple[bytes, bytes]:
    """
    Split a raw HTTP message into its header section and body.

    Both CRLF and LF-only requests are accepted because requests copied from
    terminals and text editors frequently use LF line endings.
    """

    for separator in (b"\r\n\r\n", b"\n\n"):
        position = raw.find(separator)

        if position != -1:
            return raw[:position], raw[position + len(separator) :]

    # A message with no blank line is treated as a header-only request.
    return raw, b""


def parse_raw_http_request(raw: bytes) -> RawHTTPRequest:
    """Parse a raw HTTP/1.x request from bytes."""

    header_bytes, body = split_http_message(raw)

    # HTTP/1.x headers are traditionally decoded as ISO-8859-1.
    header_text = header_bytes.decode("iso-8859-1")
    lines = header_text.splitlines()

    # Ignore empty lines accidentally placed before the request line.
    while lines and not lines[0].strip():
        lines.pop(0)

    if not lines:
        raise ValueError("The input does not contain an HTTP request line.")

    request_line_match = re.fullmatch(
        r"(\S+)\s+(\S+)\s+HTTP/(\d+(?:\.\d+)?)",
        lines[0].strip(),
    )

    if not request_line_match:
        raise ValueError(
            "Invalid request line. Expected something similar to "
            "'POST /path HTTP/1.1'."
        )

    method, target, version = request_line_match.groups()

    if version not in {"1.0", "1.1"}:
        raise ValueError(
            f"Unsupported HTTP version {version!r}. "
            "PastelParse accepts HTTP/1.0 and HTTP/1.1 requests."
        )

    headers: Headers = []

    for line in lines[1:]:
        # Obsolete folded headers are intentionally rejected. Silently joining
        # them could change the meaning of an authorization or cookie header.
        if line.startswith((" ", "\t")):
            raise ValueError(
                "Folded HTTP headers are not supported. Unfold the header "
                "before running the tool."
            )

        if not line.strip():
            continue

        if ":" not in line:
            raise ValueError(f"Invalid HTTP header line: {line!r}")

        name, value = line.split(":", 1)
        headers.append((name.strip(), value.lstrip()))

    return RawHTTPRequest(
        method=method.upper(),
        target=target,
        version=version,
        headers=headers,
        body=body,
    )


def content_type_charset(content_type: str | None) -> str:
    """Extract a charset from Content-Type, defaulting to UTF-8."""

    if not content_type:
        return "utf-8"

    match = re.search(
        r"charset\s*=\s*[\"']?([^;\"'\s]+)",
        content_type,
        flags=re.IGNORECASE,
    )

    return match.group(1) if match else "utf-8"


def parse_json_request_body(request: RawHTTPRequest) -> Any:
    """
    Detect and parse a JSON request body.

    A JSON Content-Type is preferred, but a body beginning with "{" or "[" is
    also accepted so that requests copied from unusual clients still work.
    """

    content_type = get_header(request.headers, "Content-Type", "") or ""
    stripped_body = request.body.lstrip()

    content_type_is_json = (
        "application/json" in content_type.lower()
        or "+json" in content_type.lower()
    )
    body_looks_json = stripped_body.startswith((b"{", b"["))

    if not content_type_is_json and not body_looks_json:
        raise ValueError(
            "The request body does not appear to be JSON. "
            "No JSON Content-Type or JSON-looking body was detected."
        )

    charset = content_type_charset(content_type)

    try:
        body_text = request.body.decode(charset)
    except (LookupError, UnicodeDecodeError):
        # JSON is normally UTF-8, so use it as the fallback.
        body_text = request.body.decode("utf-8-sig")

    try:
        return json.loads(body_text)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"The request body could not be parsed as JSON: {error}"
        ) from error


def format_json_path(path: Sequence[str | int]) -> str:
    """Convert internal path tokens to a readable JSONPath-like string."""

    result = "$"

    for token in path:
        if isinstance(token, int):
            result += f"[{token}]"
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
            result += f".{token}"
        else:
            result += f"[{json.dumps(token, ensure_ascii=False)}]"

    return result


def enumerate_json_fields(
    value: Any,
    current_path: tuple[str | int, ...] = (),
) -> list[FieldReference]:
    """
    Recursively enumerate every object member in a JSON document.

    Array indices are included in paths when an object exists inside an array,
    but array elements themselves are not listed as object fields.
    """

    fields: list[FieldReference] = []

    if isinstance(value, dict):
        for key, child_value in value.items():
            member_path = current_path + (key,)
            fields.append(FieldReference(member_path, child_value))
            fields.extend(enumerate_json_fields(child_value, member_path))

    elif isinstance(value, list):
        for index, child_value in enumerate(value):
            fields.extend(
                enumerate_json_fields(
                    child_value,
                    current_path + (index,),
                )
            )

    return fields


def json_type_name(value: Any) -> str:
    """Return the JSON type name for a Python value."""

    # bool must be checked before int because bool subclasses int in Python.
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"

    return type(value).__name__


def value_preview(value: Any, maximum_length: int = 90) -> str:
    """Create a compact preview for the interactive field list."""

    try:
        preview = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except TypeError:
        preview = repr(value)

    if len(preview) > maximum_length:
        return preview[: maximum_length - 3] + "..."

    return preview


def get_at_path(root: Any, path: Sequence[str | int]) -> Any:
    """Retrieve a nested JSON value by path."""

    current = root

    for token in path:
        current = current[token]

    return current


def set_node_at_path(
    root: Any,
    path: Sequence[str | int],
    replacement: Any,
) -> Any:
    """
    Replace a nested node and return the root.

    An empty path means the root itself is being replaced.
    """

    if not path:
        return replacement

    parent = root

    for token in path[:-1]:
        parent = parent[token]

    parent[path[-1]] = replacement
    return root


def replace_value_at_path(
    document: Any,
    path: Sequence[str | int],
    replacement: Any,
) -> Any:
    """Deep-copy a JSON document and replace one field value."""

    cloned = copy.deepcopy(document)
    return set_node_at_path(cloned, path, replacement)


def rename_key_at_path(
    document: Any,
    path: Sequence[str | int],
    new_key: str,
) -> Any | None:
    """
    Rename an object key while retaining its original position.

    None is returned if the new key would collide with another existing key.
    """

    old_key = path[-1]

    if not isinstance(old_key, str):
        raise ValueError("The selected path does not end in an object key.")

    cloned = copy.deepcopy(document)
    parent_path = path[:-1]
    parent = get_at_path(cloned, parent_path)

    if not isinstance(parent, dict):
        raise ValueError("The selected field's parent is not an object.")

    if new_key != old_key and new_key in parent:
        return None

    renamed_parent: dict[str, Any] = {}

    for key, value in parent.items():
        renamed_parent[new_key if key == old_key else key] = value

    return set_node_at_path(cloned, parent_path, renamed_parent)


def reverse_target_parent(
    document: Any,
    path: Sequence[str | int],
) -> Any:
    """Reverse the member order of the object containing the target field."""

    cloned = copy.deepcopy(document)
    parent_path = path[:-1]
    parent = get_at_path(cloned, parent_path)

    if not isinstance(parent, dict):
        raise ValueError("The selected field's parent is not an object.")

    reversed_parent = dict(reversed(list(parent.items())))
    return set_node_at_path(cloned, parent_path, reversed_parent)


def reverse_all_objects(value: Any) -> Any:
    """Recursively reverse the key order of every JSON object."""

    if isinstance(value, dict):
        reversed_items = reversed(list(value.items()))

        return {
            key: reverse_all_objects(child_value)
            for key, child_value in reversed_items
        }

    if isinstance(value, list):
        # Array order is deliberately preserved. Only object member order is
        # being tested by this mutation.
        return [reverse_all_objects(item) for item in value]

    return value


def compact_json_bytes(value: Any) -> bytes:
    """Serialize a JSON value deterministically as compact UTF-8 bytes."""

    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def serialize_with_duplicate_key(
    value: Any,
    target_path: Sequence[str | int],
    duplicate_value: Any,
    duplicate_first: bool,
    current_path: tuple[str | int, ...] = (),
) -> str:
    """
    Serialize JSON while inserting a duplicate occurrence of one key.

    A Python dictionary cannot contain duplicate keys, so duplicate-key
    payloads must be created by a custom serializer rather than json.dumps().
    """

    if isinstance(value, dict):
        members: list[str] = []

        for key, child_value in value.items():
            member_path = current_path + (key,)
            encoded_key = json.dumps(key, ensure_ascii=False)

            normal_member = (
                encoded_key
                + ":"
                + serialize_with_duplicate_key(
                    child_value,
                    target_path,
                    duplicate_value,
                    duplicate_first,
                    member_path,
                )
            )

            if tuple(member_path) == tuple(target_path):
                duplicate_member = (
                    encoded_key
                    + ":"
                    + serialize_with_duplicate_key(
                        duplicate_value,
                        target_path,
                        duplicate_value,
                        duplicate_first,
                        member_path,
                    )
                )

                if duplicate_first:
                    members.extend((duplicate_member, normal_member))
                else:
                    members.extend((normal_member, duplicate_member))
            else:
                members.append(normal_member)

        return "{" + ",".join(members) + "}"

    if isinstance(value, list):
        elements = [
            serialize_with_duplicate_key(
                child_value,
                target_path,
                duplicate_value,
                duplicate_first,
                current_path + (index,),
            )
            for index, child_value in enumerate(value)
        ]

        return "[" + ",".join(elements) + "]"

    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def unique_json_values(values: Iterable[Any]) -> list[Any]:
    """Deduplicate JSON values using their canonical JSON representation."""

    unique: list[Any] = []
    seen: set[str] = set()

    for value in values:
        marker = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        if marker not in seen:
            seen.add(marker)
            unique.append(value)

    return unique


def automatic_test_values(original_value: Any) -> list[Any]:
    """
    Create a conservative alternate value when the user supplies none.

    These are intentionally generic. Known role names, tenant IDs, account
    identifiers, or other application-specific values should be supplied by
    the tester with --test-value.
    """

    if original_value is None:
        return ["__PASTELPARSE_TEST__"]

    if isinstance(original_value, bool):
        return [not original_value]

    if isinstance(original_value, str):
        return ["__PASTELPARSE_TEST__"]

    if isinstance(original_value, int):
        return [original_value + 1]

    if isinstance(original_value, float):
        return [original_value + 1.0]

    if isinstance(original_value, list):
        return [
            original_value[0]
            if original_value
            else "__PASTELPARSE_TEST__"
        ]

    if isinstance(original_value, dict):
        return [{"__pastelparse_test__": True}]

    return ["__PASTELPARSE_TEST__"]


def capitalisation_variants(key: str) -> list[str]:
    """Generate useful capitalisation variants for a JSON object key."""

    variants = [
        key.lower(),
        key.upper(),
        key.swapcase(),
    ]

    if key:
        variants.extend(
            [
                key[0].upper() + key[1:],
                key[0].lower() + key[1:],
                key[0].lower() + key[1:].upper(),
            ]
        )

    # Preserve order while removing the original spelling and duplicates.
    return [
        variant
        for variant in dict.fromkeys(variants)
        if variant != key
    ]


def type_change_candidates(
    original_value: Any,
    user_values: Sequence[Any],
) -> list[tuple[str, Any]]:
    """Generate values whose JSON type differs from the original type."""

    original_type = json_type_name(original_value)

    if isinstance(original_value, str):
        string_form = original_value
    else:
        string_form = json.dumps(
            original_value,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    generic_candidates: list[tuple[str, Any]] = [
        ("as-null", None),
        ("as-string", string_form),
        ("as-number", 1),
        ("as-boolean", not original_value if isinstance(original_value, bool) else True),
        ("as-object", {"value": original_value}),
    ]

    # User-provided values with a different type are useful application-aware
    # type mutations.
    for index, value in enumerate(user_values, start=1):
        generic_candidates.append((f"user-value-{index}-type", value))

    filtered: list[tuple[str, Any]] = []
    seen: set[str] = set()

    for name, candidate in generic_candidates:
        if json_type_name(candidate) == original_type:
            continue

        marker = json.dumps(
            candidate,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        if marker not in seen:
            seen.add(marker)
            filtered.append((name, candidate))

    return filtered


def generate_mutations(
    document: Any,
    original_body: bytes,
    selected_field: FieldReference,
    supplied_values: Sequence[Any],
) -> list[Mutation]:
    """Generate all supported mutations for the selected JSON field."""

    selected_path = selected_field.path
    selected_value = selected_field.value
    selected_key = selected_path[-1]

    if not isinstance(selected_key, str):
        raise ValueError("The selected field does not end in an object key.")

    test_values = unique_json_values(
        supplied_values or automatic_test_values(selected_value)
    )

    mutations: list[Mutation] = []
    seen_bodies: set[bytes] = {original_body}

    def add_mutation(
        name: str,
        category: str,
        description: str,
        body: bytes,
        probe_values: Sequence[Any] = (),
    ) -> None:
        """
        Add a mutation unless it produces bytes already generated by another
        mutation. This avoids duplicate requests.
        """

        if body in seen_bodies:
            return

        seen_bodies.add(body)
        mutations.append(
            Mutation(
                name=name,
                category=category,
                description=description,
                body=body,
                probe_values=list(probe_values),
            )
        )

    # A semantically unchanged, reserialized control helps reveal whether
    # formatting alone affects the target.
    add_mutation(
        name="reserialized-control",
        category="control",
        description=(
            "Compactly reserializes the original JSON without changing its "
            "data model."
        ),
        body=compact_json_bytes(document),
    )

    # Generate both duplicate-key orders because parsers may use either the
    # first value or the final value.
    for index, test_value in enumerate(test_values, start=1):
        normal_first = serialize_with_duplicate_key(
            document,
            selected_path,
            test_value,
            duplicate_first=False,
        ).encode("utf-8")

        duplicate_first = serialize_with_duplicate_key(
            document,
            selected_path,
            test_value,
            duplicate_first=True,
        ).encode("utf-8")

        add_mutation(
            name=f"duplicate-original-then-test-{index}",
            category="duplicate-key",
            description=(
                "Places the original field occurrence first and the supplied "
                "test occurrence second."
            ),
            body=normal_first,
            probe_values=[test_value],
        )

        add_mutation(
            name=f"duplicate-test-then-original-{index}",
            category="duplicate-key",
            description=(
                "Places the supplied test occurrence first and the original "
                "field occurrence second."
            ),
            body=duplicate_first,
            probe_values=[test_value],
        )

    # Test ordering at the nearest object boundary and across the entire JSON
    # document.
    add_mutation(
        name="reverse-target-parent-order",
        category="key-order",
        description=(
            "Reverses the key order of the object containing the target field."
        ),
        body=compact_json_bytes(
            reverse_target_parent(document, selected_path)
        ),
    )

    add_mutation(
        name="reverse-all-object-orders",
        category="key-order",
        description=(
            "Recursively reverses the key order of every JSON object."
        ),
        body=compact_json_bytes(reverse_all_objects(document)),
    )

    # Rename only the selected key, retaining its value and position.
    for variant in capitalisation_variants(selected_key):
        renamed = rename_key_at_path(document, selected_path, variant)

        if renamed is None:
            # Skip variants that collide with an existing member name.
            continue

        add_mutation(
            name=f"key-capitalisation-{variant}",
            category="capitalisation",
            description=(
                f"Renames {selected_key!r} to {variant!r} without changing "
                "the field value."
            ),
            body=compact_json_bytes(renamed),
        )

    # Generate cross-type representations such as string, number, boolean,
    # object, and null.
    for name, replacement in type_change_candidates(
        selected_value,
        supplied_values,
    ):
        changed = replace_value_at_path(
            document,
            selected_path,
            replacement,
        )

        add_mutation(
            name=f"type-change-{name}",
            category="type-change",
            description=(
                f"Changes the selected value from JSON type "
                f"{json_type_name(selected_value)} to "
                f"{json_type_name(replacement)}."
            ),
            body=compact_json_bytes(changed),
            probe_values=[replacement],
        )

    # Scalar-versus-vector tests are separated from general type changes so
    # the report clearly identifies this common parser ambiguity.
    if isinstance(selected_value, list):
        scalar_candidates: list[Any] = []

        if selected_value:
            scalar_candidates.append(selected_value[0])

        scalar_candidates.extend(test_values)

        for index, replacement in enumerate(
            unique_json_values(scalar_candidates),
            start=1,
        ):
            changed = replace_value_at_path(
                document,
                selected_path,
                replacement,
            )

            add_mutation(
                name=f"vector-to-scalar-{index}",
                category="scalar-vector",
                description=(
                    "Replaces the selected JSON array with a single scalar "
                    "or user-provided value."
                ),
                body=compact_json_bytes(changed),
                probe_values=[replacement],
            )
    else:
        vector_candidates: list[list[Any]] = [[selected_value]]

        for test_value in test_values:
            vector_candidates.append([test_value])
            vector_candidates.append([selected_value, test_value])

        for index, replacement in enumerate(
            unique_json_values(vector_candidates),
            start=1,
        ):
            changed = replace_value_at_path(
                document,
                selected_path,
                replacement,
            )

            add_mutation(
                name=f"scalar-to-vector-{index}",
                category="scalar-vector",
                description=(
                    "Replaces the selected scalar/object value with a JSON "
                    "array representation."
                ),
                body=compact_json_bytes(changed),
                probe_values=replacement,
            )

    return mutations


def parse_host_header(host_header: str) -> tuple[str, int | None]:
    """Parse a Host header, including bracketed IPv6 addresses."""

    parsed = urllib.parse.urlsplit("//" + host_header)

    if not parsed.hostname:
        raise ValueError(f"Invalid Host header: {host_header!r}")

    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"Invalid port in Host header: {host_header!r}") from error

    return parsed.hostname, port


def resolve_destination(
    request: RawHTTPRequest,
    scheme_override: str | None,
) -> Destination:
    """Resolve the scheme, host, port, and request target."""

    # Absolute-form request targets are sometimes used with HTTP proxies.
    parsed_target = urllib.parse.urlsplit(request.target)

    if parsed_target.scheme in {"http", "https"} and parsed_target.hostname:
        scheme = scheme_override or parsed_target.scheme
        host = parsed_target.hostname
        port = parsed_target.port or (443 if scheme == "https" else 80)
        request_target = urllib.parse.urlunsplit(
            (
                "",
                "",
                parsed_target.path or "/",
                parsed_target.query,
                "",
            )
        )

        return Destination(
            scheme=scheme,
            host=host,
            port=port,
            request_target=request_target,
        )

    host_header = get_header(request.headers, "Host")

    if not host_header:
        raise ValueError(
            "The request has a relative target but does not contain a Host header."
        )

    host, explicit_port = parse_host_header(host_header)

    if scheme_override:
        scheme = scheme_override
    else:
        # Origin and Referer often provide the most reliable scheme when a raw
        # request was copied from a browser or intercepting proxy.
        scheme = ""

        for candidate_header in ("Origin", "Referer"):
            candidate = get_header(request.headers, candidate_header)

            if not candidate:
                continue

            parsed_candidate = urllib.parse.urlsplit(candidate)

            if (
                parsed_candidate.scheme in {"http", "https"}
                and parsed_candidate.hostname == host
            ):
                scheme = parsed_candidate.scheme
                break

        if not scheme:
            if explicit_port == 443:
                scheme = "https"
            elif is_loopback_host(host):
                scheme = "http"
            else:
                # HTTPS is the safer assumption for a non-local modern target.
                scheme = "https"

    port = explicit_port or (443 if scheme == "https" else 80)

    return Destination(
        scheme=scheme,
        host=host,
        port=port,
        request_target=request.target,
    )


def is_loopback_host(host: str) -> bool:
    """Return True when a host is explicitly a loopback destination."""

    normalized = host.lower().rstrip(".")

    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True

    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def format_host_for_header(destination: Destination) -> str:
    """Create a Host header value when one was not supplied."""

    host = destination.host

    # IPv6 literals must be enclosed in square brackets in a Host header.
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    default_port = 443 if destination.scheme == "https" else 80

    if destination.port != default_port:
        return f"{host}:{destination.port}"

    return host


def outgoing_headers(
    request: RawHTTPRequest,
    destination: Destination,
    body: bytes,
) -> Headers:
    """
    Build the headers that will actually be sent.

    Content-Length is recalculated for every mutation. Transfer-Encoding is
    removed because this initial implementation sends a normal fixed-length
    body rather than constructing chunked wire messages.
    """

    result: Headers = []
    has_host = False

    removed_headers = {
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-connection",
        "expect",
    }

    for name, value in request.headers:
        lowered = name.lower()

        if lowered in removed_headers:
            continue

        if lowered == "host":
            has_host = True

        result.append((name, value))

    if not has_host:
        result.insert(
            0,
            ("Host", format_host_for_header(destination)),
        )

    # A zero Content-Length is useful for POST/PUT/PATCH requests even when
    # the body is empty.
    if body or request.method in {"POST", "PUT", "PATCH"}:
        result.append(("Content-Length", str(len(body))))

    result.append(("Connection", "close"))
    return result


def wire_request_bytes(
    request: RawHTTPRequest,
    destination: Destination,
    body: bytes,
) -> bytes:
    """Construct the exact normalized HTTP/1.x request recorded in the report."""

    request_line = (
        f"{request.method} {destination.request_target} "
        f"HTTP/{request.version}\r\n"
    ).encode("iso-8859-1")

    header_lines = b"".join(
        f"{name}: {value}\r\n".encode("iso-8859-1")
        for name, value in outgoing_headers(request, destination, body)
    )

    return request_line + header_lines + b"\r\n" + body


def send_http_request(
    request: RawHTTPRequest,
    destination: Destination,
    body: bytes,
    timeout: float,
    insecure: bool,
    maximum_response_bytes: int,
) -> ResponseRecord:
    """Send one HTTP request and capture the response."""

    connection: http.client.HTTPConnection | http.client.HTTPSConnection

    if destination.scheme == "https":
        if insecure:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context()

        connection = http.client.HTTPSConnection(
            destination.host,
            destination.port,
            timeout=timeout,
            context=context,
        )
    else:
        connection = http.client.HTTPConnection(
            destination.host,
            destination.port,
            timeout=timeout,
        )

    # http.client defaults to HTTP/1.1 regardless of the parsed request line.
    # Configure it to preserve the supported input version on the wire so the
    # report's normalized request matches what was actually transmitted.
    if request.version == "1.0":
        connection._http_vsn = 10
        connection._http_vsn_str = "HTTP/1.0"
    else:
        connection._http_vsn = 11
        connection._http_vsn_str = "HTTP/1.1"

    started = time.perf_counter()

    try:
        # skip_host and skip_accept_encoding prevent http.client from silently
        # adding headers that were not in the normalized outgoing request.
        connection.putrequest(
            request.method,
            destination.request_target,
            skip_host=True,
            skip_accept_encoding=True,
        )

        for name, value in outgoing_headers(request, destination, body):
            connection.putheader(name, value)

        connection.endheaders()

        if body:
            connection.send(body)

        response = connection.getresponse()

        # Read one extra byte so the report can state whether truncation
        # occurred at the configured safety limit.
        captured_body = response.read(maximum_response_bytes + 1)
        truncated = len(captured_body) > maximum_response_bytes

        if truncated:
            captured_body = captured_body[:maximum_response_bytes]

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        version = {
            10: "1.0",
            11: "1.1",
        }.get(response.version, str(response.version))

        return ResponseRecord(
            status=response.status,
            reason=response.reason or "",
            version=version,
            headers=list(response.getheaders()),
            body=captured_body,
            elapsed_ms=elapsed_ms,
            truncated=truncated,
        )

    except Exception as error:
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        return ResponseRecord(
            status=None,
            reason="",
            version="",
            headers=[],
            body=b"",
            elapsed_ms=elapsed_ms,
            truncated=False,
            error=f"{type(error).__name__}: {error}",
        )

    finally:
        connection.close()


def decoded_response_body(response: ResponseRecord) -> bytes:
    """Decode common HTTP Content-Encoding values for comparison."""

    body = response.body
    content_encoding = (
        get_header(response.headers, "Content-Encoding", "") or ""
    ).lower()

    # Decode encodings in reverse order, as required by HTTP semantics.
    encodings = [
        encoding.strip()
        for encoding in content_encoding.split(",")
        if encoding.strip()
    ]

    try:
        for encoding in reversed(encodings):
            if encoding == "gzip":
                body = gzip.decompress(body)
            elif encoding == "deflate":
                try:
                    body = zlib.decompress(body)
                except zlib.error:
                    # Some servers send raw DEFLATE data without the zlib
                    # wrapper.
                    body = zlib.decompress(body, -zlib.MAX_WBITS)
            elif encoding in {"identity", ""}:
                continue
            else:
                # Unsupported encodings, such as Brotli, are left untouched.
                return response.body
    except (OSError, EOFError, zlib.error):
        return response.body

    return body


def response_text(response: ResponseRecord) -> str:
    """Decode a response body to text for display and comparison."""

    body = decoded_response_body(response)
    content_type = get_header(response.headers, "Content-Type", "") or ""
    charset = content_type_charset(content_type)

    try:
        return body.decode(charset)
    except (LookupError, UnicodeDecodeError):
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return body.decode("iso-8859-1", errors="replace")


def normalized_response_body(response: ResponseRecord) -> str:
    """
    Normalize a response for comparison.

    JSON responses are canonicalized by sorting object keys. Other responses
    retain their content, with line endings normalized.
    """

    if response.error:
        return f"<REQUEST ERROR: {response.error}>"

    text = response_text(response).replace("\r\n", "\n").strip()

    try:
        parsed = json.loads(text)

        return json.dumps(
            parsed,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
    except (json.JSONDecodeError, TypeError):
        return text


def compare_responses(
    baseline: ResponseRecord,
    candidate: ResponseRecord,
    maximum_diff_lines: int = 40,
) -> dict[str, Any]:
    """Compare status codes and normalized response bodies."""

    baseline_text = normalized_response_body(baseline)
    candidate_text = normalized_response_body(candidate)

    # Very large bodies are clipped for similarity calculation so a server
    # cannot force excessive CPU use in difflib.
    similarity = difflib.SequenceMatcher(
        None,
        baseline_text[:200_000],
        candidate_text[:200_000],
        autojunk=False,
    ).ratio()

    diff_iterator = difflib.unified_diff(
        baseline_text.splitlines(),
        candidate_text.splitlines(),
        fromfile="original-response",
        tofile="mutated-response",
        lineterm="",
    )

    diff_lines: list[str] = []

    for line in diff_iterator:
        if len(diff_lines) >= maximum_diff_lines:
            diff_lines.append("... diff output truncated ...")
            break

        # Clip exceptionally long minified lines in console/report summaries.
        diff_lines.append(
            line if len(line) <= 700 else line[:697] + "..."
        )

    return {
        "baseline_status": baseline.status,
        "candidate_status": candidate.status,
        "status_changed": baseline.status != candidate.status,
        "status_class_changed": (
            baseline.status is not None
            and candidate.status is not None
            and baseline.status // 100 != candidate.status // 100
        ),
        "baseline_body_length": len(baseline.body),
        "candidate_body_length": len(candidate.body),
        "raw_body_changed": baseline.body != candidate.body,
        "normalized_body_changed": baseline_text != candidate_text,
        "similarity": round(similarity, 6),
        "baseline_body_sha256": sha256_bytes(baseline.body),
        "candidate_body_sha256": sha256_bytes(candidate.body),
        "diff": diff_lines,
    }


def marker_strings(values: Sequence[Any]) -> list[str]:
    """Convert simple probe values to strings that can be searched for."""

    markers: list[str] = []

    for value in values:
        if isinstance(value, str):
            markers.append(value)
        elif value is None:
            markers.append("null")
        elif isinstance(value, (bool, int, float)):
            markers.append(
                json.dumps(value, ensure_ascii=False)
            )

    return [marker for marker in dict.fromkeys(markers) if marker]


def downgrade_confidence(label: str) -> str:
    """Reduce a confidence level by one step."""

    return {
        "CONFIRMED": "HIGH",
        "HIGH": "MEDIUM",
        "MEDIUM": "LOW",
        "LOW": "LOW",
        "NONE": "NONE",
        "ERROR": "ERROR",
    }.get(label, label)


def classify_result(
    original_response: ResponseRecord,
    mutation_response: ResponseRecord,
    response_difference: dict[str, Any],
    probe_values: Sequence[Any],
    verification_before: ResponseRecord | None,
    verification_after: ResponseRecord | None,
    formatting_control_changed: bool,
) -> dict[str, Any]:
    """
    Assign a heuristic confidence classification.

    This classification is triage assistance, not proof by itself. A result
    becomes CONFIRMED only when a supplied probe value appears in the
    verification response after the mutation but was absent before it.
    """

    reasons: list[str] = []

    if mutation_response.error:
        return {
            "label": "ERROR",
            "reasons": [mutation_response.error],
        }

    label = "NONE"

    # Verification comparisons are the strongest available evidence because
    # they can show that server-side state changed after the mutation.
    if verification_before and verification_after:
        verification_difference = compare_responses(
            verification_before,
            verification_after,
        )

        before_text = normalized_response_body(verification_before)
        after_text = normalized_response_body(verification_after)

        appeared_markers = [
            marker
            for marker in marker_strings(probe_values)
            if marker not in before_text and marker in after_text
        ]

        if appeared_markers:
            label = "CONFIRMED"
            reasons.append(
                "A probe value appeared in the post-mutation verification "
                "response: "
                + ", ".join(repr(marker) for marker in appeared_markers)
            )
        elif (
            verification_difference["status_changed"]
            or (
                verification_difference["normalized_body_changed"]
                and verification_difference["similarity"] < 0.98
            )
        ):
            label = "HIGH"
            reasons.append(
                "The verification response changed after the mutated request."
            )

    original_status = original_response.status
    mutation_status = mutation_response.status

    if original_status is not None and mutation_status is not None:
        original_success = 200 <= original_status < 400
        mutation_success = 200 <= mutation_status < 400

        if not original_success and mutation_success:
            if label not in {"CONFIRMED", "HIGH"}:
                label = "HIGH"

            reasons.append(
                "The original request was unsuccessful, while the mutated "
                "request received a successful or redirect response."
            )
        elif response_difference["status_class_changed"]:
            if label not in {"CONFIRMED", "HIGH"}:
                label = "HIGH"

            reasons.append("The HTTP response status class changed.")
        elif response_difference["status_changed"]:
            if label == "NONE":
                label = "MEDIUM"

            reasons.append("The HTTP response status code changed.")

    if response_difference["normalized_body_changed"]:
        similarity = response_difference["similarity"]

        if similarity < 0.60 and label in {"NONE", "LOW"}:
            label = "MEDIUM"
            reasons.append(
                "The normalized response body changed substantially."
            )
        elif similarity < 0.95 and label == "NONE":
            label = "LOW"
            reasons.append(
                "The normalized response body changed."
            )
        elif label == "NONE":
            label = "LOW"
            reasons.append(
                "A small normalized response body difference was detected."
            )

    if label == "NONE":
        reasons.append(
            "No meaningful status-code or normalized-content difference "
            "was detected."
        )

    # When the formatting-only control also changed server behavior, response
    # differences without verification are less confidently attributable to
    # the selected mutation.
    if (
        formatting_control_changed
        and verification_before is None
        and label in {"HIGH", "MEDIUM"}
    ):
        label = downgrade_confidence(label)
        reasons.append(
            "Confidence was reduced because the semantically unchanged "
            "formatting control also changed the response."
        )

    return {
        "label": label,
        "reasons": reasons,
    }


def request_report_record(
    request: RawHTTPRequest,
    destination: Destination,
    body: bytes,
) -> dict[str, Any]:
    """
    Create a report-safe representation of an outgoing request.

    Base64 stores the exact normalized bytes, including authentication and
    cookie headers. Reports must therefore be handled as sensitive files.
    """

    wire_bytes = wire_request_bytes(request, destination, body)

    return {
        "method": request.method,
        "scheme": destination.scheme,
        "host": destination.host,
        "port": destination.port,
        "request_target": destination.request_target,
        "headers": outgoing_headers(request, destination, body),
        "body_text": body.decode("utf-8", errors="replace"),
        "body_sha256": sha256_bytes(body),
        "wire_request_base64": base64.b64encode(wire_bytes).decode("ascii"),
    }


def response_report_record(
    response: ResponseRecord | None,
) -> dict[str, Any] | None:
    """Convert a response record to JSON-serializable report data."""

    if response is None:
        return None

    return {
        "status": response.status,
        "reason": response.reason,
        "http_version": response.version,
        "headers": response.headers,
        "elapsed_ms": round(response.elapsed_ms, 3),
        "truncated": response.truncated,
        "error": response.error,
        "body_sha256": sha256_bytes(response.body),
        "body_base64": base64.b64encode(response.body).decode("ascii"),
        "decoded_body_text": response_text(response),
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    """
    Write the report with owner-only permissions where supported.

    The report may contain bearer tokens, session cookies, CSRF tokens,
    request bodies, and sensitive response data.
    """

    path.parent.mkdir(parents=True, exist_ok=True)

    serialized = json.dumps(
        report,
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")

    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )

    with os.fdopen(descriptor, "wb") as report_file:
        report_file.write(serialized)


def parse_cli_test_value(raw_value: str) -> Any:
    """
    Parse a command-line test value as JSON.

    A value that is not valid JSON is treated as a normal string, making
    --test-value admin equivalent to the JSON string "admin".
    """

    try:
        return json.loads(raw_value)
    except json.JSONDecodeError:
        return raw_value


def prompt_for_test_values() -> list[Any]:
    """Interactively ask for application-specific test values."""

    print()
    print(
        "Enter known values to test, preferably as a JSON array."
    )
    print(
        'Example: ["admin", "beta", 1, true, null]'
    )
    print(
        "Leave the input blank to use a conservative automatically generated "
        "value."
    )

    raw = input("Test values: ").strip()

    if not raw:
        return []

    try:
        parsed = json.loads(raw)

        if isinstance(parsed, list):
            # In interactive mode, a top-level array represents several
            # candidate test values.
            return parsed

        return [parsed]

    except json.JSONDecodeError:
        # A comma-separated fallback makes simple input convenient.
        return [
            item.strip()
            for item in raw.split(",")
            if item.strip()
        ]


def select_field(
    fields: Sequence[FieldReference],
    requested_field: str | None,
) -> FieldReference:
    """Select a field by CLI value or an interactive numbered prompt."""

    print()
    print("Detected JSON fields:")
    print("-" * 80)

    for index, field in enumerate(fields, start=1):
        print(
            f"{index:>3}. "
            f"{format_json_path(field.path):<42} "
            f"type={json_type_name(field.value):<8} "
            f"value={value_preview(field.value)}"
        )

    print("-" * 80)

    if requested_field:
        # A numeric --field value is interpreted as the displayed field index.
        if requested_field.isdigit():
            selected_index = int(requested_field)

            if 1 <= selected_index <= len(fields):
                return fields[selected_index - 1]

        # Otherwise, require an exact match to the displayed JSON path.
        for field in fields:
            if format_json_path(field.path) == requested_field:
                return field

        raise ValueError(
            f"Unknown field {requested_field!r}. Use its displayed number or "
            "exact JSON path."
        )

    if not sys.stdin.isatty():
        raise ValueError(
            "Interactive field selection is unavailable. Supply --field."
        )

    raw_selection = input("Select a field number: ").strip()

    if not raw_selection.isdigit():
        raise ValueError("The field selection must be a number.")

    selected_index = int(raw_selection)

    if not 1 <= selected_index <= len(fields):
        raise ValueError("The selected field number is out of range.")

    return fields[selected_index - 1]


def require_authorization_confirmation(
    already_confirmed: bool,
) -> None:
    """Require an explicit statement of authorization before network traffic."""

    if already_confirmed:
        return

    if not sys.stdin.isatty():
        raise ValueError(
            "Network requests require --confirm-authorized in non-interactive "
            "mode."
        )

    print()
    print(
        "Only continue if you own the target or have explicit permission to "
        "perform this test."
    )

    phrase = input(
        'Type "I AM AUTHORIZED" to send the requests: '
    ).strip()

    if phrase != "I AM AUTHORIZED":
        raise ValueError("Authorization confirmation was not provided.")


def display_payload(mutation: Mutation) -> None:
    """Print the exact mutated JSON body before it is sent."""

    print()
    print("=" * 80)
    print(f"Test:        {mutation.name}")
    print(f"Category:    {mutation.category}")
    print(f"Description: {mutation.description}")
    print("-" * 80)
    print(mutation.body.decode("utf-8", errors="replace"))
    print("-" * 80)


def display_response_summary(
    label: str,
    response: ResponseRecord,
) -> None:
    """Print a compact response summary."""

    if response.error:
        print(
            f"{label}: ERROR after {response.elapsed_ms:.1f} ms - "
            f"{response.error}"
        )
        return

    truncation_note = " [truncated]" if response.truncated else ""

    print(
        f"{label}: HTTP {response.status} {response.reason} | "
        f"{len(response.body)} captured bytes | "
        f"{response.elapsed_ms:.1f} ms{truncation_note}"
    )


def display_difference(difference: dict[str, Any]) -> None:
    """Print the important parts of a response comparison."""

    print(
        "Difference: "
        f"status {difference['baseline_status']} -> "
        f"{difference['candidate_status']}; "
        f"body {difference['baseline_body_length']} -> "
        f"{difference['candidate_body_length']} bytes; "
        f"similarity={difference['similarity']:.3f}"
    )

    if difference["diff"]:
        print("Response diff:")

        for line in difference["diff"]:
            print(f"  {line}")


def default_report_path() -> Path:
    """Create a timestamped default report filename."""

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"pastelparse_report_{timestamp}.json")


def load_optional_request(path: str | None) -> RawHTTPRequest | None:
    """Load an optional raw HTTP request file."""

    if not path:
        return None

    return parse_raw_http_request(Path(path).read_bytes())


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the command-line interface."""

    parser = argparse.ArgumentParser(
        description=(
            "Generate and send JSON parser inconsistency test payloads "
            "using an authorized raw HTTP request."
        )
    )

    parser.add_argument(
        "request_file",
        help="File containing the original raw HTTP/1.x request.",
    )
    parser.add_argument(
        "--field",
        help=(
            "Field number or exact displayed JSON path. When omitted, the "
            "tool prompts interactively."
        ),
    )
    parser.add_argument(
        "--test-value",
        action="append",
        default=[],
        help=(
            "Known value to use in mutations. May be repeated. Values are "
            "parsed as JSON when possible."
        ),
    )
    parser.add_argument(
        "--scheme",
        choices=("http", "https"),
        help="Override the inferred request scheme.",
    )
    parser.add_argument(
        "--verification-request",
        help=(
            "Raw HTTP request sent immediately before and after each mutation "
            "to detect server-side state changes."
        ),
    )
    parser.add_argument(
        "--reset-request",
        help=(
            "Optional raw HTTP request sent before each mutation to reset the "
            "test account or application state."
        ),
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Output JSON report path.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request network timeout in seconds. Default: 10.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between network operations in seconds. Default: 0.5.",
    )
    parser.add_argument(
        "--max-tests",
        type=int,
        default=30,
        help="Maximum mutations to send. Default: 30.",
    )
    parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=5 * 1024 * 1024,
        help=(
            "Maximum response bytes captured per request. "
            "Default: 5242880."
        ),
    )
    parser.add_argument(
        "--diff-lines",
        type=int,
        default=40,
        help="Maximum response diff lines displayed. Default: 40.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Disable HTTPS certificate verification. Intended only for "
            "authorized lab systems using self-signed certificates."
        ),
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help=(
            "Allow non-loopback destinations. Without this option, only "
            "localhost and loopback IP addresses are accepted."
        ),
    )
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help=(
            "Confirm that you are authorized to test the target. Required "
            "when running non-interactively."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate payloads and a report without sending requests.",
    )

    return parser


def main() -> int:
    """Program entry point."""

    parser = build_argument_parser()
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")

    if args.delay < 0:
        parser.error("--delay cannot be negative.")

    if args.max_tests <= 0:
        parser.error("--max-tests must be greater than zero.")

    if args.max_response_bytes <= 0:
        parser.error("--max-response-bytes must be greater than zero.")

    report_path = args.report or default_report_path()

    try:
        original_request = parse_raw_http_request(
            Path(args.request_file).read_bytes()
        )
        json_document = parse_json_request_body(original_request)

        fields = enumerate_json_fields(json_document)

        if not fields:
            raise ValueError(
                "The JSON body does not contain any object fields to test."
            )

        selected_field = select_field(fields, args.field)

        supplied_values = [
            parse_cli_test_value(value)
            for value in args.test_value
        ]

        if not supplied_values and sys.stdin.isatty():
            supplied_values = prompt_for_test_values()

        verification_request = load_optional_request(
            args.verification_request
        )
        reset_request = load_optional_request(args.reset_request)

        original_destination = resolve_destination(
            original_request,
            args.scheme,
        )

        verification_destination = (
            resolve_destination(verification_request, args.scheme)
            if verification_request
            else None
        )

        reset_destination = (
            resolve_destination(reset_request, args.scheme)
            if reset_request
            else None
        )

        destinations = [
            destination
            for destination in (
                original_destination,
                verification_destination,
                reset_destination,
            )
            if destination is not None
        ]

        # Refuse non-loopback targets by default. This makes accidental use
        # against an unrelated public host less likely.
        for destination in destinations:
            if (
                not is_loopback_host(destination.host)
                and not args.allow_remote
            ):
                raise ValueError(
                    f"Refusing non-loopback target "
                    f"{destination.host!r}. Use --allow-remote only when you "
                    "have explicit authorization."
                )

        mutations = generate_mutations(
            json_document,
            original_request.body,
            selected_field,
            supplied_values,
        )

        total_generated = len(mutations)
        mutations = mutations[: args.max_tests]

        print()
        print("PastelParse")
        print("=" * 80)
        print(
            f"Target:       {original_destination.scheme}://"
            f"{original_destination.host}:{original_destination.port}"
            f"{original_destination.request_target}"
        )
        print(
            f"Selected:     {format_json_path(selected_field.path)} "
            f"({json_type_name(selected_field.value)})"
        )
        print(f"Generated:    {total_generated} unique mutations")
        print(f"Scheduled:    {len(mutations)} mutations")
        print(f"Report:       {report_path}")
        print()
        print(
            "Warning: the report contains exact headers, cookies, tokens, "
            "payloads, and captured responses."
        )

        report: dict[str, Any] = {
            "tool": "PastelParse",
            "report_version": 1,
            "created_at": utc_now(),
            "authorized_use_notice": (
                "This report was generated for an authorized security test."
            ),
            "sensitive_data_notice": (
                "The report may contain authentication tokens, cookies, "
                "request bodies, and sensitive response data."
            ),
            "configuration": {
                "dry_run": args.dry_run,
                "timeout_seconds": args.timeout,
                "delay_seconds": args.delay,
                "maximum_tests": args.max_tests,
                "maximum_response_bytes": args.max_response_bytes,
                "tls_verification_disabled": args.insecure,
            },
            "selected_field": {
                "path": format_json_path(selected_field.path),
                "original_type": json_type_name(selected_field.value),
                "original_value": selected_field.value,
                "supplied_test_values": supplied_values,
            },
            "original_request": request_report_record(
                original_request,
                original_destination,
                original_request.body,
            ),
            "original_response": None,
            "tests": [],
        }

        # Dry-run mode records and displays every payload without opening a
        # network connection.
        if args.dry_run:
            for mutation in mutations:
                display_payload(mutation)

                report["tests"].append(
                    {
                        "name": mutation.name,
                        "category": mutation.category,
                        "description": mutation.description,
                        "probe_values": mutation.probe_values,
                        "request": request_report_record(
                            original_request,
                            original_destination,
                            mutation.body,
                        ),
                        "response": None,
                        "response_difference": None,
                        "verification": None,
                        "confidence": {
                            "label": "DRY-RUN",
                            "reasons": [
                                "The payload was generated but not sent."
                            ],
                        },
                    }
                )

            write_report(report_path, report)
            print()
            print(f"Dry-run report written to {report_path}")
            return 0

        require_authorization_confirmation(args.confirm_authorized)

        print()
        print("Sending original request...")
        original_response = send_http_request(
            original_request,
            original_destination,
            original_request.body,
            timeout=args.timeout,
            insecure=args.insecure,
            maximum_response_bytes=args.max_response_bytes,
        )

        display_response_summary(
            "Original response",
            original_response,
        )

        report["original_response"] = response_report_record(
            original_response
        )
        write_report(report_path, report)

        if original_response.error:
            print(
                "The original request failed, so mutation testing was stopped."
            )
            print(f"Partial report written to {report_path}")
            return 2

        formatting_control_changed = False

        for test_number, mutation in enumerate(mutations, start=1):
            display_payload(mutation)
            print(f"Progress: {test_number}/{len(mutations)}")

            reset_response: ResponseRecord | None = None
            verification_before: ResponseRecord | None = None
            verification_after: ResponseRecord | None = None

            # Resetting application state is useful when requests are
            # state-changing and later tests could otherwise be contaminated
            # by an earlier mutation.
            if reset_request and reset_destination:
                print("Sending reset request...")

                reset_response = send_http_request(
                    reset_request,
                    reset_destination,
                    reset_request.body,
                    timeout=args.timeout,
                    insecure=args.insecure,
                    maximum_response_bytes=args.max_response_bytes,
                )

                display_response_summary(
                    "Reset response",
                    reset_response,
                )

                if args.delay:
                    time.sleep(args.delay)

            # A pre-mutation verification response establishes the state
            # immediately before this individual test.
            if verification_request and verification_destination:
                print("Sending pre-mutation verification request...")

                verification_before = send_http_request(
                    verification_request,
                    verification_destination,
                    verification_request.body,
                    timeout=args.timeout,
                    insecure=args.insecure,
                    maximum_response_bytes=args.max_response_bytes,
                )

                display_response_summary(
                    "Verification before",
                    verification_before,
                )

                if args.delay:
                    time.sleep(args.delay)

            print("Sending mutated request...")

            mutation_response = send_http_request(
                original_request,
                original_destination,
                mutation.body,
                timeout=args.timeout,
                insecure=args.insecure,
                maximum_response_bytes=args.max_response_bytes,
            )

            display_response_summary(
                "Mutation response",
                mutation_response,
            )

            if args.delay:
                time.sleep(args.delay)

            # The post-mutation verification is compared with the immediately
            # preceding verification response.
            if verification_request and verification_destination:
                print("Sending post-mutation verification request...")

                verification_after = send_http_request(
                    verification_request,
                    verification_destination,
                    verification_request.body,
                    timeout=args.timeout,
                    insecure=args.insecure,
                    maximum_response_bytes=args.max_response_bytes,
                )

                display_response_summary(
                    "Verification after",
                    verification_after,
                )

            response_difference = compare_responses(
                original_response,
                mutation_response,
                maximum_diff_lines=args.diff_lines,
            )

            display_difference(response_difference)

            verification_difference = None

            if verification_before and verification_after:
                verification_difference = compare_responses(
                    verification_before,
                    verification_after,
                    maximum_diff_lines=args.diff_lines,
                )

                print(
                    "Verification difference: "
                    f"status {verification_difference['baseline_status']} -> "
                    f"{verification_difference['candidate_status']}; "
                    f"similarity="
                    f"{verification_difference['similarity']:.3f}"
                )

            if mutation.category == "control":
                formatting_control_changed = bool(
                    response_difference["status_changed"]
                    or (
                        response_difference["normalized_body_changed"]
                        and response_difference["similarity"] < 0.98
                    )
                )

                confidence = {
                    "label": "CONTROL",
                    "reasons": [
                        (
                            "The formatting-only control changed the response."
                            if formatting_control_changed
                            else
                            "The formatting-only control did not cause a "
                            "meaningful response difference."
                        )
                    ],
                }
            else:
                confidence = classify_result(
                    original_response=original_response,
                    mutation_response=mutation_response,
                    response_difference=response_difference,
                    probe_values=mutation.probe_values,
                    verification_before=verification_before,
                    verification_after=verification_after,
                    formatting_control_changed=formatting_control_changed,
                )

            print(f"Confidence: {confidence['label']}")

            for reason in confidence["reasons"]:
                print(f"  - {reason}")

            report["tests"].append(
                {
                    "name": mutation.name,
                    "category": mutation.category,
                    "description": mutation.description,
                    "probe_values": mutation.probe_values,
                    "request": request_report_record(
                        original_request,
                        original_destination,
                        mutation.body,
                    ),
                    "response": response_report_record(
                        mutation_response
                    ),
                    "response_difference": response_difference,
                    "reset_response": response_report_record(
                        reset_response
                    ),
                    "verification": (
                        {
                            "before": response_report_record(
                                verification_before
                            ),
                            "after": response_report_record(
                                verification_after
                            ),
                            "difference": verification_difference,
                        }
                        if verification_request
                        else None
                    ),
                    "confidence": confidence,
                }
            )

            # Write after every test so an interrupted run still leaves a
            # useful partial report.
            report["last_updated_at"] = utc_now()
            write_report(report_path, report)

            if args.delay and test_number < len(mutations):
                time.sleep(args.delay)

        print()
        print("=" * 80)
        print(f"Testing complete. Report written to {report_path}")
        return 0

    except KeyboardInterrupt:
        print()
        print("Testing interrupted by the user.")
        return 130

    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
