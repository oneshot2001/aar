"""CONFORMANCE step 6 field rules (D-82 part 8) and the closed enums they name.

The bounded schema table and its apply helpers moved out of ``verifier``
unchanged; the table is keyed by artifact category. ``harness/field-rules.ts``
mirrors this module. Rejections go through ``verifier._fail`` by attribute so
the premise recorder sees them.
"""

from __future__ import annotations

from typing import Any

# D-88: the three action-name productions and delegation-scope actions.
ACTION_NAMES = ("camera.stream.view", "camera.ptz.preset")
TIME_CLASSES = ("asserted", "boot_bound", "externally_anchored")
PROVENANCE_CLASSES = ("self_asserted", "proxy_captured", "provider_attested")
OUTCOME_LEVELS = ("accepted", "dispatched", "device_acknowledged", "independently_sensed", "contradicted", "unknown")
TRANSFORMATION_OPERATIONS = ("decode", "crop", "embed", "ocr", "truncate", "retrieve", "normalize", "render", "redact")
# D-82 part 8: the bounded step-6 schema table. Rules are (path, kind, optional)
# in CDDL field order within each production; kind is a scalar type or a closed
# enum tuple. A container's rule precedes its members' rules (D-81 UINT_FIELDS
# generalised; the credential and presentation blocks are inline because their
# pinned precedences interleave D-73 checks).
# A rule whose kind is a list is applied to every member of the array at its
# path; each member must be a text-keyed map (amendment b: array members).
INDEX_ENTRY_RULES = (
    (("leaf_index",), "uint", False), (("receipt_id",), "bstr32", False), (("receipt_kind",), "text", False), (("issuer_kid",), "bstr32", False),
    (("issuer_seq",), "uint", False), (("epoch_seq",), "uint", False), (("committed_at",), "uint", False),
    (("subject_ids",), "bstr16[]", False), (("correlation_ids",), "bstr16[]", False),
)
INDEPENDENCE_GROUP_RULES = ((("independence_group",), "bstr16", False), (("operator_id",), "bstr16", False), (("failure_domain_id",), "bstr16", False))
INCLUSION_RULES = ((("tree_size",), "uint", False), (("leaf_index",), "uint", False), (("siblings",), "bstr32[]", False))
# Amendment (ab): the bare proof-bearing productions, typed at step 3.
MERKLE_PROOF_RULES = (
    (("batch_id",), "bstr32", False), (("tree_size",), "uint", False), (("leaf_index",), "uint", False),
    (("leaf",), "map", False), (("leaf", "tree_size"), "uint", False), (("leaf", "leaf_index"), "uint", False),
    (("leaf", "tenant_id"), "bstr16", False), (("leaf", "site_id"), "bstr16", False), (("leaf", "epoch_id"), "uint", False),
    (("leaf", "item_digest"), "bstr32", False), (("siblings",), "bstr32[]", False),
)
RANGE_ITEM_RULES = ((("entry",), "map", False), (("entry",), INDEX_ENTRY_RULES, False), (("inclusion",), "map", False), (("inclusion",), INCLUSION_RULES, False))
RANGE_PROOF_RULES = (
    (("manifest_id",), "bstr32", False), (("selector_commitment",), "bstr32", False), (("tree_size",), "uint", False),
    (("first_leaf_index",), "uint", True), (("entries",), "array", False), (("entries",), RANGE_ITEM_RULES, False),
    (("left_boundary",), "map", True), (("left_boundary",), RANGE_ITEM_RULES, False),
    (("right_boundary",), "map", True), (("right_boundary",), RANGE_ITEM_RULES, False),
)
FIELD_RULES: dict[str, tuple[tuple[tuple[str, ...], Any, bool], ...]] = {
    "rotations": ((("effective_at",), "uint", False), (("continuity_sequence",), "uint", False)),
    "delegations": ((("not_before",), "uint", False), (("not_after",), "uint", False), (("use",), ("one_time", "reusable"), False)),
    "epoch_events": (
        (("epoch_id",), "uint", False), (("event_seq",), "uint", False), (("occurred_at",), "uint", False),
        (("event",), ("open", "close", "anchor_submitted", "fork_declared"), False), (("body",), "map", False),
    ),
    "epoch_manifests": (
        (("epoch_id",), "uint", False), (("opened_at",), "uint", False), (("closed_at",), "uint", False),
        (("sequence_span",), "map", False), (("sequence_span", "first"), "uint|nil", False), (("sequence_span", "last"), "uint|nil", False),
        (("close_reason",), ("duration", "size", "administrative", "padding"), False),
        (("late_arrival_policy",), ("next_epoch_only",), False), (("anchor_deadline",), "uint", False),
        (("fork_policy",), ("reject_and_surface",), False),
        (("receipt_index",), "map", False), (("receipt_index", "leaf_count"), "uint", False), (("receipt_index", "root"), "bstr32", False),
        (("receipt_index", "entries"), "array", False), (("receipt_index", "entries"), INDEX_ENTRY_RULES, False),
    ),
    "anchors": (
        (("epoch_id",), "uint", False), (("manifest_digest",), "bstr32", False), (("submitted_at",), "uint", False), (("accepted_at",), "uint", False),
        (("anchor_tree_size",), "uint", False), (("anchor_leaf_index",), "uint", False), (("anchor_root",), "bstr32", False),
        (("inclusion",), "map", False), (("inclusion", "tree_size"), "uint", False), (("inclusion", "leaf_index"), "uint", False),
        (("inclusion", "leaf_digest"), "bstr32", False), (("inclusion", "siblings"), "bstr32[]", False),
        (("consistency",), "map", True), (("consistency", "old_tree_size"), "uint", False), (("consistency", "new_tree_size"), "uint", False),
        (("consistency", "old_root"), "bstr32", False), (("consistency", "new_root"), "bstr32", False), (("consistency", "path"), "bstr32[]", False),
        (("head",), "map", False), (("head", "observed_at"), "uint", False), (("head", "tree_size"), "uint", False),
        (("head", "root"), "bstr32", False), (("head", "max_age_s"), "uint", False),
    ),
    "merkle_batches": (
        (("tenant_id",), "bstr16", False), (("site_id",), "bstr16", False), (("epoch_owner_kid",), "bstr32", False), (("epoch_id",), "uint", False),
        (("signer_kid",), "bstr32", False), (("tree_size",), "uint", False), (("root",), "bstr32", False), (("created_at",), "uint", False), (("claim",), "text", False),
    ),
    "mediator_countersignatures": ((("mediator_observed_at",), "uint", False),),
    "receipts": (
        (("binding",), "map", False), (("binding", "tenant_id"), "bytes", False), (("binding", "site_id"), "bytes", False),
        (("binding", "epoch_owner_kid"), "bytes", False), (("binding", "epoch_id"), "uint", False), (("binding", "epoch_seq"), "uint", False),
        (("binding", "late_for_epoch_id"), "uint", True),
        (("emission",), "map", False), (("emission", "issuer_seq"), "uint", False), (("emission", "committed_at"), "uint", False),
        (("freshness",), "map", False), (("freshness", "issued_at"), "uint", False), (("freshness", "expires_at"), "uint", False),
        (("freshness", "nonce"), "bytes", False), (("freshness", "replay_domain"), "bytes", False), (("freshness", "invocation_id"), "bytes", False),
        (("freshness", "use"), "text", False), (("freshness", "intended_parents"), "array", False),
        (("evidence",), "map", False), (("evidence", "time"), "map", False), (("evidence", "time", "class"), TIME_CLASSES, False),
        (("evidence", "time", "wall_time"), "uint", False),
        (("evidence", "provenance"), "map", True), (("evidence", "provenance", "class"), PROVENANCE_CLASSES, False),
        (("evidence", "outcome"), "map", True), (("evidence", "outcome", "level"), OUTCOME_LEVELS, False),
        (("parents",), "array", False), (("parents",), ((("parent_epoch_id",), "uint", False),), False),
        (("correlation",), "map", True), (("correlation", "phase"), ("request", "ingress_ack", "accounted"), False),
        (("body",), "map", False),
    ),
}


def _type_ok(value: Any, kind: Any) -> bool:
    if kind == "uint":
        return verifier._uint(value)
    if kind in ("bstr32", "bstr16"):
        return isinstance(value, bytes)  # size is judged after type (schema/digest-size)
    if kind in ("bstr32[]", "bstr16[]"):
        return isinstance(value, list)
    if kind == "uint|nil":  # sequence-span members
        return value is None or verifier._uint(value)
    if kind == "bytes":
        return isinstance(value, bytes)
    if kind == "map":  # a text-keyed map (harness object() parity)
        return isinstance(value, dict) and all(isinstance(key, str) for key in value)
    if kind == "array":
        return isinstance(value, list)
    return isinstance(value, str)  # "text" and enums


def _check_field(container: Any, name: str, kind: Any, optional: bool = False, step: int = 6) -> None:
    """Presence (schema/missing-field), then type (schema/bad-type), then size (schema/digest-size) or enum (schema/enum-unknown)."""
    if name not in container:
        if optional:
            return
        verifier._fail("schema/missing-field", step)
    value = container[name]
    if not _type_ok(value, kind):
        verifier._fail("schema/bad-type", step)
    if kind in ("bstr32", "bstr16") and len(value) != (32 if kind == "bstr32" else 16):
        verifier._fail("schema/digest-size", step)
    if kind in ("bstr32[]", "bstr16[]"):
        size = 32 if kind == "bstr32[]" else 16
        for member in value:
            if not isinstance(member, bytes):
                verifier._fail("schema/bad-type", step)
            if len(member) != size:
                verifier._fail("schema/digest-size", step)
    if isinstance(kind, tuple) and value not in kind:
        verifier._fail("schema/enum-unknown", step)


def _apply_rules(payload: dict[str, Any], rules: tuple[tuple[tuple[str, ...], Any, bool], ...], step: int = 6) -> None:
    for path, kind, optional in rules:
        container: Any = payload
        for key in (path if isinstance(kind, tuple) and kind and isinstance(kind[0], tuple) else path[:-1]):
            if key not in container:  # an absent optional ancestor; its own rule allowed that
                container = None
                break
            container = container[key]
        if container is None:
            continue
        if isinstance(kind, tuple) and kind and isinstance(kind[0], tuple):
            for member in (container if isinstance(container, list) else [container]):  # a boundary wrapper is one map
                if not _type_ok(member, "map"):
                    verifier._fail("schema/bad-type", step)
                _apply_rules(member, kind, step)
        else:
            _check_field(container, path[-1], kind, optional, step)


def _check_transformations(transforms: Any) -> None:
    """Each text-keyed transformation map validates its closed operation enum."""
    for transform in transforms:
        if isinstance(transform, dict) and all(isinstance(key, str) for key in transform):
            _check_field(transform, "operation", TRANSFORMATION_OPERATIONS)


from . import verifier  # noqa: E402 last, so either module may be imported first
