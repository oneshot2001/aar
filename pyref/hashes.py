"""AAR v0.2 domain-separated content-ID and Merkle computations."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from typing import Any

from .cbor import dumps


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def domain_hash(domain: str, *items: Any) -> bytes:
    return sha256(dumps([domain, *items]))


def without_field(value: dict[Any, Any], field: str) -> dict[Any, Any]:
    return {key: item for key, item in value.items() if key != field}


ARTIFACT_DOMAINS = {
    "delegation_id": "AAR-DELEGATION-ID-v1",
    "credential_id": "AAR-CREDENTIAL-ID-v1",
    "snapshot_id": "AAR-STATUS-ID-v1",
    "rotation_id": "AAR-ROTATION-ID-v1",
    "event_id": "AAR-EPOCH-EVENT-ID-v1",
    "manifest_id": "AAR-EPOCH-MANIFEST-ID-v1",
    "anchor_id": "AAR-ANCHOR-ID-v1",
    "batch_id": "AAR-BATCH-ID-v1",
    "presentation_id": "AAR-PRESENTATION-MANIFEST-v1",
}


def artifact_id(payload: dict[str, Any], field: str) -> bytes:
    return domain_hash(ARTIFACT_DOMAINS[field], without_field(payload, field))


def receipt_id(receipt: dict[str, Any], protected: bytes) -> bytes:
    return domain_hash(
        "AAR-RECEIPT-ID-v1", protected, without_field(receipt, "receipt_id")
    )


def consumption_manifest_digest(manifest: dict[str, Any]) -> bytes:
    return domain_hash(
        "AAR-CONSUMPTION-MANIFEST-v1",
        without_field(manifest, "manifest_digest"),
    )


def decision_commitment(decision: dict[str, Any]) -> bytes:
    return domain_hash(
        "AAR-DECISION-RECORD-v1",
        without_field(decision, "decision_commitment"),
    )


def command_id(command: dict[str, Any]) -> bytes:
    return domain_hash("AAR-COMMAND-MANIFEST-v1", without_field(command, "command_id"))


def selector_commitment(selector: dict[str, Any]) -> bytes:
    return domain_hash("AAR-BUNDLE-SELECTOR-v1", selector)


def trust_store_digest(snapshot: dict[str, Any]) -> bytes:
    return domain_hash("AAR-TRUST-STORE-v1", without_field(snapshot, "digest"))


def manifest_index_leaf(entry: dict[str, Any]) -> bytes:
    return domain_hash("AAR-MANIFEST-INDEX-LEAF-v1", entry)


def manifest_index_node(left: bytes, right: bytes) -> bytes:
    return domain_hash("AAR-MANIFEST-INDEX-NODE-v1", left, right)


def merkle_leaf(leaf: dict[str, Any]) -> bytes:
    return domain_hash("AAR-MERKLE-LEAF-v1", leaf)


def merkle_node(left: bytes, right: bytes) -> bytes:
    return domain_hash("AAR-MERKLE-NODE-v1", left, right)


def promoted_root(leaves: Iterable[bytes], node_hash: Callable[[bytes, bytes], bytes]) -> bytes:
    level = list(leaves)
    if not level:
        raise ValueError("empty Merkle tree")
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            if index + 1 == len(level):
                next_level.append(level[index])
            else:
                next_level.append(node_hash(level[index], level[index + 1]))
        level = next_level
    return level[0]


def inclusion_root(
    leaf_hash: bytes,
    leaf_index: int,
    tree_size: int,
    siblings: Iterable[bytes],
    node_hash: Callable[[bytes, bytes], bytes],
) -> bytes:
    """Rebuild a promoted-odd tree root from its RFC 6962-style audit path."""
    index = leaf_index
    last = tree_size - 1
    value = leaf_hash
    for sibling in siblings:
        if index & 1 or index == last:
            value = node_hash(sibling, value)
            while index and not (index & 1):
                index >>= 1
                last >>= 1
        else:
            value = node_hash(value, sibling)
        index >>= 1
        last >>= 1
    return value


def anchor_leaf_input(record: dict[str, Any]) -> bytes:
    leaf = {
        "tenant_id": record["tenant_id"],
        "site_id": record["site_id"],
        "epoch_id": record["epoch_id"],
        "manifest_id": record["manifest_id"],
        "manifest_digest": record["manifest_digest"],
    }
    return dumps(["AAR-ANCHOR-LEAF-v1", leaf])


def rfc6962_leaf(data: bytes) -> bytes:
    return sha256(b"\x00" + data)


def rfc6962_node(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)

