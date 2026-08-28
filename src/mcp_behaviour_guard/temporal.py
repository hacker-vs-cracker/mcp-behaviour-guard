from __future__ import annotations

from typing import Any

from .util import stable_hash

_METADATA_FAMILIES = ("tools", "prompts", "prompt_payloads", "resources")


def normalise_metadata_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    normalised: dict[str, Any] = {}
    for family in _METADATA_FAMILIES:
        raw_family = snapshot.get(family, {})
        if not isinstance(raw_family, dict):
            normalised[family] = raw_family
            continue
        normalised[family] = {str(key): raw_family[key] for key in sorted(raw_family, key=str)}
    return normalised


def metadata_fingerprint(snapshot: dict[str, Any]) -> str:
    return stable_hash(normalise_metadata_snapshot(snapshot))


def compare_metadata_snapshots(
    reference: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    reference = normalise_metadata_snapshot(reference)
    current = normalise_metadata_snapshot(current)

    families: dict[str, Any] = {}
    for family in _METADATA_FAMILIES:
        before = reference.get(family, {})
        after = current.get(family, {})
        if not isinstance(before, dict) or not isinstance(after, dict):
            changed = stable_hash(before) != stable_hash(after)
            families[family] = {
                "changed": changed,
                "before": before if changed else None,
                "after": after if changed else None,
            }
            continue

        before_names = set(before)
        after_names = set(after)
        changed_entries: dict[str, Any] = {}
        for name in sorted(before_names & after_names):
            if stable_hash(before[name]) != stable_hash(after[name]):
                changed_entries[name] = {
                    "before": before[name],
                    "after": after[name],
                }

        families[family] = {
            "added": sorted(after_names - before_names),
            "removed": sorted(before_names - after_names),
            "changed": changed_entries,
        }

    drift_detected = any(_family_has_drift(value) for value in families.values())
    return {
        "drift_detected": drift_detected,
        "reference_fingerprint": metadata_fingerprint(reference),
        "current_fingerprint": metadata_fingerprint(current),
        "families": families,
    }


def compact_drift_summary(diff: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    families = diff.get("families", {})
    if not isinstance(families, dict):
        return summary

    for family, family_diff in families.items():
        if not isinstance(family_diff, dict) or not _family_has_drift(family_diff):
            continue
        if "added" in family_diff:
            summary[family] = {
                "added": family_diff.get("added", []),
                "removed": family_diff.get("removed", []),
                "changed": sorted((family_diff.get("changed") or {}).keys()),
            }
        else:
            summary[family] = {"changed": True}
    return summary


def _family_has_drift(family_diff: dict[str, Any]) -> bool:
    if "added" in family_diff:
        return bool(
            family_diff.get("added") or family_diff.get("removed") or family_diff.get("changed")
        )
    return bool(family_diff.get("changed"))
