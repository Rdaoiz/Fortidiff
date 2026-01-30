#!/usr/bin/env python3
"""
legacy_iid.py

Extract InstanceID + RuleID + Impact + Probability + Accuracy + Confidence +
Likelihood + Risk from one or more audit.fvdl files and write to a CSV with
eight headers:
  InstanceID,RuleID,Impact,Probability,Accuracy,Confidence,Likelihood,Risk
"""

#python legacy_iid.py .\audits --out .\instance_severity.csv


import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, List



def expand_inputs(paths: List[str]) -> List[Path]:
    expanded: List[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            expanded.extend(sorted(path.glob("*.fvdl")))
        else:
            expanded.append(path)
    return expanded


def iter_vulnerabilities_by_instance(fvdl_path: Path) -> Iterable[dict]:
    """Return vulnerability dicts keyed by InstanceID (no snippet hash dependency)."""
    try:
        tree = ET.parse(fvdl_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        sys.exit(f"Unable to parse XML {fvdl_path}: {exc}")

    if root.tag.startswith("{"):
        uri = root.tag[1:root.tag.index("}")]
        ns = {"ns": uri}
        use_ns = True
    else:
        ns = {}
        use_ns = False

    def q(tag: str) -> str:
        return f".//ns:{tag}" if use_ns else f".//{tag}"

    for vuln in root.findall(q("Vulnerability"), namespaces=ns if use_ns else None):
        instance_id = (
            (vuln.findtext(q("InstanceID"), namespaces=ns if use_ns else None) or "")
            .strip()
        )
        if not instance_id:
            continue
        rule_id = (
            (vuln.findtext(q("ClassID"), namespaces=ns if use_ns else None) or "")
            .strip()
        )
        yield {
            "iid": instance_id,
            "RuleID": rule_id,
        }


def parse_instance_confidence(fvdl_path: Path) -> dict:
    try:
        tree = ET.parse(fvdl_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        sys.exit(f"Unable to parse XML {fvdl_path}: {exc}")

    if root.tag.startswith("{"):
        uri = root.tag[1:root.tag.index("}")]
        ns = {"ns": uri}
        use_ns = True
    else:
        ns = {}
        use_ns = False

    def q(tag: str) -> str:
        return f".//ns:{tag}" if use_ns else f".//{tag}"

    confidence_map = {}
    for vuln in root.findall(q("Vulnerability"), namespaces=ns if use_ns else None):
        instance_id = (
            (vuln.findtext(q("InstanceID"), namespaces=ns if use_ns else None) or "")
            .strip()
        )
        if not instance_id:
            continue
        confidence = (
            (vuln.findtext(q("Confidence"), namespaces=ns if use_ns else None) or "")
            .strip()
        )
        confidence_map[instance_id] = confidence
    return confidence_map

def parse_instance_probability_override(fvdl_path: Path) -> dict:
    try:
        tree = ET.parse(fvdl_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        sys.exit(f"Unable to parse XML {fvdl_path}: {exc}")

    if root.tag.startswith("{"):
        uri = root.tag[1:root.tag.index("}")]
        ns = {"ns": uri}
        use_ns = True
    else:
        ns = {}
        use_ns = False

    def q(tag: str) -> str:
        return f".//ns:{tag}" if use_ns else f".//{tag}"

    overrides = {}
    for vuln in root.findall(q("Vulnerability"), namespaces=ns if use_ns else None):
        instance_id = (
            (vuln.findtext(q("InstanceID"), namespaces=ns if use_ns else None) or "")
            .strip()
        )
        if not instance_id:
            continue
        instance_info = vuln.find(q("InstanceInfo"), namespaces=ns if use_ns else None)
        if instance_info is None:
            continue
        meta_info = instance_info.find(q("MetaInfo"), namespaces=ns if use_ns else None)
        if meta_info is None:
            continue
        for group in meta_info.findall(q("Group"), namespaces=ns if use_ns else None):
            name = (group.attrib.get("name") or "").strip()
            if name == "Probability":
                overrides[instance_id] = (group.text or "").strip()
                break
    return overrides

def parse_rule_meta(fvdl_path: Path) -> dict:
    try:
        tree = ET.parse(fvdl_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        sys.exit(f"Unable to parse XML {fvdl_path}: {exc}")

    if root.tag.startswith("{"):
        uri = root.tag[1:root.tag.index("}")]
        ns = {"ns": uri}
        use_ns = True
    else:
        ns = {}
        use_ns = False

    def q(tag: str) -> str:
        return f".//ns:{tag}" if use_ns else f".//{tag}"

    rule_meta = {}
    for rule_info in root.findall(q("RuleInfo"), namespaces=ns if use_ns else None):
        for rule in rule_info.findall(q("Rule"), namespaces=ns if use_ns else None):
            rule_id = (rule.attrib.get("id") or "").strip()
            if not rule_id:
                continue
            impact = ""
            probability = ""
            accuracy = "" 
            for group in rule.findall(q("Group"), namespaces=ns if use_ns else None):
                name = (group.attrib.get("name") or "").strip()
                if name == "Impact":
                    impact = (group.text or "").strip()
                elif name == "Accuracy": 
                    accuracy = (group.text or "").strip() 
                elif name == "Probability":
                    probability = (group.text or "").strip()
            rule_meta[rule_id] = {
                "Impact": impact,
                "Probability": probability,
                "Accuracy": accuracy, 
            }
    return rule_meta


# pulled from a fortify forum
def classify_risk(impact_raw: str, likelihood_raw: str) -> str:
    try:
        impact = float((impact_raw or "").strip())
        likelihood = float((likelihood_raw or "").strip())
    except ValueError:
        return ""

# Fortify defines high values for impact and likelihood as
# those at 2.5 and above [2.5,5.0] and low values as those below 2.5 (0,2.5). 

    if impact >= 2.5 and likelihood >= 2.5: # over 2.5 impact and high likelihood = crit
        return "Critical"
    if impact >= 2.5 and likelihood < 2.5: # over 2.5 impact but lower than 2.5 likelihood is still high 
        return "High"
    if impact < 2.5 and likelihood >= 2.5: # under 2.5 impact but over 2.5 impact is medium 
        return "Medium"
    if impact < 2.5 and likelihood < 2.5: # under 2.5 impact and under 2.5 likelihood
        return "Low"
    return ""


def compute_likelihood(
    accuracy_raw: str, confidence_raw: str, probability_raw: str
) -> str:
    try:
        accuracy = float((accuracy_raw or "").strip())
        confidence = float((confidence_raw or "").strip())
        probability = float((probability_raw or "").strip())
    except ValueError:
        return ""

    likelihood = (accuracy * confidence * probability) / 25.0
    return f"{likelihood:.2f}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Extract InstanceID + RuleID + Impact + Probability + Accuracy + "
            "Confidence + Likelihood + Risk from audit.fvdl files."
        )
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Directory of FVDL files holding pre scans to build reference point.",
    )
    parser.add_argument('-o',
        '--out',
        required=True,
        help=(
            "Output CSV path (eight columns: "
            "InstanceID,RuleID,Impact,Probability,Accuracy,Confidence,Likelihood,Risk)."
        ),
    )
    args = parser.parse_args()

    fvdl_files = expand_inputs(args.inputs)
    if not fvdl_files:
        raise SystemExit("No FVDL files found.")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "InstanceID",
                "RuleID",
                "Impact",
                "Probability",
                "Accuracy",
                "Confidence",
                "Likelihood",
                "Severity",
            ]
        )

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        total_vulns = 0 # add for counter 
        for fvdl in fvdl_files:
            rule_meta = parse_rule_meta(fvdl)
            confidence_map = parse_instance_confidence(fvdl)
            probability_overrides = parse_instance_probability_override(fvdl)
            for vuln in iter_vulnerabilities_by_instance(fvdl):
                instance_id = vuln.get("iid", "")
                if not instance_id:
                    continue
                total_vulns += 1 # add for counter 
                rule_id = vuln.get("RuleID", "")
                meta = rule_meta.get(rule_id, {})
                impact = meta.get("Impact", "")
                probability = meta.get("Probability", "")
                override_probability = probability_overrides.get(instance_id, "")
                if override_probability:
                    probability = override_probability
                accuracy = meta.get("Accuracy", "")
                confidence = confidence_map.get(instance_id, "")
                likelihood = compute_likelihood(accuracy, confidence, probability)
                severity = classify_risk(impact, likelihood)
                if severity in severity_counts:
                    severity_counts[severity] += 1
                writer.writerow(
                    [
                        instance_id,
                        rule_id,
                        impact,
                        probability,
                        accuracy,
                        confidence,
                        likelihood,
                        severity,
                    ]
                )

    print(f"Wrote {out_path}")
    print(f"Total vulnerabilities: {total_vulns}") # add for counter 
    print(
        "Severity counts - "
        f"Critical: {severity_counts['Critical']}, "
        f"High: {severity_counts['High']}, "
        f"Medium: {severity_counts['Medium']}, "
        f"Low: {severity_counts['Low']}"
    )


if __name__ == "__main__":
    main()
