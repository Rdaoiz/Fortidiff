#!/usr/bin/env python3
"""
legacy_new_findings.py

Generate an HTML report of "new findings" by comparing a legacy InstanceID CSV
against one or more post-scan FVDL files. Any vulnerability whose InstanceID
is not present in the CSV is considered new.



"""

#python legacy_new_findings.py --legacy-csv legacy_findings.csv --post-fvdl post.audit.fvdl --out .\reports\new_findings.html
#python legacy_new_findings.py --legacy-csv legacy_findings.csv --post-fvdl .\post_scans --out .\reports\new_findings.html


import argparse
import csv
import json
import html
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterable, List, Set


def classify_risk(impact_raw: str, likelihood_raw: str) -> str:
    try:
        impact = float((impact_raw or "").strip())
        likelihood = float((likelihood_raw or "").strip())
    except ValueError:
        return ""
        # into 1 of 4 quadrants of a grid based on thresholds as follows (from Fortify support documentation):
        # - 'Critical' if Impact >=2.5 && Likelihood >= 2.5.
        # - 'High' If Impact >=2.5 && Likelihood < 2.5.
        # - 'Medium' If Impact < 2.5 && Likelihood >= 2.5.
        # - 'Low' if impact < 2.5 && likelihood < 2.5.
    if impact >= 2.5 and likelihood >= 2.5:
        return "Critical"
    if impact >= 2.5 and likelihood < 2.5:
        return "High"
    if impact < 2.5 and likelihood >= 2.5:
        return "Medium"
    if impact < 2.5 and likelihood < 2.5:
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


def parse_rule_meta(fvdl_path: Path) -> Dict[str, Dict[str, str]]:
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

    rule_meta: Dict[str, Dict[str, str]] = {}
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
                elif name == "Probability":
                    probability = (group.text or "").strip()
                elif name == "Accuracy":
                    accuracy = (group.text or "").strip()
            rule_meta[rule_id] = {
                "Impact": impact,
                "Probability": probability,
                "Accuracy": accuracy,
            }
    return rule_meta


def parse_instance_confidence(fvdl_path: Path) -> Dict[str, str]:
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

    confidence_map: Dict[str, str] = {}
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

def parse_instance_probability_override(fvdl_path: Path) -> Dict[str, str]:
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

    overrides: Dict[str, str] = {}
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
        #Metainfo tag search, if not present then skip over it. 
        meta_info = instance_info.find(q("MetaInfo"), namespaces=ns if use_ns else None)
        if meta_info is None:
            continue
        for group in meta_info.findall(q("Group"), namespaces=ns if use_ns else None):
            name = (group.attrib.get("name") or "").strip()
            if name == "Probability":
                overrides[instance_id] = (group.text or "").strip()
                break
    return overrides


def load_legacy_instance_ids(csv_path: Path) -> Set[str]:
    ids: Set[str] = set()
    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            instance_id = (row.get("InstanceID") or "").strip()
            if instance_id:
                ids.add(instance_id)
    return ids


def expand_inputs(paths: List[Path]) -> List[Path]:
    expanded: List[Path] = []
    for path in paths:
        if path.is_dir():
            expanded.extend(sorted(path.glob("*.fvdl")))
        else:
            expanded.append(path)
    return expanded


def extract_snippets_from_snippet_elements(xml_path: Path) -> Dict[str, Dict]:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        sys.exit(f"Unable to parse XML {xml_path}: {exc}")

    if root.tag.startswith("{"):
        uri = root.tag[1:root.tag.index("}")]
        text_tag = f"{{{uri}}}Text"
        startline_tag = f"{{{uri}}}StartLine"
    else:
        text_tag = "Text"
        startline_tag = "StartLine"

    snippets: Dict[str, Dict] = {}
    for elem in root.iter():
        if elem.tag.endswith("Snippet"):
            snippet_id = elem.attrib.get("id", f"_generated_{len(snippets)}")
            text_node = elem.find(text_tag)
            code = text_node.text.strip() if text_node is not None and text_node.text else ""

            start_line = None
            startline_node = elem.find(startline_tag)
            if startline_node is not None and startline_node.text:
                try:
                    start_line = int(startline_node.text.strip())
                except ValueError:
                    pass

            if code:
                snippet_hash = snippet_id.split("#")[0] if "#" in snippet_id else snippet_id
                snippets[snippet_hash] = {"code": code, "start_line": start_line, "full_id": snippet_id}
    return snippets


def refine_snippets_from_snippet_elements(xml_path: Path) -> Dict[str, Dict]:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        sys.exit(f"Not a parsable file: {xml_path}: {e}")
    except FileNotFoundError:
        sys.exit(f"File not found: {xml_path}")

    if root.tag.startswith("{"):
        uri = root.tag[1:root.tag.index("}")]
        snip_tag = f"{{{uri}}}Snippet"
        text_tag = f"{{{uri}}}Text"
        startline_tag = f"{{{uri}}}StartLine"
    else:
        snip_tag = "Snippet"
        text_tag = "Text"
        startline_tag = "StartLine"

    snippets: Dict[str, Dict] = {}

    for snippet_elem in root.iter(snip_tag):
        snip_id = snippet_elem.get("id") or f"{len(snippets)}"

        text_node = snippet_elem.find(text_tag)
        raw_code = text_node.text.strip() if text_node is not None else ""

        start_line = None
        for child in snippet_elem:
            tag_name = child.tag.split("}")[-1]
            if tag_name == "StartLine" and child.text:
                try:
                    start_line = int(child.text.strip())
                except ValueError:
                    start_line = None
                break

        snippet_hash = snip_id.split("#")[0] if "#" in snip_id else snip_id
        snippets[snippet_hash] = {"code": raw_code, "start_line": start_line, "full_id": snip_id}

    print(f" Extracted {len(snippets)} snippets (with start lines) from {xml_path.name}")
    return snippets


def _detect_format(root: ET.Element) -> str:
    for elem in root.iter():
        tag = elem.tag
        if tag.endswith("Snippet"):
            return "snippet"
        if tag.endswith("Vulnerability"):
            return "fvdl"
    return "fvdl"


def load_snippets(path: Path) -> Dict[str, Dict]:
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError) as e:
        sys.exit(f"Failed to parse or open {path}: {e}")

    fmt = _detect_format(root)
    print(f"Detected XML format for {path.name}: {fmt.upper()}")

    if fmt == "snippet":
        return refine_snippets_from_snippet_elements(path)
    else:
        return extract_snippets_from_snippet_elements(path)
 

def iter_vulnerabilities_by_instance(
    fvdl_path: Path,
) -> Iterable[Dict[str, str]]:
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
        info: Dict[str, str] = {
            "iid": instance_id,
            "RuleID": rule_id,
            "Kingdom": (vuln.findtext(q("Kingdom"), namespaces=ns if use_ns else None) or "").strip(),
            "Type": (vuln.findtext(q("Type"), namespaces=ns if use_ns else None) or "").strip(),
            "Category": (vuln.findtext(q("Category"), namespaces=ns if use_ns else None) or "").strip(),
            "Severity": (vuln.findtext(q("InstanceSeverity"), namespaces=ns if use_ns else None) or "").strip(),
            "FileName": "",
            "FilePath": "",
            "LineStart": "",
        }

        snippet_id = ""
        src_with_snippet = vuln.findall(
            ".//ns:SourceLocation[@snippet]" if use_ns else ".//SourceLocation[@snippet]",
            namespaces=ns if use_ns else None,
        )
        if src_with_snippet:
            snippet_attr = (src_with_snippet[0].attrib.get("snippet") or "").strip()
            if snippet_attr:
                snippet_id = snippet_attr.split("#", 1)[0]
            src = src_with_snippet[0]
        else:
            src = vuln.find(
                ".//ns:SourceLocation" if use_ns else ".//SourceLocation",
                namespaces=ns if use_ns else None,
            )
        if src is not None:
            path = (src.attrib.get("path") or "").strip()
            line = (src.attrib.get("line") or "").strip()
            info["FilePath"] = path
            info["LineStart"] = line
            if path:
                info["FileName"] = path.split("/")[-1]

        yield {
            "snippet_id": snippet_id,
            "vuln": info,
        }


def iter_new_findings(
    fvdl_paths: Iterable[Path], legacy_ids: Set[str]
) -> Iterable[Dict]:
    for fvdl_path in fvdl_paths:
        rule_meta = parse_rule_meta(fvdl_path)
        confidence_map = parse_instance_confidence(fvdl_path)
        probability_overrides = parse_instance_probability_override(fvdl_path)
        for item in iter_vulnerabilities_by_instance(fvdl_path):
            snippet_id = item["snippet_id"]
            vuln = item["vuln"]
            iid = (vuln.get("iid") or "").strip()
            if iid and iid not in legacy_ids:
                rule_id = vuln.get("RuleID", "")
                meta = rule_meta.get(rule_id, {})
                impact = meta.get("Impact", "")
                probability = meta.get("Probability", "")
                override_probability = probability_overrides.get(iid, "")
                if override_probability:
                    probability = override_probability
                accuracy = meta.get("Accuracy", "")
                confidence = confidence_map.get(iid, "")
                likelihood = compute_likelihood(accuracy, confidence, probability)
                vuln["Impact"] = impact
                vuln["Probability"] = probability
                vuln["Accuracy"] = accuracy
                vuln["Confidence"] = confidence
                vuln["Likelihood"] = likelihood
                vuln["Severity"] = classify_risk(impact, likelihood)
                yield {
                    "snippet_id": snippet_id,
                    "vuln": vuln,
                    "source_file": fvdl_path.name,
                }


#from fortidiff 
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>FortiDiff New Findings Report</title>
<style>
body{{font-family:Arial,sans-serif;margin:1em;background:#f5f5f5;}}
h1{{color:#333;}}
.summary{{background:white;padding:1em;margin-bottom:1em;border-radius:4px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}}
table{{border-collapse:collapse;width:100%;font-size:0.9em;background:white;box-shadow:0 2px 4px rgba(0,0,0,0.1);}}
th,td{{border:1px solid #ddd;padding:0.6em;vertical-align:top;}}
th{{background:#2c3e50;color:white;font-weight:bold;position:sticky;top:0;}}
tr.summary-row{{cursor:pointer;transition:background 0.2s;}}
tr.summary-row:hover{{background:#f0f0f0;}}
tr.detail-row{{display:none;background:#fafafa;}}
tr.detail-row.visible{{display:table-row;}}
.expand-icon{{display:inline-block;width:20px;text-align:center;font-weight:bold;color:#666;}}
.detail-content{{padding:1em;}}
.detail-section{{margin-bottom:1.5em;}}
.detail-section h4{{margin:0 0 0.5em 0;color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:0.3em;}}
.data-block{{padding:0.8em;border-radius:4px;background:#e3f2fd;border-left:4px solid #2196f3;}}
.data-label{{font-weight:bold;color:#555;font-size:0.85em;text-transform:uppercase;margin-bottom:0.5em;}}
.field-row{{margin:0.4em 0;font-size:0.9em;}}
.field-label{{display:inline-block;width:140px;font-weight:600;color:#666;}}
.field-value{{color:#333;}}
pre{{margin:0.5em 0 0 0;white-space:pre-wrap;font-size:0.85em;background:#f8f8f8;padding:0.8em;border-radius:4px;border:1px solid #ddd;max-height:400px;overflow:auto;}}
.status-badge{{display:inline-block;padding:0.2em 0.6em;border-radius:3px;font-weight:bold;font-size:0.85em;background:#4caf50;color:white;}}
.notes-cell{{min-width:220px;}}
.notes-input{{width:100%;min-height:1.6em;outline:none;background:#fff;}}
</style>
<script>
function toggleDetails(rowId) {{
    const detailRow = document.getElementById('detail-' + rowId);
    const icon = document.getElementById('icon-' + rowId);
    if (detailRow.classList.contains('visible')) {{
        detailRow.classList.remove('visible');
        icon.textContent = '>';
    }} else {{
        detailRow.classList.add('visible');
        icon.textContent = 'v';
    }}
}}

function notesKey(el) {{
    return el.getAttribute('data-note-key') || '';
}}

function readEmbeddedNotes() {{
    const node = document.getElementById('notes-data');
    if (!node) return {{}};
    try {{
        return JSON.parse(node.textContent || "{{}}");
    }} catch (e) {{
        return {{}};
    }}
}}

function loadNotes() {{
    const notes = readEmbeddedNotes();
    const inputs = document.querySelectorAll('.notes-input');
    inputs.forEach(el => {{
        const key = notesKey(el);
        if (!key) return;
        if (key in notes) {{
            el.textContent = notes[key];
        }}
    }});
}}

function collectNotes() {{
    const notes = {{}};
    const inputs = document.querySelectorAll('.notes-input');
    inputs.forEach(el => {{
        const key = notesKey(el);
        if (!key) return;
        const val = (el.textContent || "").trim();
        if (val) {{
            notes[key] = val;
        }}
    }});
    return notes;
}}

function saveReport() {{
    const notes = collectNotes();
    const serializer = new XMLSerializer();
    const docClone = document.documentElement.cloneNode(true);
    const notesNode = docClone.querySelector('#notes-data');
    if (notesNode) {{
        notesNode.textContent = JSON.stringify(notes);
    }}
    const html = '<!DOCTYPE html>\\n' + serializer.serializeToString(docClone);
    const blob = new Blob([html], {{ type: 'text/html;charset=utf-8' }});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'new_findings_with_notes.html';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}}

function applySeverityFilter() {{
    const allowed = new Set();
    document.querySelectorAll('.sev-filter').forEach(b => {{
        if (b.checked) allowed.add(b.value);
    }});

    const rows = document.querySelectorAll('tr.summary-row');
    rows.forEach(row => {{
        const sev = row.getAttribute('data-severity') || '';
        const show = allowed.has(sev);
        row.style.display = show ? '' : 'none';
        const detailId = row.getAttribute('data-detail-id');
        if (detailId) {{
            const detailRow = document.getElementById(detailId);
            if (detailRow) {{
                if (!show) {{
                    detailRow.classList.remove('visible');
                    detailRow.style.display = 'none';
                }} else {{
                    detailRow.style.display = '';
                }}
            }}
        }}
    }});
}}

document.addEventListener('DOMContentLoaded', () => {{
    loadNotes();
    const boxes = document.querySelectorAll('.sev-filter');
    boxes.forEach(b => b.addEventListener('change', applySeverityFilter));
    applySeverityFilter();
}});
</script>
</head><body>
<h1>FortiDiff New Findings</h1>

<div class="summary">
    <p><strong>Total new findings:</strong> {total}</p>
    <p>Critical findings: {critical_count}</p> 
    <p>High findings: {high_count}</p> 
    <p>Medium findings: {medium_count}</p> 
    <p>Low findings: {low_count}</p>
    <p><em>Click any row to expand and view vulnerability metadata and code</em></p>
</div>
<div>
    <strong>Filter by severity:</strong>
    <label><input type="checkbox" class="sev-filter" value="Critical" checked> Critical</label>
    <label><input type="checkbox" class="sev-filter" value="High" checked> High</label>
    <label><input type="checkbox" class="sev-filter" value="Medium" checked> Medium</label>
    <label><input type="checkbox" class="sev-filter" value="Low" checked> Low</label>
</div>
<button onclick="saveReport()">Save report with notes</button>

<table>
<tr>
    <th style="width:30px;"></th>
    <th>Status</th>
    <th>Instance ID</th>
    <th>RuleID</th>
    <th>Kingdom</th>
    <th>Severity</th>
    <th>Confidence</th>
    <th>Accuracy</th> 
    <th>Probability</th>
    <th>Impact</th>
    <th>Likelihood</th>
    <th>File</th>
    <th>Type</th>
    <th>SnippetID</th>
    <th>Post File</th>
    <th>Notes</th>
</tr>
<!-- ROWS_START -->
{rows}
<!-- ROWS_END -->
</table>
<script id="notes-data" type="application/json">{notes_json}</script>
</body></html>"""

#from fortidiff 
def build_html_report(
    findings: List[Dict],
    snippets: Dict[str, Dict],
    existing_rows: str,
    existing_notes: Dict[str, str],
    start_index: int,
    

    
) -> str:
    rows: List[str] = []

    for idx, item in enumerate(findings):
        row_index = start_index + idx
        snippet_id = item["snippet_id"]
        source_file = item.get("source_file", "")
        vuln = item["vuln"]

        note_key = f"note::{vuln.get('iid','')}::{snippet_id}"

        summary_row = (
            f'<tr class="summary-row" onclick="toggleDetails({row_index})" '
            f'data-severity="{vuln.get("Severity", "")}" '
            f'data-detail-id="detail-{row_index}">'
            f'<td><span class="expand-icon" id="icon-{row_index}">></span></td>'
            f'<td><span class="status-badge">New</span></td>'
            f'<td>{vuln.get("iid","")}</td>'
            f'<td>{vuln.get("RuleID", "")}</td>'
            f'<td>{vuln.get("Kingdom", "")}</td>'
            f'<td>{vuln.get("Severity", "")}</td>'
            f'<td>{vuln.get("Confidence", "")}</td>'            
            f'<td>{vuln.get("Accuracy","")}</td>'
            f'<td>{vuln.get("Probability", "")}</td>'
            f'<td>{vuln.get("Impact", "")}</td>'
            f'<td>{vuln.get("Likelihood", "")}</td>'
            f'<td>{vuln.get("FileName", "")}</td>'
            f'<td style="max-width:300px;">{str(vuln.get("Type", ""))[:100]}</td>'
            f'<td>{snippet_id or ""}</td>'
            f'<td>{source_file}</td>'
            f'<td class="notes-cell"><div class="notes-input" contenteditable="true" '
            f'data-note-key="{note_key}"></div></td>'
            '</tr>'
        )

        code = snippets.get(snippet_id, {}).get("code", " No code found ")
        safe_code = html.escape(code)
        start_line = snippets.get(snippet_id, {}).get("start_line", "")

        detail_row = f'<tr class="detail-row" id="detail-{row_index}"><td colspan="10"><div class="detail-content">'
        detail_row += '<div class="detail-section"><h4>Vulnerability Metadata</h4>'
        detail_row += '<div class="data-block">'
        detail_row += '<div class="data-label">POST Audit Scan</div>'
        detail_row += f'<div class="field-row"><span class="field-label">Severity:</span> <span class="field-value">{vuln.get("Severity", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Impact:</span> <span class="field-value">{vuln.get("Impact", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Probability:</span> <span class="field-value">{vuln.get("Probability", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Accuracy:</span> <span class="field-value">{vuln.get("Accuracy", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Confidence:</span> <span class="field-value">{vuln.get("Confidence", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Likelihood:</span> <span class="field-value">{vuln.get("Likelihood", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Instance ID:</span> <span class="field-value">{vuln.get("iid", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Rule ID:</span> <span class="field-value">{vuln.get("RuleID", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Kingdom:</span> <span class="field-value">{vuln.get("Kingdom", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">File Name:</span> <span class="field-value">{vuln.get("FileName", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">File Path:</span> <span class="field-value">{vuln.get("FilePath", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Line Start:</span> <span class="field-value">{vuln.get("LineStart", "")}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Snippet ID:</span> <span class="field-value">{snippet_id or ""}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Start Line:</span> <span class="field-value">{start_line}</span></div>'
        detail_row += '</div></div>'

        detail_row += '<div class="detail-section"><h4>Type</h4>'
        detail_row += f'<div class="data-block"><p>{vuln.get("Type", "")}</p></div>'
        detail_row += '</div>'

        detail_row += '<div class="detail-section"><h4>Code</h4>'
        detail_row += f'<div class="data-block"><pre>{safe_code}</pre></div>'
        detail_row += '</div>'

        detail_row += '</div></td></tr>'

        rows.append(summary_row + detail_row)

    new_rows = "\n".join(rows)
    combined_rows = "\n".join(
        r for r in [existing_rows.strip(), new_rows.strip()] if r
    )
    total_rows = combined_rows.count('class="summary-row"')
    severity_values = re.findall(r'data-severity="([^"]*)"', combined_rows)
    severity_counts = {
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "Critical": 0,
    }
    for sev in severity_values:
        sev = sev.strip()
        if sev in severity_counts:
            severity_counts[sev] += 1

    return HTML_TEMPLATE.format(
        total=total_rows,
        rows=combined_rows,
        notes_json=json.dumps(existing_notes), 
        critical_count=severity_counts["Critical"],
        high_count=severity_counts["High"],
        medium_count=severity_counts["Medium"],
        low_count=severity_counts["Low"],
        
    )


def load_existing_report(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {"rows": "", "notes": {}, "next_index": 0}

    content = path.read_text(encoding="utf-8", errors="ignore")
    rows_match = re.search(
        r"<!-- ROWS_START -->(.*?)<!-- ROWS_END -->",
        content,
        re.DOTALL,
    )
    rows = rows_match.group(1).strip() if rows_match else ""

    notes_match = re.search(
        r'<script id="notes-data" type="application/json">(.*?)</script>',
        content,
        re.DOTALL,
    )
    notes_raw = notes_match.group(1).strip() if notes_match else "{}"
    try:
        notes = json.loads(notes_raw) if notes_raw else {}
    except json.JSONDecodeError:
        notes = {}

    existing_indices = re.findall(r'id="detail-(\d+)"', rows)
    next_index = 0
    if existing_indices:
        try:
            next_index = max(int(x) for x in existing_indices) + 1
        except ValueError:
            next_index = 0

    return {"rows": rows, "notes": notes, "next_index": next_index}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate HTML report of new findings vs legacy InstanceID CSV."
    )
    parser.add_argument('-c','--legacy-csv', required=True, type=Path)
    parser.add_argument('-p',
        "--post-fvdl",
        required=True,
        type=Path,
        nargs="+",
        help="One or more .fvdl files or directories containing .fvdl files.",
    )
    parser.add_argument("-o", "--out", required=True, type=Path)
    args = parser.parse_args()

    legacy_ids = load_legacy_instance_ids(args.legacy_csv)
    fvdl_files = expand_inputs(args.post_fvdl)
    if not fvdl_files:
        raise SystemExit("No FVDL files found.")

    findings = list(iter_new_findings(fvdl_files, legacy_ids))

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for item in findings:
        sev = (item.get("vuln") or {}).get("Severity", "")
        if sev in severity_counts:
            severity_counts[sev] += 1

    snippets: Dict[str, Dict] = {}
    for fvdl in fvdl_files:
        snippets.update(load_snippets(fvdl))

    existing = load_existing_report(args.out)
    html_report = build_html_report(
        findings,
        snippets,
        existing_rows=existing["rows"],
        existing_notes=existing["notes"],
        start_index=existing["next_index"],
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(html_report, encoding="utf-8")

    print(f"HTML report saved to: {args.out}")
    print(
        "Severity counts - "
        f"Critical: {severity_counts['Critical']}, "
        f"High: {severity_counts['High']}, "
        f"Medium: {severity_counts['Medium']}, "
        f"Low: {severity_counts['Low']}"
    )


if __name__ == "__main__":
    main()
