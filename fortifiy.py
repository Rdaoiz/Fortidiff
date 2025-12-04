#fortidiff development file. 
# Compare two Fortify FVDL/XML files (extracted from .fpr archives) and decide
# whether a code snippet has already been reviewed.
import argparse
import html
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Tuple, Set
from difflib import SequenceMatcher
from collections import Counter



# Vuln extraction  

def extract_vulnerability_info(vuln, ns, use_ns):
    # Extract all key details from a single <Vulnerability> element.
    def q(tag: str) -> str:
        return f".//ns:{tag}" if use_ns else f".//{tag}"

    def get_text(tag: str) -> str:
        return (vuln.findtext(q(tag), namespaces=ns if use_ns else None) or "").strip()

    info = {
        "Count": get_text("Count"),
        "groupTitle": get_text(""),
        "iid": get_text("InstanceID"),
        "RuleID": get_text("ClassID"),
        "Category": get_text("Category"),
        "Folder": "", 
        "Kingdom": get_text("Kingdom"),
        "Abstract": get_text("Abstract"),
        "Friority": get_text("Friority"), 
        "FileName": "", 
        "FilePath": "",
        "LineStart": "",
        "Snippet": "", 
        "TargetFunction": "",        
        "FileName6": "", 
        "FilePath7": "",
        "LineStart8": "",
        "Snippet9": "",
        "TargetFunction10": "", 
    }

    # Snippet hash + file + line extraction
    src = vuln.find(".//ns:SourceLocation[@snippet]" if use_ns else ".//SourceLocation[@snippet]",
                    namespaces=ns if use_ns else None)
    if src is not None and "snippet" in src.attrib:
        snippet = src.attrib["snippet"]
        if "#" in snippet:
            snippet_hash, loc = snippet.split("#", 1)
            parts = loc.split(":")
            info["Snippet"] = snippet_hash
            info["Snippet9"] = snippet_hash
            if len(parts) >= 2:
                info["FilePath"], info["LineStart"] = parts[0], parts[1]
                info["FilePath7"], info["LineStart8"] = parts[0], parts[1]
                filename = parts[0].split("/")[-1]
                info["FileName"] = filename
                info["FileName6"] = filename

    return info


def parse_all_vulnerabilities(fvdl_path: Path):
# Parse all vulnerabilities in the provided FVDL file.
    try:
        tree = ET.parse(fvdl_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        sys.exit(f"Unable to parse XML {fvdl_path}: {exc}")

    # Detect namespace
    if root.tag.startswith("{"):
        uri = root.tag[1:root.tag.index("}")]
        ns = {"ns": uri}
        use_ns = True
    else:
        ns = {}
        use_ns = False

    def q(tag: str) -> str:
        return f".//ns:{tag}" if use_ns else f".//{tag}"

    vulnerabilities = root.findall(q("Vulnerability"), namespaces=ns if use_ns else None)
    
    # Create a mapping: snippet_hash -> vulnerability_info
    snippet_to_vuln = {}
    
    for v in vulnerabilities:
        instance_id = v.findtext(q("InstanceID"), namespaces=ns if use_ns else None)
        if instance_id:
            info = extract_vulnerability_info(v, ns, use_ns)
            snippet_hash = info.get("Snippet")
            if snippet_hash:
                # Map snippet hash to vulnerability info
                snippet_to_vuln[snippet_hash] = info

    print(f"Parsed {len(snippet_to_vuln)} vulnerabilities from {fvdl_path.name}")
    return snippet_to_vuln


# 
# Snippet extraction (original function)
# 

# Used to break down and detect the namespace being used in the fvdl file
# and then iterate through the elements within the script. 
def extract_snippets_from_snippet_elements(xml_path: Path) -> Dict[str, Dict]:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        sys.exit(f"Unable to parse XML {xml_path}: {exc}")

    ns = {}
    if root.tag.startswith("{"):
        uri = root.tag[1:root.tag.index("}")]
        ns = {"ns": uri}
        snippet_tag = f"{{{uri}}}Snippet"
        text_tag = f"{{{uri}}}Text"
        startline_tag = f"{{{uri}}}StartLine"
    else:
        snippet_tag = "Snippet"
        text_tag = "Text"
        startline_tag = "StartLine"

    snippets: Dict[str, Dict] = {}
    for elem in root.iter():
        if elem.tag.endswith("Snippet"):
            snippet_id = elem.attrib.get("id", f"_generated_{len(snippets)}")
            text_node = elem.find(text_tag)
            code = text_node.text.strip() if text_node is not None and text_node.text else ""
            
            # Extract start line
            start_line = None
            startline_node = elem.find(startline_tag)
            if startline_node is not None and startline_node.text:
                try:
                    start_line = int(startline_node.text.strip())
                except ValueError:
                    pass
            
            if code:
                # Extract just the hash part (before #) for easier lookup
                snippet_hash = snippet_id.split("#")[0] if "#" in snippet_id else snippet_id
                snippets[snippet_hash] = {"code": code, "start_line": start_line, "full_id": snippet_id}

    print(f" Extracted {len(snippets)} snippets from {xml_path.name}")
    return snippets

# narrow down the snippet extraction by providing more focus on the structure. Built off of previous function
# and targets the iteration and stores the empty snippets ( for code that was either deleted or added.)
def refine_snippets_from_snippet_elements(xml_path: Path) -> Dict[str, str]:
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

    #adding start line extraction 10/22 
    snippets: Dict[str, str] = {}
    
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

        # Extract just the hash part (before #) for easier lookup
        snippet_hash = snip_id.split("#")[0] if "#" in snip_id else snip_id
        snippets[snippet_hash] = {"code": raw_code, "start_line": start_line, "full_id": snip_id}

    
    print(f" Extracted {len(snippets)} snippets (with start lines) from {xml_path.name}")
    return snippets

#determines fvdl or xml formatting based on the tags, there may be differing format based 
#on how it is extracted.
def _detect_format(root: ET.Element) -> str:
    for elem in root.iter():
        tag = elem.tag
        if tag.endswith("Snippet"):
            return "snippet"
        if tag.endswith("Vulnerability"):
            return "fvdl"
    return "fvdl"

# Load snippets from a given XML or FVDL file
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

COMMENT_PATTERNS = {
    r"//.*?$": re.MULTILINE,
    r"/\*.*?\*/": re.DOTALL,
    r"#.*?$": re.MULTILINE,
    r"<!--.*?-->": re.DOTALL,  
}

#Normalize code by removing comments (patterns above), extra whitespace, normalizing
#strings and numbers to generic tokens.
def normalize_code(code: str) -> str:
    for pat, flags in COMMENT_PATTERNS.items():
        code = re.sub(pat, "", code, flags=flags)

    lines = [ln.strip() for ln in code.splitlines() if ln.strip()]
    code = " ".join(lines)
    code = re.sub(r"\s+", " ", code)

    code = re.sub(r'"[^"]*"', '"__STR__"', code)
    code = re.sub(r"'[^']*'", "'__STR__'", code)
    code = re.sub(r"\b\d+(\.\d+)?\b", "__NUM__", code)
    return code

#assigns the code into a set of tokens to proceed with a jaccard similarity comparison/calculation 
#filters out empty strings, but keeps the ID
# Improved tokenization section that searches for smaller discrepancies and operators
def tokenize(code: str) -> List[str]:
    return [tok for tok in re.split(r"\W+", code) if tok]


# Compute Jaccard similarity between two sets of tokens

# Jaccard similarity is the size of the intersection divided by the size of the union

# New version
# Addresses duplicate occurrences 
# Addresses long recurring code blocks 
# More differences show up when tokens overlap. 

def jaccard(a: List[str], b: List[str]) -> float:
    ca, cb = Counter(a), Counter(b) 
    
    intersection = sum((ca & cb).values())
    union = sum (( ca | cb ).values())
    return intersection / union if union !=0 else 1.0
#tokens in this case above are the individual words, symbols, and numbers extracted from the code snippets
#fancy string comparison 
#gg discrete math you finally were useful 

# Tokenizes and combines sequence matching and token-based Jaccard similarity for a similarity score
# Considers vocabulary overlap and key words being used 
def similarity_score(old: str, new: str) -> float:
    old_tokens = tokenize(old) 
    new_tokens = tokenize(new) 
    
    raw_ratio = SequenceMatcher(None, old, new).ratio()
    token_sim = jaccard(tokenize(old), tokenize(new)) 
    # wj = weighted_jaccard(old_tokens, new_tokens)
    
    # length_similarity = min(len(old), len(new)) / max(len(old), len(new))

    combined = 0.6*raw_ratio + 0.4* token_sim

    
    return combined * 100.0

# takes the dictionary of old and new snippets and compares them using a pairwise comparison
# It DOES take into consideration of identifying matches, addition, and deletion, of code.
def compare_sets(
    old_snips: Dict[str, str],
    new_snips: Dict[str, str],
    threshold: int = 85,
) -> List[Tuple[str, str, int, bool, str]]:
    
    # Compare two sets of Fortify snippets and compute similarity.
    # Returns tuples of (old_id, new_id, score, already_reviewed, status)
    

    results = []
    norm_old = {k: normalize_code(v["code"]) for k, v in old_snips.items()}
    norm_new = {k: normalize_code(v["code"]) for k, v in new_snips.items()}

    matched_old_ids = set()

    for new_id, new_code in norm_new.items():
        best_score = -1
        best_old_id = None

        for old_id, old_code in norm_old.items():
            score = int(round(similarity_score(old_code, new_code)))
            if score > best_score:
                best_score = score
                best_old_id = old_id

        already_rev = best_score >= threshold
        status = "Reviewed" if already_rev else "Needs Review"

        if best_old_id:
            matched_old_ids.add(best_old_id)

        results.append((best_old_id, new_id, best_score, already_rev, status))

    for old_id in norm_old:
        if old_id not in matched_old_ids:
            results.append((old_id, None, 0, False, "Not found"))

    return results


# 
# HTML REPORT WITH METADATA

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>Fortidiff Code Diff Report with Metadata</title>
<style>
body{{font-family:Arial,sans-serif;margin:1em;background:#f5f5f5;}}
h1{{color:#333;}}
.summary{{background:white;padding:1em;margin-bottom:1em;border-radius:4px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}}
table{{border-collapse:collapse;width:100%;font-size:0.9em;background:white;box-shadow:0 2px 4px rgba(0,0,0,0.1);}}
th,td{{border:1px solid #ddd;padding:0.6em;vertical-align:top;}}
th{{background:#2c3e50;color:white;font-weight:bold;position:sticky;top:0;}}
tr.summary-row{{cursor:pointer;transition:background 0.2s;}}
tr.summary-row:hover{{background:#f0f0f0;}}
tr.summary-row.same{{background:#e8f5e9;}}
tr.summary-row.diff{{background:#ffebee;}}
tr.summary-row.same:hover{{background:#c8e6c9;}}
tr.summary-row.diff:hover{{background:#ffcdd2;}}
tr.detail-row{{display:none;background:#fafafa;}}
tr.detail-row.visible{{display:table-row;}}
.expand-icon{{display:inline-block;width:20px;text-align:center;font-weight:bold;color:#666;}}
.detail-content{{padding:1em;}}
.detail-section{{margin-bottom:1.5em;}}
.detail-section h4{{margin:0 0 0.5em 0;color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:0.3em;}}
.comparison-grid{{display:grid;grid-template-columns:1fr 1fr;gap:1em;}}
.old-data,.new-data{{padding:0.8em;border-radius:4px;}}
.old-data{{background:#fff3e0;border-left:4px solid #ff9800;}}
.new-data{{background:#e3f2fd;border-left:4px solid #2196f3;}}
.data-label{{font-weight:bold;color:#555;font-size:0.85em;text-transform:uppercase;margin-bottom:0.5em;}}
.field-row{{margin:0.4em 0;font-size:0.9em;}}
.field-label{{display:inline-block;width:140px;font-weight:600;color:#666;}}
.field-value{{color:#333;}}
pre{{margin:0.5em 0 0 0;white-space:pre-wrap;font-size:0.85em;background:#f8f8f8;padding:0.8em;border-radius:4px;border:1px solid #ddd;max-height:400px;overflow:auto;}}
.score-badge{{display:inline-block;padding:0.2em 0.6em;border-radius:12px;font-weight:bold;}}
.score-high{{background:#4caf50;color:white;}}
.score-medium{{background:#ff9800;color:white;}}
.score-low{{background:#f44336;color:white;}}
.status-badge{{display:inline-block;padding:0.2em 0.6em;border-radius:3px;font-weight:bold;font-size:0.85em;}}
.status-reviewed{{background:#4caf50;color:white;}}
.status-needs-review{{background:#ff9800;color:white;}}
.status-not-found{{background:#9e9e9e;color:white;}}
</style>
<script>
function toggleDetails(rowId) {{
    const detailRow = document.getElementById('detail-' + rowId);
    const icon = document.getElementById('icon-' + rowId);
    if (detailRow.classList.contains('visible')) {{
        detailRow.classList.remove('visible');
        icon.textContent = '▶';
    }} else {{
        detailRow.classList.add('visible');
        icon.textContent = '▼';
    }}
}}
</script>
</head><body>
<h1>🔍 Fortify Snippet Semantic Diff</h1>
<div class="summary">
    <p><strong>Similarity threshold:</strong> {threshold}%</p>
    <p><em>Click any row to expand and view detailed vulnerability metadata and code comparison</em></p>
</div>
<table>
<tr>
    <th style="width:30px;"></th>
    <th>Score</th>
    <th>Status</th>
    <th>RuleID</th>
    <th>Category</th>
    <th>Kingdom</th>
    <th>Friority</th>
    <th>File</th>
    <th>Abstract</th>
</tr>
{rows}
</table>
</body></html>"""


def build_html_report(old_raw, new_raw, old_vuln_map, new_vuln_map, compare_res, threshold):
    rows = []
    
    for idx, (old_id, new_id, score, same, status) in enumerate(compare_res):
        css = "same" if same else "diff"
        
        # Get vulnerability metadata for both old and new
        old_vuln = old_vuln_map.get(old_id, {})
        new_vuln = new_vuln_map.get(new_id, {})
        
        # Use new vuln for summary row, fallback to old
        vuln = new_vuln if new_vuln else old_vuln
        
        # Score badge styling
        if score >= 80:
            score_class = "score-high"
        elif score >= 50:
            score_class = "score-medium"
        else:
            score_class = "score-low"
        
        # Status badge styling
        if status == "Reviewed":
            status_class = "status-reviewed"
        elif status == "Needs Review":
            status_class = "status-needs-review"
        else:
            status_class = "status-not-found"
        
        # Summary row (clickable)
        summary_row = (
            f'<tr class="summary-row {css}" onclick="toggleDetails({idx})">'
            f'<td><span class="expand-icon" id="icon-{idx}">▶</span></td>'
            f'<td><span class="score-badge {score_class}">{score}%</span></td>'
            f'<td><span class="status-badge {status_class}">{status}</span></td>'
            f'<td>{html.escape(str(vuln.get("RuleID", "—")))}</td>'
            f'<td>{html.escape(str(vuln.get("Category", "—")))}</td>'
            f'<td>{html.escape(str(vuln.get("Kingdom", "—")))}</td>'
            f'<td>{html.escape(str(vuln.get("Friority", "—")))}</td>'
            f'<td>{html.escape(str(vuln.get("FileName", "—")))}</td>'
            f'<td style="max-width:300px;">{html.escape(str(vuln.get("Abstract", "—"))[:100])}</td>'
            '</tr>'
        )
        
        # Detail row (expandable)
        old_code = html.escape(old_raw.get(old_id, {}).get("code", "— No code found —"))
        new_code = html.escape(new_raw.get(new_id, {}).get("code", "— No code found —"))
        
        detail_row = f'<tr class="detail-row" id="detail-{idx}"><td colspan="9"><div class="detail-content">'
        
        # Metadata comparison section
        detail_row += '<div class="detail-section"><h4>Vulnerability Metadata Comparison</h4>'
        detail_row += '<div class="comparison-grid">'
        
        # OLD vulnerability data
        detail_row += '<div class="old-data">'
        detail_row += '<div class="data-label">OLD Audit Scan</div>'
        detail_row += f'<div class="field-row"><span class="field-label">Count:</span> <span class="field-value">{html.escape(str(old_vuln.get("Count", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Group Title:</span> <span class="field-value">{html.escape(str(old_vuln.get("groupTitle", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Instance ID:</span> <span class="field-value">{html.escape(str(old_vuln.get("iid", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Rule ID:</span> <span class="field-value">{html.escape(str(old_vuln.get("RuleID", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Category:</span> <span class="field-value">{html.escape(str(old_vuln.get("Category", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Folder:</span> <span class="field-value">{html.escape(str(old_vuln.get("Folder", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Kingdom:</span> <span class="field-value">{html.escape(str(old_vuln.get("Kingdom", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Friority:</span> <span class="field-value">{html.escape(str(old_vuln.get("Friority", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">File Name:</span> <span class="field-value">{html.escape(str(old_vuln.get("FileName", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">File Path:</span> <span class="field-value">{html.escape(str(old_vuln.get("FilePath", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Line Start:</span> <span class="field-value">{html.escape(str(old_vuln.get("LineStart", "—")))}</span></div>'
        # detail_row += f'<div class="field-row"><span class="field-label">Snippet Hash:</span> <span class="field-value">{html.escape(str(old_vuln.get("Snippet", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Target Function:</span> <span class="field-value">{html.escape(str(old_vuln.get("TargetFunction", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Snippet ID:</span> <span class="field-value">{html.escape(str(old_id or "—"))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Start Line:</span> <span class="field-value">{html.escape(str(old_raw.get(old_id, {}).get("start_line", "—")))}</span></div>'
        detail_row += '</div>'
        
        # NEW vulnerability data
        detail_row += '<div class="new-data">'
        detail_row += '<div class="data-label">NEW Audit Scan</div>'
        detail_row += f'<div class="field-row"><span class="field-label">Count:</span> <span class="field-value">{html.escape(str(new_vuln.get("Count", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Group Title:</span> <span class="field-value">{html.escape(str(new_vuln.get("groupTitle", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Instance ID:</span> <span class="field-value">{html.escape(str(new_vuln.get("iid", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Rule ID:</span> <span class="field-value">{html.escape(str(new_vuln.get("RuleID", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Category:</span> <span class="field-value">{html.escape(str(new_vuln.get("Category", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Folder:</span> <span class="field-value">{html.escape(str(new_vuln.get("Folder", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Kingdom:</span> <span class="field-value">{html.escape(str(new_vuln.get("Kingdom", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Friority:</span> <span class="field-value">{html.escape(str(new_vuln.get("Friority", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">File Name:</span> <span class="field-value">{html.escape(str(new_vuln.get("FileName", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">File Path:</span> <span class="field-value">{html.escape(str(new_vuln.get("FilePath", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Line Start:</span> <span class="field-value">{html.escape(str(new_vuln.get("LineStart", "—")))}</span></div>'
        # detail_row += f'<div class="field-row"><span class="field-label">Snippet Hash:</span> <span class="field-value">{html.escape(str(new_vuln.get("Snippet", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Target Function:</span> <span class="field-value">{html.escape(str(new_vuln.get("TargetFunction", "—")))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Snippet ID:</span> <span class="field-value">{html.escape(str(new_id or "—"))}</span></div>'
        detail_row += f'<div class="field-row"><span class="field-label">Start Line:</span> <span class="field-value">{html.escape(str(new_raw.get(new_id, {}).get("start_line", "—")))}</span></div>'
        detail_row += '</div>'
        
        detail_row += '</div></div>'  # Close comparison grid and metadata section
        
        # Abstract section (full text)
        detail_row += '<div class="detail-section"><h4>Abstract / Description</h4>'
        detail_row += '<div class="comparison-grid">'
        detail_row += f'<div class="old-data"><div class="data-label">OLD</div><p>{html.escape(str(old_vuln.get("Abstract", "—")))}</p></div>'
        detail_row += f'<div class="new-data"><div class="data-label">NEW</div><p>{html.escape(str(new_vuln.get("Abstract", "—")))}</p></div>'
        detail_row += '</div></div>'
        
        # Code comparison section
        detail_row += '<div class="detail-section"><h4>Code Comparison</h4>'
        detail_row += '<div class="comparison-grid">'
        detail_row += f'<div class="old-data"><div class="data-label">OLD CODE</div><pre>{old_code}</pre></div>'
        detail_row += f'<div class="new-data"><div class="data-label">NEW CODE</div><pre>{new_code}</pre></div>'
        detail_row += '</div></div>'
        
        detail_row += '</div></td></tr>'  # Close detail content
        
        rows.append(summary_row + detail_row)
    
    return HTML_TEMPLATE.format(threshold=threshold, rows="\n".join(rows))



# MAIN FUNCTION (Modified to include metadata extraction)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Semantic diff two Fortify XML/FVDL files with vulnerability metadata."
    )
    parser.add_argument("old_fvdl", type=Path, help="Path to the older FVDL export.")
    parser.add_argument("new_fvdl", type=Path, help="Path to the newer FVDL export.")
    parser.add_argument(
        "--threshold",
        type=int,
        default=80,
        help="Similarity percentage threshold (default: 50).",
    )
    parser.add_argument(
        "--out",
        default=".\\diff_code\\snippet-diff.html",
        help="Filename for HTML report (default: snippet-diff.html).",
    )
    args = parser.parse_args()

    print("\n" + "="*80)
    print("FORTIDIFF WITH VULNERABILITY METADATA")
    print("="*80 + "\n")

    # Extract vulnerability metadata
    print("Extracting vulnerability metadata...")
    old_vuln_map = parse_all_vulnerabilities(args.old_fvdl)
    new_vuln_map = parse_all_vulnerabilities(args.new_fvdl)

    # Extract snippets
    print("\nExtracting code snippets...")
    old_snips = load_snippets(args.old_fvdl)
    new_snips = load_snippets(args.new_fvdl)

    print(f"\n[DEBUG] old_snips: {len(old_snips)} | new_snips: {len(new_snips)}")
    print(f"[DEBUG] old_vulns: {len(old_vuln_map)} | new_vulns: {len(new_vuln_map)}")

    if not old_snips:
        sys.exit("No results in OLD file.")
    if not new_snips:
        sys.exit("No results in NEW file.")

    # Compare snippets
    print(f"\nComparing snippets (threshold: {args.threshold}%)")
    compare_res = compare_sets(old_snips, new_snips, threshold=args.threshold)
    compare_res.sort(key=lambda x: x[2])

    # Generate HTML report with metadata
    print("\nGenerating HTML report with vulnerability metadata")
    html_report = build_html_report(old_snips, new_snips, old_vuln_map, new_vuln_map, compare_res, args.threshold)
    
    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_report, encoding="utf-8")
    print(f"HTML report saved to: {args.out}")

    # Generate JSON summary with metadata
    print("\nGenerating JSON summary with metadata...")
    summary = []
    for old_id, new_id, score, already, status in compare_res:
        old_vuln = old_vuln_map.get(old_id, {})
        new_vuln = new_vuln_map.get(new_id, {})
        
        # Use new vulnerability data, fallback to old
        vuln = new_vuln if new_vuln else old_vuln
        
        summary.append({
            "score": score,
            "status": status,
            "already_reviewed": already,
            "Count": vuln.get("Count"),
            "groupTitle": vuln.get("groupTitle"),
            "iid": vuln.get("iid"),
            "RuleID": vuln.get("RuleID"),
            "Category": vuln.get("Category"),
            "Folder": vuln.get("Folder"),
            "Kingdom": vuln.get("Kingdom"),
            "Abstract": vuln.get("Abstract"),
            "Friority": vuln.get("Friority"),
            "FileName": vuln.get("FileName"),
            "FilePath": vuln.get("FilePath"),
            "LineStart": vuln.get("LineStart"),
            "Snippet": vuln.get("Snippet"),
            "TargetFunction": vuln.get("TargetFunction"),
            "FileName6": vuln.get("FileName6"),
            "FilePath7": vuln.get("FilePath7"),
            "LineStart8": vuln.get("LineStart8"),
            "Snippet9": vuln.get("Snippet9"),
            "TargetFunction10": vuln.get("TargetFunction10"),
            "old_snippet_id": old_id,
            "new_snippet_id": new_id,
            "old_start_line": old_snips.get(old_id, {}).get("start_line"),
            "new_start_line": new_snips.get(new_id, {}).get("start_line"),
        })
    
    json_path = Path(args.out).with_suffix(".json")
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"JSON summary saved to: {json_path}")

    # Summary statistics
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    reviewed = sum(1 for _, _, _, already, _ in compare_res if already)
    needs_review = sum(1 for _, _, _, already, status in compare_res if not already and status != "Not found")
    not_found = sum(1 for _, _, _, _, status in compare_res if status == "Not found")
    
    print(f"Total comparisons: {len(compare_res)}")
    print(f"Already reviewed (≥{args.threshold}%): {reviewed}")
    print(f"Needs review (<{args.threshold}%): {needs_review}")
    print(f"Not found in new scan: {not_found}")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
