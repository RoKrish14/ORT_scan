#!/usr/bin/env python3
"""
Build a single-file HTML dashboard from ORT + SBOM results,
with a GUI folder chooser to select the output directory.
"""

import sys, os, json, datetime, html as html_mod, glob, subprocess, shutil
from collections import Counter

# --- Try to import tkinter for the GUI folder picker ---
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except Exception as e:
    tk = None
    filedialog = None

# --- Ensure PyYAML is available (auto-install if needed) ---
def ensure_pyyaml():
    try:
        import yaml  # noqa
        return True
    except Exception:
        try:
            # Try installing into the user site-packages
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "PyYAML"], stdout=subprocess.DEVNULL)
            import yaml  # noqa
            return True
        except Exception as err:
            print(f"[!] Could not import or install PyYAML automatically: {err}")
            return False

def load_yaml(path):
    if not path or not os.path.isfile(path):
        return None
    import yaml  # ensured by ensure_pyyaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_json(path):
    if not path or not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def newest(dir_path, pattern):
    if not os.path.isdir(dir_path):
        return None
    files = sorted(glob.glob(os.path.join(dir_path, pattern)))
    return files[-1] if files else None

def summarize_spdx(doc):
    comps = 0
    lic = Counter()
    if not doc:
        return {"components": 0, "top_licenses": []}
    pkgs = doc.get("packages") or []
    comps += len(pkgs)
    for p in pkgs:
        for key in ("licenseConcluded", "licenseDeclared"):
            val = p.get(key)
            if not val:
                continue
            if isinstance(val, str):
                lic[val] += 1
            elif isinstance(val, list):
                for x in val:
                    lic[str(x)] += 1
    return {"components": comps, "top_licenses": lic.most_common(10)}

def summarize_cyclonedx(doc):
    comps = 0
    lic = Counter()
    if not doc:
        return {"components": 0, "top_licenses": []}
    components = doc.get("components") or []
    comps += len(components)
    for c in components:
        for l in (c.get("licenses") or []):
            if isinstance(l, dict):
                if "license" in l and isinstance(l["license"], dict):
                    lid = l["license"].get("id") or l["license"].get("name")
                    if lid:
                        lic[str(lid)] += 1
                elif "expression" in l:
                    lic[str(l["expression"])] += 1
    return {"components": comps, "top_licenses": lic.most_common(10)}

def pill(label, value):
    return f'<div class="pill"><span>{html_mod.escape(label)}</span><strong>{html_mod.escape(str(value))}</strong></div>'

def kv_table(items):
    rows = "".join(f"<tr><td>{html_mod.escape(str(k))}</td><td>{html_mod.escape(str(v))}</td></tr>" for k, v in items)
    return f'<table class="kv"><tbody>{rows}</tbody></table>'

def card(title, body_html):
    return f"""
    <section class="card">
      <h2>{html_mod.escape(title)}</h2>
      {body_html}
    </section>
    """

def top_licenses_list(tups):
    if not tups:
        return "<p class='muted'>No license data found.</p>"
    lis = "".join(f"<li><code>{html_mod.escape(k)}</code> — {v}</li>" for k, v in tups)
    return f"<ol class='top-list'>{lis}</ol>"

def severity_bar(by_sev):
    # Expected keys like ERROR/WARNING/HINT/INFO/UNKNOWN
    order = ["ERROR", "WARNING", "HINT", "INFO", "UNKNOWN"]
    total = sum(by_sev.values()) or 1
    parts = []
    for sev in order:
        n = by_sev.get(sev, 0)
        pct = int((n / total) * 100)
        parts.append(f'<div class="bar {sev.lower()}" style="width:{pct}%;" title="{sev}: {n}"></div>')
    legend = "".join(f'<span class="lg {s.lower()}">{s}: {by_sev.get(s,0)}</span>' for s in order)
    return f'<div class="stackbar">{"".join(parts)}</div><div class="legend">{legend}</div>'

def build_html(data):
    kpi_html = "".join([
        pill("Projects", data["ort"]["analyzer"]["summary"].get("projects", "—")),
        pill("Packages", data["ort"]["analyzer"]["summary"].get("packages", "—")),
        pill("Scanner Issues", data["ort"]["scanner"]["summary"].get("issues", "—")),
        pill("License Findings", data["ort"]["scanner"]["summary"].get("license_findings", "—")),
        pill("Advisor Vulns", data["ort"]["advisor"]["summary"].get("vulnerabilities", "—")),
        pill("Policy Violations", data["ort"]["evaluator"]["summary"].get("violations", "—")),
        pill("Syft SPDX Components", data["sbom"]["syft_spdx"]["summary"].get("components", "—")),
        pill("Syft CDX Components", data["sbom"]["syft_cdx"]["summary"].get("components", "—")),
        pill("Trivy SPDX Components", (data["sbom"]["trivy_spdx"]["summary"] or {}).get("components", "—")),
        pill("Trivy CDX Components", (data["sbom"]["trivy_cdx"]["summary"] or {}).get("components", "—")),
    ])

    an_html = card("ORT Analyzer",
        kv_table([
            ("Result file", data["ort"]["analyzer"]["file"] or "—"),
            ("Projects", data["ort"]["analyzer"]["summary"].get("projects", "—")),
            ("Packages", data["ort"]["analyzer"]["summary"].get("packages", "—")),
        ]) + "<h3>Top Licenses</h3>" + top_licenses_list(data["ort"]["analyzer"]["summary"].get("top_licenses"))
    )

    sc_html = card("ORT Scanner",
        kv_table([
            ("Result file", data["ort"]["scanner"]["file"] or "—"),
            ("Scan results", data["ort"]["scanner"]["summary"].get("scan_results", "—")),
            ("Issues", data["ort"]["scanner"]["summary"].get("issues", "—")),
            ("License findings", data["ort"]["scanner"]["summary"].get("license_findings", "—")),
        ])
    )

    ad_html = card("ORT Advisor",
        kv_table([
            ("Result file", data["ort"]["advisor"]["file"] or "—"),
            ("Vulnerabilities", data["ort"]["advisor"]["summary"].get("vulnerabilities", "—")),
            ("Sources", ", ".join(data["ort"]["advisor"]["summary"].get("sources", [])) or "—"),
        ])
    )

    ev_bysev = data["ort"]["evaluator"]["summary"].get("by_severity", {})
    ev_html = card("ORT Evaluator (Policy)",
        kv_table([
            ("Result file", data["ort"]["evaluator"]["file"] or "—"),
            ("Violations", data["ort"]["evaluator"]["summary"].get("violations", "—")),
        ]) + (severity_bar(ev_bysev) if ev_bysev else "<p class='muted'>No severity breakdown found.</p>")
    )

    sb_html = card("SBOMs (Syft & Trivy)",
        "<div class='twocol'>" +
        card("Syft SPDX", kv_table([
            ("File", data["sbom"]["syft_spdx"]["file"] or "—"),
            ("Components", data["sbom"]["syft_spdx"]["summary"].get("components", "—")),
        ]) + "<h3>Top Licenses</h3>" + top_licenses_list(data["sbom"]["syft_spdx"]["summary"].get("top_licenses"))) +
        card("Syft CycloneDX", kv_table([
            ("File", data["sbom"]["syft_cdx"]["file"] or "—"),
            ("Components", data["sbom"]["syft_cdx"]["summary"].get("components", "—")),
        ]) + "<h3>Top Licenses</h3>" + top_licenses_list(data["sbom"]["syft_cdx"]["summary"].get("top_licenses"))) +
        card("Trivy SPDX", kv_table([
            ("File", data["sbom"]["trivy_spdx"]["file"] or "—"),
            ("Components", (data["sbom"]["trivy_spdx"]["summary"] or {}).get("components", "—")),
        ]) + "<h3>Top Licenses</h3>" + top_licenses_list((data["sbom"]["trivy_spdx"]["summary"] or {}).get("top_licenses"))) +
        card("Trivy CycloneDX", kv_table([
            ("File", data["sbom"]["trivy_cdx"]["file"] or "—"),
            ("Components", (data["sbom"]["trivy_cdx"]["summary"] or {}).get("components", "—")),
        ]) + "<h3>Top Licenses</h3>" + top_licenses_list((data["sbom"]["trivy_cdx"]["summary"] or {}).get("top_licenses"))) +
        "</div>"
    )

    html_page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Unified OSS Risk Dashboard</title>
<style>
  :root {{
    --bg:#0f172a; --panel:#111827; --muted:#9ca3af; --text:#f8fafc; --accent:#22d3ee;
    --ok:#10b981; --warn:#fbbf24; --err:#ef4444; --hint:#60a5fa;
  }}
  * {{ box-sizing:border-box }}
  body {{ margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:linear-gradient(120deg,#0b1220,#111827); color:var(--text); }}
  header.hero {{ padding:28px 24px 10px; border-bottom:1px solid #1f2937; }}
  header.hero h1 {{ margin:0; font-size:20px; font-weight:700; letter-spacing:.3px }}
  header.hero .meta {{ color:var(--muted); font-size:12px; margin-top:6px }}
  main {{ padding:18px; max-width:1200px; margin:0 auto }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-bottom:16px }}
  .pill {{ background:#0b1220; border:1px solid #1f2937; border-radius:14px; padding:10px 12px; display:flex; align-items:center; justify-content:space-between; box-shadow:0 0 0 1px rgba(255,255,255,0.02) inset; }}
  .pill span {{ color:var(--muted); font-size:12px }}
  .pill strong {{ font-size:18px }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:16px }}
  .twocol {{ display:grid; grid-template-columns:repeat(2,minmax(280px,1fr)); gap:12px }}
  @media (max-width:900px) {{ .twocol {{ grid-template-columns:1fr }} }}
  .card {{ background:rgba(255,255,255,0.02); border:1px solid #1f2937; border-radius:16px; padding:14px }}
  .card h2 {{ margin:4px 0 10px; font-size:16px }}
  .card h3 {{ margin:12px 0 6px; font-size:14px; color:var(--muted) }}
  .kv {{ width:100%; border-collapse:collapse; font-size:13px; margin-bottom:6px }}
  .kv td {{ padding:6px 8px; border-bottom:1px dashed #1f2937 }}
  .kv td:first-child {{ color:var(--muted) }}
  .top-list {{ margin:6px 0 0 16px; font-size:13px }}
  .muted {{ color:var(--muted) }}
  .stackbar {{ display:flex; height:10px; border-radius:6px; overflow:hidden; background:#0b1220; border:1px solid #1f2937; margin-top:6px }}
  .bar {{ height:100% }}
  .bar.error {{ background:var(--err) }}
  .bar.warning {{ background:var(--warn) }}
  .bar.hint {{ background:var(--hint) }}
  .bar.info {{ background:#14b8a6 }}
  .bar.unknown {{ background:#334155 }}
  .legend {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:6px; font-size:12px; color:var(--muted) }}
  .legend .lg::before {{ content:""; display:inline-block; width:10px; height:10px; margin-right:6px; vertical-align:-2px; border-radius:2px }}
  .legend .error::before {{ background:var(--err) }}
  .legend .warning::before {{ background:var(--warn) }}
  .legend .hint::before {{ background:var(--hint) }}
  .legend .info::before {{ background:#14b8a6 }}
  .legend .unknown::before {{ background:#334155 }}
  footer {{ text-align:center; color:var(--muted); font-size:12px; padding:18px 0 28px }}
</style>
</head>
<body>
  <header class="hero">
    <h1>Unified OSS Risk Dashboard</h1>
    <div class="meta">Generated: {html_mod.escape(data["meta"]["generated_at"])}</div>
  </header>
  <main>
    <div class="kpis">{kpi_html}</div>
    <div class="grid">
      {an_html}
      {sc_html}
      {ad_html}
      {ev_html}
      {sb_html}
    </div>
  </main>
  <footer>
    ORT • Syft • Trivy — single-file dashboard
  </footer>
</body>
</html>"""
    return html_page

def pick_dir_gui():
    # Use GUI folder chooser if possible; else fall back to CLI arg or CWD.
    if tk and filedialog:
        root = tk.Tk()
        root.withdraw()
        root.update_idletasks()
        title = "Select ORT output directory (contains analyzer-result, scanner-result, …)"
        chosen = filedialog.askdirectory(title=title, mustexist=True)
        root.destroy()
        return chosen or None
    return None

def main():
    # 1) Locate root folder (GUI pick, or CLI arg, or CWD)
    root_dir = None
    # CLI support: python build_unified_dashboard.py /path/to/OUTPUT_DIR
    if len(sys.argv) >= 2:
        root_dir = os.path.abspath(sys.argv[1])

    if not root_dir:
        root_dir = pick_dir_gui()

    if not root_dir:
        print("No folder selected. You can also run: python build_unified_dashboard.py /path/to/OUTPUT_DIR")
        sys.exit(1)

    if not os.path.isdir(root_dir):
        print(f"Not a directory: {root_dir}")
        sys.exit(1)

    # 2) Ensure PyYAML
    if not ensure_pyyaml():
        print("Please install PyYAML manually:  pip install PyYAML")
        sys.exit(2)

    # 3) Resolve expected subfolders
    paths = {
        "analyzer":     os.path.join(root_dir, "analyzer-result"),
        "scanner":      os.path.join(root_dir, "scanner-result"),
        "advisor":      os.path.join(root_dir, "advisor-result"),
        "evaluator":    os.path.join(root_dir, "evaluator-result"),
        "reports":      os.path.join(root_dir, "report-result"),
        "syft":         os.path.join(root_dir, "syft-result"),
        "trivy":        os.path.join(root_dir, "trivy-result"),
    }

    analyzer_file = newest(paths["analyzer"], "analyzer-result*.yml")
    scanner_file  = newest(paths["scanner"], "scan-result*.yml")
    advisor_file  = newest(paths["advisor"], "advisor-result*.yml")
    eval_file     = newest(paths["evaluator"], "evaluation-result*.yml")

    syft_spdx     = os.path.join(paths["syft"], "sbom-spdx.json")
    syft_cdx      = os.path.join(paths["syft"], "sbom-cdx.json")
    trivy_spdx    = os.path.join(paths["trivy"], "trivy-spdx.json")
    trivy_cdx     = os.path.join(paths["trivy"], "trivy-cdx.json")

    data = {
        "meta": {
            "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        },
        "ort": {
            "analyzer": {"file": analyzer_file, "summary": {}},
            "scanner":  {"file": scanner_file,  "summary": {}},
            "advisor":  {"file": advisor_file,  "summary": {}},
            "evaluator":{"file": eval_file,     "summary": {}},
        },
        "sbom": {
            "syft_spdx": {"file": syft_spdx, "summary": {}},
            "syft_cdx":  {"file": syft_cdx,  "summary": {}},
            "trivy_spdx":{"file": trivy_spdx,"summary": {}},
            "trivy_cdx": {"file": trivy_cdx, "summary": {}},
        }
    }

    # 4) Parse & summarize
    analyzer = load_yaml(analyzer_file) if analyzer_file else None
    if analyzer:
        res = analyzer.get("analyzer", {}).get("result", {})
        projects = res.get("projects", []) or []
        pkgs     = res.get("packages", []) or []
        license_counter = Counter()
        for p in pkgs:
            lic = (p.get("declared_license") or
                   p.get("declared_licenses") or
                   p.get("declared_licenses_processed"))
            if isinstance(lic, str):
                license_counter[lic] += 1
            elif isinstance(lic, list):
                for l in lic:
                    license_counter[str(l)] += 1
            elif isinstance(lic, dict):
                # best-effort extraction
                expr = lic.get("spdx_expression")
                if isinstance(expr, str):
                    license_counter[expr] += 1
                elif isinstance(expr, list):
                    for l in expr:
                        license_counter[str(l)] += 1
        data["ort"]["analyzer"]["summary"] = {
            "projects": len(projects),
            "packages": len(pkgs),
            "top_licenses": license_counter.most_common(10)
        }

    scanner = load_yaml(scanner_file) if scanner_file else None
    if scanner:
        scan = scanner.get("scanner", {}).get("results", {})
        sr = scan.get("scan_results", []) or []
        issues_total = 0
        license_findings = 0
        for r in sr:
            issues_total += len(r.get("issues", []) or [])
            results = r.get("results", {}) or {}
            license_findings += len(results.get("license_findings", []) or [])
        data["ort"]["scanner"]["summary"] = {
            "scan_results": len(sr),
            "issues": issues_total,
            "license_findings": license_findings,
        }

    advisor = load_yaml(advisor_file) if advisor_file else None
    if advisor:
        adv = advisor.get("advisor", {}) or {}
        results = adv.get("results") or {}
        vulns_count = 0
        def walk(node):
            nonlocal vulns_count
            if isinstance(node, dict):
                for k, v in node.items():
                    if k.lower() in ("vulnerabilities", "vulnerability") and isinstance(v, list):
                        vulns_count += len(v)
                    walk(v)
            elif isinstance(node, list):
                for it in node:
                    walk(it)
        walk(results)
        sources = list((adv.get("advice") or {}).keys())
        data["ort"]["advisor"]["summary"] = {
            "vulnerabilities": vulns_count,
            "sources": sources or ["OSV","OSSIndex"],
        }

    evaluation = load_yaml(eval_file) if eval_file else None
    if evaluation:
        ev = evaluation.get("evaluator", {}) or {}
        violations = ev.get("violations", []) or []
        by_severity = Counter(v.get("severity", "UNKNOWN") for v in violations)
        data["ort"]["evaluator"]["summary"] = {
            "violations": len(violations),
            "by_severity": dict(by_severity),
        }

    syft_spdx_doc  = load_json(syft_spdx)
    syft_cdx_doc   = load_json(syft_cdx)
    trivy_spdx_doc = load_json(trivy_spdx)
    trivy_cdx_doc  = load_json(trivy_cdx)

    data["sbom"]["syft_spdx"]["summary"]  = summarize_spdx(syft_spdx_doc)
    data["sbom"]["syft_cdx"]["summary"]   = summarize_cyclonedx(syft_cdx_doc)
    data["sbom"]["trivy_spdx"]["summary"] = summarize_spdx(trivy_spdx_doc) if trivy_spdx_doc else {}
    data["sbom"]["trivy_cdx"]["summary"]  = summarize_cyclonedx(trivy_cdx_doc) if trivy_cdx_doc else {}

    # 5) Emit HTML into report-result/UnifiedDashboard.html
    reports_dir = paths["reports"]
    os.makedirs(reports_dir, exist_ok=True)
    out_html = os.path.join(reports_dir, "UnifiedDashboard.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(build_html(data))

    print(f"[OK] Dashboard written to:\n{out_html}")

    # Optional: offer to open the file
    try:
        if tk:
            root = tk.Tk(); root.withdraw()
            if messagebox.askyesno("Open dashboard?", "Open UnifiedDashboard.html now?"):
                # cross-platform open
                if sys.platform.startswith("darwin"):
                    subprocess.Popen(["open", out_html])
                elif os.name == "nt":
                    os.startfile(out_html)  # type: ignore[attr-defined]
                else:
                    subprocess.Popen(["xdg-open", out_html])
            root.destroy()
    except Exception:
        pass

if __name__ == "__main__":
    main()
