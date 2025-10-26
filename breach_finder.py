#!/usr/bin/env python3
"""
OSINT Breach & Credential Exposure Tracker
Simple CLI tool: search an offline breach CSV for a domain or list of emails,
score exposures by severity, and write CSV / JSON / Markdown outputs.

Keep this project ethical: use fictional or authorized test data only.
"""
import argparse
import os
import sys
import json
import time
from datetime import datetime
from typing import List, Dict, Any
import pandas as pd

# ---- Helpers ----

def parse_args():
    """
    Parse command-line arguments.
    --domain : filter matches by email domain (e.g., example.com)
    --emails : path to a file with one email per line
    --offline: path to offline CSV with breach records
    --out    : output directory for generated reports
    --max-hibp: optional cap for HIBP lookups (0 = skip)
    """
    p = argparse.ArgumentParser(description="OSINT Breach & Credential Exposure Tracker")
    g = p.add_mutually_exclusive_group(required=False)
    g.add_argument("--domain", help="Filter by domain, e.g., example.com")
    g.add_argument("--emails", help="Path to file with one email per line")
    p.add_argument("--offline", default="sample_data/sample_breaches.csv",
                   help="Offline breach CSV (email,source,breach_date,compromised_data,password_hash(optional))")
    p.add_argument("--out", default="examples", help="Output directory")
    p.add_argument("--max-hibp", type=int, default=0, help="Max number of HIBP lookups (0 = skip)")
    return p.parse_args()

def load_offline_dataset(path: str) -> pd.DataFrame:
    """
    Load the offline CSV of breach records and normalize expected columns.
    Expected columns (case-insensitive): email, source, breach_date, compromised_data
    Optionally: password_hash
    Returns a pandas DataFrame with breach_date parsed as datetime.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Offline dataset not found: {path}")
    df = pd.read_csv(path)

    # Ensure required columns exist (case-insensitive)
    expected = {"email", "source", "breach_date", "compromised_data"}
    missing = expected - set([c.lower() for c in df.columns])
    if missing:
        raise ValueError(f"Offline CSV missing expected columns: {missing}")

    # Map columns to consistent lower-case names if necessary
    colmap = {c.lower(): c for c in df.columns}
    for need in list(expected) + ["password_hash"]:
        if need in colmap:
            df.rename(columns={colmap[need]: need}, inplace=True)

    # Convert breach_date to datetime (coerce invalid -> NaT)
    df["breach_date"] = pd.to_datetime(df["breach_date"], errors="coerce")
    return df

def read_emails_file(path: str) -> List[str]:
    """
    Read a plain text file containing one email address per line.
    Returns a sorted list of unique emails (lowercasing handled later).
    """
    emails = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            e = line.strip()
            # Basic sanity check for an email-like string
            if e and "@" in e:
                emails.append(e)
    return list(sorted(set(emails)))

def filter_by_domain(df: pd.DataFrame, domain: str) -> pd.DataFrame:
    """
    Return rows where the email ends with @<domain>.
    Uses case-insensitive comparison.
    """
    return df[df["email"].str.lower().str.endswith(f"@{domain.lower()}")].copy()

def filter_by_emails(df: pd.DataFrame, emails: List[str]) -> pd.DataFrame:
    """
    Return rows where the email is one of the provided email addresses.
    """
    emails_lower = set([e.lower() for e in emails])
    return df[df["email"].str.lower().isin(emails_lower)].copy()

def severity_for_row(row) -> int:
    """
    Compute a simple severity score (0-5) for a single breach row.
    Scoring factors:
      - Recency: breaches within 1 year -> +2, within 3 years -> +1
      - Data sensitivity: passwords/hash -> +3, emails/usernames -> +1, personal data -> +1
    The score is capped at 5.
    """
    sev = 0
    # Recency factor (newer breaches are more severe)
    if pd.notna(row["breach_date"]):
        years = (pd.Timestamp.now() - row["breach_date"]).days / 365.25
        if years < 1:
            sev += 2
        elif years < 3:
            sev += 1

    # Data type factors
    dt = str(row.get("compromised_data", "")).lower()
    if any(k in dt for k in ["password", "pwd", "hash"]):
        sev += 3
    if any(k in dt for k in ["email", "username"]):
        sev += 1
    if any(k in dt for k in ["phone", "address", "dob"]):
        sev += 1

    # Cap the severity
    return min(sev, 5)

def risk_band(score: float) -> str:
    """
    Convert a numeric score to a qualitative risk band.
    """
    if score >= 4:
        return "High"
    if score >= 2.5:
        return "Medium"
    return "Low"

def summarize(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Create an overall summary dict from matched breach rows.
    Includes:
      - counts (total records, unique emails, distinct breaches)
      - generated timestamp
      - overall risk score and band
      - per-breach aggregates (records, unique emails, avg severity, top compromised data)
    """
    if df.empty:
        return {
            "total_exposed_accounts": 0,
            "unique_emails": 0,
            "breaches": [],
            "risk_score": 0,
            "risk_band": "Low"
        }

    df = df.copy()
    # Compute severity for each matched record
    df["severity"] = df.apply(severity_for_row, axis=1)

    per_breach = []
    # Group records by breach source and compute aggregates
    for source, g in df.groupby("source"):
        sev_avg = float(g["severity"].mean())
        latest = g["breach_date"].max()
        per_breach.append({
            "source": source,
            "records": int(len(g)),
            "unique_emails": int(g["email"].nunique()),
            "latest_breach_date": None if pd.isna(latest) else latest.date().isoformat(),
            "avg_severity": round(sev_avg, 2),
            "risk_band": risk_band(sev_avg),
            # List top compromised data types in this breach (simple frequency)
            "compromised_data_top": list(pd.Series(" | ".join(g["compromised_data"].astype(str)).split("|")).str.strip().value_counts().head(5).index)
        })

    overall_score = float(df["severity"].mean())
    out = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_exposed_accounts": int(len(df)),
        "unique_emails": int(df["email"].nunique()),
        "distinct_breaches": int(df["source"].nunique()),
        "risk_score": round(overall_score, 2),
        "risk_band": risk_band(overall_score),
        # Sort breaches by avg severity then by number of records (descending)
        "breaches": sorted(per_breach, key=lambda x: (-x["avg_severity"], -x["records"])),
    }
    return out

def write_outputs(outdir: str, df_matches: pd.DataFrame, summary: Dict[str, Any]):
    """
    Write three outputs into the specified directory:
      - exposed_accounts.csv : detailed matched rows (CSV)
      - results.json : structured summary (JSON)
      - sample_run_results.md : human-readable Markdown report
    """
    os.makedirs(outdir, exist_ok=True)

    # CSV of exposed accounts (sorted for readability)
    exposed_csv = os.path.join(outdir, "exposed_accounts.csv")
    df_to_save = df_matches.copy()
    if not df_to_save.empty:
        df_to_save["breach_date"] = pd.to_datetime(df_to_save["breach_date"], errors="coerce")
        df_to_save = df_to_save.sort_values(["email", "breach_date", "source"], ascending=[True, True, True])
    df_to_save.to_csv(exposed_csv, index=False)

    # JSON summary
    results_json = os.path.join(outdir, "results.json")
    with open(results_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Markdown human-readable report
    md = os.path.join(outdir, "sample_run_results.md")
    with open(md, "w", encoding="utf-8") as f:
        f.write(render_markdown(summary, df_matches))

    return exposed_csv, results_json, md

def render_markdown(summary: Dict[str, Any], df_matches: pd.DataFrame) -> str:
    """
    Produce a simple Markdown report summarizing findings.
    Includes top breaches and a small sample table of matched exposures.
    """
    lines = []
    lines.append("# Data Breach & Credential Exposure – Findings\n")
    lines.append(f"Generated: `{summary.get('generated_at','')}`\n")
    lines.append(f"- **Total exposed accounts:** {summary['total_exposed_accounts']}")
    lines.append(f"- **Unique emails:** {summary['unique_emails']}")
    lines.append(f"- **Distinct breaches:** {summary.get('distinct_breaches', 0)}")
    lines.append(f"- **Overall risk score:** {summary['risk_score']} ({summary['risk_band']})\n")
    lines.append("## Top Breaches by Severity\n")

    if not summary["breaches"]:
        lines.append("_No matches found in dataset._\n")
    else:
        for b in summary["breaches"][:10]:
            lines.append(f"- **{b['source']}** — {b['records']} records | {b['unique_emails']} emails | "
                         f"Avg severity: {b['avg_severity']} ({b['risk_band']}) | "
                         f"Latest: {b['latest_breach_date']}")

    lines.append("\n## Exposure Types (Examples)\n")
    if df_matches.empty:
        lines.append("_N/A_\n")
    else:
        # Show a small sample table of matched rows (first 15)
        sample = df_matches.copy()
        sample["breach_date"] = pd.to_datetime(sample["breach_date"], errors="coerce").dt.date
        sample = sample[["email", "source", "breach_date", "compromised_data"]].head(15)
        lines.append(sample.to_markdown(index=False))

    lines.append("\n---\n**Note:** This report uses an offline sample dataset for demonstration. Live enrichment via HIBP can be enabled with an API key.")
    return "\n".join(lines)

# ---- Optional HIBP lookup (stub with structure; skip if no key/max == 0) ----

def hibp_lookup_many(emails: List[str], max_count: int = 0) -> Dict[str, Any]:
    """
    Placeholder function to show where HaveIBeenPwned (HIBP) enrichment would happen.
    By default this is a stub to keep the project key-optional and safe to run offline.
    """
    if max_count <= 0:
        return {}
    looked_up = {}
    for e in emails[:max_count]:
        # Respectful pacing for any external API (sleep here as a stub)
        time.sleep(0.5)
        # Minimal placeholder structure; real implementation would call HIBP endpoints
        looked_up[e] = {"pwned": False, "breaches": []}
    return looked_up

# ---- Main execution flow ----

def main():
    # Parse CLI args
    args = parse_args()

    # Load the offline dataset (CSV)
    df = load_offline_dataset(args.offline)

    # Prepare an empty DataFrame with same columns to collect matches
    selected = pd.DataFrame(columns=df.columns)
    selected_emails = set()

    # If domain specified, filter dataset for that domain
    if args.domain:
        selected = pd.concat([selected, filter_by_domain(df, args.domain)], ignore_index=True)
        selected_emails.update([e for e in selected["email"].unique()])

    # If an emails file specified, read and filter
    if args.emails:
        ems = read_emails_file(args.emails)
        selected_emails.update(ems)
        selected = pd.concat([selected, filter_by_emails(df, ems)], ignore_index=True)

    # Remove duplicate rows if any
    selected.drop_duplicates(inplace=True)

    # Summarize matched records
    summary = summarize(selected)

    # Optional enrichment: HIBP lookups if requested (max_hibp > 0)
    if args.max_hibp > 0 and selected_emails:
        enrichment = hibp_lookup_many(sorted(selected_emails), args.max_hibp)
        summary["hibp_enrichment"] = enrichment

    # Write outputs (CSV, JSON, Markdown) into the output directory
    exposed_csv, results_json, md = write_outputs(args.out, selected, summary)

    # Print simple terminal messages for the user
    print(f"[+] Saved: {exposed_csv}")
    print(f"[+] Saved: {results_json}")
    print(f"[+] Saved: {md}")
    print("[*] Done.")

if __name__ == "__main__":
    main()

