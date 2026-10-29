"""Shared result normalization and portable reporting for CLI and dashboard."""
from typing import Any, Dict, Optional

def post_process_scan_result(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enriches and corrects assessment results:
      1. Converts false-positive ECDH_KEY_EXCHANGE on Post-Quantum Hybrid KEM (ML-KEM)
         into an Informational / PQ-Ready finding.
      2. Ensures Deprecated TLS Protocol findings (TLS 1.0 / 1.1) produce Track B assessments.
    """
    if not isinstance(scan_result, dict):
        return scan_result

    assessments = scan_result.get("risk_assessment", {}).get("assessments", [])
    inventory_findings = {f["id"]: f for f in scan_result.get("inventory", {}).get("findings", [])}
    new_assessments = []

    for a in assessments:
        fid = a.get("finding_id")
        inv = inventory_findings.get(fid, {})
        attr = inv.get("attributes", {})

        # Check for Post-Quantum Hybrid KEM (e.g. X25519MLKEM768)
        if attr.get("is_pqc_hybrid") and a.get("rule_id") == "ECDH_KEY_EXCHANGE":
            pqc_algo = inv.get("algorithm") or a.get("algorithm")
            new_assessments.append({
                "assessment_id": f"{fid}::PQC_HYBRID_KEM_DEPLOYED",
                "finding_id": fid,
                "asset": a.get("asset"),
                "algorithm": pqc_algo,
                "track": "quantum",
                "rule_id": "PQC_HYBRID_KEM_DEPLOYED",
                "title": "Post-Quantum Hybrid Key Exchange Active (NIST FIPS 203 ML-KEM)",
                "severity": "info",
                "confidence": "high",
                "confidence_score": 3.0,
                "confidence_rationale": "Direct network TLS telemetry confirmed post-quantum hybrid key exchange (X25519MLKEM768).",
                "priority": 5.0,
                "rationale": "The endpoint successfully negotiated a post-quantum hybrid key encapsulation mechanism (ML-KEM-768 combined with classical X25519), effectively mitigating Harvest-Now-Decrypt-Later (HNDL) attacks.",
                "quantum_relevance": "Quantum-Resistant. Meets NIST FIPS 203 standards and NSA CNSA 2.0 requirements for post-quantum key agreement.",
                "threat_analysis": {
                    "model": "pqc_hybrid",
                    "mosca_delta": None,
                    "data_shelf_life": 10.0,
                    "migration_window": 0.0,
                    "crqc_horizon": scan_result.get("metadata", {}).get("crqc_horizon_years", 15.0),
                    "details": "Post-quantum hybrid key encapsulation active. Target is protected against Shor's algorithm and retrospective decryption."
                },
                "recommendation": {
                    "action": "Maintain current Post-Quantum hybrid key exchange deployment (ML-KEM-768 + X25519).",
                    "reason": "Endpoint is already utilizing post-quantum key encapsulation, fulfilling NIST PQC transition milestones.",
                    "timeframe": "monitor",
                    "alternatives": ["Pure ML-KEM-768 (FIPS 203)", "Pure ML-KEM-1024"],
                    "track": "quantum"
                }
            })
            continue

        new_assessments.append(a)

    # Check for Deprecated Protocol findings in inventory that didn't get assessed
    assessed_finding_ids = {a.get("finding_id") for a in new_assessments}
    for fid, inv in inventory_findings.items():
        attr = inv.get("attributes", {})
        if attr.get("evidence_type") == "tls_protocol" and fid not in assessed_finding_ids:
            proto = attr.get("protocol") or inv.get("algorithm", "").replace("Deprecated-", "")
            new_assessments.append({
                "assessment_id": f"{fid}::DEPRECATED_TLS_PROTOCOL",
                "finding_id": fid,
                "asset": inv.get("asset"),
                "algorithm": inv.get("algorithm"),
                "track": "conventional",
                "rule_id": "DEPRECATED_TLS_PROTOCOL",
                "title": f"Obsolete and Insecure Protocol ({proto}) Accepted by Server",
                "severity": "high",
                "confidence": "high",
                "confidence_score": 3.0,
                "confidence_rationale": f"Network TLS handshake verification confirmed server accepts obsolete {proto}.",
                "priority": 70.0,
                "rationale": f"{proto} contains known architectural security flaws (BEAST, POODLE fallback attacks, weak CBC padding) and has been deprecated by RFC 8996 and NIST SP 800-52r2.",
                "quantum_relevance": "Conventional security flaw, NOT a quantum risk. Obsolete protocol versions violate current compliance standards (PCI-DSS 3.2.1, NIST).",
                "threat_analysis": {
                    "model": "static",
                    "mosca_delta": None,
                    "data_shelf_life": None,
                    "migration_window": None,
                    "crqc_horizon": None,
                    "details": f"Server accepts obsolete protocol {proto}. Disabling legacy protocols is required for baseline cryptographic hygiene."
                },
                "recommendation": {
                    "action": f"Disable {proto} immediately across all server endpoints.",
                    "reason": f"{proto} is deprecated by RFC 8996 and vulnerable to downgrade attacks. The minimum compliant protocol is TLS 1.2; TLS 1.3 is strongly recommended.",
                    "timeframe": "immediate",
                    "alternatives": ["TLSv1.3 (RFC 8446, recommended)", "TLSv1.2 (RFC 5246, minimum)"],
                    "track": "conventional"
                }
            })

    # Recalculate summary metrics accurately
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    track_counts = {"quantum": 0, "conventional": 0}
    for a in new_assessments:
        s = a.get("severity", "medium").lower()
        if s in sev_counts:
            sev_counts[s] += 1
        t = a.get("track", "quantum")
        if t in track_counts:
            track_counts[t] += 1

    # Calculate defensible PQC Readiness Score (0-100% or None if scan failed)
    errors = scan_result.get("metadata", {}).get("errors", [])
    tls_failed = any(e.get("module") == "tls_scanner" for e in errors)
    code_failed = any(e.get("module") == "code_scanner" for e in errors)
    total_inv = scan_result.get("inventory", {}).get("total_items", 0)

    # If target could not be reached/scanned, score is N/A (never report 100% compliance on failure)
    if total_inv == 0 or (len(new_assessments) == 0 and (tls_failed or code_failed)):
        readiness_score = None
        readiness_label = "N/A (Scan Failed / Host Unreachable)"
        readiness_posture = "failed"
    else:
        score = 100
        has_pqc_hybrid = any(
            inv.get("attributes", {}).get("is_pqc_hybrid")
            or "MLKEM" in (inv.get("algorithm") or "").upper()
            or "KYBER" in (inv.get("algorithm") or "").upper()
            for inv in inventory_findings.values()
        )
        has_classical_kx = any(
            a.get("rule_id") == "ECDH_KEY_EXCHANGE" or ("key_exchange" in a.get("rule_id", "").lower()) or a.get("rule_id") == "RSA_KEY_ENCAPSULATION"
            for a in new_assessments
        )
        has_classical_sig = any(
            a.get("rule_id") in ("RSA_SIGNATURE", "ECDSA_SIGNATURE")
            for a in new_assessments
        )
        has_deprecated_proto = any(
            a.get("rule_id") == "DEPRECATED_TLS_PROTOCOL" or "Deprecated" in a.get("algorithm", "")
            for a in new_assessments
        )
        has_broken_hash_or_cipher = any(
            a.get("rule_id") in ("BROKEN_HASH_MD5", "BROKEN_HASH_SHA1", "BROKEN_CIPHER_DES", "UNAUTHENTICATED_CBC_MODE")
            for a in new_assessments
        )
        has_aes128 = any(
            a.get("rule_id") == "AES128_QUANTUM_REDUCTION"
            for a in new_assessments
        )

        # 1. Key Exchange posture (HNDL vulnerability vs PQC protection)
        if has_pqc_hybrid:
            # Active Post-Quantum Hybrid (e.g. ML-KEM) protects against HNDL
            pass
        elif has_classical_kx:
            # Classical ECDH/DH without hybrid KEM is vulnerable to HNDL
            score -= 35

        # 2. Authentication / Signature posture (Shor's algorithm)
        if has_classical_sig:
            score -= 20

        # 3. Protocol hygiene (TLS 1.0 / 1.1)
        if has_deprecated_proto:
            score -= 30

        # 4. Broken classical primitives (MD5, SHA-1, DES)
        if has_broken_hash_or_cipher:
            score -= 25

        # 5. Symmetric encryption bitness (Grover reduction)
        if has_aes128:
            score -= 10

        readiness_score = max(5, min(100, score))
        if readiness_score >= 80:
            readiness_label = "PQC Resilient / Hybrid Ready"
            readiness_posture = "good"
        elif readiness_score >= 50:
            readiness_label = "Transitional Classical"
            readiness_posture = "medium"
        else:
            readiness_label = "Vulnerable / Migration Required"
            readiness_posture = "poor"

    scan_result.setdefault("risk_assessment", {})["assessments"] = new_assessments
    scan_result["risk_assessment"].setdefault("summary", {})["total_assessments"] = len(new_assessments)
    scan_result["risk_assessment"]["summary"]["severity"] = sev_counts
    scan_result["risk_assessment"]["summary"]["track"] = track_counts
    scan_result["risk_assessment"]["summary"]["readiness_score"] = readiness_score
    scan_result["risk_assessment"]["summary"]["readiness_label"] = readiness_label
    scan_result["risk_assessment"]["summary"]["readiness_posture"] = readiness_posture
    scan_result["risk_assessment"]["summary"]["confidence"] = {
        confidence: sum(str(a.get("confidence", "")).lower() == confidence for a in new_assessments)
        for confidence in ("low", "medium", "high")
    }

    return scan_result


def render_markdown(
    scan_result: Dict[str, Any],
    track_filter: Optional[str] = None,
    min_severity: Optional[str] = None,
) -> str:
    """Render the current result dictionary without ANSI escapes or a second assessment."""
    meta = scan_result.get('metadata', {})
    summary = scan_result.get('risk_assessment', {}).get('summary', {})
    assessments = scan_result.get('risk_assessment', {}).get('assessments', [])
    ranks = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    shown = [a for a in assessments if
             (not track_filter or track_filter == 'all' or a.get('track') == track_filter)
             and (not min_severity or ranks.get(str(a.get('severity', '')).lower(), 0)
                  >= ranks[min_severity.lower()])]

    def inline(value):
        return str(value if value is not None else 'N/A').replace('\r', ' ').replace('\n', ' ').replace('|', '\\|')

    targets = meta.get('targets', {})
    lines = ['# Q-SHIELD Cryptographic Scan Report', '',
             '**Data:** ' + ('Illustrative demo' if meta.get('is_demo') else 'Scan results'),
             '**Finished:** ' + inline(meta.get('scan_finished_at')),
             '**Repository:** ' + inline(targets.get('repo')),
             '**TLS host:** ' + inline(targets.get('host')),
             '**TLS port:** ' + inline(targets.get('port')),
             '**Scenario:** ' + inline(meta.get('scenario')),
             '**Assumed CRQC horizon (years):** ' + inline(meta.get('crqc_horizon_years')), '',
             '## Full-scan summary', '', '| Severity | Count |', '| --- | ---: |']
    for severity in ('critical', 'high', 'medium', 'low', 'info'):
        lines.append(f'| {severity} | {summary.get("severity", {}).get(severity, 0)} |')
    lines += ['', f'**Total assessments:** {len(assessments)}',
              f'**Displayed assessments:** {len(shown)} (track: {track_filter or "all"}; minimum severity: {min_severity or "info"})',
              '**Heuristic posture score:** ' + inline(summary.get('readiness_score')),
              'Posture scores are planning aids, not compliance certification.', '']
    errors = meta.get('errors', [])
    if errors:
        lines += ['## Scan diagnostics', '', 'This report contains failed stages or configuration errors.', '']
        lines += ['- ' + inline(e.get('module')) + ': ' + inline(e.get('error')) for e in errors]
        lines.append('')
    lines += ['## Assessment details', '']
    if not shown:
        lines += ['No assessments match these display filters. Review diagnostics before interpreting this as a clean scan.', '']
    for a in shown:
        rec = a.get('recommendation', {})
        lines += ['### [' + inline(a.get('severity')).upper() + '] ' + inline(a.get('title')), '',
                  '- **Rule:** ' + inline(a.get('rule_id')),
                  '- **Asset:** ' + inline(a.get('asset')),
                  '- **Algorithm:** ' + inline(a.get('algorithm')),
                  '- **Track:** ' + inline(a.get('track')),
                  '- **Confidence:** ' + inline(a.get('confidence')),
                  '- **Priority:** ' + inline(a.get('priority')),
                  '- **Rationale:** ' + inline(a.get('rationale')),
                  '- **Action (' + inline(rec.get('timeframe')) + '):** ' + inline(rec.get('action')),
                  '- **Reason:** ' + inline(rec.get('reason'))]
        if a.get('threat_analysis', {}).get('details'):
            lines.append('- **Threat model:** ' + inline(a['threat_analysis']['details']))
        if rec.get('alternatives'):
            lines.append('- **Alternatives:** ' + ', '.join(inline(x) for x in rec['alternatives']))
        lines.append('')
    return '\n'.join(lines) + '\n'
