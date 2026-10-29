"""Shared result normalization and portable reporting for CLI and dashboard."""
from typing import Any, Dict, Optional
from crypto_evidence import mlkem_group, redact_evidence


def post_process_scan_result(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """Assess only observed identities; unknown evidence never establishes safety."""
    if not isinstance(scan_result, dict):
        return scan_result
    clean = redact_evidence(scan_result)
    scan_result.clear()
    scan_result.update(clean)
    inventory = {f['id']: f for f in scan_result.get('inventory', {}).get('findings', [])}
    assessments = scan_result.get('risk_assessment', {}).get('assessments', [])
    pq = {}
    for fid, item in inventory.items():
        attrs = item.get('attributes', {})
        group = attrs.get('group')
        if group is None and attrs.get('is_pqc_hybrid'):
            group = item.get('algorithm', '').split(' ')[0]
        identity = mlkem_group(group)
        if identity:
            pq[fid] = (group, identity)
    assessments = [a for a in assessments if a.get('finding_id') not in pq or
                   a.get('rule_id') not in ('ECDH_KEY_EXCHANGE','PQC_HYBRID_KEM_DEPLOYED')]

    def add(fid, rule_id, title, track, severity, rationale, action):
        if any(a.get('assessment_id') == fid+'::'+rule_id for a in assessments):
            return
        item = inventory[fid]
        assessments.append(dict(assessment_id=fid+'::'+rule_id, finding_id=fid,
            asset=item.get('asset'), algorithm=item.get('algorithm'), rule_id=rule_id,
            title=title, track=track, severity=severity, confidence='high', confidence_score=3.0,
            confidence_rationale='Direct observation of the named primitive or protocol only.',
            priority=5.0 if severity=='info' else 70.0, rationale=rationale,
            quantum_relevance='Scoped observation; not a claim of complete protection or compliance.',
            threat_analysis=dict(model='observed', mosca_delta=None, details=rationale),
            recommendation=dict(action=action, reason=rationale,
                timeframe='monitor' if severity=='info' else 'immediate', alternatives=[], track=track)))

    for fid,(group,(identity,hybrid)) in pq.items():
        add(fid,'PQC_HYBRID_KEM_DEPLOYED', 'Observed '+identity+' '+('hybrid exchange' if hybrid else 'key encapsulation'),
            'quantum','info', 'The probe reported '+group+'. This observation does not verify authentication, every connection, or standards compliance.',
            'Maintain the observed '+identity+' deployment; verify implementation, authentication and all other assets.')
    for fid,item in inventory.items():
        attrs=item.get('attributes',{})
        if attrs.get('evidence_type')=='tls_protocol':
            proto=attrs.get('protocol') or item.get('algorithm')
            add(fid,'DEPRECATED_TLS_PROTOCOL','Obsolete protocol '+str(proto)+' accepted',
                'conventional','high',str(proto)+' is obsolete; update the server protocol policy.',
                'Disable '+str(proto)+'; use TLS 1.3 or an appropriately configured TLS 1.2 deployment.')
    assessments.sort(key=lambda a:a.get('priority',0),reverse=True)
    active = {fid:item for fid,item in inventory.items() if not item.get('attributes',{}).get('is_comment')
              and item.get('attributes',{}).get('match_type') not in ('IMPORT_STATEMENT','STRING_REFERENCE','COMMENT_ONLY')}
    assessed_ids={a.get('finding_id') for a in assessments}
    unknown=[]
    from risk_engine import normalize_algorithm
    for fid,item in active.items():
        algorithm=item.get('algorithm','')
        normalized = normalize_algorithm(algorithm)
        missing_size = (normalized.family in ('aes','rsa','ec_key','ec_dsa','dsa')
                        and item.get('key_bits') is None and normalized.key_bits is None)
        if fid not in assessed_ids or missing_size:
            unknown.append(fid)
    errors=scan_result.get('metadata',{}).get('errors',[])
    modules=scan_result.get('modules') or {}
    partial = bool(errors) or (modules.get('code_scanner') or {}).get('coverage_status')=='partial'
    if not active:
        score=None
        label='N/A (Scan Failed / Host Unreachable)' if errors else 'No cryptographic operations observed'
        posture='failed' if errors else 'unassessed'
    elif unknown or partial:
        score=None
        label='Incomplete evidence / readiness undetermined'
        posture='unknown'
    else:
        rule_ids={a.get('rule_id') for a in assessments}
        score=100
        if rule_ids & {'ECDH_KEY_EXCHANGE','DH_KEY_EXCHANGE','RSA_KEY_ENCAPSULATION'}: score-=35
        if rule_ids & {'RSA_SIGNATURE','RSA_KEY_MATERIAL','ECDSA_SIGNATURE','EC_KEY_MATERIAL','ED25519_SIGNATURE','ED448_SIGNATURE','DSA_SIGNATURE'}: score-=20
        conventional=[a.get('severity') for a in assessments if a.get('track')=='conventional']
        if 'critical' in conventional: score-=45
        elif 'high' in conventional: score-=30
        elif 'medium' in conventional: score-=15
        if 'AES128_QUANTUM_REDUCTION' in rule_ids: score-=10
        score=max(0,score)
        label=('No assessed migration blockers in observed scope' if score==100 else
               'Migration or remediation required')
        posture='good' if score==100 else 'medium' if score>=50 else 'poor'
    result=scan_result.setdefault('risk_assessment',{})
    result['assessments']=assessments
    summary=result.setdefault('summary',{})
    summary.update(total_assessments=len(assessments),
        severity={s:sum(a.get('severity')==s for a in assessments) for s in ('critical','high','medium','low','info')},
        track={t:sum(a.get('track')==t for a in assessments) for t in ('quantum','conventional')},
        confidence={c:sum(str(a.get('confidence','')).lower()==c for a in assessments) for c in ('low','medium','high')},
        readiness_score=score,readiness_label=label,readiness_posture=posture,
        coverage=dict(status='partial' if partial else 'unknown' if unknown else 'complete' if active else 'no_findings',
                      unknown_finding_ids=unknown, note='Static and network observations are not security certification.'))
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
