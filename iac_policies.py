"""Exact, offline policy catalog reviewed against vendor docs on 2026-10-29.

This catalog states only whether listed policies allow TLS older than 1.2.
It does not assert that a listed modern policy is safe in every other respect.
"""
CATALOG_VERSION = '2026-10-29'
ELB_SOURCE = 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html'
NLB_SOURCE = 'https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html'
CF_SOURCE = 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html'
INGRESS_SOURCE = 'https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/'

ELB_LEGACY = frozenset({
    'ELBSecurityPolicy-2016-08',
    'ELBSecurityPolicy-TLS-1-1-2017-01',
    'ELBSecurityPolicy-TLS13-1-1-2021-06',
    'ELBSecurityPolicy-TLS13-1-0-2021-06',
    'ELBSecurityPolicy-TLS13-1-0-PQ-2025-09',
})
ELB_MODERN = frozenset({
    'ELBSecurityPolicy-TLS-1-2-2017-01',
    'ELBSecurityPolicy-TLS-1-2-Ext-2018-06',
    'ELBSecurityPolicy-TLS13-1-2-2021-06',
    'ELBSecurityPolicy-TLS13-1-2-Res-2021-06',
    'ELBSecurityPolicy-TLS13-1-3-2021-06',
    'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09',
})
CF_LEGACY = frozenset({'SSLv3', 'TLSv1', 'TLSv1_2016', 'TLSv1.1_2016'})
CF_MODERN = frozenset({'TLSv1.2_2018', 'TLSv1.2_2019', 'TLSv1.2_2021', 'TLSv1.2_2025', 'TLSv1.3_2025'})

RULES = {
    'IAC_DOCKER_TLS_VERIFY_DISABLED': ('Container TLS verification explicitly disabled', 'Restore certificate verification and install the appropriate CA trust bundle.'),
    'IAC_INGRESS_LEGACY_TLS': ('Ingress upstream TLS configuration includes deprecated protocols', 'Use only TLSv1.2/TLSv1.3 for supported upstream TLS settings; verify controller behavior after deployment.'),
    'IAC_INGRESS_WEAK_CIPHER': ('Ingress configuration explicitly includes a weak cipher', 'Remove the observed weak cipher and select a reviewed supported cipher list.'),
    'IAC_INGRESS_VERIFY_DISABLED': ('Ingress upstream HTTPS certificate verification disabled', 'Enable proxy-ssl-verify and configure the correct trust secret and upstream name.'),
    'IAC_AWS_LEGACY_TLS_POLICY': ('Configured AWS TLS policy permits deprecated protocols', 'Select a documented policy requiring TLS 1.2 or later after checking client compatibility.'),
}


def rule_definitions():
    """Static-only rules; don't reuse runtime handshake assertions for declarations."""
    return [dict(id=rule_id, track='conventional', title=title,
        match={'iac_rule_id': rule_id}, severity_model='static', severity='high',
        rationale=title+'. Static configured intent only, not observed runtime TLS posture; applicability requires verification.',
        quantum_relevance='Conventional configuration risk. No PQC support or runtime TLS claim.',
        recommendation={'action': remediation, 'reason': 'Correct the explicitly observed configuration and verify the deployment.',
                        'timeframe': 'immediate', 'alternatives': []})
        for rule_id,(title,remediation) in RULES.items()]
