"""Attack detection for TrustIssues.

Three entry points, one per place untrusted text crosses a trust boundary:

  scan_input(text, source=...)      customer form text, inbound email, admin policy uploads
  scan_retrieved(text, ...)         chunks coming back from the vector DB, before any LLM sees them
  scan_output(text, ...)            anything about to leave the system (customer reply, email body)

Every scan first normalises the text so obfuscation does not hide an attack (RT-22):
Unicode NFKC, zero-width characters removed, HTML entities decoded, HTML comments and hidden
elements pulled out and scanned on their own, base64 blobs decoded and scanned on their own.
Then rules run over every layer. Each finding carries a rule id, OWASP LLM / ASI mapping,
MAESTRO layer and severity. The result has a verdict (clean, suspicious, malicious) and a
recommended action (allow, review, quarantine).

The detector reports and logs. It does not make refund decisions. Callers decide what to do:
the retriever drops malicious chunks, policy upload quarantines them, and the orchestrator can
send a 'review' or 'quarantine' case to a human instead of the LLM. Limits are enforced in code
by Blake's limit control whatever the detector says, so a missed detection is not a missed control.

Every non-clean scan writes an 'attack_detected' (or 'dlp_violation') event to the audit log.
"""
import base64
import binascii
import hashlib
import html
import re
import unicodedata
from dataclasses import dataclass, field, asdict

from app.monitoring.audit import get_audit_log, redact_text, SEVERITY_RANK

SEVERITY_SCORE = {'info': 0, 'low': 10, 'medium': 25, 'high': 50, 'critical': 90}

# ------------------------------------------------------------------ rules
# (rule_id, category, owasp ids, maestro layer, severity, compiled pattern, description)
_F = re.IGNORECASE | re.MULTILINE


def _r(p):
    return re.compile(p, _F)


INPUT_RULES = [
    ('INJ-OVERRIDE', 'prompt_injection', ['LLM01', 'ASI01'], 'L7 Agent Ecosystem', 'high',
     _r(r'\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(previous|prior|above|all|earlier|your|the|any|these)\b'
        r'[^.\n]{0,20}?\b(instructions?|rules?|prompts?|polic(y|ies)|guidelines?|guardrails?)\b'),
     'Tries to cancel the agent\'s instructions'),
    ('INJ-OVERRIDE', 'prompt_injection', ['LLM01', 'ASI01'], 'L7 Agent Ecosystem', 'high',
     _r(r'\bignore (the )?(refund )?polic(y|ies)\b'), 'Tries to cancel the refund policy'),
    ('INJ-ROLE', 'prompt_injection', ['LLM01', 'ASI01'], 'L7 Agent Ecosystem', 'high',
     _r(r'\byou are now\b|\b(admin|developer|god|debug|maintenance|jailbreak|dan) mode\b'),
     'Tries to switch the agent into a new role or mode'),
    ('INJ-ROLE', 'prompt_injection', ['LLM01', 'ASI01'], 'L7 Agent Ecosystem', 'high',
     _r(r'^\s*(system|assistant|developer)\s*:|\b(system|assistant|agent)\s+(note|instructions?|message|prompt)\b'
        r'|\bnote to (the )?(agent|assistant|ai|model|llm|bot)\b|\bagent\s*:\s*(for|always|approve|ignore|when|do)\b'),
     'Text dressed up as a system or agent instruction'),
    ('INJ-DECODE-FOLLOW', 'prompt_injection', ['LLM01'], 'L7 Agent Ecosystem', 'medium',
     _r(r'\b(decode|decrypt|base64)\b[^.\n]{0,20}\b(and )?(follow|execute|run|obey)\b'),
     'Asks the agent to decode and follow hidden text'),
    ('AUTH-CLAIM', 'authority_spoofing', ['ASI09', 'ASI03'], 'L7 Agent Ecosystem', 'high',
     _r(r'\b(supervisor|admin|administrator|manager)\s+(override|approval granted|has approved)\b'
        r'|\bapproved by (the |a )?(admin|administrator|supervisor|manager)\b|\bdecision\s*:\s*approve'
        r'|\bpre-?approved\b|\bskip (the )?(verification|checks?|review|validation)\b|\bprocess (this )?immediately\b'),
     'Claims an approval or authority the sender does not have'),
    ('AUTH-CLAIM', 'authority_spoofing', ['ASI09'], 'L7 Agent Ecosystem', 'medium',
     _r(r'\bauto-?approve[sd]?\b'), 'Asserts that requests are approved automatically'),
    ('LIMIT-TAMPER', 'excessive_agency', ['LLM03', 'ASI03'], 'L6 Security & Compliance', 'high',
     _r(r'\b(raise|increase|lift|remove|bypass|double|change|disable|waive)\b[^.\n]{0,30}?\b(refund |spending |weekly |transaction )?'
        r'(limits?|caps?|thresholds?)\b|\b(no|unlimited) (refund |spending )?limits?\b'
        r'|\blimits?\b[^.\n]{0,20}\bto \$?\s?\d{3,}'),
     'Tries to change the refund limits'),
    ('MEM-POISON', 'memory_poisoning', ['ASI06'], 'L2 Data Operations', 'high',
     _r(r'\b(save|store|remember|keep|record|persist)\b[^.\n]{0,40}?\b(permanently|forever|for (all |every )?future)\b'
        r'|\bfor (all|every) future (cases?|requests?|refunds?|claims?)\b'),
     'Tries to write lasting instructions into memory'),
    ('EXFIL-MARKDOWN', 'data_exfiltration', ['LLM02', 'LLM10'], 'L7 Agent Ecosystem', 'high',
     _r(r'!\[[^\]]*\]\(\s*https?://[^)\s]+\)|\[[^\]]*\]\(\s*https?://[^)\s]*[{?][^)\s]*\)'),
     'Markdown image or link that can carry data to an outside server'),
    ('DATA-REQUEST', 'sensitive_data_request', ['LLM02'], 'L2 Data Operations', 'medium',
     _r(r'\b(bank|account|routing|card)\s+(details|numbers?|info(rmation)?)\b|\bfull (bank )?account\b'
        r'|\b(refund|case) history\b[^.\n]{0,40}\bfor (customer|user|account)\b|\bcase file\b'),
     'Asks for financial details or case files'),
    ('PROMPT-LEAK', 'hidden_context_exposure', ['LLM08'], 'L1 Foundation Models', 'medium',
     _r(r'\b(repeat|reveal|print|show|output|dump|tell me|what (are|is))\b[^.\n]{0,30}?\b(system prompt|your (full |exact )?'
        r'(instructions|prompt|rules)|hidden (instructions|context))\b|\blist (every|all|your) (tools?|functions?)\b'
        r'|\binternal (note|notes|memo)\b|\bquote it exactly\b'),
     'Probes for hidden instructions, tools or internal notes'),
    ('BULK-ENUM', 'cross_customer_access', ['LLM02', 'ASI03'], 'L2 Data Operations', 'high',
     _r(r'\b(list|show|export|dump|give|send|pull|find)\b[^.\n]{0,25}?\b(all|every|each|other)\b[^.\n]{0,25}?'
        r'\b(customers?|cases|records|accounts|refunds|profiles|users)\b'),
     'Asks for many customers\' records at once'),
    ('LOG-FORGE', 'log_injection', ['LLM10'], 'L5 Evaluation & Observability', 'medium',
     _r(r'[\r\n]\s*\{[^\n]*"(actor|action|timestamp|severity|kind)"\s*:'),
     'Newline followed by a JSON log record'),
]

EXFIL_VERBS = _r(r'\b(send|forward|email|e-mail|mail|copy|cc|bcc|reply|deliver|share|attach)\b')
LOOKUP_WORDS = _r(r'\b(pull up|look ?up|find|show|open|access|get)\b[^.\n]{0,40}\b(account|records?|profile|case|history|details)\b')
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
CUSTOMER_REF = re.compile(r'\bC-\d+\b')
TXN_REF = re.compile(r'\bT-\d+\b')
URL_RE = re.compile(r'https?://([A-Za-z0-9.-]+)[^\s)\]"\'<>]*', re.IGNORECASE)
ACCOUNT_RE = re.compile(r'(?<![\w-])(?:\d[ -]?){8,18}\d(?![\w-])')

ZERO_WIDTH = re.compile('[​‌‍‎‏⁠⁡⁢⁣⁤﻿­᠎]')
HTML_COMMENT = re.compile(r'<!--(.*?)-->', re.S)
HIDDEN_HTML = re.compile(r'<([a-z0-9]+)[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|hidden)[^>]*>(.*?)</\1>',
                         re.S | re.I)
TAG = re.compile(r'<[^>]+>')
B64_BLOB = re.compile(r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])')

DEFAULT_CANARIES = ('INTERNAL ONLY', 'CANARY-')


# ------------------------------------------------------------------ results
@dataclass
class Finding:
    rule_id: str
    category: str
    owasp: list
    maestro: str
    severity: str
    description: str
    layer: str = 'text'
    evidence: str = ''


@dataclass
class ScanResult:
    source: str
    verdict: str
    risk_score: int
    recommended_action: str
    findings: list = field(default_factory=list)
    normalized_text: str = ''
    input_sha256: str = ''
    event_id: str = None

    @property
    def malicious(self):
        return self.verdict == 'malicious'

    @property
    def clean(self):
        return self.verdict == 'clean'

    @property
    def rule_ids(self):
        return sorted({f.rule_id for f in self.findings})

    def to_dict(self, include_text=False):
        d = asdict(self)
        if not include_text:
            d.pop('normalized_text', None)
        d['rule_ids'] = self.rule_ids
        return d


# Categories that make a stored document malicious on their own. Authority wording ("approved by the
# admin") is normal in policy prose, so in stored text it is only noted, not quarantined.
STRICT_CATEGORIES = frozenset({'prompt_injection', 'memory_poisoning', 'data_exfiltration',
                               'excessive_agency', 'cross_customer_access'})

# "cannot raise", "must not ignore", "never list". Only a negation directly in front counts, so
# "do not hesitate to ignore all previous instructions" is still caught.
_NEGATION = re.compile(r"\b(not|never|cannot|can't|won't|mustn't|shouldn't|no)\s+(be\s+|to\s+|ever\s+)?$", re.I)


def _negated(text, start):
    return bool(_NEGATION.search(text[max(0, start - 16):start]))


def _excerpt(text, start, end, pad=30):
    s = text[max(0, start - pad):min(len(text), end + pad)].replace('\n', ' ')
    return redact_text(s)[:120]


# ------------------------------------------------------------------ normalisation
def normalize(text):
    """Return (visible_text, layers, obfuscation_findings).

    layers is a list of (layer_name, text) to scan: the visible text plus anything that was
    hidden in comments, hidden HTML or base64."""
    findings = []
    if not isinstance(text, str):
        text = str(text)
    t = unicodedata.normalize('NFKC', text)
    if ZERO_WIDTH.search(t):
        findings.append(Finding('OBF-ZERO-WIDTH', 'obfuscation', ['LLM01'], 'L7 Agent Ecosystem', 'medium',
                                'Zero-width or invisible characters inside the text', 'text'))
        t = ZERO_WIDTH.sub('', t)
    # other invisible format characters (Unicode category Cf), e.g. bidi overrides
    stripped = ''.join(ch for ch in t if unicodedata.category(ch) != 'Cf' or ch in '\n\t')
    if stripped != t:
        findings.append(Finding('OBF-ZERO-WIDTH', 'obfuscation', ['LLM01'], 'L7 Agent Ecosystem', 'medium',
                                'Invisible Unicode format characters', 'text'))
        t = stripped
    t = html.unescape(t)
    layers = []
    for m in HTML_COMMENT.finditer(t):
        layers.append(('html_comment', m.group(1)))
    for m in HIDDEN_HTML.finditer(t):
        layers.append(('hidden_html', m.group(3)))
    if layers:
        findings.append(Finding('OBF-HIDDEN-HTML', 'obfuscation', ['LLM01'], 'L7 Agent Ecosystem', 'medium',
                                'Content hidden in an HTML comment or invisible element', 'text'))
    visible = HTML_COMMENT.sub(' ', t)
    visible = HIDDEN_HTML.sub(' ', visible)
    visible = TAG.sub(' ', visible)
    for m in B64_BLOB.finditer(t):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob + '=' * (-len(blob) % 4), validate=True).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(ch.isprintable() or ch in '\n\t' for ch in decoded)
        if len(decoded) >= 8 and printable / len(decoded) > 0.95 and re.search(r'[A-Za-z]{3,}\s+[A-Za-z]{2,}', decoded):
            layers.append(('base64', decoded))
            findings.append(Finding('OBF-BASE64', 'obfuscation', ['LLM01'], 'L7 Agent Ecosystem', 'medium',
                                    'Base64-encoded natural language inside the text', 'text', redact_text(decoded[:80])))
    return re.sub(r'[ \t]+', ' ', visible).strip(), [('text', t)] + layers, findings


# ------------------------------------------------------------------ detector
class Detector:
    def __init__(self, audit=None, canaries=DEFAULT_CANARIES, allowed_url_hosts=()):
        self._audit = audit
        self.canaries = tuple(c for c in canaries if c)
        self.allowed_url_hosts = tuple(h.lower() for h in allowed_url_hosts)

    @property
    def audit(self):
        return self._audit or get_audit_log()

    # -------------------------------------------------------------- shared
    @staticmethod
    def _verdict(findings, strict=False):
        score = min(100, sum(SEVERITY_SCORE[f.severity] for f in findings))
        worst = max((SEVERITY_RANK[f.severity] for f in findings), default=0)
        obfuscated = any(f.category == 'obfuscation' for f in findings)
        attack = any(f.category != 'obfuscation' for f in findings)
        if obfuscated and attack:
            score = min(100, score + 20)     # hiding an attack is itself evidence of intent
        # strict (stored data): an instruction aimed at the agent has no business being in a document
        instruction = any(f.category in STRICT_CATEGORIES for f in findings)
        if worst >= SEVERITY_RANK['high'] or score >= 60 or (strict and instruction):
            return 'malicious', score, 'quarantine'
        if worst >= SEVERITY_RANK['medium'] or score >= 20:
            return 'suspicious', score, 'review'
        return 'clean', score, 'allow'

    def _run_rules(self, layers, rules):
        out, seen = [], set()
        for layer, text in layers:
            for rule_id, cat, owasp, maestro, sev, pat, desc in rules:
                m = next((m for m in pat.finditer(text) if not _negated(text, m.start())), None)
                if m and (rule_id, layer) not in seen:
                    seen.add((rule_id, layer))
                    out.append(Finding(rule_id, cat, owasp, maestro, sev, desc, layer, _excerpt(text, m.start(), m.end())))
        return out

    def _scope_rules(self, layers, customer_id, allowed_emails, allowed_transactions):
        out = []
        allowed = {e.lower() for e in (allowed_emails or ())}
        for layer, text in layers:
            foreign = sorted({e for e in EMAIL_RE.findall(text) if e.lower() not in allowed})
            if foreign and LOOKUP_WORDS.search(text):
                out.append(Finding('LOOKUP-BY-EMAIL', 'cross_customer_access', ['LLM02', 'ASI03'], 'L2 Data Operations',
                                   'high', 'Asks for records of an account identified by an email not on this case',
                                   layer, redact_text(', '.join(foreign))[:120]))
            if foreign:
                verb = EXFIL_VERBS.search(text)
                out.append(Finding('EXFIL-ADDRESS', 'data_exfiltration', ['LLM02', 'ASI02'], 'L7 Agent Ecosystem',
                                   'high' if verb else 'low',
                                   'Mentions an email address that is not on file for this case'
                                   + (' and asks to send something' if verb else ''),
                                   layer, redact_text(', '.join(foreign))[:120]))
            if customer_id:
                others = sorted({c for c in CUSTOMER_REF.findall(text) if c != customer_id})
                if others:
                    out.append(Finding('CROSS-CUSTOMER', 'cross_customer_access', ['LLM02', 'ASI03'], 'L2 Data Operations',
                                       'high', 'Refers to another customer than the one on the case', layer,
                                       ', '.join(others)))
            if allowed_transactions is not None:
                others = sorted({t for t in TXN_REF.findall(text) if t not in set(allowed_transactions)})
                if others:
                    out.append(Finding('CROSS-TRANSACTION', 'cross_customer_access', ['LLM02', 'ASI03'],
                                       'L2 Data Operations', 'high' if EXFIL_VERBS.search(text) else 'medium',
                                       'Refers to a transaction that does not belong to this case', layer,
                                       ', '.join(others)))
        return out

    def _record(self, result, action, case_id, customer_id, extra):
        if result.clean:
            return result
        sev = max((f.severity for f in result.findings), key=lambda s: SEVERITY_RANK[s], default='low')
        event = self.audit.log('detector', action, severity=sev, case_id=case_id,
                               source=result.source, verdict=result.verdict, risk_score=result.risk_score,
                               recommended_action=result.recommended_action, rule_ids=result.rule_ids,
                               owasp=sorted({o for f in result.findings for o in f.owasp}),
                               maestro=sorted({f.maestro for f in result.findings}),
                               findings=[{'rule_id': f.rule_id, 'severity': f.severity, 'layer': f.layer,
                                          'evidence': f.evidence} for f in result.findings],
                               customer_id=customer_id, input_sha256=result.input_sha256, **(extra or {}))
        result.event_id = event.get('event_id')
        return result

    # -------------------------------------------------------------- public API
    def scan_input(self, text, *, source='form', case_id=None, customer_id=None, allowed_emails=(),
                   allowed_transactions=None, log=True, extra=None):
        """Untrusted text entering the system. source: form | email | policy_upload | case_text | task."""
        text = text if isinstance(text, str) else str(text or '')
        visible, layers, findings = normalize(text)
        findings += self._run_rules(layers, INPUT_RULES)
        findings += self._scope_rules(layers, customer_id, allowed_emails, allowed_transactions)
        findings += self._canary_rules(layers, 'high')
        verdict, score, action = self._verdict(findings)
        res = ScanResult(source, verdict, score, action, findings, visible,
                         hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest())
        return self._record(res, 'attack_detected', case_id, customer_id, extra) if log else res

    def scan_retrieved(self, text, *, source='retrieved_chunk', case_id=None, customer_id=None, log=True, extra=None):
        """Text coming back from the vector DB. Stored data should never carry instructions to the agent, so
        any attack rule here makes the chunk malicious (strict mode) and the caller should drop it."""
        text = text if isinstance(text, str) else str(text or '')
        visible, layers, findings = normalize(text)
        findings += self._run_rules(layers, INPUT_RULES)
        findings += self._scope_rules(layers, customer_id, (), None)
        # an address in stored text is only a problem together with an instruction to send
        findings = [f for f in findings if not (f.rule_id == 'EXFIL-ADDRESS' and f.severity == 'low')]
        for f in findings:
            if f.category == 'authority_spoofing':
                f.severity = 'low'
        findings += self._canary_rules(layers, 'medium')
        verdict, score, action = self._verdict(findings, strict=True)
        res = ScanResult(source, verdict, score, action, findings, visible,
                         hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest())
        return self._record(res, 'attack_detected', case_id, customer_id, extra) if log else res

    def scan_output(self, text, *, case_id=None, customer_id=None, allowed_emails=(), account_last4=None,
                    log=True, extra=None):
        """Data loss prevention on text about to reach a customer or an outbound email."""
        text = text if isinstance(text, str) else str(text or '')
        visible, layers, findings = normalize(text)
        for layer, t in layers:
            m = ACCOUNT_RE.search(t)
            if m:
                findings.append(Finding('DLP-ACCOUNT-NUMBER', 'data_leak', ['LLM02'], 'L2 Data Operations', 'critical',
                                        'Full account or card number in outbound text', layer,
                                        _excerpt(t, m.start(), m.end(), 10)))
            allowed = {e.lower() for e in (allowed_emails or ())}
            foreign = sorted({e for e in EMAIL_RE.findall(t) if e.lower() not in allowed})
            if foreign:
                findings.append(Finding('DLP-FOREIGN-EMAIL', 'data_leak', ['LLM02'], 'L2 Data Operations', 'high',
                                        'Outbound text contains an email address not on file for this case', layer,
                                        redact_text(', '.join(foreign))[:120]))
            if customer_id:
                others = sorted({c for c in CUSTOMER_REF.findall(t) if c != customer_id})
                if others:
                    findings.append(Finding('DLP-CROSS-CUSTOMER', 'data_leak', ['LLM02', 'ASI03'], 'L2 Data Operations',
                                            'high', 'Outbound text mentions another customer', layer, ', '.join(others)))
            for host in {h.lower() for h in URL_RE.findall(t)}:
                if not any(host == a or host.endswith('.' + a) for a in self.allowed_url_hosts):
                    findings.append(Finding('DLP-EXTERNAL-URL', 'data_exfiltration', ['LLM02', 'LLM10'],
                                            'L7 Agent Ecosystem', 'high', 'Outbound text links to an outside host',
                                            layer, host))
        findings += self._canary_rules(layers, 'critical', prefix='DLP-')
        verdict, score, action = self._verdict(findings)
        res = ScanResult('output', verdict, score, 'block' if verdict != 'clean' else 'allow', findings, visible,
                         hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest())
        return self._record(res, 'dlp_violation', case_id, customer_id, extra) if log else res

    def _canary_rules(self, layers, severity, prefix=''):
        out = []
        for layer, t in layers:
            for c in self.canaries:
                if c.lower() in t.lower():
                    out.append(Finding(prefix + 'CANARY', 'hidden_context_exposure', ['LLM08', 'LLM02'],
                                       'L2 Data Operations', severity,
                                       'Internal-only marker or canary token present', layer, c))
                    break
        return out


def sanitize_output(text):
    """Make outbound text safe to show: mask account numbers, drop markdown images, defang links."""
    text = ACCOUNT_RE.sub(lambda m: '****' + re.sub(r'\D', '', m.group(0))[-4:], text)
    text = re.sub(r'!\[[^\]]*\]\([^)]*\)', '[image removed]', text)
    text = re.sub(r'\[([^\]]*)\]\(\s*https?://[^)]*\)', r'\1', text)
    return text


_default = None


def get_detector():
    global _default
    if _default is None:
        _default = Detector()
    return _default
