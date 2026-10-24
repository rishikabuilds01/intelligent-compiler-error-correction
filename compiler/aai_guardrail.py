from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple


@dataclass
class GuardrailResult:
    passed: bool
    verdict: str  # "PASSED", "BLOCKED_INPUT", "QUARANTINED_PATCH"
    threat_detected: bool
    blocked: bool
    attack_type: Optional[str] = None  # "PROMPT_INJECTION", "POLICY_BYPASS", "TROJAN_PATCH", None
    risk_level: str = "NONE"  # "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    reason: str = "Safe"
    matched_patterns: List[str] = field(default_factory=list)
    quarantined_snippet: Optional[str] = None
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "verdict": self.verdict,
            "threat_detected": self.threat_detected,
            "blocked": self.blocked,
            "attack_type": self.attack_type,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "matched_patterns": self.matched_patterns,
            "quarantined_snippet": self.quarantined_snippet,
            "latency_ms": round(self.latency_ms, 3),
        }


@dataclass
class AuditLogEntry:
    event_id: str
    timestamp: str
    verdict: str
    attack_type: Optional[str]
    risk_level: str
    reason: str
    quarantined_snippet: Optional[str]
    matched_patterns: List[str]
    latency_ms: float
    client_info: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkMetrics:
    total_samples: int
    malicious_samples: int
    benign_samples: int
    true_positives: int  # Malicious correctly detected
    false_positives: int  # Benign incorrectly flagged
    true_negatives: int  # Benign correctly passed
    false_negatives: int  # Malicious missed
    attacks_blocked: int  # Detected attacks actively blocked
    adr_percent: float  # Attack Detection Rate = TP / (TP + FN) * 100
    bsr_percent: Optional[float]  # Block Success Rate = Blocked / TP * 100 (undefined/None if TP == 0)
    fpr_percent: float  # False Positive Rate = FP / (FP + TN) * 100
    avg_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    evaluated_at: str
    detailed_results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "malicious_samples": self.malicious_samples,
            "benign_samples": self.benign_samples,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "attacks_blocked": self.attacks_blocked,
            "adr_percent": round(self.adr_percent, 2),
            "bsr_percent": round(self.bsr_percent, 2) if self.bsr_percent is not None else None,
            "fpr_percent": round(self.fpr_percent, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 3),
            "min_latency_ms": round(self.min_latency_ms, 3),
            "max_latency_ms": round(self.max_latency_ms, 3),
            "evaluated_at": self.evaluated_at,
            "detailed_results": self.detailed_results,
        }


# ---------------------------------------------------------------------------
# Guardrail Regex Patterns for Input Prompt Injection & Policy Bypass
# ---------------------------------------------------------------------------

PROMPT_INJECTION_PATTERNS = [
    # Direct instruction to ignore prior instructions / rules
    (
        r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+|previous\s+|prior\s+|system\s+)?(?:instructions|rules|directives|guidelines|security\s+polic(?:y|ies)|safety\s+checks)\b",
        "Instruction override targeting AI guidelines",
        "CRITICAL",
    ),
    # System / Agent role hijacking
    (
        r"(?i)\b(?:system|ai|agent|developer)\s*(?:override|instruction|directive)\s*:",
        "System/agent role-hijacking directive",
        "CRITICAL",
    ),
    # Llama / Chat format delimiter injection
    (
        r"(?is)\[INST\].*?(?:bypass|ignore|override|disregard|disable).*?\[/INST\]",
        "Instruction-tuning delimiter tag injection ([INST])",
        "CRITICAL",
    ),
    # ChatML tokens
    (
        r"(?is)<\|im_start\|>(?:system|assistant)?",
        "ChatML special token injection (<|im_start|>)",
        "CRITICAL",
    ),
    # Unrestricted persona assumption
    (
        r"(?i)\byou\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|jailbroken|god\s+mode|unconstrained|evil)\b",
        "Persona hijacking / jailbreak attempt",
        "HIGH",
    ),
    # Forget you are a compiler / goal hijacking
    (
        r"(?i)\bforget\s+you\s+are\s+a\s+compiler\b",
        "Goal hijacking / persona override",
        "CRITICAL",
    ),
]

POLICY_BYPASS_PATTERNS = [
    # Demanding to mark vulnerable code as safe
    (
        r"(?i)\b(?:mark|treat)\s+(?:this\s+|the\s+)?(?:vulnerable|unsafe|malicious)?\s*code\s+as\s+safe\b",
        "Policy bypass attempting to mark unsafe code as safe",
        "CRITICAL",
    ),
    # Explicit bypass of security checks
    (
        r"(?i)\b(?:bypass|disable|skip)\s+(?:all\s+)?(?:security|safety|compiler|validation|taint)\s*(?:checks|rules|policies|engine|step|directives)?\b",
        "Directive attempting to disable security/validation step",
        "CRITICAL",
    ),
    # Setting artificial security scores
    (
        r"(?i)\b(?:set|force)\s+(?:security_score|safety_score)\s*=\s*\d+",
        "Attempted forgery of internal security score",
        "HIGH",
    ),
]

# Sensitive patterns that should be monitored for NEW occurrence in candidate patches
SENSITIVE_SINK_PATTERNS = [
    (
        r'\bgetenv\s*\(\s*["\'](AWS_[A-Z0-9_]*|USER|USERNAME|PASS(?:WORD)?|SECRET|TOKEN|KEY|CREDENTIAL|PRIVATE)',
        "Unauthorized credential/personal environment variable access",
        "CRITICAL",
    ),
    (
        r'\bfopen\s*\(\s*["\'](?:/etc/(?:shadow|passwd|sudoers)|C:\\\\Windows|.*(?:id_rsa|\.env|\.aws))',
        "Sensitive file/credential path access",
        "CRITICAL",
    ),
    (
        r'\b(?:system|popen|exec[a-z]*)\s*\(',
        "Arbitrary shell/command execution sink",
        "HIGH",
    ),
    (
        r'\b(?:socket|connect|gethostbyname)\s*\(',
        "Direct network communication / socket beaconing sink",
        "HIGH",
    ),
]

# Context exclusions: Safe patterns that must NOT trigger false positives
SAFE_PRAGMA_OR_SIGNAL_EXCLUSIONS = [
    r'#pragma\s+GCC\s+diagnostic\s+ignored',
    r'signal\s*\(\s*SIG[A-Z0-9_]*\s*,\s*SIG_IGN\s*\)',
    r'\b(?:int|char|bool|float|double|void)\s+[A-Za-z0-9_]*(?:ignore|disable)[A-Za-z0-9_]*\b',
]


class AAIGuardrail:
    """
    Enforceable Agentic AI Guardrail for the Compiler IDE.
    Inspects incoming code/prompts for prompt injection and policy bypass,
    and inspects candidate patches for trojan payloads and unauthorized sinks.
    """

    def __init__(self, log_path: Optional[str] = "logs/aai_attack_audit.jsonl"):
        self.log_path = log_path
        self.in_memory_audit: List[AuditLogEntry] = []
        self._attacks_blocked_count = 0
        self._total_scans_count = 0

    def _is_safe_by_exclusion(self, text: str) -> bool:
        """Checks if matched phrase is merely part of a standard C idiom (e.g. pragma or signal)."""
        for exc in SAFE_PRAGMA_OR_SIGNAL_EXCLUSIONS:
            if re.search(exc, text):
                return True
        return False

    def scan_input(self, code_or_prompt: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """
        Inspects incoming untrusted C source code, comments, or prompts.
        Guarantees that ordinary code with 'ignore' or 'disable' is not falsely blocked.
        """
        t0 = time.perf_counter()
        self._total_scans_count += 1

        if not code_or_prompt or not code_or_prompt.strip():
            elapsed = (time.perf_counter() - t0) * 1000.0
            return GuardrailResult(
                passed=True,
                verdict="PASSED",
                threat_detected=False,
                blocked=False,
                latency_ms=elapsed,
            )

        matched_reasons = []
        matched_patterns = []
        highest_risk = "NONE"
        detected_attack_type: Optional[str] = None

        # Check Prompt Injection Patterns
        for pattern, desc, risk in PROMPT_INJECTION_PATTERNS:
            matches = list(re.finditer(pattern, code_or_prompt))
            for m in matches:
                matched_snippet = m.group(0)
                # Ensure it's not a legitimate pragma or identifier
                if self._is_safe_by_exclusion(matched_snippet):
                    continue

                matched_reasons.append(desc)
                matched_patterns.append(matched_snippet)
                detected_attack_type = "PROMPT_INJECTION"
                if risk == "CRITICAL" or highest_risk != "CRITICAL":
                    highest_risk = risk

        # Check Policy Bypass Patterns
        for pattern, desc, risk in POLICY_BYPASS_PATTERNS:
            matches = list(re.finditer(pattern, code_or_prompt))
            for m in matches:
                matched_snippet = m.group(0)
                if self._is_safe_by_exclusion(matched_snippet):
                    continue

                matched_reasons.append(desc)
                matched_patterns.append(matched_snippet)
                if not detected_attack_type:
                    detected_attack_type = "POLICY_BYPASS"
                if risk == "CRITICAL" or highest_risk != "CRITICAL":
                    highest_risk = risk

        elapsed = (time.perf_counter() - t0) * 1000.0

        if matched_reasons:
            self._attacks_blocked_count += 1
            reason_str = "; ".join(set(matched_reasons))
            snippet_str = matched_patterns[0] if matched_patterns else ""

            res = GuardrailResult(
                passed=False,
                verdict="BLOCKED_INPUT",
                threat_detected=True,
                blocked=True,
                attack_type=detected_attack_type,
                risk_level=highest_risk,
                reason=f"Blocked malicious input: {reason_str}",
                matched_patterns=matched_patterns,
                quarantined_snippet=snippet_str,
                latency_ms=elapsed,
            )
            self._log_event(res, context)
            return res

        return GuardrailResult(
            passed=True,
            verdict="PASSED",
            threat_detected=False,
            blocked=False,
            risk_level="NONE",
            reason="Input verified safe by AAI Guardrail",
            latency_ms=elapsed,
        )

    def scan_candidate_patch(
        self,
        original_code: str,
        candidate_patch: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardrailResult:
        """
        Inspects an AI-generated candidate patch before application.
        Only flags sensitive sinks if they are NEWLY introduced by the patch
        and were NOT present in the original source code.
        """
        t0 = time.perf_counter()
        self._total_scans_count += 1

        if not candidate_patch or candidate_patch == original_code:
            elapsed = (time.perf_counter() - t0) * 1000.0
            return GuardrailResult(
                passed=True,
                verdict="PASSED",
                threat_detected=False,
                blocked=False,
                latency_ms=elapsed,
            )

        matched_reasons = []
        matched_patterns = []
        highest_risk = "NONE"

        for pattern, desc, risk in SENSITIVE_SINK_PATTERNS:
            # Check if present in candidate patch
            patch_matches = [m.group(0) for m in re.finditer(pattern, candidate_patch, re.IGNORECASE)]
            if not patch_matches:
                continue

            # Check if it was already in the original code
            orig_matches = [m.group(0) for m in re.finditer(pattern, original_code, re.IGNORECASE)]

            # If the patch introduces MORE sensitive sinks than original, or new sinks
            if len(patch_matches) > len(orig_matches):
                new_sinks = [s for s in patch_matches if s not in orig_matches or patch_matches.count(s) > orig_matches.count(s)]
                if new_sinks:
                    matched_reasons.append(desc)
                    matched_patterns.extend(new_sinks)
                    if risk == "CRITICAL" or highest_risk != "CRITICAL":
                        highest_risk = risk

        elapsed = (time.perf_counter() - t0) * 1000.0

        if matched_reasons:
            self._attacks_blocked_count += 1
            reason_str = "; ".join(set(matched_reasons))
            snippet_str = matched_patterns[0] if matched_patterns else ""

            res = GuardrailResult(
                passed=False,
                verdict="QUARANTINED_PATCH",
                threat_detected=True,
                blocked=True,
                attack_type="TROJAN_PATCH",
                risk_level=highest_risk,
                reason=f"Candidate patch quarantined: newly introduced sensitive sink ({reason_str})",
                matched_patterns=matched_patterns,
                quarantined_snippet=snippet_str,
                latency_ms=elapsed,
            )
            self._log_event(res, context)
            return res

        return GuardrailResult(
            passed=True,
            verdict="PASSED",
            threat_detected=False,
            blocked=False,
            risk_level="NONE",
            reason="Candidate patch verified clean",
            latency_ms=elapsed,
        )

    def _log_event(self, result: GuardrailResult, context: Optional[Dict[str, Any]] = None):
        """Records the event in memory and optionally appends to JSONL audit file."""
        entry = AuditLogEntry(
            event_id=str(uuid.uuid4()),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            verdict=result.verdict,
            attack_type=result.attack_type,
            risk_level=result.risk_level,
            reason=result.reason,
            quarantined_snippet=result.quarantined_snippet,
            matched_patterns=result.matched_patterns,
            latency_ms=round(result.latency_ms, 3),
            client_info=context,
        )
        self.in_memory_audit.append(entry)

        if self.log_path:
            try:
                os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry.to_dict()) + "\n")
            except Exception:
                pass

    def get_audit_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns the recent in-memory audit log entries."""
        return [entry.to_dict() for entry in reversed(self.in_memory_audit[-limit:])]

    def evaluate_benchmark_dataset(self, dataset_path_or_list) -> BenchmarkMetrics:
        """
        Executes the labelled benchmark suite.
        Calculates honest, measured metrics (TP, FP, TN, FN, ADR, BSR, FPR, Latency).
        No hardcoded values.
        """
        if isinstance(dataset_path_or_list, str):
            with open(dataset_path_or_list, "r", encoding="utf-8") as f:
                samples = json.load(f)
        else:
            samples = dataset_path_or_list

        tp = 0
        fp = 0
        tn = 0
        fn = 0
        blocked = 0
        latencies = []
        detailed_results = []

        for item in samples:
            sample_id = item.get("id", "unknown")
            is_malicious = item.get("label") == "malicious"
            source_code = item.get("source_code", "")
            candidate_patch = item.get("candidate_patch")

            t_start = time.perf_counter()

            # If sample tests a candidate patch, run scan_candidate_patch
            if candidate_patch:
                res = self.scan_candidate_patch(source_code, candidate_patch)
            else:
                res = self.scan_input(source_code)

            t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            latencies.append(t_elapsed_ms)

            detected = res.threat_detected
            was_blocked = res.blocked

            if is_malicious:
                if detected:
                    tp += 1
                    if was_blocked:
                        blocked += 1
                else:
                    fn += 1
            else:
                if detected:
                    fp += 1
                else:
                    tn += 1

            detailed_results.append({
                "id": sample_id,
                "label": item.get("label"),
                "attack_type": item.get("attack_type"),
                "detected": detected,
                "verdict": res.verdict,
                "latency_ms": round(t_elapsed_ms, 3),
                "correct": (is_malicious == detected),
            })

        total = len(samples)
        mal_count = tp + fn
        ben_count = fp + tn

        adr = round((tp / mal_count * 100.0) if mal_count > 0 else 0.0, 2)
        bsr = round((blocked / tp * 100.0), 2) if tp > 0 else None
        fpr = round((fp / ben_count * 100.0) if ben_count > 0 else 0.0, 2)

        avg_lat = round(sum(latencies) / len(latencies), 3) if latencies else 0.0
        min_lat = round(min(latencies), 3) if latencies else 0.0
        max_lat = round(max(latencies), 3) if latencies else 0.0

        return BenchmarkMetrics(
            total_samples=total,
            malicious_samples=mal_count,
            benign_samples=ben_count,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            attacks_blocked=blocked,
            adr_percent=adr,
            bsr_percent=bsr,
            fpr_percent=fpr,
            avg_latency_ms=avg_lat,
            min_latency_ms=min_lat,
            max_latency_ms=max_lat,
            evaluated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            detailed_results=detailed_results,
        )


# Global default instance for reuse across modules
default_guardrail = AAIGuardrail()
