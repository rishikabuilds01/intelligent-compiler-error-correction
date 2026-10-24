from typing import Dict, Any, List, Optional
import time

from compiler.error_classifier import classify_error_message
from compiler.error_corrector import apply_correction
from compiler.lexical_corrector import fix_common_lexical_issues
from compiler.ai_error_corrector import ai_generate_patch_candidates
from compiler.identifier_corrector import fix_identifier_typo_at
from compiler.semantic_checker import SemanticChecker
from compiler.security_checker import SecurityChecker
from compiler.taint_checker import TaintChecker
from compiler.string_flow_checker import StringFlowChecker
from compiler.unused_var_fixer import remove_unused_decl_at
from compiler.security_auto_fixer import SecurityAutoFixer
from compiler.green_energy import GreenEnergyTracker
from compiler.green_system import GreenSystemTracker
from compiler.aai_guardrail import default_guardrail, GuardrailResult

from test_parser import (
    parse_source,
    has_any_errors,
    get_all_error_strings,
    get_first_error_object,
    build_symbols,
    DETERMINISTIC_REASONS,
    _select_best_ai_candidate_by_reparse,
)

# ---------------------------------------------------------
# Optional green modules
# Safe fallback if the files are not created yet
# ---------------------------------------------------------
try:
    from compiler.green_metrics import GreenMetrics  # type: ignore
except Exception:
    class GreenMetrics:
        def __init__(self):
            self._starts = {}
            self._phase_ms = {}
            self._counters = {}
            self._values = {}

        def start(self, phase: str) -> None:
            self._starts[phase] = time.perf_counter()

        def end(self, phase: str) -> None:
            started = self._starts.get(phase)
            if started is None:
                return
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            self._phase_ms[phase] = self._phase_ms.get(phase, 0.0) + elapsed_ms
            del self._starts[phase]

        def inc(self, key: str, value: int = 1) -> None:
            self._counters[key] = self._counters.get(key, 0) + value

        def set(self, key: str, value: Any) -> None:
            self._values[key] = value

        def to_dict(self) -> Dict[str, Any]:
            total_ms = sum(self._phase_ms.values())
            return {
                "total_runtime_ms": round(total_ms, 2),
                "phase_ms": {k: round(v, 2) for k, v in self._phase_ms.items()},
                "counters": dict(self._counters),
                "values": dict(self._values),
            }


try:
    from compiler.green_scorer import build_green_report  # type: ignore
except Exception:
    def build_green_report(metrics: Dict[str, Any]) -> Dict[str, Any]:
        phase_ms = metrics.get("phase_ms", {})
        counters = metrics.get("counters", {})
        values = metrics.get("values", {})

        score = 100
        total_ms = metrics.get("total_runtime_ms", 0.0)

        score -= min(int(total_ms / 80), 30)
        score -= min(counters.get("ai_fixes", 0) * 4, 20)
        score -= min(counters.get("rule_fixes", 0) * 2, 10)
        score -= min(counters.get("lex_fixes", 0), 5)
        score -= min(values.get("semantic_issue_count", 0) * 3, 15)

        if values.get("parse_success"):
            score += 5

        if values.get("status") == "STOPPED":
            score -= 15
        elif values.get("status") == "UNFIXABLE":
            score -= 10

        score = max(0, min(100, score))

        hotspot = "overall pipeline"
        hotspot_time = -1.0
        for name, ms in phase_ms.items():
            if ms > hotspot_time:
                hotspot = name
                hotspot_time = ms

        suggestion = "Pipeline looks efficient."
        if counters.get("ai_fixes", 0) >= 4:
            suggestion = "Reduce repeated AI fallback by improving deterministic fixes and early stopping."
        elif hotspot == "syntax_repair":
            suggestion = "Syntax repair dominates runtime; add stronger sync-point recovery and candidate pruning."
        elif hotspot == "semantic_phase":
            suggestion = "Semantic checking dominates runtime; consider lightweight pre-checks before full analysis."
        elif hotspot == "security_phase":
            suggestion = "Security phase dominates runtime; run targeted checks only after parse success."
        elif values.get("semantic_issue_count", 0) > 0:
            suggestion = "Reduce downstream semantic issues by improving identifier and declaration fixes earlier."

        return {
            **metrics,
            "green_score": score,
            "hotspot": hotspot,
            "suggestion": suggestion,
        }


try:
    from compiler.green_logger import GreenLogger  # type: ignore
except Exception:
    class GreenLogger:
        def log_run(self, payload: Dict[str, Any]) -> None:
            return


def _compute_changed_lines(old_text: str, new_text: str) -> List[int]:
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    max_len = max(len(old_lines), len(new_lines))
    changed = []

    for i in range(max_len):
        old_line = old_lines[i] if i < len(old_lines) else ""
        new_line = new_lines[i] if i < len(new_lines) else ""
        if old_line != new_line:
            changed.append(i + 1)

    return changed


def _build_suggestions(
    original_source: str,
    repaired_source: str,
    steps: List[str],
) -> List[Dict[str, Any]]:
    orig_lines = original_source.splitlines()
    rep_lines = repaired_source.splitlines()
    max_len = max(len(orig_lines), len(rep_lines))
    suggestions = []

    for i in range(max_len):
        old_l = orig_lines[i] if i < len(orig_lines) else ""
        new_l = rep_lines[i] if i < len(rep_lines) else ""
        if old_l != new_l:
            line_num = i + 1
            explanation = "Syntax or code structure repair required."
            for st in steps:
                if f"L{line_num}" in st or f"line {line_num}" in st.lower():
                    explanation = st
                    break
            if explanation == "Syntax or code structure repair required." and steps:
                step_idx = min(len(suggestions), len(steps) - 1)
                explanation = steps[step_idx]

            sug_id = f"sug_L{line_num}_{abs(hash(old_l)) % 1000000:06d}"
            category = "SYNTAX"
            if any(k in explanation for k in ["SYM:", "SEM:", "undeclared"]):
                category = "SEMANTIC"
            elif any(k in explanation for k in ["SEC:", "Security", "unsafe"]):
                category = "SECURITY"
            elif "LEX:" in explanation:
                category = "LEXICAL"

            suggestions.append({
                "id": sug_id,
                "category": category,
                "title": f"Fix at line {line_num}",
                "line": line_num,
                "column": 1,
                "original_snippet": old_l,
                "suggested_snippet": new_l,
                "explanation": explanation,
                "diff": {
                    "delete": old_l,
                    "insert": new_l,
                },
            })

    return suggestions


def _collect_security_issues(source_text: str) -> List[str]:
    issues = []

    security_checker = SecurityChecker()
    taint_checker = TaintChecker()
    string_checker = StringFlowChecker()

    for issue in security_checker.check(source_text):
        issues.append(f"[{issue.severity}] {issue.message} (score={issue.score})")

    for issue in taint_checker.check(source_text):
        issues.append(f"[{issue.severity}] {issue.message} (score={issue.score})")

    for issue in string_checker.check(source_text):
        issues.append(f"[{issue.severity}] {issue.message} (score={issue.score})")

    return issues


def _collect_semantic_issues(tree) -> List[Dict[str, Any]]:
    checker = SemanticChecker()
    checker.visit(tree)
    return checker.get_issues()


def _status_from_security(security_warnings: List[str]) -> str:
    if not security_warnings:
        return "SUCCESS"

    blocked = False
    total_score = 0

    for item in security_warnings:
        if "[CRITICAL]" in item:
            blocked = True

        marker = "(score="
        pos = item.find(marker)
        if pos != -1:
            end = item.find(")", pos)
            if end != -1:
                try:
                    total_score += int(item[pos + len(marker):end])
                except ValueError:
                    pass

    if blocked or total_score >= 6:
        return "BLOCKED_SECURITY"

    return "SUCCESS_WITH_WARNINGS"


def _try_remove_unused_decl(
    working: str,
    issue: Dict[str, Any],
) -> tuple[str, Optional[str]]:
    name = issue.get("name")
    line = issue.get("line")
    col = issue.get("col")

    corrected = None
    msg = None

    try:
        corrected, msg = remove_unused_decl_at(working, line, col, name)
    except TypeError:
        try:
            corrected, msg = remove_unused_decl_at(working, line, col)
        except TypeError:
            try:
                corrected, msg = remove_unused_decl_at(working, line, name)
            except Exception:
                corrected, msg = None, None
    except Exception:
        corrected, msg = None, None

    return corrected if corrected is not None else working, msg


def _run_semantic_phase_for_gui(
    filename: str,
    working: str,
    tree,
    listeners,
    parser,
    steps: List[str],
    logs: List[str],
    stats: Dict[str, int],
    green: Optional[GreenMetrics] = None,
):
    MAX_SEM_EDITS = 5
    sem_edits = 0

    if green is not None:
        green.start("semantic_phase")

    while sem_edits < MAX_SEM_EDITS:
        issues = _collect_semantic_issues(tree)

        if not issues:
            break

        first = issues[0]
        kind = first.get("kind")

        if kind == "unused":
            corrected, msg = _try_remove_unused_decl(working, first)

            if msg is None or corrected == working:
                break

            working = corrected
            steps.append(f"SEM: {msg}")
            logs.append(f"Applied semantic fix: {msg}")
            stats["sem_fixes"] = stats.get("sem_fixes", 0) + 1
            sem_edits += 1

            if green is not None:
                green.inc("sem_fixes")

            tree2, listeners2, parser2 = parse_source(working, f"{filename} (unused-removed)")
            if tree2 is None or has_any_errors(listeners2):
                remaining = get_all_error_strings(listeners2) if tree2 is not None else []
                if green is not None:
                    green.end("semantic_phase")
                return {
                    "status": "STOPPED",
                    "working": working,
                    "tree": tree2,
                    "listeners": listeners2,
                    "parser": parser2,
                    "semantic_issues": issues,
                    "parse_errors": remaining,
                }

            tree, listeners, parser = tree2, listeners2, parser2
            continue

        if kind == "undeclared":
            name = first.get("name")
            line = first.get("line")
            col = first.get("col")

            symbols = build_symbols(tree)
            corrected, msg = fix_identifier_typo_at(
                working,
                line,
                col,
                symbols,
                max_dist=2,
                expected_name=name,
            )

            if msg is None or corrected == working:
                break

            working = corrected
            steps.append(f"SEM: {msg}")
            logs.append(f"Applied semantic fix: {msg}")
            stats["sem_fixes"] = stats.get("sem_fixes", 0) + 1
            sem_edits += 1

            if green is not None:
                green.inc("sem_fixes")

            tree2, listeners2, parser2 = parse_source(working, f"{filename} (sym-fixed-sem)")
            if tree2 is None or has_any_errors(listeners2):
                remaining = get_all_error_strings(listeners2) if tree2 is not None else []
                if green is not None:
                    green.end("semantic_phase")
                return {
                    "status": "STOPPED",
                    "working": working,
                    "tree": tree2,
                    "listeners": listeners2,
                    "parser": parser2,
                    "semantic_issues": issues,
                    "parse_errors": remaining,
                }

            tree, listeners, parser = tree2, listeners2, parser2
            continue

        break

    issues = _collect_semantic_issues(tree)

    if green is not None:
        green.end("semantic_phase")

    return {
        "status": "SEM_CLEAN" if not issues else "SEM_ISSUES",
        "working": working,
        "tree": tree,
        "listeners": listeners,
        "parser": parser,
        "semantic_issues": issues,
    }


def _emit_progress(
    kind: str,
    message: str,
    working: str,
    steps: List[str],
    stats: Dict[str, int],
    status: str = "RUNNING",
) -> Dict[str, Any]:
    total_done = (
        stats.get("lex_fixes", 0)
        + stats.get("rule_fixes", 0)
        + stats.get("ai_fixes", 0)
        + stats.get("sym_fixes", 0)
        + stats.get("sem_fixes", 0)
    )

    return {
        "type": kind,
        "status": status,
        "message": message,
        "corrected_code": working,
        "applied_steps": steps[:],
        "stats": dict(stats),
        "total_repairs": total_done,
    }


def _finalize_green_report(
    green: GreenMetrics,
    filename: str,
    result: Dict[str, Any],
) -> None:
    green.set("status", result.get("status"))
    green.set("parse_success", result.get("status") not in {"STOPPED", "UNFIXABLE"})
    green.set("semantic_issue_count", len(result.get("semantic_issues", [])))
    green.set("security_warning_count", len(result.get("security_warnings", [])))

    metrics = green.to_dict()
    result["green_report"] = build_green_report(metrics)

    try:
        logger = GreenLogger()
        logger.log_run({
            "filename": filename,
            "status": result.get("status"),
            "green_report": result["green_report"],
            "stats": result.get("stats", {}),
        })
    except Exception:
        pass


def repair_source_for_gui_stream(
    source_text: str,
    filename: str = "main.c",
    autocorrect: bool = True,
):
    original_source = source_text
    working = source_text

    steps: List[str] = []
    logs: List[str] = []
    parse_errors: List[str] = []
    semantic_issues: List[Dict[str, Any]] = []
    security_warnings: List[str] = []
    security_changed_lines: List[int] = []

    MAX_LEX_EDITS = 5
    MAX_SYN_EDITS = 120
    NO_IMPROVE_LIMIT = 8
    REPEAT_LIMIT = 6

    stats = {
        "lex_fixes": 0,
        "rule_fixes": 0,
        "ai_fixes": 0,
        "sym_fixes": 0,
        "sem_fixes": 0,
        "iterations": 0,
    }

    # Step 1: Input Guardrail Check
    yield _emit_progress("guardrail", "Scanning input with AAI Guardrail...", working if autocorrect else original_source, steps, stats)
    guard_res = default_guardrail.scan_input(source_text, context={"filename": filename})
    if not guard_res.passed:
        yield _emit_progress(
            "guardrail_blocked",
            f"AAI Guardrail Alert: {guard_res.reason}",
            working if autocorrect else original_source,
            steps,
            stats,
            status="BLOCKED_AAI_ATTACK",
        )
        blocked_result = {
            "type": "done",
            "success": False,
            "status": "BLOCKED_AAI_ATTACK",
            "filename": filename,
            "original_code": original_source,
            "corrected_code": original_source if autocorrect else None,
            "autocorrect": autocorrect,
            "applied_steps": [],
            "logs": [f"AAI Guardrail Alert: {guard_res.reason}"],
            "errors": [f"Blocked malicious attack payload: {guard_res.quarantined_snippet}"],
            "semantic_issues": [],
            "security_warnings": [],
            "changed_lines": [],
            "security_changed_lines": [],
            "stats": stats,
            "green_report": {},
            "guardrail_report": guard_res.to_dict(),
            "suggestions": [],
            "total_applied_steps": 0,
            "total_repairs": 0,
        }
        yield blocked_result
        return

    yield _emit_progress("start", f"Started repairing {filename}", working if autocorrect else original_source, steps, stats)

    green = GreenMetrics()

    energy = GreenEnergyTracker()
    system = GreenSystemTracker()

    energy.start()
    system.start()

    green.start("total")
    green.start("lexical_phase")

    for _ in range(MAX_LEX_EDITS):
        new_src, lex_fix = fix_common_lexical_issues(working)
        if not lex_fix or new_src == working:
            break

        working = new_src
        step_msg = f"LEX: {lex_fix}"
        steps.append(step_msg)
        logs.append(f"Applied lexical fix: {lex_fix}")
        stats["lex_fixes"] += 1
        green.inc("lex_fixes")

        yield _emit_progress("fix", step_msg, working, steps, stats)

    green.end("lexical_phase")
    green.start("initial_parse")

    tree, listeners, parser = parse_source(working, f"{filename} (gui-after-lex)")

    green.end("initial_parse")

    if tree is None:
        green.end("total")
        final_payload = {
            "type": "done",
            "status": "STOPPED",
            "message": "Parsing stopped after lexical phase.",
            "corrected_code": working,
            "applied_steps": steps,
            "stats": stats,
            "logs": logs,
            "errors": parse_errors,
            "semantic_issues": [],
            "security_warnings": [],
            "changed_lines": _compute_changed_lines(original_source, working),
            "security_changed_lines": [],
            "success": False,
        }
        _finalize_green_report(green, filename, final_payload)
        yield final_payload
        return

    edits = 0
    parse_errors = get_all_error_strings(listeners) if has_any_errors(listeners) else []
    best_error_count = len(parse_errors)
    no_improve_rounds = 0
    last_sig = None
    repeat = 0

    green.start("syntax_repair")

    while has_any_errors(listeners) and edits < MAX_SYN_EDITS:
        stats["iterations"] += 1
        errs = get_all_error_strings(listeners)
        parse_errors = errs[:]

        error_obj = get_first_error_object(listeners)
        if not error_obj:
            break

        msg = error_obj["msg"]
        line = error_obj["line"]
        col = error_obj["column"]
        stage = error_obj.get("stage", "?")
        off = error_obj.get("offending")

        classification = classify_error_message(msg)

        yield _emit_progress(
            "detect",
            f"Detected {classification.reason} at line {line}",
            working,
            steps,
            stats,
        )

        sig = (stage, line, col, classification.reason, msg)
        if sig == last_sig:
            repeat += 1
        else:
            repeat = 0
        last_sig = sig

        if repeat >= REPEAT_LIMIT:
            break

        symbols = build_symbols(tree)

        if off and isinstance(off, str):
            import re
            if re.match(r"^[A-Za-z_][A-Za-z_0-9]*$", off):
                corrected, msg2 = fix_identifier_typo_at(working, line, col, symbols, max_dist=2)
                if msg2 is not None and corrected != working:
                    working = corrected
                    steps.append(f"SYM: {msg2}")
                    stats["sym_fixes"] += 1
                    green.inc("sym_fixes")
                    edits += 1

                    yield _emit_progress("fix", f"SYM: {msg2}", working, steps, stats)

                    tree, listeners, parser = parse_source(working, f"{filename} (gui-sym-fixed)")
                    if tree is None:
                        break

                    cur_error_count = len(get_all_error_strings(listeners))
                    if cur_error_count < best_error_count:
                        best_error_count = cur_error_count
                        no_improve_rounds = 0
                    else:
                        no_improve_rounds += 1

                    if no_improve_rounds >= NO_IMPROVE_LIMIT:
                        break

                    if not has_any_errors(listeners):
                        break
                    continue

        if stage == "LEX":
            candidates = ai_generate_patch_candidates(
                working, line, col, reason=classification.reason, top_k=5, debug=False
            )

            ai_src, cmd, tree2, listeners2, parser2 = _select_best_ai_candidate_by_reparse(
                filename, working, candidates
            )

            if cmd is None or ai_src == working or tree2 is None:
                break

            patch_check = default_guardrail.scan_candidate_patch(working, ai_src, context={"filename": filename, "source": "ai_stream"})
            if not patch_check.passed:
                yield _emit_progress("detect", f"Quarantined patch: {patch_check.reason}", working if autocorrect else original_source, steps, stats, status="UNFIXABLE")
                break

            working = ai_src
            steps.append(f"AI: {cmd}")
            stats["ai_fixes"] += 1
            green.inc("ai_fixes")
            edits += 1
            tree, listeners, parser = tree2, listeners2, parser2

            yield _emit_progress("fix", f"AI: {cmd}", working if autocorrect else original_source, steps, stats)

        else:
            deterministic_attempted = False
            deterministic_changed = False

            if classification.reason in DETERMINISTIC_REASONS:
                deterministic_attempted = True
                corrected, applied = apply_correction(working, line, col, classification)

                if applied is not None and corrected != working:
                    deterministic_changed = True
                    working = corrected
                    steps.append(f"RULE: {applied}")
                    stats["rule_fixes"] += 1
                    green.inc("rule_fixes")
                    edits += 1

                    tree, listeners, parser = parse_source(working, f"{filename} (gui-rule-fixed)")
                    if tree is None:
                        break

                    yield _emit_progress("fix", f"RULE: {applied}", working if autocorrect else original_source, steps, stats)

            if has_any_errors(listeners):
                if classification.reason not in DETERMINISTIC_REASONS or (
                    deterministic_attempted and not deterministic_changed
                ):
                    candidates = ai_generate_patch_candidates(
                        working, line, col, reason=classification.reason, top_k=5, debug=False
                    )

                    ai_src, cmd, tree2, listeners2, parser2 = _select_best_ai_candidate_by_reparse(
                        filename, working, candidates
                    )

                    if cmd is None or ai_src == working or tree2 is None:
                        break

                    patch_check = default_guardrail.scan_candidate_patch(working, ai_src, context={"filename": filename, "source": "ai_stream_fallback"})
                    if not patch_check.passed:
                        yield _emit_progress("detect", f"Quarantined patch: {patch_check.reason}", working if autocorrect else original_source, steps, stats, status="UNFIXABLE")
                        break

                    working = ai_src
                    steps.append(f"AI: {cmd}")
                    stats["ai_fixes"] += 1
                    green.inc("ai_fixes")
                    edits += 1
                    tree, listeners, parser = tree2, listeners2, parser2

                    yield _emit_progress("fix", f"AI: {cmd}", working if autocorrect else original_source, steps, stats)

        cur_error_count = len(get_all_error_strings(listeners))
        if cur_error_count < best_error_count:
            best_error_count = cur_error_count
            no_improve_rounds = 0
        else:
            no_improve_rounds += 1

        if no_improve_rounds >= NO_IMPROVE_LIMIT:
            break

        if not has_any_errors(listeners):
            break

    green.end("syntax_repair")

    final_result = repair_source_for_gui(original_source, filename, autocorrect=autocorrect)
    final_result["type"] = "done"
    final_result["total_repairs"] = (
        final_result["stats"].get("lex_fixes", 0)
        + final_result["stats"].get("rule_fixes", 0)
        + final_result["stats"].get("ai_fixes", 0)
        + final_result["stats"].get("sym_fixes", 0)
        + final_result["stats"].get("sem_fixes", 0)
    )
    yield final_result


def repair_source_for_gui(
    source_text: str,
    filename: str = "main.c",
    autocorrect: bool = True,
) -> Dict[str, Any]:
    original_source = source_text
    working = source_text

    steps: List[str] = []
    logs: List[str] = []
    parse_errors: List[str] = []
    semantic_issues: List[Dict[str, Any]] = []
    security_warnings: List[str] = []
    security_changed_lines: List[int] = []

    MAX_LEX_EDITS = 5
    MAX_SYN_EDITS = 120
    MAX_SECURITY_ROUNDS = 5
    NO_IMPROVE_LIMIT = 8
    REPEAT_LIMIT = 6

    stats = {
        "lex_fixes": 0,
        "rule_fixes": 0,
        "ai_fixes": 0,
        "sym_fixes": 0,
        "sem_fixes": 0,
        "iterations": 0,
    }

    # Step 1: Input Guardrail Check
    guard_res = default_guardrail.scan_input(source_text, context={"filename": filename})
    if not guard_res.passed:
        logs.append(f"AAI Guardrail Alert: {guard_res.reason}")
        return {
            "success": False,
            "status": "BLOCKED_AAI_ATTACK",
            "filename": filename,
            "original_code": original_source,
            "corrected_code": original_source if autocorrect else None,
            "autocorrect": autocorrect,
            "applied_steps": [],
            "logs": logs,
            "errors": [f"Blocked malicious attack payload: {guard_res.quarantined_snippet}"],
            "semantic_issues": [],
            "security_warnings": [],
            "changed_lines": [],
            "security_changed_lines": [],
            "stats": stats,
            "green_report": {},
            "guardrail_report": guard_res.to_dict(),
            "suggestions": [],
            "total_applied_steps": 0,
        }

    green = GreenMetrics()

    energy = GreenEnergyTracker()
    system = GreenSystemTracker()

    energy.start()
    system.start()

    green.start("total")

    result: Dict[str, Any] = {
        "success": False,
        "status": "STOPPED",
        "filename": filename,
        "original_code": original_source,
        "corrected_code": working if autocorrect else None,
        "autocorrect": autocorrect,
        "applied_steps": [],
        "logs": [],
        "errors": [],
        "semantic_issues": [],
        "security_warnings": [],
        "changed_lines": [],
        "security_changed_lines": [],
        "stats": stats,
        "green_report": {},
        "guardrail_report": guard_res.to_dict(),
        "suggestions": [],
    }

    # ---------------------------------------------------------
    # Phase 1: lexical cleanup
    # ---------------------------------------------------------
    green.start("lexical_phase")

    for _ in range(MAX_LEX_EDITS):
        new_src, lex_fix = fix_common_lexical_issues(working)
        if not lex_fix or new_src == working:
            break

        working = new_src
        step_msg = f"LEX: {lex_fix}"
        steps.append(step_msg)
        logs.append(f"Applied lexical fix: {lex_fix}")
        stats["lex_fixes"] += 1
        green.inc("lex_fixes")

    green.end("lexical_phase")

    # ---------------------------------------------------------
    # Initial parse after lexical cleanup
    # ---------------------------------------------------------
    green.start("initial_parse")
    tree, listeners, parser = parse_source(working, f"{filename} (gui-after-lex)")
    green.end("initial_parse")

    if tree is None:
        result["status"] = "STOPPED"
        result["corrected_code"] = working
        result["applied_steps"] = steps
        result["logs"] = logs + ["Parsing stopped: tree is None after lexical phase."]
        result["changed_lines"] = _compute_changed_lines(original_source, working)
        result["security_changed_lines"] = []
        green.end("total")
        _finalize_green_report(green, filename, result)
        return result

    if has_any_errors(listeners):
        parse_errors = get_all_error_strings(listeners)

    # ---------------------------------------------------------
    # Phase 2: syntax repair loop
    # ---------------------------------------------------------
    edits = 0
    best_error_count = len(parse_errors) if parse_errors else 0
    no_improve_rounds = 0
    last_sig = None
    repeat = 0

    green.start("syntax_repair")

    while has_any_errors(listeners) and edits < MAX_SYN_EDITS:
        stats["iterations"] += 1
        errs = get_all_error_strings(listeners)
        parse_errors = errs[:]
        logs.append("Parsing failed; attempting repair.")
        logs.extend(errs)

        error_obj = get_first_error_object(listeners)
        if not error_obj:
            result["status"] = "STOPPED"
            break

        msg = error_obj["msg"]
        line = error_obj["line"]
        col = error_obj["column"]
        stage = error_obj.get("stage", "?")
        off = error_obj.get("offending")

        classification = classify_error_message(msg)

        logs.append(
            f"Classified error -> stage={stage}, category={classification.category}, "
            f"reason={classification.reason}, fixable={classification.fixable}"
        )

        sig = (stage, line, col, classification.reason, msg)
        if sig == last_sig:
            repeat += 1
        else:
            repeat = 0
        last_sig = sig

        if repeat >= REPEAT_LIMIT:
            logs.append("Stopping: repeating same error (stuck).")
            result["status"] = "STOPPED"
            break

        symbols = build_symbols(tree)

        if off and isinstance(off, str):
            import re
            if re.match(r"^[A-Za-z_][A-Za-z_0-9]*$", off):
                corrected, msg2 = fix_identifier_typo_at(working, line, col, symbols, max_dist=2)
                if msg2 is not None and corrected != working:
                    working = corrected
                    steps.append(f"SYM: {msg2}")
                    logs.append(f"Applied symbol fix: {msg2}")
                    stats["sym_fixes"] += 1
                    green.inc("sym_fixes")
                    edits += 1

                    tree, listeners, parser = parse_source(working, f"{filename} (gui-sym-fixed)")
                    if tree is None:
                        result["status"] = "STOPPED"
                        break

                    cur_error_count = len(get_all_error_strings(listeners))
                    if cur_error_count < best_error_count:
                        best_error_count = cur_error_count
                        no_improve_rounds = 0
                    else:
                        no_improve_rounds += 1

                    if no_improve_rounds >= NO_IMPROVE_LIMIT:
                        logs.append("Stopping: not improving error count (stuck).")
                        result["status"] = "STOPPED"
                        break

                    if not has_any_errors(listeners):
                        break

                    continue

        if stage == "LEX":
            logs.append("Lexer-stage error remains; invoking AI patch candidates.")

            candidates = ai_generate_patch_candidates(
                working,
                line,
                col,
                reason=classification.reason,
                top_k=5,
                debug=False,
            )

            ai_src, cmd, tree2, listeners2, parser2 = _select_best_ai_candidate_by_reparse(
                filename,
                working,
                candidates,
            )

            if cmd is None or ai_src == working or tree2 is None:
                logs.append("AI: no valid patch produced.")
                result["status"] = "UNFIXABLE"
                break

            patch_check = default_guardrail.scan_candidate_patch(working, ai_src, context={"filename": filename, "source": "ai_repair"})
            if not patch_check.passed:
                logs.append(f"AAI Guardrail quarantined AI candidate patch: {patch_check.reason}")
                result["status"] = "UNFIXABLE"
                break

            working = ai_src
            steps.append(f"AI: {cmd}")
            logs.append(f"Applied AI patch: {cmd}")
            stats["ai_fixes"] += 1
            green.inc("ai_fixes")
            edits += 1

            tree, listeners, parser = tree2, listeners2, parser2

        else:
            deterministic_attempted = False
            deterministic_changed = False

            if classification.reason in DETERMINISTIC_REASONS:
                deterministic_attempted = True
                corrected, applied = apply_correction(working, line, col, classification)

                if applied is not None and corrected != working:
                    deterministic_changed = True
                    working = corrected
                    steps.append(f"RULE: {applied}")
                    logs.append(f"Applied deterministic fix: {applied}")
                    stats["rule_fixes"] += 1
                    green.inc("rule_fixes")
                    edits += 1

                    tree, listeners, parser = parse_source(working, f"{filename} (gui-rule-fixed)")
                    if tree is None:
                        result["status"] = "STOPPED"
                        break
                else:
                    logs.append("Deterministic fix made no change; allowing AI fallback.")

            if has_any_errors(listeners):
                if classification.reason not in DETERMINISTIC_REASONS or (
                    deterministic_attempted and not deterministic_changed
                ):
                    logs.append("Invoking AI patch-based correction.")

                    candidates = ai_generate_patch_candidates(
                        working,
                        line,
                        col,
                        reason=classification.reason,
                        top_k=5,
                        debug=False,
                    )

                    ai_src, cmd, tree2, listeners2, parser2 = _select_best_ai_candidate_by_reparse(
                        filename,
                        working,
                        candidates,
                    )

                    if cmd is None or ai_src == working or tree2 is None:
                        logs.append("AI: no valid patch produced.")
                        result["status"] = "UNFIXABLE"
                        break

                    patch_check = default_guardrail.scan_candidate_patch(working, ai_src, context={"filename": filename, "source": "ai_fallback"})
                    if not patch_check.passed:
                        logs.append(f"AAI Guardrail quarantined AI candidate patch: {patch_check.reason}")
                        result["status"] = "UNFIXABLE"
                        break

                    working = ai_src
                    steps.append(f"AI: {cmd}")
                    logs.append(f"Applied AI patch: {cmd}")
                    stats["ai_fixes"] += 1
                    green.inc("ai_fixes")
                    edits += 1

                    tree, listeners, parser = tree2, listeners2, parser2

        cur_error_count = len(get_all_error_strings(listeners))
        if cur_error_count < best_error_count:
            best_error_count = cur_error_count
            no_improve_rounds = 0
        else:
            no_improve_rounds += 1

        if no_improve_rounds >= NO_IMPROVE_LIMIT:
            logs.append("Stopping: not improving error count (stuck).")
            result["status"] = "STOPPED"
            break

        if not has_any_errors(listeners):
            break

    green.end("syntax_repair")

    # ---------------------------------------------------------
    # Final status after syntax phase
    # ---------------------------------------------------------
    if tree is None:
        result["status"] = "STOPPED"
    elif has_any_errors(listeners):
        if result["status"] not in {"STOPPED", "UNFIXABLE"}:
            result["status"] = "UNFIXABLE"
        parse_errors = get_all_error_strings(listeners)
    else:
        result["status"] = "PARSE_SUCCESS"

    # ---------------------------------------------------------
    # Phase 3: semantic + iterative security
    # ---------------------------------------------------------
    if tree is not None and not has_any_errors(listeners):
        security_rounds = 0

        while True:
            sem_result = _run_semantic_phase_for_gui(
                filename,
                working,
                tree,
                listeners,
                parser,
                steps,
                logs,
                stats,
                green=green,
            )

            working = sem_result["working"]
            tree = sem_result["tree"]
            listeners = sem_result["listeners"]
            parser = sem_result["parser"]
            semantic_issues = sem_result.get("semantic_issues", [])
            parse_errors = sem_result.get("parse_errors", parse_errors)

            if sem_result["status"] == "STOPPED":
                result["status"] = "STOPPED"
                result["success"] = False
                break

            green.start("security_phase")
            security_warnings = _collect_security_issues(working)

            if security_warnings:
                logs.append(f"Security issues detected: {len(security_warnings)}")
                logs.append("Invoking SecurityAutoFixer for GUI parity with CLI.")

                try:
                    auto_fixer = SecurityAutoFixer()
                    fix_result = auto_fixer.apply_fixes(working)

                    if fix_result.source != working:
                        patch_check = default_guardrail.scan_candidate_patch(working, fix_result.source, context={"filename": filename, "source": "security_fixer"})
                        if not patch_check.passed:
                            logs.append(f"AAI Guardrail quarantined security fix: {patch_check.reason}")
                        else:
                            changed_now = _compute_changed_lines(working, fix_result.source)
                            security_changed_lines = sorted(set(security_changed_lines + changed_now))

                            for step in fix_result.applied_steps:
                                steps.append(step)
                                logs.append(f"Applied security fix: {step}")

                            ai_sec_count = sum(1 for s in fix_result.applied_steps if s.startswith("AISEC:"))
                            stats["ai_fixes"] += ai_sec_count
                            if ai_sec_count > 0:
                                green.inc("ai_fixes", ai_sec_count)

                            working = fix_result.source
                            security_rounds += 1

                            if security_rounds > MAX_SECURITY_ROUNDS:
                                green.end("security_phase")
                                logs.append("Stopping: exceeded maximum security reparse rounds.")
                                result["status"] = "STOPPED"
                                result["success"] = False
                                break

                            tree2, listeners2, parser2 = parse_source(
                                working,
                                f"{filename} (gui-after-security-{security_rounds})",
                            )

                            if tree2 is None or has_any_errors(listeners2):
                                green.end("security_phase")
                                logs.append("Stopping: security fix broke parsing.")
                                parse_errors = get_all_error_strings(listeners2) if tree2 is not None else []
                                result["status"] = "STOPPED"
                                result["success"] = False
                                tree = tree2
                                listeners = listeners2
                                parser = parser2
                                break

                            tree, listeners, parser = tree2, listeners2, parser2
                            green.end("security_phase")
                            continue

                    logs.append("SecurityAutoFixer produced no code change.")
                except Exception as e:
                    logs.append(f"Security auto-fix failed: {str(e)}")

            green.end("security_phase")

            if semantic_issues:
                result["status"] = "SEM_ISSUES"
                result["success"] = True
                break

            final_status = _status_from_security(security_warnings)

            if security_warnings:
                logs.append(f"Security warnings remaining: {len(security_warnings)}")
            else:
                logs.append("No security warnings found.")

            result["status"] = final_status
            result["success"] = final_status in {"SUCCESS", "SUCCESS_WITH_WARNINGS"}
            break

        result["semantic_issues"] = semantic_issues
        result["security_warnings"] = security_warnings

    else:
        result["semantic_issues"] = []
        result["security_warnings"] = _collect_security_issues(working)
        result["success"] = False

    # ---------------------------------------------------------
    # Final payload
    # ---------------------------------------------------------
    changed_lines = _compute_changed_lines(original_source, working)
    suggestions = _build_suggestions(original_source, working, steps)

    result["original_code"] = original_source
    result["autocorrect"] = autocorrect
    result["corrected_code"] = working if autocorrect else None
    result["suggestions"] = suggestions
    result["applied_steps"] = steps
    result["logs"] = logs
    result["errors"] = parse_errors
    result["changed_lines"] = changed_lines if autocorrect else []
    result["security_changed_lines"] = security_changed_lines if autocorrect else []
    result["stats"] = stats
    result["total_applied_steps"] = len(steps)
    logs.append(f"Total applied steps: {len(steps)}")

    if not autocorrect and result.get("success"):
        result["status"] = "SUGGESTIONS_READY"

    green.end("total")

    system.sample()
    sys_stats = system.stop()
    energy_stats = energy.stop()

    for k, v in sys_stats.items():
        green.set(k, v)

    for k, v in energy_stats.items():
        green.set(k, v)

    _finalize_green_report(green, filename, result)

    return result