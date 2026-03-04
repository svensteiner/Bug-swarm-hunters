"""
data_boundary_hunter.py — Sucht hardcoded >= 200 Annahmen via AST.

Typische Bugs:
  - lookback=200 (Indikator-Perioden)
  - MA200 / SMA200 (hardcoded Fenstergröße)
  - if len(df) >= 200: (Datenmenge-Annahmen)
  - Binance liefert max 200 Klines per Default → führt zu "Not enough data"

Open-Source Bug Hunter Arena — MIT License
"""
from __future__ import annotations

import ast
from pathlib import Path

from core.base_hunter import BaseHunter, BugFinding
import logging

logger = logging.getLogger("bug_swarm")

# Verdächtige numerische Werte (Boundary-Konstanten)
_SUSPICIOUS_VALUES = {200, 500, 1000, 1440, 288}  # Typische Candlestick-Grenzen

# Verdächtige String-Patterns im Code (als Substring)
_SUSPICIOUS_STRINGS = ["MA200", "SMA200", "EMA200", "lookback_200", "LOOKBACK_200"]


class DataBoundaryHunter(BaseHunter):
    """
    Sucht hardcoded Datenmenge-Annahmen die zu "Not enough data"-Bugs führen.

    Methode: AST-Scan aller .py-Dateien → Konstante >= 200 in kritischen Kontexten.
    """

    name = "DataBoundaryHunter"
    specialty = "data_boundary"
    description = "Hardcoded >= 200 Annahmen die Indikator-Berechnungen blockieren"

    def hunt(self, project_root: Path) -> list[BugFinding]:
        findings: list[BugFinding] = []
        py_files = list(project_root.rglob("*.py"))
        for py_file in py_files:
            if self._should_skip(py_file, project_root):
                continue
            findings.extend(self._scan_file(py_file, project_root))
        return findings

    def _should_skip(self, path: Path, root: Path) -> bool:
        rel = str(path.relative_to(root))
        skip_dirs = {"venv", "venv_win", ".git", "__pycache__", "tests", "node_modules"}
        return any(part in skip_dirs for part in path.parts)

    def _scan_file(self, path: Path, root: Path) -> list[BugFinding]:
        findings: list[BugFinding] = []
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, OSError):
            return findings

        rel_path = str(path.relative_to(root))
        lines = source.splitlines()

        for node in ast.walk(tree):
            finding = self._check_node(node, lines, rel_path)
            if finding:
                findings.append(finding)

        return findings

    def _check_node(
        self, node: ast.AST, lines: list[str], rel_path: str
    ) -> BugFinding | None:
        # Konstante: >= 200 in Vergleichsausdruck
        if isinstance(node, ast.Compare):
            for comparator in node.comparators:
                if isinstance(comparator, ast.Constant) and comparator.value in _SUSPICIOUS_VALUES:
                    lineno = getattr(node, "lineno", None)
                    line_text = lines[lineno - 1].strip() if lineno and lineno <= len(lines) else ""
                    # HTTP-Statuscodes und Cache-Limits ausschließen
                    if "status_code" in line_text or "cache" in line_text.lower():
                        continue
                    # Pagination: "if len(x) < N: break" oder "while len(x) < N:"
                    if "break" in line_text or line_text.strip().startswith("while"):
                        continue
                    # String-Truncation: "[:N]" oder "truncat"
                    if "[:" in line_text or "truncat" in line_text.lower():
                        continue
                    # Security-Input-Validation: return/raise nach dem Check
                    if any(kw in line_text for kw in ("return", "raise", "Error", "invalid")):
                        continue
                    # Kommentar deutet auf bewusste Limit/Security-Prüfung hin
                    if "# " in line_text and any(
                        kw in line_text.lower() for kw in ("prevent", "limit", "max", "security", "input")
                    ):
                        continue
                    if any(kw in line_text for kw in ("len(", "lookback", "period", "window")):
                        return self._make_finding(
                            severity="high",
                            file_path=rel_path,
                            line_number=lineno,
                            description=f"Hardcoded Datenmenge-Check mit {comparator.value}",
                            evidence=line_text,
                            suggested_fix=(
                                f"Ersetze {comparator.value} durch konfigurierbare Konstante "
                                f"(z.B. MIN_CANDLES = {comparator.value}) in config/strategy_config.json"
                            ),
                        )

        # Keyword-Argument: lookback=200, period=200
        if isinstance(node, ast.keyword):
            if (
                node.arg in ("lookback", "period", "window", "length", "timeperiod")
                and isinstance(node.value, ast.Constant)
                and node.value.value in _SUSPICIOUS_VALUES
            ):
                lineno = getattr(node, "lineno", None)
                line_text = lines[lineno - 1].strip() if lineno and lineno <= len(lines) else ""
                # Pagination / Truncation / Validation auch hier ausschließen
                if any(kw in line_text for kw in ("break", "truncat", "return", "raise")):
                    return None
                if "[:" in line_text:
                    return None
                return self._make_finding(
                    severity="medium",
                    file_path=rel_path,
                    line_number=lineno,
                    description=f"Hardcoded Indikator-Parameter {node.arg}={node.value.value}",
                    evidence=line_text,
                    suggested_fix=(
                        f"Lese {node.arg} aus strategy_config.json statt hardcoded {node.value.value}"
                    ),
                )

        return None
