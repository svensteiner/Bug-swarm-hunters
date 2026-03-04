"""
schema_hunter.py — Sucht cls(**data) ohne Key-Filterung via AST.

Typisches Bug-Pattern:
  obj = SomeDataclass(**data_dict)   # TypeError bei Extra-Keys

Das ist der Root-Cause des 0-Trades Bugs (TradingSignal.from_dict):
Analyzer fügt extra Keys in Signal-Dict → from_dict(**data) → TypeError.

Open-Source Bug Hunter Arena — MIT License
"""
from __future__ import annotations

import ast
from pathlib import Path

from core.base_hunter import BaseHunter, BugFinding
import logging

logger = logging.getLogger("bug_swarm")

# Klassen die häufig mit **dict instanziiert werden
_RISKY_CONSTRUCTORS = {
    "TradingSignal", "Order", "Position", "Trade", "Config",
    "AgentMessage", "HealResult", "BugFinding",
}


class SchemaHunter(BaseHunter):
    """
    Sucht `cls(**data)` ohne vorangehende Key-Filterung.

    Das führt zu TypeError bei Extra-Keys (z.B. nach API-Versionswechsel
    oder wenn Upstream-Code mehr Keys hinzufügt als der Dataclass bekannt sind).

    Methode: AST-Scan auf Call-Nodes mit **kwargs-Expansion.
    """

    name = "SchemaHunter"
    specialty = "schema_mismatch"
    description = "cls(**data) ohne Key-Filterung → TypeError bei Extra-Keys"

    def hunt(self, project_root: Path) -> list[BugFinding]:
        findings: list[BugFinding] = []
        for py_file in project_root.rglob("*.py"):
            if self._should_skip(py_file, project_root):
                continue
            findings.extend(self._scan_file(py_file, project_root))
        return findings

    def _should_skip(self, path: Path, root: Path) -> bool:
        skip = {"venv", "venv_win", ".git", "__pycache__", "tests", "node_modules"}
        return any(part in skip for part in path.parts)

    def _scan_file(self, path: Path, root: Path) -> list[BugFinding]:
        findings: list[BugFinding] = []
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, OSError):
            return findings

        rel_path = str(path.relative_to(root))
        lines = source.splitlines()

        # Suche alle from_dict / __init__ Methoden mit cls(**...) Pattern
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name in ("from_dict", "from_json", "deserialize", "load"):
                finding = self._check_from_dict(node, lines, rel_path)
                if finding:
                    findings.append(finding)

        # Suche direkte cls(**data) Calls
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            finding = self._check_unfiltered_call(node, lines, rel_path)
            if finding:
                findings.append(finding)

        return findings

    def _check_from_dict(
        self, func: ast.FunctionDef, lines: list[str], rel_path: str
    ) -> BugFinding | None:
        """Prüft ob from_dict cls(**data) ohne Filterung aufruft."""
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            # cls(**data) oder ClassName(**data)
            has_kwargs = any(
                isinstance(arg, ast.Starred) or (isinstance(kw, ast.keyword) and kw.arg is None)
                for kw in node.keywords
                for arg in ([] if not hasattr(node, "starargs") else [])
            )
            has_double_star = any(
                isinstance(kw, ast.keyword) and kw.arg is None
                for kw in node.keywords
            )
            if not has_double_star:
                continue

            # Prüfe ob Key-Filterung vorhanden (known_fields, dataclasses.fields)
            func_source = "\n".join(
                lines[func.lineno - 1: getattr(func, "end_lineno", func.lineno + 20)]
            )
            has_filter = any(
                kw in func_source
                for kw in ("known_fields", "dataclasses.fields", "fields(cls)", "get_fields", "filter")
            )
            if has_filter:
                return None  # Bereits gesichert

            lineno = getattr(node, "lineno", None)
            line_text = lines[lineno - 1].strip() if lineno and lineno <= len(lines) else ""
            return self._make_finding(
                severity="critical",
                file_path=rel_path,
                line_number=lineno,
                description=(
                    f"from_dict() nutzt **data ohne Key-Filterung → "
                    f"TypeError bei Extra-Keys (Root-Cause: 0-Trades Bug)"
                ),
                evidence=line_text,
                suggested_fix=(
                    "Füge Key-Filterung hinzu:\n"
                    "  known = {f.name for f in dataclasses.fields(cls)}\n"
                    "  filtered = {k: v for k, v in data.items() if k in known}\n"
                    "  return cls(**filtered)"
                ),
            )
        return None

    def _check_unfiltered_call(
        self, node: ast.Call, lines: list[str], rel_path: str
    ) -> BugFinding | None:
        """Sucht direkte ClassName(**dict_var) Calls für bekannte Dataclasses."""
        has_double_star = any(
            isinstance(kw, ast.keyword) and kw.arg is None
            for kw in node.keywords
        )
        if not has_double_star:
            return None

        # Prüfe ob bekannter Konstruktor
        func = node.func
        cls_name = None
        if isinstance(func, ast.Name):
            cls_name = func.id
        elif isinstance(func, ast.Attribute):
            cls_name = func.attr

        if cls_name not in _RISKY_CONSTRUCTORS:
            return None

        lineno = getattr(node, "lineno", None)
        line_text = lines[lineno - 1].strip() if lineno and lineno <= len(lines) else ""
        return self._make_finding(
            severity="high",
            file_path=rel_path,
            line_number=lineno,
            description=f"{cls_name}(**data) ohne Key-Filterung",
            evidence=line_text,
            suggested_fix=(
                f"Filtere Keys vor Instantiierung:\n"
                f"  known = {{f.name for f in dataclasses.fields({cls_name})}}\n"
                f"  {cls_name}(**{{k: v for k, v in data.items() if k in known}})"
            ),
        )
