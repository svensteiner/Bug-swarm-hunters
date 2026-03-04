"""
process_hunter.py — Sucht subprocess/Process ohne cleanup via AST.

Typisches Bug-Pattern:
  p = multiprocessing.Process(target=worker)
  p.start()
  # kein p.terminate() in finally-Block → Zombie-Process auf Windows

Windows killt Child-Processes NICHT automatisch wenn Parent stirbt.
Dies war der Root-Cause des Trader-Exit-Bugs (MEMORY.md).

Open-Source Bug Hunter Arena — MIT License
"""
from __future__ import annotations

import ast
from pathlib import Path

from core.base_hunter import BaseHunter, BugFinding
import logging

logger = logging.getLogger("bug_swarm")

# Process-Typen die cleanup benötigen
_PROCESS_TYPES = {
    "Process",          # multiprocessing.Process
    "Thread",           # threading.Thread
    "Popen",            # subprocess.Popen
}

# Cleanup-Methoden die als ausreichend gelten
_CLEANUP_METHODS = {"terminate", "kill", "join", "wait", "close"}


class ProcessHunter(BaseHunter):
    """
    Sucht Process()/Thread()-Instanziierungen ohne terminate() in finally-Block.

    Besonders kritisch auf Windows: keine automatische Child-Termination
    wenn Parent-Process stirbt → Zombie-Processes die DB und State blockieren.
    """

    name = "ProcessHunter"
    specialty = "process_leak"
    description = "Process/Thread ohne terminate() in finally → Zombie-Processes auf Windows"

    def hunt(self, project_root: Path) -> list[BugFinding]:
        findings: list[BugFinding] = []
        for py_file in project_root.rglob("*.py"):
            if self._should_skip(py_file, project_root):
                continue
            findings.extend(self._scan_file(py_file, project_root))
        return findings

    def _should_skip(self, path: Path, root: Path) -> bool:
        skip = {"venv", "venv_win", ".git", "__pycache__", "tests", "hunters"}
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

        # Klassen die irgendwo terminate()/kill() aufrufen → lifecycle managed
        class_has_cleanup: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                    if child.func.attr in _CLEANUP_METHODS:
                        class_has_cleanup.add(node.name)
                        break

        # Funktionen prüfen — aber nicht wenn Klasse eigenes Cleanup hat
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Methode in einer Klasse mit eigenem Cleanup? → überspringen
            parent_class = self._get_parent_class(tree, node)
            if parent_class and parent_class in class_has_cleanup:
                continue
            findings.extend(self._check_function(node, lines, rel_path))

        return findings

    def _get_parent_class(self, tree: ast.AST, func: ast.FunctionDef) -> str | None:
        """Gibt den Namen der umschließenden Klasse zurück, falls vorhanden."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for child in ast.walk(node):
                if child is func:
                    return node.name
        return None

    def _check_function(
        self, func: ast.FunctionDef, lines: list[str], rel_path: str
    ) -> list[BugFinding]:
        """Prüft eine Funktion auf multiprocessing.Process ohne Cleanup."""
        findings: list[BugFinding] = []
        risky = self._find_risky_processes(func)
        if not risky:
            return findings

        has_cleanup = self._has_process_cleanup(func)
        if not has_cleanup:
            for cls_name, lineno in risky:
                line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
                findings.append(self._make_finding(
                    severity="high",
                    file_path=rel_path,
                    line_number=lineno,
                    description=(
                        f"multiprocessing.{cls_name}() ohne terminate() in finally "
                        f"→ Zombie-Process auf Windows möglich"
                    ),
                    evidence=line_text,
                    suggested_fix=(
                        f"Umhülle mit try/finally:\n"
                        f"  p = {cls_name}(...)\n"
                        f"  p.start()\n"
                        f"  try:\n"
                        f"      ...\n"
                        f"  finally:\n"
                        f"      p.terminate()\n"
                        f"      p.join(timeout=5)"
                    ),
                ))
        return findings

    def _find_risky_processes(
        self, func: ast.FunctionDef
    ) -> list[tuple[str, int]]:
        """
        Sucht multiprocessing.Process() Konstruktoren OHNE daemon=True.

        Wichtig:
        - threading.Thread(daemon=True) ist safe → ignoriert
        - psutil.Process() liest existierende Prozesse → ignoriert
        - multiprocessing.Process() ohne daemon → potentieller Zombie
        """
        risky: list[tuple[str, int]] = []
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            cls_name = self._extract_constructor_name(node)
            if cls_name != "Process":
                continue
            # psutil.Process(pid) liest existierende Prozesse, erstellt keine neuen
            if isinstance(node.func, ast.Attribute):
                module = node.func.value
                if isinstance(module, ast.Name) and module.id == "psutil":
                    continue
                if isinstance(module, ast.Attribute) and module.attr == "psutil":
                    continue
            # Hat daemon=True? Dann safe.
            has_daemon = any(
                kw.arg == "daemon"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value
                for kw in node.keywords
            )
            if not has_daemon:
                lineno = getattr(node, "lineno", 0)
                risky.append((cls_name, lineno))
        return risky

    def _extract_constructor_name(self, node: ast.Call) -> str:
        """Extrahiert den Klassennamen aus einem Call-Node."""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return ""

    def _has_process_cleanup(self, func: ast.FunctionDef) -> bool:
        """Prüft ob eine try/finally-Cleanup-Struktur vorhanden ist."""
        for node in ast.walk(func):
            if not isinstance(node, ast.Try):
                continue
            # Prüfe finally-Block auf cleanup-Methoden
            for finally_node in node.finalbody:
                for sub in ast.walk(finally_node):
                    if isinstance(sub, ast.Call):
                        if isinstance(sub.func, ast.Attribute):
                            if sub.func.attr in _CLEANUP_METHODS:
                                return True
                    # terminate() direkt
                    if isinstance(sub, ast.Expr) and isinstance(sub.value, ast.Call):
                        call = sub.value
                        if isinstance(call.func, ast.Attribute):
                            if call.func.attr in _CLEANUP_METHODS:
                                return True
        return False
