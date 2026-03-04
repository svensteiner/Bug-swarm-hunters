"""
time_window_hunter.py — Sucht 24h-Fenster Deadlocks via Grep + Kontext.

Typisches Bug-Pattern:
  if time.time() - last_update > 86400:  # 24h Cooldown
  → Bei Paper-Trading: Bot lernt/adaptiert nicht in 24h → Signal-Starvation

Sucht nach hardcoded zeitlichen Constraints die im Paper-Trading zu
langen Stagnations-Phasen führen.

Open-Source Bug Hunter Arena — MIT License
"""
from __future__ import annotations

import re
from pathlib import Path

from core.base_hunter import BaseHunter, BugFinding
import logging

logger = logging.getLogger("bug_swarm")

# Sekunden-Werte die zu lange Wartezeiten sind
_LONG_COOLDOWNS_SECONDS = {
    86400: "24h",
    43200: "12h",
    7 * 86400: "7d",
    3 * 86400: "3d",
}

# Patterns die auf Cooldown/Throttle-Code hindeuten
_COOLDOWN_PATTERNS = [
    r"86400",           # 24h in Sekunden
    r"timedelta\(hours=24\)",
    r"timedelta\(days=\d+\)",
    r"COOLDOWN.*=.*86400",
    r"_COOLDOWN.*=.*\d{4,}",
    r"hours=24",
    r"hours=48",
    r"hours=72",
]

# Kontext-Schlüsselwörter die echte Deadlocks anzeigen
_DEADLOCK_CONTEXT = {
    "density", "last_update", "last_scan", "last_retrain",
    "last_evolution", "last_bug_hunt", "cooldown", "throttle",
}


class TimeWindowHunter(BaseHunter):
    """
    Sucht zeitliche Constraints (Cooldowns/Throttles) die im Paper-Trading
    zu langen Stagnations-Phasen führen.

    Methode: Regex-Scan + Zeilen-Kontext-Analyse.
    """

    name = "TimeWindowHunter"
    specialty = "time_window"
    description = "24h-Fenster Deadlocks → Bot lernt/adaptiert nicht schnell genug"

    def hunt(self, project_root: Path) -> list[BugFinding]:
        findings: list[BugFinding] = []
        for py_file in project_root.rglob("*.py"):
            if self._should_skip(py_file, project_root):
                continue
            findings.extend(self._scan_file(py_file, project_root))
        return findings

    def _should_skip(self, path: Path, root: Path) -> bool:
        skip = {"venv", "venv_win", ".git", "__pycache__", "tests", "node_modules", "hunters"}
        return any(part in skip for part in path.parts)

    def _scan_file(self, path: Path, root: Path) -> list[BugFinding]:
        findings: list[BugFinding] = []
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings

        rel_path = str(path.relative_to(root))
        lines = source.splitlines()

        compiled = [re.compile(p) for p in _COOLDOWN_PATTERNS]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for pattern in compiled:
                if not pattern.search(line):
                    continue

                # Kontext-Check: Ist das wirklich ein problematisches Cooldown?
                context = self._get_context(lines, i, window=3)
                severity, note = self._assess_severity(line, context)

                if severity is None:
                    continue

                # Suche den konkreten Sekunden-Wert
                seconds_value = self._extract_seconds(line)
                human_time = _LONG_COOLDOWNS_SECONDS.get(seconds_value, f"{seconds_value}s")

                findings.append(self._make_finding(
                    severity=severity,
                    file_path=rel_path,
                    line_number=i,
                    description=(
                        f"Hardcoded {human_time}-Cooldown → "
                        f"Im Paper-Trading zu langsam für effektives Lernen. {note}"
                    ),
                    evidence=stripped,
                    suggested_fix=(
                        f"Erwäge DRY_RUN-spezifischen Cooldown:\n"
                        f"  if os.getenv('DRY_RUN') == '1':\n"
                        f"      cooldown = {seconds_value} // 4  # 4x schneller im Paper-Trading\n"
                        f"  else:\n"
                        f"      cooldown = {seconds_value}"
                    ),
                ))
                break  # Pro Zeile nur ein Finding

        return findings

    def _get_context(self, lines: list[str], lineno: int, window: int = 3) -> str:
        start = max(0, lineno - window - 1)
        end = min(len(lines), lineno + window)
        return "\n".join(lines[start:end])

    def _assess_severity(self, line: str, context: str) -> tuple[str | None, str]:
        """Bewertet Schwere. Gibt (severity, note) zurück, oder (None, '') wenn kein Bug."""
        line_lower = line.lower()
        ctx_lower = context.lower()

        # Sehr langer Cooldown + Learning-Context = high
        if "86400" in line or "timedelta(hours=24" in line:
            if any(kw in ctx_lower for kw in ("evolution", "train", "retrain", "learn")):
                return "high", "Evolution/Learning blockiert für 24h"
            if any(kw in ctx_lower for kw in ("goal", "assess", "coach", "strategy")):
                return "medium", "Goal/Strategy Assessment zu selten"
            if any(kw in ctx_lower for kw in ("cooldown", "throttle", "last_")):
                return "low", "Langer Cooldown — prüfen ob paper-trading-optimiert"

        # Noch längere Cooldowns
        if "7 * 86400" in line or "604800" in line:
            return "high", "7-Tage-Cooldown → fast kein Lernen im Paper-Trading"

        return None, ""

    def _extract_seconds(self, line: str) -> int:
        """Extrahiert Sekunden-Wert aus Zeile."""
        for seconds, _ in sorted(_LONG_COOLDOWNS_SECONDS.items(), reverse=True):
            if str(seconds) in line:
                return seconds
        # Fallback: erste 4-5-stellige Zahl
        m = re.search(r'\b(\d{4,6})\b', line)
        return int(m.group(1)) if m else 86400
