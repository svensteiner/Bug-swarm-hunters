"""
signal_flow_hunter.py — Sucht Gate-Ketten die 100% der Signale blockieren.

Typisches Bug-Pattern:
  MCM=UNFAVORABLE → Gate 1 blocked
  EPM-Filter aktiv → Gate 2 blocked
  min_score=8 (zu hoch) → Gate 3 blocked
  → Alle Signale blockiert → Signal-Starvation

Analysiert strategy_config.json + trading_config.json auf kombinierte
Gate-Konfigurationen die praktisch keine Signale durchlassen.

Open-Source Bug Hunter Arena — MIT License
"""
from __future__ import annotations

import json
from pathlib import Path

from core.base_hunter import BaseHunter, BugFinding
import logging

logger = logging.getLogger("bug_swarm")

# Config-Datei-Pfade (relativ zum project_root)
_CONFIG_PATHS = [
    "config/strategy_config.json",
    "config/trading_config.json",
]

# Schwellwerte für kombinierte Gate-Analyse
_MIN_SCORE_WARNING = 6      # >= 6 ist sehr restriktiv
_MIN_SCORE_CRITICAL = 8     # >= 8 blockiert fast alles

# EPM-Felder die Gate-Effekt haben
_EPM_GATE_FIELDS = {
    "epm_filter_enabled",
    "epm_strict_mode",
    "EPM_FILTER_ENABLED",
    "EPM_STRICT",
}

# MCM-Felder
_MCM_GATE_FIELDS = {
    "mcm_gate_enabled",
    "mcm_strict",
    "MCM_GATE_ENABLED",
    "market_condition_gate",
}


class SignalFlowHunter(BaseHunter):
    """
    Analysiert Config-Dateien auf Gate-Kombinationen die Signal-Starvation erzeugen.

    Prüft:
    1. min_score zu hoch (>= 6)
    2. MCM-Gate aktiv + EPM-Gate aktiv = Triple-Lock
    3. Swarm_min_confidence zu hoch kombiniert mit anderen Gates
    """

    name = "SignalFlowHunter"
    specialty = "signal_starvation"
    description = "MCM+EPM+min_score Gate-Kombination → 100% Signal-Blockade"

    def hunt(self, project_root: Path) -> list[BugFinding]:
        findings: list[BugFinding] = []

        # Config laden
        config = self._load_configs(project_root)
        if not config:
            return findings

        findings.extend(self._check_min_score(config, project_root))
        findings.extend(self._check_gate_combination(config, project_root))
        findings.extend(self._check_swarm_confidence(config, project_root))
        return findings

    def _load_configs(self, root: Path) -> dict:
        """Lädt alle Config-Dateien und merged sie."""
        merged: dict = {}
        for rel_path in _CONFIG_PATHS:
            full_path = root / rel_path
            if not full_path.exists():
                continue
            try:
                with open(full_path, encoding="utf-8") as f:
                    data = json.load(f)
                merged.update(data)
                merged[f"_source_{rel_path}"] = str(full_path)
            except (OSError, json.JSONDecodeError) as exc:
                logger.debug(f"[SIGNAL-FLOW] Config nicht geladen: {rel_path}: {exc}")
        return merged

    def _check_min_score(self, config: dict, root: Path) -> list[BugFinding]:
        """Prüft ob min_score zu restriktiv ist."""
        findings: list[BugFinding] = []
        min_score = config.get("min_score", config.get("MIN_SCORE"))
        if min_score is None:
            return findings

        try:
            score = int(min_score)
        except (TypeError, ValueError):
            return findings

        if score >= _MIN_SCORE_CRITICAL:
            config_file = self._find_config_source(config, "min_score")
            findings.append(self._make_finding(
                severity="critical",
                file_path=config_file,
                line_number=None,
                description=(
                    f"min_score={score} ist extrem restriktiv → "
                    f"Nur Ausnahme-Signale (>={score}/10) passieren. "
                    f"Bei durchschnittlichem Markt: ~0-5% aller Signale."
                ),
                evidence=f"min_score={score}",
                suggested_fix=(
                    f"Reduziere min_score auf 4-5 für Paper-Trading. "
                    f"Aktuell: {score} → Vorschlag: 4 (oder 3 bei niedriger win_rate). "
                    f"Anpassen via strategy_config.json (requires restart)."
                ),
            ))
        elif score >= _MIN_SCORE_WARNING:
            config_file = self._find_config_source(config, "min_score")
            findings.append(self._make_finding(
                severity="high",
                file_path=config_file,
                line_number=None,
                description=(
                    f"min_score={score} ist sehr restriktiv → "
                    f"Kombiniert mit MCM/EPM-Gates kann Signal-Starvation entstehen."
                ),
                evidence=f"min_score={score}",
                suggested_fix=(
                    f"Erwäge min_score=4-5 für Paper-Trading. Aktuell: {score}. "
                    f"Prüfe: Wie viele Signale werden täglich generiert?"
                ),
            ))
        return findings

    def _check_gate_combination(self, config: dict, root: Path) -> list[BugFinding]:
        """Prüft ob MCM + EPM gleichzeitig aktiv sind (Triple-Lock)."""
        findings: list[BugFinding] = []

        mcm_active = any(
            config.get(f) in (True, "true", "1", 1)
            for f in _MCM_GATE_FIELDS
        )
        epm_active = any(
            config.get(f) in (True, "true", "1", 1)
            for f in _EPM_GATE_FIELDS
        )
        min_score = int(config.get("min_score", config.get("MIN_SCORE", 0)) or 0)

        active_gates = []
        if mcm_active:
            active_gates.append("MCM-Gate")
        if epm_active:
            active_gates.append("EPM-Filter")
        if min_score >= _MIN_SCORE_WARNING:
            active_gates.append(f"min_score={min_score}")

        if len(active_gates) >= 2:
            config_file = self._find_config_source(config, "min_score")
            findings.append(self._make_finding(
                severity="high" if len(active_gates) == 2 else "critical",
                file_path=config_file,
                line_number=None,
                description=(
                    f"Multi-Gate-Lock: {' + '.join(active_gates)} aktiv → "
                    f"Signale müssen ALLE Gates passieren → Signal-Starvation wahrscheinlich"
                ),
                evidence=" | ".join(f"{g}=True" for g in active_gates),
                suggested_fix=(
                    f"Deaktiviere mindestens ein Gate:\n"
                    f"  1. EPM-Filter: setze epm_filter_enabled=false\n"
                    f"  2. MCM-Gate: setze mcm_gate_enabled=false\n"
                    f"  3. min_score: reduziere auf 3-4\n"
                    f"Empfehlung für Paper-Trading: nur min_score=4, kein MCM/EPM-Gate"
                ),
            ))
        return findings

    def _check_swarm_confidence(self, config: dict, root: Path) -> list[BugFinding]:
        """Prüft ob swarm_min_confidence in Kombination zu restriktiv ist."""
        findings: list[BugFinding] = []
        confidence = config.get("swarm_min_confidence", config.get("SWARM_MIN_CONFIDENCE"))
        if confidence is None:
            return findings

        try:
            conf = float(confidence)
        except (TypeError, ValueError):
            return findings

        if conf >= 0.75:
            config_file = self._find_config_source(config, "swarm_min_confidence")
            findings.append(self._make_finding(
                severity="medium",
                file_path=config_file,
                line_number=None,
                description=(
                    f"swarm_min_confidence={conf:.0%} → "
                    f"Nur starker Swarm-Konsens wird akzeptiert. "
                    f"Bei unklarem Markt: fast keine Signale."
                ),
                evidence=f"swarm_min_confidence={conf}",
                suggested_fix=(
                    f"Reduziere swarm_min_confidence auf 0.55-0.65 für Paper-Trading. "
                    f"Aktuell: {conf:.0%} → Vorschlag: 0.60"
                ),
            ))
        return findings

    def _find_config_source(self, config: dict, key: str) -> str:
        """Findet welche Config-Datei den Key enthält."""
        for rel_path in _CONFIG_PATHS:
            source_key = f"_source_{rel_path}"
            if source_key in config:
                full_path = config[source_key]
                try:
                    with open(full_path, encoding="utf-8") as f:
                        data = json.load(f)
                    if key in data:
                        return rel_path
                except (OSError, json.JSONDecodeError):
                    pass
        return "config/strategy_config.json"
