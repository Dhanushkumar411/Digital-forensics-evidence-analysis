"""
ForenSight AI - Machine Learning Anomaly Detection Engine
Leverages Scikit-Learn IsolationForest, feature vector scaling, and heuristic
forensic rules to identify anomalous files, evasion techniques, and potential malware.
"""

import math
import re
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from core.models import EvidenceItem, AnomalyResult
from engines.evidence_engine import EvidenceEngine


# Baseline synthetic dataset to train the reference IsolationForest model on startup
# Features: [entropy, log_size, ext_mismatch, is_exec, double_ext, timestomp, sus_name, sus_cmd, net_indicator]
BASELINE_BENIGN_PROFILES = [
    # Normal images (JPEG/PNG)
    [7.1, 5.3, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    [7.3, 5.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    [6.9, 4.9, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    # Normal documents (PDF/DOCX)
    [6.8, 5.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    [7.0, 5.6, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    [6.4, 4.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    # Normal text / logs / configs
    [4.2, 3.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    [4.8, 4.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    [3.5, 3.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    # Normal standard compiled executables
    [6.2, 5.9, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    [6.4, 6.2, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    [6.1, 5.5, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
]

SUSPICIOUS_KEYWORD_PATTERN = re.compile(
    r"(?i)(mimikatz|payload|beacon|ransom|c2|meterpreter|backdoor|inject|exploit|keylogger|rootkit|dropper|stealer|miner|cobalt|bypass)"
)


class AIFDEngine:
    """Forensic AI Anomaly Detection Engine combining Isolation Forest with expert rules."""

    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.15,
            random_state=42
        )
        self._is_fitted = False
        self._init_baseline_model()

    def _init_baseline_model(self):
        """Fits baseline model with reference forensic distribution."""
        X_train = np.array(BASELINE_BENIGN_PROFILES)
        self.scaler.fit(X_train)
        scaled_X = self.scaler.transform(X_train)
        self.model.fit(scaled_X)
        self._is_fitted = True

    def extract_features(self, item: EvidenceItem, indicators: Optional[Dict[str, Any]] = None) -> Tuple[np.ndarray, Dict[str, float]]:
        """
        Extracts 9-dimensional forensic vector for ML classification:
        [entropy, log_size, ext_mismatch, is_exec, double_ext, timestomp, sus_name, sus_cmd, net_indicator]
        """
        # Feature 1: Entropy (0 - 8)
        f_entropy = float(item.entropy)

        # Feature 2: Log10 File Size
        f_log_size = float(math.log10(max(item.file_size, 1)))

        # Feature 3: Extension Mismatch flag
        f_ext_mismatch = 1.0 if item.extension_mismatch else 0.0

        # Feature 4: Is executable or script
        is_exec = any(k in item.detected_type for k in ["Executable", "Script", "Mach-O", "Class"])
        f_is_exec = 1.0 if is_exec else 0.0

        # Feature 5: Double extension
        has_double_ext = bool(re.search(r"\.[a-z0-9]{2,4}\.(exe|scr|bat|cmd|vbs|ps1|dll)$", item.file_name.lower()))
        f_double_ext = 1.0 if has_double_ext else 0.0

        # Feature 6: Timestomp flag
        f_timestomp = 1.0 if any("precedes creation" in r for r in item.flagged_reasons) else 0.0

        # Feature 7: Suspicious filename keywords
        f_sus_name = 1.0 if SUSPICIOUS_KEYWORD_PATTERN.search(item.file_name) else 0.0

        # Feature 8 & 9: Command and network indicators (from string analysis if available)
        f_sus_cmd = 0.0
        f_net_indicator = 0.0
        if indicators:
            if indicators.get("suspicious_commands"):
                f_sus_cmd = min(len(indicators["suspicious_commands"]) * 0.5, 1.0)
            if indicators.get("ip_addresses") or indicators.get("urls"):
                f_net_indicator = 1.0

        feature_dict = {
            "entropy": f_entropy,
            "log_size": round(f_log_size, 2),
            "ext_mismatch": f_ext_mismatch,
            "is_exec": f_is_exec,
            "double_ext": f_double_ext,
            "timestomp": f_timestomp,
            "sus_name": f_sus_name,
            "sus_cmd": f_sus_cmd,
            "net_indicator": f_net_indicator
        }

        feature_vector = np.array([
            f_entropy, f_log_size, f_ext_mismatch, f_is_exec,
            f_double_ext, f_timestomp, f_sus_name, f_sus_cmd, f_net_indicator
        ], dtype=float)

        return feature_vector, feature_dict

    def analyze_evidence(self, item: EvidenceItem, indicators: Optional[Dict[str, Any]] = None) -> AnomalyResult:
        """
        Runs ML anomaly inference and feature explanation for a given evidence item.
        """
        if indicators is None and Path(item.file_path).is_file():
            try:
                indicators = EvidenceEngine.extract_strings_and_indicators(item.file_path)
            except Exception:
                indicators = {}

        vec, feat_dict = self.extract_features(item, indicators)

        # Scale feature vector and calculate ML decision score
        vec_reshaped = vec.reshape(1, -1)
        scaled_vec = self.scaler.transform(vec_reshaped)
        decision_score = self.model.decision_function(scaled_vec)[0]  # Lower = more anomalous

        # Convert decision score to anomaly percentage [0.0% to 100.0%]
        # Decision score typically ranges between -0.4 (extreme outlier) and +0.3 (inlier)
        # We invert and map to [0, 100]
        ml_score = max(0.0, min(100.0, (0.25 - decision_score) * 150.0))

        # Heuristic Rule Weights (Forensic Expert System boost)
        heuristic_boost = 0.0
        reasons: List[str] = list(item.flagged_reasons)

        if feat_dict["ext_mismatch"] > 0:
            heuristic_boost += 65.0
            if not any("mismatch" in r.lower() for r in reasons):
                reasons.append("AI Alert: Critical file type extension mismatch detected.")

        if feat_dict["double_ext"] > 0:
            heuristic_boost += 55.0
            if not any("double extension" in r.lower() for r in reasons):
                reasons.append("AI Alert: Masquerading double file extension detected.")

        if feat_dict["entropy"] >= 7.2:
            heuristic_boost += 45.0
            if not any("entropy" in r.lower() for r in reasons):
                reasons.append(f"AI Alert: Extremely high Shannon entropy ({feat_dict['entropy']:.2f}) indicates encrypted payload or code packing.")

        if feat_dict["timestomp"] > 0:
            heuristic_boost += 35.0

        if feat_dict["sus_name"] > 0:
            heuristic_boost += 40.0
            reasons.append(f"AI Alert: Filename contains known threat actor keyword match: '{item.file_name}'")

        if feat_dict["sus_cmd"] > 0:
            heuristic_boost += 45.0
            reasons.append("AI Alert: Embedded shell execution commands (PowerShell/CMD/Bash) found inside file.")

        if feat_dict["net_indicator"] > 0 and feat_dict["is_exec"] > 0:
            heuristic_boost += 35.0
            reasons.append("AI Alert: Hardcoded external IP address / C2 URL found inside binary file.")

        # Combined composite anomaly score:
        # High-confidence forensic indicators reliably elevate the risk score
        blended = ml_score * 0.4 + heuristic_boost * 0.6
        composite_score = min(100.0, round(max(blended, heuristic_boost), 1))

        # Categorize Risk Level
        if composite_score >= 80.0:
            risk_level = "Critical Anomaly"
        elif composite_score >= 60.0:
            risk_level = "High Risk"
        elif composite_score >= 35.0:
            risk_level = "Suspicious"
        else:
            risk_level = "Benign"

        # Update item fields
        item.anomaly_score = composite_score
        item.risk_level = risk_level
        item.is_suspicious = (risk_level != "Benign")
        item.flagged_reasons = list(set(reasons))

        return AnomalyResult(
            evidence_id=item.id or 0,
            anomaly_score=composite_score,
            risk_level=risk_level,
            algorithm="IsolationForest (Scikit-Learn) + Forensic Rule Engine",
            feature_vector=feat_dict,
            reasons=item.flagged_reasons,
            signature_matches=[]
        )

    def retrain_with_case_evidence(self, items: List[EvidenceItem]):
        """
        Dynamically fits the Isolation Forest on the current case's evidence population.
        Identifies outliers relative to the specific environment/case.
        """
        if len(items) < 5:
            return  # Need at least a small sample size to train meaningful clusters

        vectors = []
        for it in items:
            v, _ = self.extract_features(it)
            vectors.append(v)

        X = np.array(vectors)
        self.scaler.fit(X)
        scaled_X = self.scaler.transform(X)
        self.model.fit(scaled_X)
        self._is_fitted = True
