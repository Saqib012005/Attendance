"""Empirical calibration, diagnostics, and versioned configuration generation.

Fits evidence weights and operating points from labelled ground-truth datasets,
computes calibration diagnostics (Brier score, ECE, reliability diagram, FAR/FRR),
and emits valid, immutable versioned configuration artifacts.
"""
import json
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..analytics import metrics
from . import config

MIN_SAMPLE_COUNT = 20
SMOOTHING_ALPHA = 1.0  # Laplace smoothing pseudo-count


@dataclass(frozen=True)
class LabelledSample:
    features: Mapping[str, bool]  # feature_name -> is_present
    is_ground_truth_present: bool
    metadata: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class CalibrationDiagnostics:
    sample_count: int
    positive_count: int
    negative_count: int
    brier_score: float
    expected_calibration_error: float
    reliability_bins: List[Tuple[float, float, int]]  # (mean_conf, mean_acc, count)
    far_at_operating_point: float
    frr_at_operating_point: float
    operating_threshold_millinats: int


def calculate_feature_log_odds(
    samples: Sequence[LabelledSample],
    feature_name: str,
    alpha: float = SMOOTHING_ALPHA,
) -> int:
    """Calculate empirical log-likelihood ratio in millinats with Laplace smoothing.
    
    millinats = 1000 * ln( P(Feature=True | Present) / P(Feature=True | Absent) )
    """
    pos_samples = [s for s in samples if s.is_ground_truth_present]
    neg_samples = [s for s in samples if not s.is_ground_truth_present]

    pos_total = len(pos_samples)
    neg_total = len(neg_samples)

    if pos_total == 0 or neg_total == 0:
        return 1000  # Default neutral positive weight

    pos_true = sum(1 for s in pos_samples if s.features.get(feature_name, False))
    neg_true = sum(1 for s in neg_samples if s.features.get(feature_name, False))

    # Laplace smoothed probabilities
    p_feat_given_pos = (pos_true + alpha) / (pos_total + 2.0 * alpha)
    p_feat_given_neg = (neg_true + alpha) / (neg_total + 2.0 * alpha)

    lr = p_feat_given_pos / max(1e-6, p_feat_given_neg)
    log_odds = math.log(max(1e-4, lr))
    millinats = int(round(log_odds * 1000.0))

    # Clamp within declared parameter bounds [1, 10000]
    return max(1, min(10000, millinats))


def compute_brier_score(probabilities: Sequence[float], labels: Sequence[bool]) -> float:
    """Compute Brier Score: Mean squared error of predicted probabilities."""
    if not probabilities or len(probabilities) != len(labels):
        return 0.0
    total_sq = sum((p - (1.0 if y else 0.0)) ** 2 for p, y in zip(probabilities, labels))
    return total_sq / len(probabilities)


def compute_reliability_diagram(
    probabilities: Sequence[float],
    labels: Sequence[bool],
    num_bins: int = 10,
) -> Tuple[float, List[Tuple[float, float, int]]]:
    """Calculate Expected Calibration Error (ECE) and binning statistics."""
    if not probabilities or len(probabilities) != len(labels):
        return 0.0, []

    bin_data: List[List[Tuple[float, bool]]] = [[] for _ in range(num_bins)]
    for p, y in zip(probabilities, labels):
        b_idx = min(num_bins - 1, int(p * num_bins))
        bin_data[b_idx].append((p, y))

    n_total = len(probabilities)
    ece = 0.0
    bins_summary = []

    for b in bin_data:
        if not b:
            continue
        count = len(b)
        mean_conf = sum(p for p, _ in b) / count
        mean_acc = sum(1.0 for _, y in b if y) / count
        ece += (count / n_total) * abs(mean_acc - mean_conf)
        bins_summary.append((round(mean_conf, 3), round(mean_acc, 3), count))

    return round(ece, 4), bins_summary


def compute_operating_curve(
    scores_millinats: Sequence[int],
    labels: Sequence[bool],
    threshold_step: int = 200,
) -> List[Dict[str, Any]]:
    """Compute FAR (False Accept Rate) and FRR (False Reject Rate) across score thresholds."""
    if not scores_millinats:
        return []

    min_score = min(scores_millinats)
    max_score = max(scores_millinats)

    curve = []
    threshold = min_score
    while threshold <= max_score + threshold_step:
        # Predict Present if score >= threshold
        tp = fp = tn = fn = 0
        for s, y in zip(scores_millinats, labels):
            pred = (s >= threshold)
            if pred and y:
                tp += 1
            elif pred and not y:
                fp += 1
            elif not pred and not y:
                tn += 1
            else:
                fn += 1

        far = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        frr = (fn / (tp + fn)) if (tp + fn) > 0 else 0.0

        curve.append({
            "threshold_millinats": threshold,
            "far_pct": round(far * 100.0, 2),
            "frr_pct": round(frr * 100.0, 2),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        })
        threshold += threshold_step

    return curve


def fit_and_emit_artifact(
    samples: Sequence[LabelledSample],
    version_tag: str,
    calibration_state: str = config.SIMULATOR_FITTED,
    notes: str = "Empirically fitted from lab/field dataset",
    base_artifact: Optional[config.Artifact] = None,
) -> Tuple[config.Artifact, CalibrationDiagnostics]:
    """Fit feature weights from samples and generate a valid immutable configuration artifact."""
    if len(samples) < MIN_SAMPLE_COUNT:
        raise ValueError(f"Need at least {MIN_SAMPLE_COUNT} samples to calibrate, got {len(samples)}")

    base = base_artifact or config.active()
    new_values = dict(base.values)

    # Fit each feature weight that appears in configuration
    feature_keys = [
        ("identity_authenticated", "fusion.weight.identity_authenticated"),
        ("device_bound", "fusion.weight.device_bound"),
        ("challenge_committed", "fusion.weight.challenge_committed"),
        ("biometric_outcome", "fusion.weight.biometric_outcome"),
        ("origin_direct", "fusion.weight.origin_direct"),
        ("clock_consistency", "fusion.weight.clock_consistency"),
    ]

    for feat_name, param_name in feature_keys:
        fitted_weight = calculate_feature_log_odds(samples, feat_name)
        new_values[param_name] = fitted_weight

    # Evaluate sample scores using fitted weights
    scores = []
    labels = []
    probs = []
    for s in samples:
        score = sum(
            new_values[param_name]
            for feat_name, param_name in feature_keys
            if s.features.get(feat_name, False)
        )
        scores.append(score)
        labels.append(s.is_ground_truth_present)
        # Convert millinats to sigmoid probability for calibration check
        prob = 1.0 / (1.0 + math.exp(-score / 1000.0))
        probs.append(prob)

    brier = compute_brier_score(probs, labels)
    ece, bins = compute_reliability_diagram(probs, labels)
    curve = compute_operating_curve(scores, labels)

    op_thresh = new_values.get("decide.present_millinats", 4500)
    op_entry = next((c for c in curve if c["threshold_millinats"] >= op_thresh), (curve[-1] if curve else {}))

    diagnostics = CalibrationDiagnostics(
        sample_count=len(samples),
        positive_count=sum(1 for s in samples if s.is_ground_truth_present),
        negative_count=sum(1 for s in samples if not s.is_ground_truth_present),
        brier_score=round(brier, 4),
        expected_calibration_error=ece,
        reliability_bins=bins,
        far_at_operating_point=op_entry.get("far_pct", 0.0),
        frr_at_operating_point=op_entry.get("frr_pct", 0.0),
        operating_threshold_millinats=op_thresh,
    )

    # Validate against config parameter bounds
    checked_values = {
        name: config.PARAMETERS[name].check(name, new_values[name])
        for name in sorted(new_values)
        if name in config.PARAMETERS
    }

    artifact = config.Artifact(
        version=version_tag,
        calibration=calibration_state,
        notes=notes,
        values=checked_values,
    )
    return artifact, diagnostics
