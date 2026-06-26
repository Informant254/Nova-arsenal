"""
Nova-Arsenal Result Correlation Engine.

Correlates findings across multiple tools to identify
high-confidence, multi-source vulnerabilities that
individual tools might miss.
"""

from .correlator import Correlator, CorrelatedFinding, CorrelationResult

__all__ = ["Correlator", "CorrelatedFinding", "CorrelationResult"]
