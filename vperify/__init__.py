"""
VPerify - LLM-Driven Vulnerability Verification Tool

Combines Qiling framework ICFG analysis with LLM-driven seed generation.
"""

from .path_coverage_analyzer import (
    PathCoverageAnalyzer,
    VulnPath,
    CoverageResult
)

from .seed_generator import (
    LLMSeedGenerator,
    Seed
)

from .verification_engine import (
    VulnerabilityVerificationEngine,
    VerificationConfig,
    VerificationResult
)

from .runtime_icfg_tool import gen_runtime_icfg

__all__ = [
    "PathCoverageAnalyzer", "VulnPath", "CoverageResult",
    "LLMSeedGenerator", "Seed",
    "VulnerabilityVerificationEngine", "VerificationConfig", "VerificationResult",
    "gen_runtime_icfg",
]

__version__ = "0.1.0"
