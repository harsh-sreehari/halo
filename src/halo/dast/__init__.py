"""Autonomous DAST active probing subsystem."""

from halo.dast.csrf import CSRFHarvester
from halo.dast.oracles import (
    SemanticDifferOracle,
    SemanticDifferResult,
    StateMutationResult,
    WireOracle,
)
from halo.dast.sandbox import SafeModeViolationError, SandboxManager
from halo.dast.synthesizer import PayloadSynthesizer
from halo.dast.vault import IdentityPersona, PersonaType, SessionVault

__all__ = [
    "CSRFHarvester",
    "IdentityPersona",
    "PayloadSynthesizer",
    "PersonaType",
    "SafeModeViolationError",
    "SandboxManager",
    "SemanticDifferOracle",
    "SemanticDifferResult",
    "SessionVault",
    "StateMutationResult",
    "WireOracle",
]
