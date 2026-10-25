"""veritaschain-vcp: offline core for VeritasChain Protocol (VCP) v1.2 events.

Pre-release (0.x). First-party software from the VeritasChain Standards
Organization (VSO) / VeritasChain Co., Ltd. It is not an external or
independent implementation, it is not certified, and a VALID result from its
verifier is not a VCP conformance claim. See README.md and INTERPRETATIONS.md.
"""

__version__ = "0.1.0"
VCP_SPEC_VERSION = "1.2.0"
VCP_SPEC_COMMIT = "b23acb266f88df81d960d36d58fb64ceaa0dd5ed"

from . import jcs, merkle  # noqa: E402
from .hashing import compute_event_hash, format_event_hash, parse_hash  # noqa: E402
from .jcs import CanonicalizationError, canonicalize  # noqa: E402
from .jsonio import StrictJSONError  # noqa: E402
from .jsonio import loads as loads_strict  # noqa: E402
from .producer import Batch, Producer, anchor_record, build_batch, seal_event  # noqa: E402
from .signing import (  # noqa: E402
    SigningKey,
    VerifyKey,
    generate_key,
    sign_event_hash,
    sign_merkle_root,
    verify_event_signature,
    verify_root_signature,
)
from .timeutil import iso_from_ns, ns_from_iso, uuid7  # noqa: E402
from .verify import (  # noqa: E402
    INDETERMINATE,
    INVALID,
    VALID,
    Check,
    Report,
    verify_batch,
    verify_chain,
    verify_event,
    verify_inclusion_proof,
)

__all__ = [
    "__version__",
    "VCP_SPEC_VERSION",
    "VCP_SPEC_COMMIT",
    "jcs",
    "merkle",
    "canonicalize",
    "CanonicalizationError",
    "loads_strict",
    "StrictJSONError",
    "compute_event_hash",
    "format_event_hash",
    "parse_hash",
    "SigningKey",
    "VerifyKey",
    "generate_key",
    "sign_event_hash",
    "verify_event_signature",
    "sign_merkle_root",
    "verify_root_signature",
    "uuid7",
    "iso_from_ns",
    "ns_from_iso",
    "Producer",
    "Batch",
    "seal_event",
    "build_batch",
    "anchor_record",
    "VALID",
    "INVALID",
    "INDETERMINATE",
    "Check",
    "Report",
    "verify_event",
    "verify_batch",
    "verify_chain",
    "verify_inclusion_proof",
]
