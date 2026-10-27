# Interoperability verification workplan

Status: non-normative discussion. No VSO change-control adoption is implied.

The SDK's existing INTERPRETATIONS.md describes implementation-specific choices. Before asserting interoperability across independent implementations, VSO must decide the canonical representation of integers larger than 2^53, the RFC 6962 Merkle tree construction and proof encoding, and the exact signed bytes and authenticated metadata for events and anchors.

## Verification gates

1. Record each decision in the specification repository through change control. Preserve existing signed records and version the migration behavior.
2. Publish versioned fixtures for numeric boundaries, non-power-of-two Merkle trees, signature byte inputs, unsigned anchor metadata, and unavailable external-anchor evidence.
3. For every fixture, provide expected bytes, digest, proof or signature, and VALID/INVALID/INDETERMINATE result as applicable.
4. Run the same fixtures in Python and TypeScript, then obtain separately authored third-party reproduction. Two first-party language implementations are not independent validation.
5. Keep unresolved issues and unsupported verification steps explicitly INDETERMINATE. A cryptographic check does not prove the underlying event was true or that unrecorded events did not occur.

Reference: ../INTERPRETATIONS.md
