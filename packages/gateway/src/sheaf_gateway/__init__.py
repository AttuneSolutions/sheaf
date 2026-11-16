"""The Sheaf write gateway (standard section 7).

The only writer of a tenant's `evidence` container. It validates every artefact and entry with
`sheaf_core`, chains each entry, and commits it. Azure SDKs belong here and in the witness, never
in `sheaf_core`.
"""
