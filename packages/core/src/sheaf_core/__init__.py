"""Canonical form, digests and chain rules for the Sheaf evidence dossier standard.

This package is shared by the gateway, which writes the record, and the verifier, which checks
it, so both apply exactly the same rules. It must never depend on Azure or on anything that
needs a network: the verifier promises to run on a downloaded copy of a container.
"""

SPEC = "sheaf/1"
