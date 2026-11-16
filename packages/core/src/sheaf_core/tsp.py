"""RFC 3161 time-stamp tokens (5.2): the request the witness sends, and the offline check the
gateway runs before it commits a witness (7.2 step 5) and the verifier runs on every token (9).

A token is checked against the roots the mandate pins for its authority, never the system store:
its status, its content type, the message imprint and nonce, the signer named in the signed
attributes, the digest of the TSTInfo, the CMS signature, the time-stamping key usage, and a
certificate chain to a pinned certificate, each valid at the token's `genTime`. Whether the token is
qualified is read from it (the ETSI EN 319 422 statement), never from configuration.
"""

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from asn1crypto import cms, core, tsp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from sheaf_core.problems import Problem

QUALIFIED_STATEMENT = "0.4.0.19422.1.1"
"""esi4-qtstStatement-1 (ETSI EN 319 422): the token is a qualified electronic time stamp."""
_QC_STATEMENTS = "1.3.6.1.5.5.7.1.3"
_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
_MAX_CHAIN = 8


class _QcStatement(core.Sequence):
    _fields = [
        ("statement_id", core.ObjectIdentifier),
        ("statement_info", core.Any, {"optional": True}),
    ]


class _QcStatements(core.SequenceOf):
    _child_spec = _QcStatement


class _Response(core.Sequence):
    # asn1crypto's TimeStampResp requires the token, which a refusal leaves out (RFC 3161 2.4.2).
    _fields = [
        ("status", tsp.PKIStatusInfo),
        ("time_stamp_token", cms.ContentInfo, {"optional": True}),
    ]


@dataclass(frozen=True)
class Token:
    """What a verified token says."""

    gen_time: datetime
    qualified: bool
    policy: str
    serial: int
    nonce: int | None


class _Refused(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code, self.detail = code, detail


def request(imprint: bytes, nonce: int) -> bytes:
    """An RFC 3161 request for a SHA-256 imprint, with a nonce, asking for the certificates."""
    if len(imprint) != 32:
        raise ValueError("the imprint is a 32-byte SHA-256 digest")
    return tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": imprint,
            },
            "nonce": nonce,
            "cert_req": True,
        }
    ).dump()


def check_token(
    response: bytes,
    *,
    imprint: bytes,
    roots: Iterable[bytes],
    nonce: int | None = None,
    path: str = "$",
) -> tuple[Token | None, list[Problem]]:
    """Check one authority's time-stamp response, exactly as received, against the imprint it
    should cover and the DER certificates the mandate pins for that authority. `nonce` is checked
    when the caller knows it (the witness, at stamping). A token only if there are no problems."""
    try:
        return _check(response, imprint, list(roots), nonce), []
    except _Refused as refused:
        return None, [Problem(refused.code, path, refused.detail)]


def _check(response: bytes, imprint: bytes, roots: list[bytes], nonce: int | None) -> Token:
    try:
        parsed = _Response.load(response, strict=True)
        status = parsed["status"]["status"].native
    except (ValueError, TypeError, KeyError) as error:
        raise _Refused("token_unparseable", f"not an RFC 3161 response: {error}") from error
    if status not in ("granted", "granted_with_mods"):
        raise _Refused("token_status", f"the authority answered {status}")
    try:
        return _check_granted(parsed, imprint, roots, nonce)
    except _Refused:
        raise
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as error:
        raise _Refused("token_unparseable", f"the token cannot be read: {error}") from error


def _check_granted(
    parsed: _Response, imprint: bytes, roots: list[bytes], nonce: int | None
) -> Token:
    token = parsed["time_stamp_token"]
    if token["content_type"].native != "signed_data":
        raise _Refused("token_content", "a token is CMS signed data")
    signed = token["content"]
    encapsulated = signed["encap_content_info"]
    if encapsulated["content_type"].native != "tst_info":
        raise _Refused("token_content", "a token signs a TSTInfo")
    content = encapsulated["content"]
    tst_bytes = content.contents
    info = content.parsed

    message = info["message_imprint"]
    if (
        message["hash_algorithm"]["algorithm"].native != "sha256"
        or message["hashed_message"].native != imprint
    ):
        raise _Refused("token_imprint", "the token is over another imprint")
    if nonce is not None and info["nonce"].native != nonce:
        raise _Refused("token_nonce", "the token answers another request")
    gen_time = info["gen_time"].native

    signer_infos = list(signed["signer_infos"])
    if len(signer_infos) != 1:
        raise _Refused("token_signer", "a token has exactly one signer")
    signer_info = signer_infos[0]
    certificates = [
        choice.chosen for choice in (signed["certificates"] or []) if choice.name == "certificate"
    ]
    signer = _signer(signer_info["sid"], certificates)

    attributes = {a["type"].native: a["values"][0] for a in signer_info["signed_attrs"]}
    if attributes.get("content_type") is None or attributes["content_type"].native != "tst_info":
        raise _Refused("token_content", "the signed content type is not TSTInfo")
    digest_name = signer_info["digest_algorithm"]["algorithm"].native
    if digest_name not in _HASHES:
        raise _Refused("token_signature", f"{digest_name} is not an accepted digest")
    digested = attributes.get("message_digest")
    if digested is None or digested.native != hashlib.new(digest_name, tst_bytes).digest():
        raise _Refused("token_digest", "the signed digest is not that of the TSTInfo")
    _check_signing_certificate(attributes, signer)

    signed_bytes = b"\x31" + signer_info["signed_attrs"].dump()[1:]
    signer_cert = x509.load_der_x509_certificate(signer.dump())
    _verify(signer_cert, signer_info, digest_name, signed_bytes)
    _check_usage(signer_cert)
    pool = [x509.load_der_x509_certificate(c.dump()) for c in certificates]
    pool += [x509.load_der_x509_certificate(der) for der in roots]
    _check_chain(signer_cert, pool, {hashlib.sha256(der).digest() for der in roots}, gen_time)

    return Token(
        gen_time=gen_time,
        qualified=_qualified(info),
        policy=info["policy"].dotted,
        serial=info["serial_number"].native,
        nonce=info["nonce"].native,
    )


def _signer(sid, certificates):
    chosen = sid.chosen
    for certificate in certificates:
        if sid.name == "issuer_and_serial_number":
            if (
                certificate.issuer == chosen["issuer"]
                and certificate.serial_number == chosen["serial_number"].native
            ):
                return certificate
        elif certificate.key_identifier == chosen.native:
            return certificate
    raise _Refused("token_signer", "the token does not carry its signer's certificate")


def _check_signing_certificate(attributes, signer) -> None:
    """RFC 3161 binds the signer's certificate in a signing-certificate attribute (ESS)."""
    if "signing_certificate_v2" in attributes:
        first = attributes["signing_certificate_v2"]["certs"][0]
        name = first["hash_algorithm"]["algorithm"].native
        expected = first["cert_hash"].native
    elif "signing_certificate" in attributes:
        name, expected = "sha1", attributes["signing_certificate"]["certs"][0]["cert_hash"].native
    else:
        raise _Refused("token_signing_certificate", "no signing-certificate attribute")
    if hashlib.new(name, signer.dump()).digest() != expected:
        raise _Refused("token_signing_certificate", "the attribute names another certificate")


def _verify(certificate, signer_info, digest_name: str, data: bytes) -> None:
    algorithm = signer_info["signature_algorithm"]
    signature = signer_info["signature"].native
    key = certificate.public_key()
    try:
        name = algorithm.signature_algo
        if name == "rsassa_pss":
            parameters = algorithm["parameters"]
            hash_type = _HASHES[parameters["hash_algorithm"]["algorithm"].native]
            scheme = padding.PSS(
                mgf=padding.MGF1(hash_type()), salt_length=parameters["salt_length"].native
            )
            key.verify(signature, data, scheme, hash_type())
            return
        try:
            hash_type = _HASHES[algorithm.hash_algo]
        except (ValueError, KeyError):
            hash_type = _HASHES[digest_name]
        if name == "rsassa_pkcs1v15" and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, data, padding.PKCS1v15(), hash_type())
        elif name == "ecdsa" and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, ec.ECDSA(hash_type()))
        else:
            raise _Refused("token_signature", f"{name} is not an accepted signature")
    except InvalidSignature as error:
        raise _Refused("token_signature", "the signature does not verify") from error
    except KeyError as error:
        raise _Refused("token_signature", f"{error} is not an accepted digest") from error


def _check_usage(certificate) -> None:
    try:
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound as error:
        raise _Refused("token_usage", "the signer is not a time-stamping certificate") from error
    if not usage.critical or list(usage.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        raise _Refused("token_usage", "the signer's key usage is not time stamping alone")


def _check_chain(certificate, pool, pinned: set[bytes], at: datetime) -> None:
    current = certificate
    for _ in range(_MAX_CHAIN):
        if not current.not_valid_before_utc <= at <= current.not_valid_after_utc:
            raise _Refused("token_chain", f"{current.subject.rfc4514_string()} was not valid then")
        if _fingerprint(current) in pinned:
            return
        candidates = sorted(
            (c for c in pool if c.subject == current.issuer and c is not current),
            key=lambda c: _fingerprint(c) not in pinned,
        )
        issuer = next((c for c in candidates if _issued(current, c)), None)
        if issuer is None or not _is_ca(issuer):
            raise _Refused("token_chain", "the certificate chain does not reach a pinned root")
        current = issuer
    raise _Refused("token_chain", "the certificate chain is too long")


def _fingerprint(certificate) -> bytes:
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).digest()


def _issued(certificate, issuer) -> bool:
    try:
        certificate.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def _is_ca(certificate) -> bool:
    try:
        return certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _qualified(info) -> bool:
    if info["extensions"].native is None:
        return False
    for extension in info["extensions"]:
        if extension["extn_id"].dotted != _QC_STATEMENTS:
            continue
        statements = _QcStatements.load(extension["extn_value"].contents)
        if any(s["statement_id"].dotted == QUALIFIED_STATEMENT for s in statements):
            return True
    return False
