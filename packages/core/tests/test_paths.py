from datetime import UTC, date, datetime

from sheaf_core import paths

SHA = "9f2c" + "0" * 60
AT = datetime(2026, 11, 26, 18, 4, 11, tzinfo=UTC)


def test_artefacts_are_addressed_by_sha256():
    assert paths.artefact(SHA) == f"artefacts/sha256/9f/2c/{SHA}"


def test_a_dossier_is_filed_under_the_month_it_opened():
    assert paths.dossier("case-review", AT, "cr-1") == "dossiers/case-review/2026/11/cr-1/"


def test_chain_level_entries_are_filed_under_the_year():
    assert paths.chain_dossier("case-review", AT) == "dossiers/case-review/2026/_chain/"


def test_chain_segments_are_filed_by_day():
    assert paths.chain_segment("case-review", AT) == "chain/case-review/2026/11/26/"


def test_each_entry_is_its_own_blob_named_so_a_listing_is_in_seq_order():
    folder = paths.dossier("case-review", AT, "cr-1")

    assert paths.entry(folder, 42) == "dossiers/case-review/2026/11/cr-1/0000000000000042.json"
    names = [paths.entry(folder, seq) for seq in (9, 10, 100, 2**53 - 1)]
    assert names == sorted(names)


def test_witness_paths():
    day = date(2026, 11, 26)

    assert paths.witness_daily("case-review", day) == "witness/case-review/2026/11/26.json"
    assert (
        paths.daily_token("case-review", day, "tsa-a") == "witness/case-review/2026/11/26.tsa-a.tsr"
    )
    assert paths.daily_revocation("case-review", day, "tsa-a") == (
        "witness/case-review/2026/11/26.tsa-a.rev"
    )
    assert paths.witness_interim("case-review", 18342) == "witness/case-review/interim/18342.json"
    assert paths.interim_token("case-review", 18342, "tsa-b") == (
        "witness/case-review/interim/18342.tsa-b.tsr"
    )


def test_trust_and_registry_paths():
    assert paths.witness_key("acme-witness/3f1c") == "trust/witness-keys/acme-witness/3f1c.pem"
    assert paths.registry("1.0.0") == "registry/sheaf-1/1.0.0/"


def test_an_authority_certificate_is_filed_by_its_sha256():
    assert paths.tsa_certificate("freetsa", "ab" * 32) == f"trust/tsa/freetsa/{'ab' * 32}.der"
