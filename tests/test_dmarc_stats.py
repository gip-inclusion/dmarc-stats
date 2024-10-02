import pathlib

import pytest

from dmarc_stats import DMARCAggregateResults, process_dmarc_aggregate

spec = {
    "count.json": DMARCAggregateResults(total=2, spf_success=2, dkim_success=2),
    "success.json": DMARCAggregateResults(total=1, spf_success=1, dkim_success=1),
    "spf_fail.json": DMARCAggregateResults(
        total=1,
        dkim_success=1,
        spf_failures={"a1016722.bnc3.mailjet.com": 1},
    ),
    "spf_fail_alignment.json": DMARCAggregateResults(
        total=1,
        dkim_success=1,
        spf_alignment={"gmail.com": 1},
    ),
    "spf_neutral.json": DMARCAggregateResults(
        total=1,
        dkim_success=1,
        spf_neutral={"inclusion.beta.gouv.fr": 1},
    ),
    "dkim_fail_alignment.json": DMARCAggregateResults(
        total=1,
        spf_success=1,
        dkim_domain={"inclusion.beta.gouv.fr": 1},
    ),
    "dkim_fail_multiple.json": DMARCAggregateResults(
        total=1,
        spf_alignment={"ac-toulouse.fr": 1},
        dkim_sig={
            (
                "ac-toulouse.fr",
                # First selector.
                "selector2-mongreta-onmicrosoft-com"
                "._domainkey.mongreta.onmicrosoft.com, "
                # Second selector.
                "mail._domainkey.inclusion.beta.gouv.fr",
            ): 1
        },
    ),
    "dkim_fail_single.json": DMARCAggregateResults(
        total=1,
        spf_success=1,
        dkim_sig={
            ("inclusion.beta.gouv.fr", "zendesk2._domainkey.inclusion.beta.gouv.fr"): 1
        },
    ),
}


def generate_test_data():
    root = pathlib.Path(__file__).parent.parent.resolve(strict=True)
    datadir = root / "tests" / "data"
    for json_path in datadir.glob("*.json"):
        expected = spec[json_path.name]
        yield pytest.param(json_path, expected, id=str(json_path.relative_to(root)))


@pytest.mark.parametrize("json_path,expected", generate_test_data())
def test_dmarc_stats(json_path, expected):
    assert process_dmarc_aggregate(json_path) == expected
