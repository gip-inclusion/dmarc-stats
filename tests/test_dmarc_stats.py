import pathlib
from datetime import date

import pytest

from dmarc_stats import DMARCAggregateResults, process_dmarc_aggregate

spec = {
    "count.json": (
        {date(2024, 9, 8): {"TOTAL": 2, "SPF_OK": 2, "DKIM_OK": 2}},
        DMARCAggregateResults(total=2, spf_success=2, dkim_success=2),
    ),
    "success.json": (
        {date(2024, 9, 8): {"TOTAL": 1, "SPF_OK": 1, "DKIM_OK": 1}},
        DMARCAggregateResults(total=1, spf_success=1, dkim_success=1),
    ),
    "spf_fail.json": (
        {date(2024, 9, 8): {"TOTAL": 1, "DKIM_OK": 1}},
        DMARCAggregateResults(
            total=1, dkim_success=1, spf_failures={"a1016722.bnc3.mailjet.com": 1}
        ),
    ),
    "spf_fail_alignment.json": (
        {date(2024, 9, 8): {"TOTAL": 1, "DKIM_OK": 1}},
        DMARCAggregateResults(total=1, dkim_success=1, spf_alignment={"gmail.com": 1}),
    ),
    "spf_neutral.json": (
        {date(2024, 9, 8): {"TOTAL": 1, "DKIM_OK": 1}},
        DMARCAggregateResults(
            total=1, dkim_success=1, spf_neutral={"inclusion.beta.gouv.fr": 1}
        ),
    ),
    "dkim_fail_alignment.json": (
        {date(2024, 9, 8): {"TOTAL": 1, "SPF_OK": 1}},
        DMARCAggregateResults(
            total=1,
            spf_success=1,
            dkim={"inclusion.beta.gouv.fr": {"default": {"pass": 1}}},
        ),
    ),
    "dkim_fail_multiple.json": (
        {date(2024, 9, 8): {"TOTAL": 1}},
        DMARCAggregateResults(
            total=1,
            spf_alignment={"ac-toulouse.fr": 1},
            dkim={
                "ac-toulouse.fr": {
                    "selector2-mongreta-onmicrosoft-com": {"fail": 1},
                    "mail": {"fail": 1},
                }
            },
        ),
    ),
    "dkim_fail_single.json": (
        {date(2024, 9, 8): {"TOTAL": 1, "SPF_OK": 1}},
        DMARCAggregateResults(
            total=1,
            spf_success=1,
            dkim={"inclusion.beta.gouv.fr": {"zendesk2": {"fail": 1}}},
        ),
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
    expected_daily_stats, expected_aggregate_results = expected
    daily_stats, aggregate_results = process_dmarc_aggregate(json_path)
    assert aggregate_results == expected_aggregate_results
    assert daily_stats == expected_daily_stats
