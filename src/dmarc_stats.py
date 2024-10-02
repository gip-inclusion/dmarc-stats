import argparse
import datetime
import json
import pathlib
from collections import Counter, defaultdict
from typing import NamedTuple


class DMARCAggregateResults(NamedTuple):
    total: int = 0
    spf_success: int = 0
    dkim_success: int = 0
    spf_alignment: dict[str, int] = {}
    spf_failures: dict[str, int] = {}
    spf_neutral: dict[str, int] = {}
    dkim_sig: dict[tuple[str, str], int] = {}
    dkim_domain: dict[str, int] = {}
    overridden_policies: list[str] = []


def entrypoint():
    parser = argparse.ArgumentParser()
    parser.add_argument("aggregate_file_path", type=pathlib.Path)
    parser.add_argument("--since", type=datetime.date.fromisoformat)
    args = parser.parse_args()
    results = process_dmarc_aggregate(args.aggregate_file_path, args.since)
    print_report(results)


def pluralize(count):
    if count >= 2:
        return "s"
    return ""


def sort_value_key(item):
    return -item[1], item[0]


def process_dmarc_aggregate(report_json_file, since=None):
    total = 0
    spf_success = 0
    dkim_success = 0
    spf_alignment = defaultdict(int)
    spf_failures = defaultdict(int)
    spf_neutral = defaultdict(int)
    dkim_sig = defaultdict(int)
    dkim_domain = defaultdict(int)
    overridden_policies = []
    with open(report_json_file, "rb") as f:
        data = json.load(f)
        for report in data:
            if since:
                end_date_str = report["report_metadata"]["end_date"]
                if datetime.datetime.fromisoformat(end_date_str).date() <= since:
                    continue
            for record in report["records"]:
                evaluation_results = record["policy_evaluated"]
                if override_reasons := evaluation_results["policy_override_reasons"]:
                    hashable_policy = json.dumps(override_reasons)
                    overridden_policies.append(hashable_policy)
                    continue

                count = record["count"]
                spf_result = evaluation_results["spf"]
                dkim_result = evaluation_results["dkim"]
                if spf_result == "pass":
                    spf_success += count
                if dkim_result == "pass":
                    dkim_success += count

                if spf_result == "fail":
                    envelope_from = record["identifiers"]["envelope_from"]
                    failure_details = [
                        entry
                        for entry in record["auth_results"]["spf"]
                        if entry["result"] == "fail"
                    ]
                    if failure_details:
                        assert len(failure_details) == 1
                        spf_failures[envelope_from] += count
                    else:
                        neutral_details = [
                            entry
                            for entry in record["auth_results"]["spf"]
                            if entry["result"] == "neutral"
                        ]
                        if neutral_details:
                            assert len(neutral_details) == 1
                            spf_neutral[envelope_from] += count
                        else:
                            assert not record["alignment"]["spf"]
                            spf_alignment[envelope_from] += count
                if dkim_result == "fail":
                    envelope_from = record["identifiers"]["envelope_from"]
                    failure_details = [
                        dkim_check
                        for dkim_check in record["auth_results"]["dkim"]
                        if dkim_check["result"] == "fail"
                    ]
                    if failure_details:
                        selector = ", ".join(
                            f"{dkim_entry['selector']}._domainkey.{dkim_entry['domain']}"
                            for dkim_entry in failure_details
                        )
                        dkim_sig[(envelope_from, selector)] += count
                    else:
                        # Valid signature, but for the wrong domain
                        # (invalid envelope_from).
                        dkim_domain[envelope_from] += count
                total += count
    return DMARCAggregateResults(
        total,
        spf_success,
        dkim_success,
        spf_alignment,
        spf_failures,
        spf_neutral,
        dkim_sig,
        dkim_domain,
        overridden_policies,
    )


def print_report(results: DMARCAggregateResults):
    [
        total,
        spf_success,
        dkim_success,
        spf_alignment,
        spf_failures,
        spf_neutral,
        dkim_sig,
        dkim_domain,
        overridden_policies,
    ] = results

    spf_issues = total - spf_success
    dkim_issues = total - dkim_success
    print(f"Total email{pluralize(total)}: {total}")
    print(f"SPF issue{pluralize(spf_issues)}: {spf_issues}")
    print(f"DKIM issue{pluralize(dkim_issues)}: {dkim_issues}")
    print()
    print(f"# SPF ({spf_issues}):")
    print(f"## Check failed ({sum(count for _, count in spf_failures.items())}):")
    for envelope_from, count in sorted(spf_failures.items(), key=lambda item: -item[1]):
        print(f"Envelope from: {envelope_from}: {count} attempt{pluralize(count)}")
    print()
    print(f"## Misaligned ({sum(count for _, count in spf_alignment.items())}):")
    for envelope_from, count in sorted(spf_alignment.items(), key=sort_value_key):
        print(f"Envelope from: {envelope_from}: {count} attempt{pluralize(count)}")
    print()
    print(f"## Neutral ({sum(count for _, count in spf_neutral.items())})")
    for envelope_from, count in sorted(spf_neutral.items(), key=sort_value_key):
        print(f"Envelope from: {envelope_from}: {count} attempt{pluralize(count)}")
    print()
    print()
    print(f"# DKIM: {dkim_issues}")
    print(f"## Invalid signature ({sum(count for _, count in dkim_sig.items())}):")
    for (envelope_from, selector), count in sorted(
        dkim_sig.items(), key=sort_value_key
    ):
        print(
            f"Envelope from: {envelope_from} {selector=}: "
            f"{count} attempt{pluralize(count)}"
        )
    print()
    print(f"## Invalid domain ({sum(count for _, count in dkim_domain.items())}):")
    for envelope_from, count in sorted(dkim_domain.items(), key=sort_value_key):
        print(f"Envelope from: {envelope_from}: {count} attempt{pluralize(count)}")
    print()
    print("# Overridden policies:")
    for policy, count in Counter(overridden_policies).most_common():
        print(f"{policy} ({count})")
