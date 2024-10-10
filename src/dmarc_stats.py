import argparse
import csv
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
    no_dkim: dict[str, int] = {}
    dkim: dict[str, dict[str, dict[str, int]]] = {}
    overridden_policies: list[str] = []


def entrypoint():
    parser = argparse.ArgumentParser()
    parser.add_argument("aggregate_file_path", type=pathlib.Path)
    parser.add_argument("--output-stats-csv", type=pathlib.Path)
    parser.add_argument("--since", type=datetime.date.fromisoformat)
    args = parser.parse_args()
    daily_stats, aggregate_results = process_dmarc_aggregate(
        args.aggregate_file_path, args.since
    )
    print_report(aggregate_results)
    if args.output_stats_csv:
        with open(args.output_stats_csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["date", "total", "SPF success", "DKIM success"])
            for date, stats in sorted(daily_stats.items(), key=lambda item: item[0]):
                writer.writerow(
                    [date, stats["TOTAL"], stats["SPF_OK"], stats["DKIM_OK"]]
                )


def pluralize(count):
    if count >= 2:
        return "s"
    return ""


def sort_value_key(item):
    return -item[1], item[0]


def count_dkim(stats):
    return sum(
        count
        for reason_results in stats.values()
        for reason, count in reason_results.items()
        if reason != "pass"
    )


def naive_date(timestamp_str):
    naive_datetime = datetime.datetime.fromisoformat(timestamp_str)
    utc_datetime = naive_datetime.replace(tzinfo=datetime.timezone.utc)
    return utc_datetime.date()


def process_dmarc_aggregate(report_json_file, since=None):
    total = 0
    spf_success = 0
    dkim_success = 0
    spf_alignment = defaultdict(int)
    spf_failures = defaultdict(int)
    spf_neutral = defaultdict(int)
    no_dkim = defaultdict(int)
    dkim = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    overridden_policies = []
    daily_stats: dict[datetime.date, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    with open(report_json_file, "rb") as f:
        data = json.load(f)
        for report in data:
            start_date = naive_date(report["report_metadata"]["begin_date"])
            end_date = naive_date(report["report_metadata"]["end_date"])
            if since and end_date <= since:
                continue

            def assign_stats_for_date_range(key, value):
                date = start_date
                while date < end_date:
                    daily_stats[date][key] += value
                    date += datetime.timedelta(days=1)

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
                    assign_stats_for_date_range("SPF_OK", count)
                if dkim_result == "pass":
                    dkim_success += count
                    assign_stats_for_date_range("DKIM_OK", count)

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
                    dkim_results = record["auth_results"]["dkim"]
                    for res in dkim_results:
                        dkim[envelope_from][res["selector"]][res["result"]] += count
                    if not dkim_results:
                        no_dkim[envelope_from] += count
                total += count
                assign_stats_for_date_range("TOTAL", count)
    return daily_stats, DMARCAggregateResults(
        total,
        spf_success,
        dkim_success,
        spf_alignment,
        spf_failures,
        spf_neutral,
        no_dkim,
        dkim,
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
        no_dkim,
        dkim,
        overridden_policies,
    ] = results

    spf_issues = total - spf_success
    dkim_issues = total - dkim_success
    print(f"Total email{pluralize(total)}: {total}")
    print(f"SPF issue{pluralize(spf_issues)}: {spf_issues}")
    print(f"DKIM issue{pluralize(dkim_issues)}: {dkim_issues}")
    print()
    print(f"# SPF ({spf_issues}):")
    print(f"## Check failed ({sum(count for count in spf_failures.values())}):")
    for envelope_from, count in sorted(spf_failures.items(), key=lambda item: -item[1]):
        print(f"Envelope from: {envelope_from}: {count} attempt{pluralize(count)}")
    print()
    print(f"## Misaligned ({sum(count for count in spf_alignment.values())}):")
    for envelope_from, count in sorted(spf_alignment.items(), key=sort_value_key):
        print(f"Envelope from: {envelope_from}: {count} attempt{pluralize(count)}")
    print()
    print(f"## Neutral ({sum(count for count in spf_neutral.values())})")
    for envelope_from, count in sorted(spf_neutral.items(), key=sort_value_key):
        print(f"Envelope from: {envelope_from}: {count} attempt{pluralize(count)}")
    print()
    print()
    print(f"# DKIM: {dkim_issues}")
    print(f"## Missing signature ({sum(no_dkim.values())}):")
    for envelope_from, count in sorted(no_dkim.items(), key=sort_value_key):
        print(f"Envelope from: {envelope_from}: {count} attempt{pluralize(count)}")
    print()
    dkim_report = sorted(dkim.items(), key=lambda item: -count_dkim(item[1]))
    dkim_fail_count = sum(count_dkim(stats) for stats in dkim.values())
    print(f"## Invalid signature ({dkim_fail_count}):")
    for envelope_from, stats in dkim_report:
        print(f"Envelope from: {envelope_from} ({count_dkim(stats)})")
        for selector, reasons in stats.items():
            reason_str = ", ".join(
                [
                    f"{reason}: {count}"
                    for reason, count in sorted(
                        reasons.items(), key=lambda item: item[0]
                    )
                ]
            )
            print(f"  Selector: {selector} - {{{reason_str}}}")
    print()
    print("# Overridden policies:")
    for policy, count in Counter(overridden_policies).most_common():
        print(f"{policy} ({count})")
