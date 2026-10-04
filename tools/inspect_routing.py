"""Offline DOMAIN/DOMAIN-SUFFIX routing reference, not a Loon runtime emulator."""
import argparse
import csv
import json
import random
import statistics
import time
import tracemalloc
from collections import Counter
from pathlib import Path

from rulegrammar import parse_rule


def load_domain_routes(tree: Path, include_heavy: bool = False):
    """Read the manifest's actual order; Heavy is opt-in as in private Loon configs."""
    rules = []
    rows = csv.reader(line for line in (tree / "MANIFEST.csv").read_text().splitlines()
                      if line.strip() and not line.lstrip().startswith("#"))
    for tag, policy, filename, _ in rows:
        if tag == "Ads-Reject-Heavy" and not include_heavy:
            continue
        for line in (tree / Path(filename).name).read_text().splitlines():
            rule = parse_rule(line)
            if rule and rule.rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
                rules.append((rule.rule_type, rule.value, policy))
    return rules


class DomainRouter:
    def __init__(self, rules):
        self.exact = {}
        self.suffix = {}
        for rank, (kind, value, policy) in enumerate(rules):
            target = self.exact if kind == "DOMAIN" else self.suffix
            target.setdefault(value, (rank, policy))

    def match(self, host):
        host = host.lower().rstrip(".")
        best = self.exact.get(host)
        labels = host.split(".")
        for index in range(len(labels)):
            candidate = self.suffix.get(".".join(labels[index:]))
            if candidate is not None and (best is None or candidate[0] < best[0]):
                best = candidate
        return best[1] if best is not None else "FINAL"


def linear_match(rules, host):
    host = host.lower().rstrip(".")
    return next((policy for kind, value, policy in rules if host == value or
                 kind == "DOMAIN-SUFFIX" and host.endswith("." + value)), "FINAL")


def benchmark(tree, include_heavy, rounds, probes=None):
    start = time.perf_counter()
    rules = load_domain_routes(tree, include_heavy)
    parse_seconds = time.perf_counter() - start
    tracemalloc.start()
    start = time.perf_counter()
    router = DomainRouter(rules)
    index_seconds = time.perf_counter() - start
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rng = random.Random(20261004)
    by_policy = {}
    for kind, value, policy in rules:
        by_policy.setdefault(policy, []).append(value)
    ads = rng.sample(by_policy.get("广告分流", []), min(30, len(by_policy.get("广告分流", []))))
    services = [value for _, value, policy in rules if policy != "广告分流"]
    samples = ads + rng.sample(services, min(30, len(services)))
    probes = probes if probes is not None else samples + [f"unmatched-{index}.invalid" for index in range(20)]
    expected = [linear_match(rules, host) for host in probes]
    assert [router.match(host) for host in probes] == expected
    timings = {"linear": [], "indexed": [], "linear_misses": [], "indexed_misses": []}
    for _ in range(rounds):
        for label, evaluator in (("linear", lambda host: linear_match(rules, host)), ("indexed", router.match)):
            for suffix, corpus in (("", probes), ("_misses", probes[-20:])):
                start = time.perf_counter()
                for host in corpus:
                    evaluator(host)
                timings[label + suffix].append(time.perf_counter() - start)
    return {
        "include_heavy": include_heavy, "domain_rule_count": len(rules),
        "rules_by_policy": dict(Counter(policy for _, _, policy in rules)),
        "parse_seconds": parse_seconds, "index_seconds": index_seconds,
        "python_index_peak_bytes": peak_bytes, "probe_count": len(probes),
        "probe_hosts": probes,
        "rounds": rounds, "median_seconds": {key: statistics.median(values) for key, values in timings.items()},
        "index_reference_agreement": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", type=Path, default=Path(__file__).resolve().parents[1] / "rules/loon/generated")
    parser.add_argument("--compare-tree", type=Path)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("rounds must be positive")
    result = {"scope": "Offline Python DOMAIN/DOMAIN-SUFFIX matching only. Excludes IP/ASN, regex, process rules, node speed and Loon runtime memory; no device-performance claim."}
    if args.compare_tree:
        result["baseline"] = [benchmark(args.compare_tree, heavy, args.rounds) for heavy in (False, True)]
    result["current"] = [benchmark(args.tree, heavy, args.rounds, result["baseline"][index]["probe_hosts"] if "baseline" in result else None)
                         for index, heavy in enumerate((False, True))]
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.json_output:
        args.json_output.write_text(text)
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
