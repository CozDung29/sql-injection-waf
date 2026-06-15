import argparse
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="One command: expand_from_blocked -> test_variants -> learn_mutate_rules (optional apply)."
    )
    ap.add_argument(
        "--fresh",
        action="store_true",
        help="Truncate adversarial_from_blocked.jsonl and test_results.jsonl before expand.",
    )
    ap.add_argument("--blocked-tail", type=int, default=None, metavar="N")
    ap.add_argument("--ml-waf-root", type=Path, default=None)
    ap.add_argument("--blocked-jsonl", type=Path, default=None)
    ap.add_argument("--rules", type=Path, default=None)
    ap.add_argument("--max-per-source", type=int, default=64)
    ap.add_argument("--expand-out", type=Path, default=DATA_DIR / "adversarial_from_blocked.jsonl")
    ap.add_argument("--test-in", type=Path, default=None, help="Default: same as --expand-out")
    ap.add_argument("--test-out", type=Path, default=DATA_DIR / "test_results.jsonl")
    ap.add_argument("--test-tail", type=int, default=None, metavar="N")
    ap.add_argument("--max-tests", type=int, default=None)
    ap.add_argument("--sleep", type=float, default=0.0)
    ap.add_argument("--no-stop-on-401", action="store_true")
    ap.add_argument("--skip-expand", action="store_true")
    ap.add_argument("--skip-test", action="store_true")
    ap.add_argument("--skip-learn", action="store_true")
    ap.add_argument(
        "--apply-learned",
        action="store_true",
        help="learn_mutate_rules --apply (copy suggested order into data/mutate_rules.json).",
    )
    ap.add_argument("--learn-out", type=Path, default=DATA_DIR / "mutate_rules.suggested.json")
    ap.add_argument("--base-rules", type=Path, default=DATA_DIR / "mutate_rules.json")
    ap.add_argument(
        "--adv-encodings-out",
        type=Path,
        default=DATA_DIR / "adv_learned_encodings.json",
        help="Summary like ml-waf learned_encodings (from test_results).",
    )
    ap.add_argument("--skip-adv-summary", action="store_true", help="Do not write adv_learned_encodings.json")
    ap.add_argument(
        "--resume-test",
        action="store_true",
        help="Pass --resume to test_variants (skip bypass/blocked already in test_results).",
    )
    ns = ap.parse_args(argv)

    if ns.fresh:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        ns.expand_out.write_text("", encoding="utf-8")
        ns.test_out.write_text("", encoding="utf-8")

    from adv_learned_encodings import write_summary
    from expand_from_blocked import main as expand_main
    from learn_mutate_rules import main as learn_main
    from test_variants import main as test_main

    if not ns.skip_expand:
        expand_args: list[str] = ["--out", str(ns.expand_out)]
        if ns.ml_waf_root is not None:
            expand_args += ["--ml-waf-root", str(ns.ml_waf_root)]
        if ns.blocked_jsonl is not None:
            expand_args += ["--blocked-jsonl", str(ns.blocked_jsonl)]
        if ns.blocked_tail is not None:
            expand_args += ["--tail", str(ns.blocked_tail)]
        expand_args += ["--max-per-source", str(ns.max_per_source)]
        if ns.rules is not None:
            expand_args += ["--rules", str(ns.rules)]
        c = expand_main(expand_args)
        if c != 0:
            return c

    if not ns.skip_test:
        test_in = ns.test_in or ns.expand_out
        test_args: list[str] = ["--in", str(test_in), "--out", str(ns.test_out)]
        if ns.test_tail is not None:
            test_args += ["--tail", str(ns.test_tail)]
        if ns.max_tests is not None:
            test_args += ["--max-tests", str(ns.max_tests)]
        if ns.sleep:
            test_args += ["--sleep", str(ns.sleep)]
        if ns.no_stop_on_401:
            test_args += ["--no-stop-on-401"]
        if ns.resume_test:
            test_args += ["--resume"]
        c = test_main(test_args)
        if c != 0:
            return c
        if not ns.skip_adv_summary:
            p_sum, _ = write_summary(ns.test_out, ns.adv_encodings_out)
            print(f"Wrote {p_sum.resolve()} (bypass/block rates per adv_label)")

    if not ns.skip_learn:
        learn_args: list[str] = [
            "--test-results",
            str(ns.test_out),
            "--base-rules",
            str(ns.base_rules),
            "--out",
            str(ns.learn_out),
        ]
        if ns.apply_learned:
            learn_args.append("--apply")
        c = learn_main(learn_args)
        if c != 0:
            return c

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
