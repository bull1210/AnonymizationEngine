"""anonymizer CLI: validate-config | dry-run | worker | bridge | serve | eval | demo"""
from __future__ import annotations

import argparse
import json
import logging
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="anonymizer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("validate-config", help="validate app + policy config")
    p.add_argument("--app", default="config/app.yaml")
    p.add_argument("--policy", default="config/masking_policy.yaml")

    p = sub.add_parser("dry-run", help="transform one message file; write no artifacts")
    p.add_argument("--input", required=True,
                   help='JSON: {"file_id","text","findings":[...],"job":{...}}')
    p.add_argument("--config", default="config/app.yaml")
    p.add_argument("--redline", help="write HTML redline diff to this path")

    p = sub.add_parser("run", help="anonymize one file or every file in a folder")
    p.add_argument("--in", dest="in_path", required=True,
                   help="a .json/.txt file, or a folder containing them")
    p.add_argument("--target", choices=["training", "rag"], default="training")
    p.add_argument("--config", default="config/app.yaml")
    p.add_argument("--job-id", default=None, help="default: <target>-<timestamp>")
    p.add_argument("--tenant", default="default")

    p = sub.add_parser("worker", help="run a worker (directory or kafka source)")
    p.add_argument("--config", default="config/app.yaml")

    p = sub.add_parser("bridge", help="assemble jobs from detection scan results "
                                      "(Kafka in -> directory queue out)")
    p.add_argument("--bootstrap", default="kafka:9092")
    p.add_argument("--topic", default="files.scan.results")
    p.add_argument("--group", default="anonymizer-bridge")
    p.add_argument("--text-store-url", required=True,
                   help="extraction service base URL serving GET /text/{doc_id}")
    p.add_argument("--out-dir", default="/data/input",
                   help="the worker's directory-queue input folder")
    p.add_argument("--target", choices=["training", "rag"], default="training")
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--tenant", default="default")
    p.add_argument("--job-id", default=None,
                   help="stable job id (default: bridge-<target>) — keep stable "
                        "so receipt idempotency dedups reprocessed documents")
    p.add_argument("--flush-after", type=float, default=300.0,
                   help="seconds before an incomplete document is emitted anyway")

    p = sub.add_parser("serve", help="run the dry-run/preview FastAPI service")
    p.add_argument("--config", default="config/app.yaml")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8000)

    p = sub.add_parser("eval", help="run the evaluation harness")
    p.add_argument("--docs", type=int, default=40)
    p.add_argument("--json", dest="json_out", help="also write JSON report here")

    sub.add_parser("demo", help="print a side-by-side demo of both modes")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}')
    return _dispatch(args)


def _dispatch(args: argparse.Namespace) -> int:
    if args.cmd == "bridge":
        from .bridge import run_bridge

        job = {
            "job_id": args.job_id or f"bridge-{args.target}",
            "downstream_target": args.target,
            "tenant_id": args.tenant,
            "confidence_threshold": args.threshold,
        }
        return run_bridge(args.bootstrap, args.topic, args.group,
                          args.text_store_url, args.out_dir, job,
                          flush_after_s=args.flush_after)

    if args.cmd == "validate-config":
        from .core.policyload import load_policy_yaml
        from .runtime import load_app_config

        load_app_config(args.app)
        table = load_policy_yaml(args.policy)
        print(f"OK: policy version {table.version}, {len(table.entries)} entries, "
              "mode invariants hold")
        return 0

    if args.cmd == "dry-run":
        from .core.redline import redline_html
        from .core.types import finding_from_dict, jobspec_from_dict
        from .runtime import Runtime, load_app_config

        msg = json.loads(open(args.input, encoding="utf-8").read())
        rt = Runtime(load_app_config(args.config))
        job = jobspec_from_dict(msg["job"])
        findings = [finding_from_dict(d) for d in msg.get("findings", [])]
        result = rt.engine_for(job).transform(msg["text"], findings, job,
                                              str(msg.get("file_id", "adhoc")))
        r = result.receipt
        print(json.dumps({"masked_text": result.masked_text, "status": r.status,
                          "replacements": len(r.replacements)}, indent=2))
        if args.redline:
            html = redline_html(msg["text"], result.masked_text,
                                file_id=r.file_id, mode=r.mode,
                                policy_version=r.policy_version, status=r.status,
                                count=len(r.replacements))
            open(args.redline, "w", encoding="utf-8").write(html)
            print(f"redline written: {args.redline}", file=sys.stderr)
        return 0 if r.status != "LEAK_DETECTED" else 3

    if args.cmd == "run":
        from .batch import run_batch

        return run_batch(args.in_path, args.target, args.config, args.job_id, args.tenant)

    if args.cmd == "worker":
        import os

        from .runtime import Runtime, load_app_config
        from .worker import DirectorySource, KafkaSource, Worker

        try:  # Prometheus /metrics endpoint (PROMETHEUS_PORT, default 9100)
            from prometheus_client import start_http_server

            start_http_server(int(os.environ.get("PROMETHEUS_PORT", "9100")))
        except ImportError:
            pass

        cfg = load_app_config(args.config)
        rt = Runtime(cfg)
        worker = Worker(rt)
        input_cfg = cfg.get("input", {"mode": "dir", "dir": "input"})
        if input_cfg.get("mode") == "kafka":
            source = KafkaSource(input_cfg["bootstrap_servers"])
            while True:
                for message, _ in source.poll():
                    worker.process(message)
        else:
            worker.run_forever(DirectorySource(input_cfg.get("dir", "input")))
        return 0

    if args.cmd == "serve":
        import os

        import uvicorn

        os.environ["ANON_CONFIG"] = args.config
        uvicorn.run("anonymizer.api:app", host=args.host, port=args.port)
        return 0

    if args.cmd == "eval":
        from .evalharness import format_report, run_eval

        report = run_eval(args.docs)
        print(format_report(report))
        if args.json_out:
            open(args.json_out, "w", encoding="utf-8").write(json.dumps(report, indent=2))
        return 0

    if args.cmd == "demo":
        from .core.detection import RegexDetector
        from .core.engine import Engine
        from .core.policyload import build_policy_table
        from .core.pseudonym import MemoryCollisionRegistry
        from .core.types import Finding, JobSpec, Target
        from .evalharness import DEFAULT_POLICY

        text = ("Dr. Priya Sharma (phone 9840123456) was admitted on 2024-03-12 and "
                "discharged on 2024-03-15. Prescribed Metformin. "
                "Card on file: 4111 1111 1111 1111. Later, SHARMA, Priya confirmed.")

        def find(surface: str, etype: str, conf: float) -> Finding:
            start = text.index(surface)
            return Finding(etype, start, start + len(surface), conf)

        findings = [
            find("Dr. Priya Sharma", "PERSON", 0.98),
            find("9840123456", "PHONE", 0.95),
            find("2024-03-12", "DATE", 0.9),
            find("2024-03-15", "DATE", 0.9),
            find("Metformin", "MEDICATION", 0.85),
            find("4111 1111 1111 1111", "CREDIT_CARD", 0.99),
            find("SHARMA, Priya", "PERSON", 0.9),
        ]
        policy = build_policy_table(DEFAULT_POLICY)
        print("ORIGINAL:\n  " + text + "\n")
        for target in (Target.TRAINING, Target.RAG):
            engine = Engine(policy,
                            salt_provider=(lambda j: b"\x07" * 32)
                            if target == Target.RAG else None,
                            detector=RegexDetector(),
                            collision_registry=MemoryCollisionRegistry()
                            if target == Target.RAG else None)
            job = JobSpec(job_id="demo", target=target)
            res = engine.transform(text, findings, job, "demo")
            print(f"{target.value.upper()} ({res.receipt.status}):\n  {res.masked_text}\n")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
