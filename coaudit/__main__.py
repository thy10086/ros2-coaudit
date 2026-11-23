import argparse
import json
from pathlib import Path

from .pipeline import run_bundle
from .report import render_html


def main():
    parser = argparse.ArgumentParser(description="ROS2-CoAudit: offline SROS2 source-policy and task-contract audit")
    parser.add_argument("bundle", type=Path, help="path to bundle.json")
    parser.add_argument("--output", type=Path, required=True, help="output directory for result.json and index.html")
    parser.add_argument("--gate", action="store_true", help="exit 1 for BLOCK/REVIEW; normal audit completion is otherwise 0")
    args = parser.parse_args()
    result = run_bundle(args.bundle)
    inputs = {(args.bundle.parent / item["path"]).resolve() for item in result["evidence"]}
    outputs = [args.output / "result.json", args.output / "index.html"]
    if any(p.resolve() in inputs for p in outputs):
        parser.error("output would overwrite an input evidence file")
    args.output.mkdir(parents=True, exist_ok=True)
    outputs[0].write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    outputs[1].write_text(render_html(result), encoding="utf-8")
    print(f"{result['name']}: {result['input_status']} / {result['decision']}")
    print(f"JSON: {outputs[0]}\nHTML: {outputs[1]}")
    if result["input_status"] == "INPUT_ERROR":
        return 2
    return 1 if args.gate and result["decision"] != "MODEL_PASS" else 0


if __name__ == "__main__":
    raise SystemExit(main())
