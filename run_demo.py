"""Run bundled local examples and create an index; only writes --output."""
import argparse
import html
import json
from pathlib import Path
from coaudit.pipeline import run_bundle
from coaudit.report import render_html


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "runs" / "demo")
    args = parser.parse_args()
    source = Path(__file__).parent / "examples"
    results, rows = [], []
    for bundle in sorted(source.glob("*/bundle.json")):
        result = run_bundle(bundle)
        dest = args.output / bundle.parent.name
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (dest / "index.html").write_text(render_html(result), encoding="utf-8")
        results.append(result)
        rows.append(f'<li><a href="{bundle.parent.name}/index.html">{html.escape(result["name"])}</a> · {result["decision"]}</li>')
        print(f'{bundle.parent.name}: {result["input_status"]} / {result["decision"]}')
    if not results:
        parser.error("no bundled examples")
    (args.output / "index.html").write_text('<!doctype html><meta charset="utf-8"><title>ROS2-CoAudit 演示</title><style>body{font:17px/2 system-ui;max-width:950px;margin:50px auto;color:#18303a}a{color:#006d70}</style><h1>ROS2-CoAudit · 离线联合审计</h1><p>合成配置与日志场景；点击进入证据报告。并非 ROS/DDS 运行实验。</p><ol>'+''.join(rows)+'</ol>', encoding="utf-8")
    (args.output / "all_results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Open {args.output / 'index.html'}")
    return 2 if any(r["input_status"] == "INPUT_ERROR" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
