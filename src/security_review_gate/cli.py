import argparse
import json
import sys
from pathlib import Path

from .baseline import baseline_decision
from .diff_parser import parse_unified_diff
from .features import extract_features


def main() -> None:
    parser = argparse.ArgumentParser(description="Prioriza um diff para revisão de segurança.")
    parser.add_argument("--file", type=Path, help="Arquivo contendo diff unificado")
    parser.add_argument("--json", action="store_true", help="Produz saída JSON")
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Gera explicação em linguagem natural com o LLM (Claude), "
        "com grounding nos sinais do baseline e fallback determinístico.",
    )
    args = parser.parse_args()

    content = args.file.read_text(encoding="utf-8") if args.file else sys.stdin.read()
    parsed = parse_unified_diff(content)
    features = extract_features(parsed)
    decision = baseline_decision(features)

    result = {
        "review_level": decision.level,
        "score": decision.score,
        "signals": decision.signals,
        "summary": {
            "files_changed": features.files_changed,
            "lines_added": features.lines_added,
            "lines_removed": features.lines_removed,
        },
        "warning": "Prioridade de revisão; não é confirmação de vulnerabilidade.",
    }

    explanation = None
    if args.explain:
        from .llm_explainer import explain

        explanation = explain(decision, features, content)
        result["explanation"] = {"text": explanation.text, "source": explanation.source}

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print(f"Revisão de segurança: {decision.level.upper()}")
    print(f"Score do baseline: {decision.score}/100")
    if decision.signals:
        print("Sinais:")
        for signal in decision.signals:
            print(f"- {signal}")
    else:
        print("Sinais: nenhum sinal estrutural relevante no baseline.")
    if explanation is not None:
        rotulo = "LLM" if explanation.source == "llm" else "fallback determinístico"
        print(f"\nExplicação ({rotulo}):")
        print(explanation.text)
    print(result["warning"])


if __name__ == "__main__":
    main()
