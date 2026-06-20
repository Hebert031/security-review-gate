import json
import unittest
from types import SimpleNamespace

from security_review_gate.baseline import ReviewDecision
from security_review_gate.features import DiffFeatures
from security_review_gate.llm_explainer import explain


def _text_response(payload: dict):
    """Imita a resposta da Messages API: content com um bloco de texto JSON."""
    block = SimpleNamespace(type="text", text=json.dumps(payload))
    return SimpleNamespace(content=[block])


def _decision() -> ReviewDecision:
    return ReviewDecision(
        score=80,
        level="high",
        signals=["possível material secreto adicionado", "controle de segurança possivelmente desabilitado"],
    )


def _features() -> DiffFeatures:
    return DiffFeatures(
        files_changed=2,
        lines_added=10,
        lines_removed=3,
        test_files_changed=0,
        sensitive_paths=1,
        infrastructure_files=0,
        dependency_files=0,
        binary_files=0,
        auth_signals=0,
        crypto_signals=0,
        sql_signals=0,
        command_signals=0,
        input_signals=0,
        secret_signals=2,
        security_disable_signals=1,
    )


class FakeClient:
    """Cliente Anthropic falso: devolve uma resposta válida contra o schema."""

    def __init__(self, response) -> None:
        self._response = response
        self.messages = SimpleNamespace(create=self._create)
        self.last_kwargs = None

    def _create(self, **kwargs):
        self.last_kwargs = kwargs
        return self._response


class LlmExplainerTests(unittest.TestCase):
    def test_uses_llm_output_when_valid(self) -> None:
        response = _text_response(
            {
                "explanation": "Há um segredo hardcoded e verificação desabilitada; vale revisar.",
                "grounded_in_signals": True,
            }
        )
        client = FakeClient(response)

        result = explain(_decision(), _features(), "diff fake", client=client)

        self.assertEqual(result.source, "llm")
        self.assertTrue(result.grounded)
        self.assertIn("segredo", result.text)
        # O modelo correto foi usado e os sinais foram enviados como grounding.
        self.assertEqual(client.last_kwargs["model"], "claude-opus-4-8")
        self.assertIn("json_schema", json.dumps(client.last_kwargs["output_config"]))
        user_msg = client.last_kwargs["messages"][0]["content"]
        self.assertIn("material secreto", user_msg)

    def test_falls_back_when_llm_raises(self) -> None:
        class Boom:
            def __init__(self) -> None:
                self.messages = SimpleNamespace(create=self._create)

            def _create(self, **kwargs):
                raise RuntimeError("sem rede")

        result = explain(_decision(), _features(), "diff fake", client=Boom())

        self.assertEqual(result.source, "fallback")
        self.assertFalse(result.grounded)
        # O fallback é derivado apenas dos sinais do baseline.
        self.assertIn("material secreto", result.text)

    def test_falls_back_when_output_empty(self) -> None:
        response = _text_response({"explanation": "   ", "grounded_in_signals": True})
        result = explain(_decision(), _features(), "diff fake", client=FakeClient(response))

        self.assertEqual(result.source, "fallback")


if __name__ == "__main__":
    unittest.main()
