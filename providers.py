"""Thin adapters around official provider SDKs.

Each adapter exposes .send(system, user) -> str. Imports are lazy so you only
need the SDK for the provider you're actually testing against.
"""


class AnthropicProvider:
    def __init__(self, model: str, base_url: str | None = None):
        try:
            import anthropic
        except ImportError as e:
            raise SystemExit("Anthropic provider needs the SDK: pip install anthropic") from e
        self._client = anthropic.Anthropic(base_url=base_url) if base_url else anthropic.Anthropic()
        self._model = model

    def send(self, system: str, user: str) -> str:
        # ponytail: broad catch is deliberate -- auth/config errors (missing key)
        # raise plain TypeError from the SDK, not an APIError subclass, and this
        # function's contract is "always return a status string, never crash a run".
        try:
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as e:
            return f"[error] {e}"
        if resp.stop_reason == "refusal":
            return "[refusal]"
        return "".join(b.text for b in resp.content if b.type == "text")


class OpenAIProvider:
    """Also works against any OpenAI-compatible endpoint (Ollama, vLLM, local servers) via base_url."""

    def __init__(self, model: str, base_url: str | None = None):
        try:
            import openai
        except ImportError as e:
            raise SystemExit("OpenAI provider needs the SDK: pip install openai") from e
        self._client = openai.OpenAI(base_url=base_url) if base_url else openai.OpenAI()
        self._model = model

    def send(self, system: str, user: str) -> str:
        try:
            resp = self._client.chat.completions.create(
                model=self._model,
                max_tokens=1024,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            )
        except Exception as e:
            return f"[error] {e}"
        return resp.choices[0].message.content or "[empty]"


PROVIDERS = {"anthropic": AnthropicProvider, "openai": OpenAIProvider}
DEFAULT_MODELS = {"anthropic": "claude-opus-4-8", "openai": "gpt-4o-mini"}
