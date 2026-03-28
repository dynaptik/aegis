# src/aegis/infrastructure/adapters/anthropic_adapter.py

import json
import logging
from typing import List, Type, TypeVar
from pydantic import BaseModel, ValidationError
from anthropic import  Anthropic
from aegis.domain.models import Vulnerability
from aegis.domain.exceptions import SecurityAgentError
from aegis.ports.llm import ILlmClient

logger = logging.getLogger(__name__)

T = TypeVar('T', bound=BaseModel)

class VulnerabilityList(BaseModel):
    """A helper model to force the llm to return a list of vulns."""
    vulnerabilities: List[Vulnerability]

class AnthropicAdapter(ILlmClient):
    """Concrete implementation of the llm interface using Claude models."""
    # TODO check if model switching is best located here in a hexa arch
    def __init__(self, api_key: str, model: str = "claude-4.6-sonnet-latest"):
        self.client = Anthropic(api_key=api_key)
        self.model = model

    def ask_structured(self, prompt: str, response_model: Type[T]) -> T:
        """
        Forces claude to return JSON that perfectly matches the pydantics schema.
        This is an esssential boundary I must enforce!
        """
        # TODO reconsider JSON vs TOON vs JSON compact for token optimization later

        # 1. extract the json schema automatically from the domain model
        schema = response_model.model_json_schema()

        # TODO move the prompt later
        system_prompt = (
            "You are an expert security researcher. "
            "You must respond ONLY with valid, raw JSON. Do not use Markdown formatting. "
            f"Your output MUST strictly adhere to this JSON schema: {json.dumps(schema)}"
        )

        try:
            # 2. call the anthropic API
            # TODO reconsider where these type of configurations ideally live
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096, # no idea where the sweet spot will be, test later
                temperature=0.2, # this is quite deterministic, experiment with it later
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}]
            )

            # 3. clean the response up (especially if it starts wrapping in markdown anyway)
            raw_output = response.content[0].text.strip()
            if raw_output.startswith("```json"):
                raw_output = raw_output[7:-3].strip()
            if raw_output.startswith("```"):
                raw_output = raw_output[3:-3].strip()

            # 4. squeeze it into our domain model
            return response_model.model_validate_json(raw_output)

        except ValidationError as e:
            # in case claude hallucinates something malformed, data type or state
            logger.error(f"Claude returned malformed JSON that violated the Domain rules: {e}")
            raise SecurityAgentError(f"LLM hallucination rejected by Pydantic: {e}") from e
        except Exception as e:
            raise SecurityAgentError(f"Anthropic API failure: {e}") from e

    def analyze_code_for_vulnerabilities(self, code_snippet: str, context: str) -> List[Vulnerability]:
        """Implements the port method using our structured json caller"""
        # TODO refactor this later, also decide if it should be a more narrow focus for vuln classes
        prompt = (
            f"Context: {context}\n\n"
            f"Code snippet to analyze:\n{code_snippet}\n\n"
            "Identify any security vulnerabilities. If none are found, return an empty list."
        )

        # we ask claude for a VulnerabilityList, then extract the list
        result = self.ask_structured(prompt=prompt, response_model=VulnerabilityList)
        return result.vulnerabilities

    def generate_exploit_script(self, vulnerability: Vulnerability, target_info: str) -> str:
        """Implements the port method for raw text generation (code)."""
        prompt = (
            f"Write a python script to verify this vulnerability: {vulnerability.title} ({vulnerability.cwe_id}).\n"
            f"Description: {vulnerability.description}\n"
            f"Target Information: {target_info}\n\n"
            "Return ONLY the executable Python code. Do NOT include Markdown formatting or explanations."
        )

        response = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            temperature=0.4, # TODO test what temp is best for codegen
            messages=[{"role": "user", "content": prompt}]
        )

        script = response.content[0].text.strip()
        # some clean up
        if script.startswith("```python"):
            script = script[9:-3].strip()
        elif script.startswith("```"):
            script = script[3:-3].strip()

        return script
