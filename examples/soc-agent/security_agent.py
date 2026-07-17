"""Chapter 1 baseline: an intentionally ungoverned SOC assistant."""

import asyncio
import os
from dataclasses import dataclass

from agents import Agent, Runner


@dataclass(frozen=True)
class AgentConfiguration:
    model_name: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    agent_name: str = "SecurityIncidentAgent"


class SecurityIncidentAgent:
    """Small wrapper that becomes the governance interception boundary."""

    def __init__(self, config: AgentConfiguration | None = None) -> None:
        self.config = config or AgentConfiguration()
        self.agent = Agent(
            name=self.config.agent_name,
            instructions=(
    "You are a security operations assistant. "
    "For every security incident: "
    "1. Explain why the activity is suspicious. "
    "2. Identify the likely security risk. "
    "3. Recommend investigation steps. "
    "4. Recommend safe containment steps. "
    "5. Do not claim that you performed any investigation or containment action. "
    '6. End with this exact statement: "No containment actions were performed. '
    'This baseline agent has no tools and only provides recommendations."'
),
            model=self.config.model_name,
        )

    async def run(self, user_query: str) -> str:
        result = await Runner.run(self.agent, user_query)
        return str(result.final_output)


async def execute_security_query(query: str) -> None:
    response = await SecurityIncidentAgent().run(query)
    print(response)


if __name__ == "__main__":
    asyncio.run(
        execute_security_query(
            "A finance employee had five failed logins followed by a successful "
            "login from a new country. Explain the risk and recommend next steps."
        )
    )

