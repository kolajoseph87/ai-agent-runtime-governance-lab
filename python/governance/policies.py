"""Small Chapter 2 policies for visible boundary decisions."""

import re

from .models import ExecutionContext, ToolIdentity


SUSPICIOUS_INPUT_PATTERNS = (
    "ignore previous instructions",
    "ignore all security requirements",
    "print environment variables",
    "read every .env",
    "reveal api keys",
)

SECRET_PATTERN = re.compile(
    r"(?:"
    r"sk-[A-Za-z0-9_-]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")",
    re.IGNORECASE,
)


async def require_code_review_claim(
    context: ExecutionContext, payload: str
) -> tuple[bool, str]:
    del payload
    if "code:review" not in context.principal.claims:
        return False, "Principal lacks the code:review claim"
    return True, "Principal is entitled to request code review"


async def deny_goal_manipulation(
    context: ExecutionContext, payload: str
) -> tuple[bool, str]:
    del context
    normalized = payload.lower()
    if any(pattern in normalized for pattern in SUSPICIOUS_INPUT_PATTERNS):
        return False, "Potential goal-manipulation instruction detected"
    return True, "No blocked goal-manipulation pattern detected"


async def deny_secret_output(
    context: ExecutionContext, payload: str
) -> tuple[bool, str]:
    del context
    if SECRET_PATTERN.search(payload):
        return False, "Potential secret detected in agent output"
    return True, "No secret pattern detected in agent output"


def find_tool(
    context: ExecutionContext, tool_name: str
) -> ToolIdentity | None:
    return next(
        (tool for tool in context.tool_inventory if tool.tool_name == tool_name),
        None,
    )


async def authorize_tool_request(
    context: ExecutionContext, payload: str
) -> tuple[bool, str]:
    """Payload format for Chapter 2: tool_name|required_scope."""

    try:
        tool_name, required_scope = payload.split("|", maxsplit=1)
    except ValueError:
        return False, "Malformed tool authorization request"

    tool = find_tool(context, tool_name)
    if tool is None:
        return False, f"Tool {tool_name} is not in the immutable inventory"
    if required_scope not in tool.allowed_scopes:
        return False, f"Tool {tool_name} does not allow {required_scope}"
    if required_scope not in context.principal.claims:
        return False, f"Principal is not entitled to {required_scope}"
    return True, f"Principal and tool both permit {required_scope}"
