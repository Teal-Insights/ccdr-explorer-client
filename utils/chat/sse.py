from openai import AsyncOpenAI
from openai.lib.streaming._assistants import AsyncAssistantStreamManager
from openai.types.beta.threads.run_submit_tool_outputs_params import ToolOutput
from openai.types.beta.assistant_stream_event import (
    ThreadRunRequiresAction
)
from openai.types.beta.threads.run import RequiredAction
from pydantic import BaseModel
from typing import Dict, Any, Optional
from fastapi import HTTPException
from logging import getLogger
from dataclasses import dataclass

logger = getLogger("uvicorn.error")


# --- Helper Classes ---


@dataclass
class AssistantStreamMetadata:
    """Metadata for assistant stream events that require further processing."""
    type: str  # Always "metadata"
    required_action: Optional[RequiredAction]
    step_id: str
    run_requires_action_event: Optional[ThreadRunRequiresAction]

    @classmethod
    def create(cls, 
               required_action: Optional[RequiredAction],
               step_id: str,
               run_requires_action_event: Optional[ThreadRunRequiresAction]
    ) -> "AssistantStreamMetadata":
        """Factory method to create a metadata instance with validation."""
        return cls(
            type="metadata",
            required_action=required_action,
            step_id=step_id,
            run_requires_action_event=run_requires_action_event
        )

    def requires_tool_call(self) -> bool:
        """Check if this metadata indicates a required tool call."""
        return (self.required_action is not None 
                and self.required_action.submit_tool_outputs is not None 
                and bool(self.required_action.submit_tool_outputs.tool_calls))

    def get_run_id(self) -> str:
        """Get the run ID from the requires action event, or empty string if none."""
        return self.run_requires_action_event.data.id if self.run_requires_action_event else ""


class ToolCallOutputs(BaseModel):
    tool_outputs: Dict[str, Any]
    runId: str


# --- Helper Functions ---


def sse_format(event: str, data: str, retry: int | None = None) -> str:
    """
    Helper function to format a Server-Sent Event (SSE) message.

    Args:
        event: The name/type of the event.
        data: The data payload as a string.
        retry: Optional retry timeout in milliseconds.

    Returns:
        A formatted SSE message string.
    """
    output = f"event: {event}\n"
    if retry is not None:
        output += f"retry: {retry}\n"
    # Ensure each line of data is prefixed with "data: "
    for line in data.splitlines():
        output += f"data: {line}\n"
    output += "\n"  # An extra newline indicates the end of the message.
    return output


async def post_tool_outputs(client: AsyncOpenAI, data: Dict[str, Any], thread_id: str) -> AsyncAssistantStreamManager:
    """
    data is expected to be something like
    {
      "tool_outputs": {
        "output": [{"location": "City", "temperature": 70, "conditions": "Sunny"}],
        "tool_call_id": "call_123"
      },
      "runId": "some-run-id",
    }
    """
    try:
        outputs_list = [
            ToolOutput(
                output=str(data["tool_outputs"]["output"]),
                tool_call_id=data["tool_outputs"]["tool_call_id"]
            )
        ]


        stream_manager = client.beta.threads.runs.submit_tool_outputs_stream(
            thread_id=thread_id,
            run_id=data["runId"],
            tool_outputs=outputs_list,
        )

        return stream_manager

    except Exception as e:
        logger.error(f"Error submitting tool outputs: {e}")
        raise HTTPException(status_code=500, detail=str(e))