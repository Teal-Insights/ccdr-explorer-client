# TODO: These need to be authenticated routes, or else they could be intercepted and/or abused

import os
import json
import re
from datetime import datetime
from logging import getLogger, Logger
from typing import Optional, List, Dict, Any, AsyncGenerator, Union
from dotenv import load_dotenv
from fastapi import APIRouter, Form, Depends, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import Response, HTMLResponse, StreamingResponse
from openai import AsyncOpenAI
from sqlmodel import Session
from openai.lib.streaming._assistants import (
    AsyncAssistantStreamManager,
    AsyncAssistantEventHandler,
)
from openai.types.beta.assistant_stream_event import (
    ThreadMessageCreated,
    ThreadMessageDelta,
    ThreadRunCompleted,
    ThreadRunRequiresAction,
    ThreadRunStepCreated,
    ThreadRunStepDelta,
)
from openai.types.beta.threads.text_delta import TextDelta
from openai.types.beta import AssistantStreamEvent
from openai.types.beta.threads.message_content_delta import MessageContentDelta
from openai.types.beta.threads.text_delta_block import TextDeltaBlock
from openai.types.beta.threads.run import RequiredAction

from exceptions.http_exceptions import OpenAIError
from utils.chat.functions import get_weather
from utils.chat.sse import sse_format, post_tool_outputs
from utils.chat.sse import AssistantStreamMetadata
from utils.chat.files import FILE_PATHS, DOCUMENT_CITATIONS
from utils.core.dependencies import (
    get_user_with_relations,
    get_authenticated_user,
    get_session,
)
from utils.core.models import User
from utils.chat.threads import create_thread
from routers.files import router as files_router

logger = getLogger("uvicorn.error")

router: APIRouter = APIRouter(prefix="/chat", tags=["chat"])

# Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Check if environment variables are missing
load_dotenv(os.getenv("ENVIRONMENT", ".env"))
openai_api_key = os.getenv("OPENAI_API_KEY")
assistant_id_from_env = os.getenv("ASSISTANT_ID")

if openai_api_key and assistant_id_from_env:
    assistant_id = assistant_id_from_env
else:
    raise OpenAIError("OpenAI API key or assistant ID is missing")


# --- Authenticated Routes ---


@router.get("/")
async def read_chat(
    request: Request,
    user: Optional[User] = Depends(get_user_with_relations),
    thread_id: Optional[str] = None,
    messages: List[Dict[str, Any]] = [],
) -> Response:
    # Create a new assistant chat thread if no thread ID is provided
    if not thread_id or thread_id == "None" or thread_id == "null":
        thread_id = await create_thread()

    return templates.TemplateResponse(
        "chat/index.html",
        {
            "request": request,
            "user": user,
            "messages": messages,
            "thread_id": thread_id,
        },
    )


# Route to submit a new user message to a thread and mount a component that
# will start an assistant run stream
@router.post("/{thread_id}/send")
async def send_message(
    request: Request,
    thread_id: str,
    userInput: str = Form(...),
    user: User = Depends(get_authenticated_user),
    client: AsyncOpenAI = Depends(lambda: AsyncOpenAI()),
) -> HTMLResponse:
    # Create a new message in the thread
    await client.beta.threads.messages.create(
        thread_id=thread_id,
        role="user",
        content=f"System: Today's date is {datetime.today().strftime('%Y-%m-%d')}\n{userInput}",
    )

    # Render the component templates with the context
    user_message_html = templates.get_template("chat/user-message.html").render(
        user_input=userInput
    )
    assistant_run_html = templates.get_template("chat/assistant-run.html").render(
        request=request, assistant_id=assistant_id, thread_id=thread_id
    )

    return HTMLResponse(content=(user_message_html + assistant_run_html))


def wrap_for_oob_swap(step_id: str, text_value: str) -> str:
    return f'<span hx-swap-oob="beforeend:#step-{step_id}">{text_value}</span>'


# Route to stream the response from the assistant via server-sent events
@router.get("/{thread_id}/receive")
async def stream_response(
    thread_id: str,
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
    client: AsyncOpenAI = Depends(lambda: AsyncOpenAI()),
) -> StreamingResponse:
    """
    Streams the assistant response via Server-Sent Events (SSE). If the assistant requires
    a tool call, we capture that action, invoke the tool, and then re-run the stream
    until completion. This is done in a DRY way by extracting the streaming logic
    into a helper function.
    """

    async def handle_assistant_stream(
        templates: Jinja2Templates,
        logger: Logger,
        stream_manager: AsyncAssistantStreamManager,
        step_id: str = "",
    ) -> AsyncGenerator[Union[AssistantStreamMetadata, str], None]:
        """
        Async generator to yield SSE events.
        We yield a final AssistantStreamMetadata instance once we're done.
        """
        required_action: Optional[RequiredAction] = None
        run_requires_action_event: Optional[ThreadRunRequiresAction] = None

        event_handler: AsyncAssistantEventHandler
        async with stream_manager as event_handler:
            event: AssistantStreamEvent
            async for event in event_handler:
                if isinstance(event, ThreadMessageCreated):
                    step_id = event.data.id
                    logger.debug(f"Message Created - Step ID: {step_id}")

                    yield sse_format(
                        "messageCreated",
                        templates.get_template("chat/assistant-step.html").render(
                            step_type="assistantMessage", step_id=step_id
                        ),
                    )

                if isinstance(event, ThreadMessageDelta) and event.data.delta.content:
                    delta_content_item: MessageContentDelta = event.data.delta.content[
                        0
                    ]
                    if (
                        isinstance(delta_content_item, TextDeltaBlock)
                        and delta_content_item.text
                    ):
                        step_id = event.data.id
                        text_delta: TextDelta = delta_content_item.text
                        current_delta_text_value: Optional[str] = text_delta.value
                        annotations = text_delta.annotations

                        # This will be the text actually sent in textDelta
                        final_text_for_this_delta = current_delta_text_value

                        # Check for file citation annotations
                        if annotations:
                            for annotation in annotations:
                                logger.debug(f"Annotation: {str(annotation)}")
                                if (
                                    annotation.type == "file_citation"
                                    and hasattr(annotation, "file_citation")
                                    and annotation.file_citation
                                ):
                                    if current_delta_text_value:
                                        match = re.search(
                                            r"【.*?†(.*?)】", current_delta_text_value
                                        )
                                        if match:
                                            document_id = match.group(1).split(".")[0]
                                            # Get the file URL from the FILE_PATHS dictionary
                                            file_url = FILE_PATHS.get(document_id, None)
                                            # Get the citation text from the DOCUMENT_CITATIONS dictionary
                                            citation_text = DOCUMENT_CITATIONS.get(
                                                document_id, None
                                            )
                                            if file_url and citation_text:
                                                final_text_for_this_delta = (
                                                    f" ([{citation_text}]({file_url}))"
                                                )
                                            else:
                                                # file_url not found for document_id
                                                logger.warning(
                                                    f"Could not find file URL or citation text for document ID: {document_id}"
                                                )
                                                # Keep original text_value if file_url is None
                                                pass  # text_value remains unchanged

                                        else:
                                            logger.warning(
                                                f"Could not find citation pattern in text: {current_delta_text_value}"
                                            )
                                    else:
                                        # This case shouldn't occur
                                        logger.warning(
                                            "File citation annotation found, but text_delta.value is unexpectedly None."
                                        )

                                # Handle file_path (code interpreter generated files)
                                elif (
                                    annotation.type == "file_path"
                                    and hasattr(annotation, "file_path")
                                    and annotation.file_path
                                    and annotation.file_path.file_id
                                ):
                                    file_id = annotation.file_path.file_id
                                    # annotation.text is the "key" for replacement (e.g., "sandbox:/mnt/data/file.csv")
                                    sandbox_link_text_in_markdown = annotation.text

                                    # We will replace it with our app's download URL for the OpenAI-hosted file
                                    download_url = files_router.url_path_for(
                                        "download_openai_file", file_id=file_id
                                    )

                                    replacement_payload = f"{sandbox_link_text_in_markdown}|{download_url}"
                                    logger.debug(
                                        f"Replacement payload: {replacement_payload}"
                                    )
                                    # Use step_id (message_id) for OOB targeting the correct message container
                                    sse_replacement_data = wrap_for_oob_swap(
                                        step_id, replacement_payload
                                    )
                                    yield sse_format(
                                        "textReplacement", sse_replacement_data
                                    )
                                    logger.debug(
                                        f"Sent textReplacement event for {sandbox_link_text_in_markdown} with {download_url}"
                                    )

                                    break

                        # Only send SSE if there's a non-None text value to transmit
                        if final_text_for_this_delta is not None:
                            # Use step_id (message_id) for OOB targeting the correct message container
                            sse_data = wrap_for_oob_swap(
                                step_id, final_text_for_this_delta
                            )
                            yield sse_format("textDelta", sse_data)

                if (
                    isinstance(event, ThreadRunStepCreated)
                    and event.data.type == "tool_calls"
                ):
                    logger.debug(f"Tool Call Created - Data: {str(event.data)}")
                    step_id = event.data.id

                    yield sse_format(
                        "toolCallCreated",
                        templates.get_template("chat/assistant-step.html").render(
                            step_type="toolCall", step_id=step_id
                        ),
                    )

                if (
                    isinstance(event, ThreadRunStepDelta)
                    and event.data.delta.step_details
                    and event.data.delta.step_details.type == "tool_calls"
                ):
                    tool_calls = event.data.delta.step_details.tool_calls
                    step_id = event.data.id
                    if tool_calls:
                        # TODO: Support parallel function calling
                        tool_call = tool_calls[0]

                        # Handle function tool call
                        if tool_call.type == "function":
                            if tool_call.function and tool_call.function.name:
                                yield sse_format(
                                    "toolDelta",
                                    wrap_for_oob_swap(
                                        step_id, tool_call.function.name + "<br>"
                                    ),
                                )
                            if tool_call.function and tool_call.function.arguments:
                                yield sse_format(
                                    "toolDelta",
                                    wrap_for_oob_swap(
                                        step_id, tool_call.function.arguments
                                    ),
                                )

                        # Handle code interpreter tool calls
                        elif tool_call.type == "code_interpreter":
                            if (
                                tool_call.code_interpreter
                                and tool_call.code_interpreter.input is not None
                            ):
                                if tool_call.code_interpreter.input == "":
                                    yield sse_format(
                                        "toolDelta",
                                        wrap_for_oob_swap(
                                            step_id,
                                            "<em>Code Interpreter tool call</em><br>",
                                        ),
                                    )
                                else:
                                    yield sse_format(
                                        "toolDelta",
                                        wrap_for_oob_swap(
                                            step_id,
                                            str(tool_call.code_interpreter.input),
                                        ),
                                    )
                            if (
                                tool_call.code_interpreter
                                and tool_call.code_interpreter.outputs
                            ):
                                for output in tool_call.code_interpreter.outputs:
                                    logger.debug(
                                        f"Code Interpreter Output Type: {output.type}"
                                    )
                                    if output.type == "logs" and output.logs:
                                        # Replace "\n" in the logs with "\n> " to format it as console output
                                        output_logs = "\n\n> " + str(
                                            output.logs
                                        ).strip().replace("\n", "\n> ")
                                        yield sse_format(
                                            "toolDelta",
                                            wrap_for_oob_swap(step_id, output_logs),
                                        )
                                    elif (
                                        output.type == "image"
                                        and output.image
                                        and output.image.file_id
                                    ):
                                        logger.debug(
                                            f"Image Output - File ID: {output.image.file_id}"
                                        )
                                        # Create the image HTML on the backend
                                        image_html = f'<img src="/chat/files/{output.image.file_id}/content" class="code-interpreter-image">'
                                        yield sse_format(
                                            "imageOutput",
                                            wrap_for_oob_swap(step_id, image_html),
                                        )
                        elif tool_call.type == "file_search":
                            yield sse_format(
                                "toolDelta",
                                wrap_for_oob_swap(
                                    step_id, "<em>File search tool call</em>"
                                ),
                            )

                # If the assistant run requires an action (a tool call), break and handle it
                if isinstance(event, ThreadRunRequiresAction):
                    required_action = event.data.required_action
                    run_requires_action_event = event
                    logger.debug("Run Requires Action Event")
                    if required_action and required_action.submit_tool_outputs:
                        break

                if isinstance(event, ThreadRunCompleted):
                    yield sse_format("endStream", "DONE")

        # At the end (or break) of this async generator, yield a final AssistantStreamMetadata
        yield AssistantStreamMetadata.create(
            required_action=required_action,
            step_id=step_id,
            run_requires_action_event=run_requires_action_event,
        )

    async def event_generator() -> AsyncGenerator[str, None]:
        """
        Main generator for SSE events. We call our helper function to handle the assistant
        stream, and if the assistant requests a tool call, we do it and then re-stream the stream.
        """
        step_id: str = ""
        stream_manager: AsyncAssistantStreamManager[AsyncAssistantEventHandler] = (
            client.beta.threads.runs.stream(
                thread_id=thread_id,
                assistant_id=assistant_id,
                parallel_tool_calls=False,
            )
        )

        while True:
            event: Union[AssistantStreamMetadata, str]
            async for event in handle_assistant_stream(
                templates, logger, stream_manager, step_id
            ):
                if isinstance(event, AssistantStreamMetadata):
                    # Use the helper methods from our class
                    step_id = event.step_id
                    if event.requires_tool_call():
                        for (
                            tool_call
                        ) in event.required_action.submit_tool_outputs.tool_calls:  # type: ignore
                            if tool_call.type == "function":
                                try:
                                    args = json.loads(tool_call.function.arguments)
                                    location = args.get("location", "Unknown")
                                    dates_raw = args.get(
                                        "dates", [datetime.today().strftime("%Y-%m-%d")]
                                    )
                                    dates = [
                                        datetime.strptime(d, "%Y-%m-%d")
                                        for d in dates_raw
                                        if isinstance(d, str)
                                    ]
                                except Exception as err:
                                    logger.error(
                                        f"Failed to parse function arguments: {err}"
                                    )
                                    location = "Unknown"
                                    dates = [datetime.today()]

                                try:
                                    weather_output: list = get_weather(location, dates)
                                    logger.info(f"Weather output: {weather_output}")

                                    # Render the weather widget
                                    weather_widget_html = templates.get_template(
                                        "chat/weather-widget.html"
                                    ).render(reports=weather_output)

                                    # Yield the rendered HTML
                                    yield sse_format("toolOutput", weather_widget_html)

                                    data_for_tool = {
                                        "tool_outputs": {
                                            "output": str(weather_output),
                                            "tool_call_id": tool_call.id,
                                        },
                                        "runId": event.get_run_id(),
                                    }
                                except Exception as err:
                                    error_message = (
                                        f"Failed to get weather output: {err}"
                                    )
                                    logger.error(error_message)
                                    yield sse_format("toolOutput", error_message)
                                    data_for_tool = {
                                        "tool_outputs": {
                                            "output": error_message,
                                            "tool_call_id": tool_call.id,
                                        },
                                        "runId": event.get_run_id(),
                                    }

                                # Afterwards, create a fresh stream_manager for the next iteration
                                new_stream_manager = await post_tool_outputs(
                                    client, data_for_tool, thread_id
                                )
                                stream_manager = new_stream_manager
                                # proceed to rerun the loop
                                break
                    else:
                        # No more tool calls needed; we're done streaming
                        return
                else:
                    # Normal SSE events: yield them to the client
                    yield str(event)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )
