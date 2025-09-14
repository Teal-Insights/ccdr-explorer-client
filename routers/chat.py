import json
from urllib.parse import quote as url_quote
from datetime import datetime
from logging import getLogger, Logger
from typing import Optional, List, Dict, Any, AsyncGenerator
from fastapi import APIRouter, Form, Depends, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import Response, HTMLResponse, StreamingResponse
from fastapi import HTTPException
from sqlmodel import Session
from openai.types.responses import (
    ResponseCreatedEvent, ResponseOutputItemAddedEvent,
    ResponseFunctionCallArgumentsDeltaEvent, ResponseFunctionCallArgumentsDoneEvent,
    ResponseCompletedEvent, ResponseTextDeltaEvent, ResponseRefusalDeltaEvent,
    ResponseFileSearchCallSearchingEvent, ResponseCodeInterpreterCallInProgressEvent,
    ResponseOutputTextAnnotationAddedEvent, ResponseContentPartAddedEvent,
    ResponseFileSearchCallInProgressEvent, ResponseFileSearchCallCompletedEvent,
    ResponseOutputItemDoneEvent, ResponseInProgressEvent, ResponseTextDoneEvent,
    ResponseContentPartDoneEvent, ResponseCodeInterpreterCallCodeDeltaEvent,
    ResponseCodeInterpreterCallCodeDoneEvent, ResponseCodeInterpreterCallInterpretingEvent,
    ResponseCodeInterpreterCallCompletedEvent
)
from openai import AsyncOpenAI

from utils.chat.custom_functions import get_function_tool_def, get_weather
from utils.chat.sse import sse_format
from utils.chat.files import FILE_PATHS, DOCUMENT_CITATIONS
from utils.chat.prompt import PROMPT
from utils.core.dependencies import (
    get_user_with_relations,
    get_authenticated_user,
    get_session,
)
from utils.core.models import User
from utils.chat.conversations import create_conversation
from routers.files import router as files_router

logger: Logger = getLogger("uvicorn.error")

router: APIRouter = APIRouter(
    prefix="/chat", tags=["chat"]
)

# Jinja2 templates
templates = Jinja2Templates(directory="templates")


def wrap_for_oob_swap(step_id: str, text_value: str) -> str:
    return f'<span hx-swap-oob="beforeend:#step-{step_id}">{text_value}</span>'


# --- Authenticated Routes ---


@router.get("/")
async def read_chat(
    request: Request,
    user: Optional[User] = Depends(get_user_with_relations),
    conversation_id: Optional[str] = None,
    messages: List[Dict[str, Any]] = [],
) -> Response:
    # Create a new conversation if none provided
    if not conversation_id or conversation_id == "None" or conversation_id == "null":
        conversation_id = await create_conversation()

    return templates.TemplateResponse(
        "chat/index.html",
        {
            "request": request,
            "user": user,
            "messages": messages,
            "conversation_id": conversation_id
        },
    )


# Route to submit a new user message to a thread and mount a component that
# will start an assistant run stream
@router.post("{conversation_id}/send/")
async def send_message(
    request: Request,
    conversation_id: str,
    userInput: str = Form(...),
    user: User = Depends(get_authenticated_user),
    client: AsyncOpenAI = Depends(lambda: AsyncOpenAI()),
) -> HTMLResponse:
    # Create a new conversation item for the user's message
    await client.conversations.items.create(
        conversation_id=conversation_id,
        items=[{
            "type": "message",
            "role": "user",
            "content": [{
                "type": "input_text",
                "text": f"System: Today's date is {datetime.today().strftime('%Y-%m-%d')}\n{userInput}"
            }]
        }]
    )

    # Render the component templates with the context
    user_message_html = templates.get_template("chat/user-message.html").render(
        request=request, user_input=userInput
    )
    assistant_run_html = templates.get_template("chat/assistant-run.html").render(
        request=request, conversation_id=conversation_id
    )

    return HTMLResponse(content=(user_message_html + assistant_run_html))


# Route to stream the response from the assistant via server-sent events
@router.get("{conversation_id}/receive/")
async def stream_response(
    conversation_id: str,
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

    async def event_generator() -> AsyncGenerator[str, None]:
        """
        Async generator to yield SSE events.
        We yield a final AssistantStreamMetadata instance once we're done.
        """
        # Load config from env
        import os
        from dotenv import load_dotenv
        load_dotenv(override=True)
        model = os.getenv("RESPONSES_MODEL", "gpt-5-mini")
        instructions = os.getenv("RESPONSES_INSTRUCTIONS", PROMPT)
        enabled_tools = [t.strip() for t in os.getenv("ENABLED_TOOLS", "").split(",") if t.strip()]

        # Build tools
        tools: list[Dict[str, Any]] = []
        if "file_search" in enabled_tools:
            vector_store_id = os.getenv("VECTOR_STORE_ID")
            if vector_store_id and vector_store_id.replace("_", "").replace("-", "").isalnum():
                tools.append({"type": "file_search", "vector_store_ids": [vector_store_id]})
        if "code_interpreter" in enabled_tools:
            # Per Responses schema: container requires a type and container_id, not id
            tools.append({
                "type": "code_interpreter",
                "container": {"type": "auto"}
            })
        if "function" in enabled_tools:
            tools.append(get_function_tool_def())


        stream = await client.responses.create(
            input="",
            conversation=conversation_id,
            model=model,
            tools=tools or None,
            instructions=instructions,
            parallel_tool_calls=False,
            stream=True
        )

        async def iterate_stream(s, response_id: str = "") -> AsyncGenerator[str, None]:
            nonlocal model, conversation_id, tools, instructions
            current_item_id: str = ""
            # Accumulate function call args per current_item_id
            fn_args_buffer: Dict[str, str] = {}

            async with s as events:
                async for event in events:
                    match event:
                        case ResponseCreatedEvent():
                            response_id = event.response.id

                        case ResponseInProgressEvent() | \
                            ResponseFileSearchCallInProgressEvent() | \
                            ResponseFileSearchCallCompletedEvent() | \
                            ResponseOutputItemDoneEvent() | \
                            ResponseTextDoneEvent() | \
                            ResponseContentPartDoneEvent() | \
                            ResponseOutputItemDoneEvent() | \
                            ResponseCodeInterpreterCallCodeDoneEvent() | \
                            ResponseCodeInterpreterCallInterpretingEvent() | \
                            ResponseCodeInterpreterCallCompletedEvent():
                            # Don't need to handle "in progress" or intermediate "done" events
                            # (though long-running code interpreter interpreting might warrant handling)
                            continue
                    
                        case ResponseFileSearchCallSearchingEvent() | ResponseCodeInterpreterCallInProgressEvent():
                            tool = event.type.split(".")[1].split("_call")[0]
                            current_item_id = event.item_id
                            yield sse_format(
                                    "toolCallCreated",
                                    templates.get_template('chat/assistant-step.html').render(
                                        step_type='toolCall',
                                        step_id=event.item_id,
                                        content=f"Calling {tool} tool..." + ("\n" if isinstance(event, ResponseCodeInterpreterCallInProgressEvent) else "")
                                    )
                                )

                        case ResponseOutputItemAddedEvent():
                            # Skip reasoning steps by default (later make this configurable and/or mount a thinking indicator)
                            if event.item.id and event.item.type in ["message", "output_text"]:
                                current_item_id = event.item.id
                                yield sse_format(
                                    "messageCreated",
                                    templates.get_template("chat/assistant-step.html").render(
                                        step_type="assistantMessage",
                                        step_id=event.item.id
                                    )
                                )

                        case ResponseContentPartAddedEvent():
                            # This event indicates the start of annotations; skip creating a new assistantMessage
                            continue

                        case ResponseTextDeltaEvent() | ResponseRefusalDeltaEvent():
                            if event.delta and current_item_id:
                                yield sse_format("textDelta", wrap_for_oob_swap(current_item_id, event.delta))

                        case ResponseOutputTextAnnotationAddedEvent():
                            if event.annotation and current_item_id:
                                logger.info(f"ResponseOutputTextAnnotationAddedEvent: {event.annotation}")
                                if event.annotation["type"] == "file_citation":
                                    filename = event.annotation["filename"]
                                    # Emit a literal HTML anchor to avoid markdown parsing edge cases
                                    encoded_filename = url_quote(filename, safe="")
                                    split_filename = encoded_filename.split(".")[0]
                                    file_url_path = FILE_PATHS[split_filename]
                                    citation = f"(<a href=\"{file_url_path}\">{DOCUMENT_CITATIONS[split_filename]}</a>)"
                                    yield sse_format("textDelta", wrap_for_oob_swap(current_item_id, citation))
                                elif event.annotation["type"] == "container_file_citation":
                                    container_id = event.annotation["container_id"]
                                    file_id = event.annotation["file_id"]
                                    file = await client.containers.files.retrieve(file_id, container_id=container_id)
                                    container_file_path = file.path
                                    file_url_path = files_router.url_path_for("download_container_file", container_id=container_id, file_id=file_id)
                                    replacement_payload = f"sandbox:{container_file_path}|{file_url_path}"
                                    yield sse_format("textReplacement", wrap_for_oob_swap(current_item_id, replacement_payload))
                                else:
                                    logger.error(f"Unhandled annotation type: {event.annotation['type']}")

                        case ResponseCodeInterpreterCallCodeDeltaEvent():
                            if event.delta and current_item_id:
                                yield sse_format("toolDelta", wrap_for_oob_swap(current_item_id, event.delta))

                        case ResponseFunctionCallArgumentsDeltaEvent():
                            current_item_id = event.item_id
                            delta = event.delta
                            if current_item_id:
                                # Emit a toolCallCreated once per current_item_id
                                if current_item_id not in fn_args_buffer:
                                    yield sse_format(
                                        "toolCallCreated",
                                        templates.get_template('chat/assistant-step.html').render(
                                            step_type='toolCall',
                                            step_id=current_item_id
                                        )
                                    )
                                    fn_args_buffer[current_item_id] = ""
                                fn_args_buffer[current_item_id] += str(delta)
                                yield sse_format("toolDelta", wrap_for_oob_swap(current_item_id, str(delta)))

                        case ResponseFunctionCallArgumentsDoneEvent():
                            current_item_id = event.item_id
                            args_json = fn_args_buffer.get(current_item_id, "{}")
                            # Execute function
                            try:
                                args = json.loads(args_json or "{}")
                                location = args.get("location", "Unknown")
                                dates_raw = args.get("dates", [datetime.today().strftime("%Y-%m-%d")])
                                weather_output = get_weather(location, dates_raw)
                                # Render widget
                                weather_widget_html = templates.get_template(
                                    "chat/weather-widget.html"
                                ).render(reports=weather_output)
                                yield sse_format("toolOutput", weather_widget_html)
                                # Submit outputs and continue streaming
                                try:
                                    items = await client.conversations.items.list(
                                        conversation_id=conversation_id
                                    )
                                    function_call_item = next((item for item in items.data if item.id == current_item_id), None)
                                    if function_call_item:
                                        call_id = function_call_item.call_id
                                        await client.conversations.items.create(
                                            conversation_id=conversation_id,
                                            items=[{
                                                "type": "function_call_output",
                                                "call_id": call_id,
                                                "output": json.dumps({
                                                    "weather": weather_output
                                                })
                                            }]
                                        )
                                        next_stream = await client.responses.create(
                                            input="",
                                            conversation=conversation_id,
                                            model=model,
                                            tools=tools or None,
                                            instructions=instructions,
                                            parallel_tool_calls=False,
                                            stream=True
                                        )
                                        async for out in iterate_stream(next_stream, response_id):
                                            yield out
                                except Exception as e:
                                    logger.error(f"Error submitting tool outputs: {e}")
                                    raise HTTPException(status_code=500, detail=str(e))
                            except Exception as err:
                                yield sse_format("toolOutput", f"Function error: {err}")

                        case ResponseCompletedEvent():
                            yield sse_format("runCompleted", "<span hx-swap-oob=\"outerHTML:.dots\"></span>")
                            yield sse_format("endStream", "DONE")

                        case _:
                            logger.error(f"Unhandled event: {event}")

        async for sse in iterate_stream(stream):
            yield sse

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )