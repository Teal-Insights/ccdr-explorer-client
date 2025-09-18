from __future__ import annotations

import functools
import inspect
import json
import warnings
from collections.abc import Callable
from typing import Generic, Optional, TypeVar, get_type_hints, get_origin, get_args, Union, Any

from pydantic import BaseModel

from utils.chat.function_definitions import FuncMetadata, func_metadata


T = TypeVar("T")

class ToolResult(BaseModel, Generic[T]):
    error: Optional[str] = None
    warning: Optional[str] = None
    result: Optional[T] = None


class ToolRuntimeError(Exception):
    """Base error for tool runtime."""


class ToolNotFoundError(ToolRuntimeError):
    """Raised when a tool is not found."""


class ToolCallError(ToolRuntimeError):
    """Raised on execution failure."""


class Context(BaseModel):
    """Optional context object you can enrich for your app."""
    request_id: str | None = None
    user_id: str | None = None

    # Add whatever you like (logger, db handles, etc.)
    # logger: logging.Logger | None = None
    # db: Any = None

    model_config = {"arbitrary_types_allowed": True, "extra": "allow"}


def _is_async_callable(obj: Any) -> bool:
    while isinstance(obj, functools.partial):
        obj = obj.func
    return inspect.iscoroutinefunction(obj) or (
        callable(obj) and inspect.iscoroutinefunction(getattr(obj, "__call__", None))
    )


def _find_context_parameter(fn: Callable[..., Any]) -> str | None:
    """Find a parameter annotated with our Context type (including Optional/Union)."""
    try:
        hints = get_type_hints(fn)
    except Exception:
        return None

    for name, anno in hints.items():
        # Direct match
        if anno is Context:
            return name
        # Optional[Context] / Union[Context, None]
        origin = get_origin(anno)
        if origin in (Optional, Union):
            for arg in get_args(anno):
                if arg is Context:
                    return name
    return None


class ToolRegistration(BaseModel):
    fn: Callable[..., Any]
    name: str
    description: str
    parameters: dict[str, Any]
    fn_metadata: FuncMetadata
    is_async: bool
    context_kwarg: str | None = None

    model_config = {"arbitrary_types_allowed": True, "extra": "allow"}

    @classmethod
    def from_function(
        cls,
        fn: Callable[..., Any],
        name: str | None = None,
        description: str | None = None,
        *,
        structured_output: bool | None = None,
        context_kwarg: str | None = None,
    ) -> "ToolRegistration":
        func_name = name or fn.__name__
        func_doc = (description if description is not None else (inspect.getdoc(fn) or "").strip())
        is_async = _is_async_callable(fn)

        if context_kwarg is None:
            context_kwarg = _find_context_parameter(fn)

        meta = func_metadata(
            fn,
            skip_names=[context_kwarg] if context_kwarg else [],
            structured_output=structured_output,
        )
        params_schema = meta.arg_model.model_json_schema(by_alias=True)
        return cls(
            fn=fn,
            name=func_name,
            description=func_doc,
            parameters=params_schema,
            fn_metadata=meta,
            is_async=is_async,
            context_kwarg=context_kwarg,
        )

    async def run(
        self,
        arguments: dict[str, Any],
        *,
        context: Context | None = None,
        return_structured: bool = False,
    ) -> Any:
        """Validate, inject context, call, and optionally convert output to structured format.

        If return_structured is False:
          - returns the function's raw return value
        If return_structured is True and the return annotation is serializable:
          - returns (raw_result, structured_dict) where structured_dict matches your schema
        """
        try:
            injected = {self.context_kwarg: context} if (self.context_kwarg and context is not None) else None
            result = await self.fn_metadata.call_fn_with_arg_validation(
                self.fn,
                self.is_async,
                arguments,
                injected,
            )
            return self.fn_metadata.convert_result(result) if return_structured else result
        except Exception as e:
            raise ToolCallError(f"Error calling tool '{self.name}': {e}") from e


class ToolRegistry:
    """Simple registry that supports registration and dispatch by name."""

    def __init__(self, warn_on_duplicate: bool = True):
        self._tools: dict[str, ToolRegistration] = {}
        self.warn_on_duplicate = warn_on_duplicate

    def add_function(
        self,
        fn: Callable[..., Any],
        *,
        name: str | None = None,
        description: str | None = None,
        structured_output: bool | None = None,
        context_kwarg: str | None = None,
    ) -> ToolRegistration:
        reg = ToolRegistration.from_function(
            fn,
            name=name,
            description=description,
            structured_output=structured_output,
            context_kwarg=context_kwarg,
        )
        if reg.name in self._tools and self.warn_on_duplicate:
            # Replace silently or raise; here we replace silently.
            pass
        self._tools[reg.name] = reg
        return reg

    def tool(
        self,
        name: str | None = None,
        description: str | None = None,
        structured_output: bool | None = None,
        context_kwarg: str | None = None,
    ):
        """Decorator to register a function."""
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.add_function(
                fn,
                name=name,
                description=description,
                structured_output=structured_output,
                context_kwarg=context_kwarg,
            )
            return fn
        return decorator

    def get(self, name: str) -> ToolRegistration:
        tool = self._tools.get(name)
        if not tool:
            raise ToolNotFoundError(f"Unknown tool: {name}")
        return tool

    def list(self) -> list[ToolRegistration]:
        return list(self._tools.values())

    async def call(
        self,
        name: str,
        arguments: dict[str, Any] | str | None = None,
        *,
        context: Context | None = None,
        return_structured: bool = False,
    ) -> ToolResult[Any]:
        """Parse arguments, validate, and call a registered function.

        Always returns a ToolResult wrapper. The `return_structured` flag is
        currently ignored and raw function results are placed into ToolResult.result.
        """
        tool = self.get(name)
        if arguments is None:
            payload: dict[str, Any] = {}
        elif isinstance(arguments, str):
            payload = json.loads(arguments)
            if not isinstance(payload, dict):
                return ToolResult(error="Top-level arguments must be a JSON object")
        else:
            payload = arguments

        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                raw_result = await tool.run(payload, context=context, return_structured=False)
            warning_msg = "; ".join(f"{w.category.__name__}: {w.message}" for w in caught) or None
            return ToolResult(result=raw_result, warning=warning_msg)
        except Exception as e:
            return ToolResult(error=str(e))
