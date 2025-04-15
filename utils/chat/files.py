from openai import AsyncOpenAI
from fastapi import HTTPException, Depends

# Helper function to get or create a vector store
async def get_vector_store(assistantId: str, client: AsyncOpenAI = Depends(lambda: AsyncOpenAI())) -> str:
    assistant = await client.beta.assistants.retrieve(assistantId)
    if assistant.tool_resources and assistant.tool_resources.file_search and assistant.tool_resources.file_search.vector_store_ids:
        return assistant.tool_resources.file_search.vector_store_ids[0]
    raise HTTPException(status_code=404, detail="Vector store not found")