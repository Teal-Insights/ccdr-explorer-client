import os
import logging
from dotenv import load_dotenv
from openai import AsyncOpenAI
from fastapi import HTTPException, Depends

load_dotenv(override=True)

logger = logging.getLogger("uvicorn.error")

S3_BUCKET = os.getenv("S3_BUCKET")

# Helper function to get or create a vector store
async def get_vector_store(assistantId: str, client: AsyncOpenAI = Depends(lambda: AsyncOpenAI())) -> str:
    assistant = await client.beta.assistants.retrieve(assistantId)
    if assistant.tool_resources and assistant.tool_resources.file_search and assistant.tool_resources.file_search.vector_store_ids:
        return assistant.tool_resources.file_search.vector_store_ids[0]
    raise HTTPException(status_code=404, detail="Vector store not found")


S3_FILE_PATHS = {
    "dl_005.pdf": "pub_002/dl_005.pdf",
    "dl_004.pdf": "pub_002/dl_004.pdf",
    "dl_006.pdf": "pub_002/dl_006.pdf",
    "dl_007.pdf": "pub_002/dl_007.pdf",
    "dl_008.pdf": "pub_003/dl_008.pdf",
    "dl_001.pdf": "pub_001/dl_001.pdf",
    "dl_018.pdf": "pub_006/dl_018.pdf",
    "dl_003.pdf": "pub_002/dl_003.pdf",
    "dl_021.pdf": "pub_007/dl_021.pdf",
    "dl_017.pdf": "pub_006/dl_017.pdf",
    "dl_015.pdf": "pub_005/dl_015.pdf",
    "dl_026.pdf": "pub_008/dl_026.pdf",
    "dl_010.pdf": "pub_004/dl_010.pdf",
    "dl_025.pdf": "pub_008/dl_025.pdf",
    "dl_019.pdf": "pub_007/dl_019.pdf",
    "dl_023.pdf": "pub_008/dl_023.pdf",
    "dl_033.pdf": "pub_010/dl_033.pdf",
    "dl_035.pdf": "pub_011/dl_035.pdf",
    "dl_032.pdf": "pub_010/dl_032.pdf",
    "dl_028.pdf": "pub_009/dl_028.pdf",
    "dl_030.pdf": "pub_010/dl_030.pdf",
    "dl_038.pdf": "pub_012/dl_038.pdf",
    "dl_034.pdf": "pub_010/dl_034.pdf",
    "dl_048.pdf": "pub_014/dl_048.pdf",
    "dl_051.pdf": "pub_015/dl_051.pdf",
    "dl_052.pdf": "pub_015/dl_052.pdf",
    "dl_050.pdf": "pub_015/dl_050.pdf",
    "dl_049.pdf": "pub_015/dl_049.pdf",
    "dl_053.pdf": "pub_015/dl_053.pdf",
    "dl_041.pdf": "pub_013/dl_041.pdf",
    "dl_043.pdf": "pub_013/dl_043.pdf",
    "dl_060.pdf": "pub_017/dl_060.pdf",
    "dl_062.pdf": "pub_017/dl_062.pdf",
    "dl_064.pdf": "pub_018/dl_064.pdf",
    "dl_054.pdf": "pub_016/dl_054.pdf",
    "dl_046.pdf": "pub_014/dl_046.pdf",
    "dl_063.pdf": "pub_018/dl_063.pdf",
    "dl_068.pdf": "pub_019/dl_068.pdf",
    "dl_061.pdf": "pub_017/dl_061.pdf",
    "dl_065.pdf": "pub_018/dl_065.pdf",
    "dl_058.pdf": "pub_017/dl_058.pdf",
    "dl_070.pdf": "pub_019/dl_070.pdf",
    "dl_067.pdf": "pub_018/dl_067.pdf",
    "dl_077.pdf": "pub_022/dl_077.pdf",
    "dl_078.pdf": "pub_023/dl_078.pdf",
    "dl_073.pdf": "pub_021/dl_073.pdf",
    "dl_075.pdf": "pub_022/dl_075.pdf",
    "dl_086.pdf": "pub_025/dl_086.pdf",
    "dl_066.pdf": "pub_018/dl_066.pdf",
    "dl_079.pdf": "pub_024/dl_079.pdf",
    "dl_092.pdf": "pub_027/dl_092.pdf",
    "dl_083.pdf": "pub_025/dl_083.pdf",
    "dl_071.pdf": "pub_020/dl_071.pdf",
    "dl_095.pdf": "pub_028/dl_095.pdf",
    "dl_087.pdf": "pub_025/dl_087.pdf",
    "dl_090.pdf": "pub_027/dl_090.pdf",
    "dl_106.pdf": "pub_031/dl_106.pdf",
    "dl_107.pdf": "pub_031/dl_107.pdf",
    "dl_088.pdf": "pub_026/dl_088.pdf",
    "dl_098.pdf": "pub_029/dl_098.pdf",
    "dl_109.pdf": "pub_031/dl_109.pdf",
    "dl_105.pdf": "pub_031/dl_105.pdf",
    "dl_101.pdf": "pub_030/dl_101.pdf",
    "dl_108.pdf": "pub_031/dl_108.pdf",
    "dl_115.pdf": "pub_033/dl_115.pdf",
    "dl_120.pdf": "pub_034/dl_120.pdf",
    "dl_121.pdf": "pub_035/dl_121.pdf",
    "dl_110.pdf": "pub_032/dl_110.pdf",
    "dl_132.pdf": "pub_038/dl_132.pdf",
    "dl_128.pdf": "pub_037/dl_128.pdf",
    "dl_139.pdf": "pub_039/dl_139.pdf",
    "dl_140.pdf": "pub_039/dl_140.pdf",
    "dl_124.pdf": "pub_036/dl_124.pdf",
    "dl_131.pdf": "pub_038/dl_131.pdf",
    "dl_111.pdf": "pub_032/dl_111.pdf",
    "dl_147.pdf": "pub_041/dl_147.pdf",
    "dl_118.pdf": "pub_034/dl_118.pdf",
    "dl_146.pdf": "pub_041/dl_146.pdf",
    "dl_148.pdf": "pub_041/dl_148.pdf",
    "dl_155.pdf": "pub_042/dl_155.pdf",
    "dl_154.pdf": "pub_042/dl_154.pdf",
    "dl_143.pdf": "pub_040/dl_143.pdf",
    "dl_151.pdf": "pub_042/dl_151.pdf",
    "dl_161.pdf": "pub_044/dl_161.pdf",
    "dl_162.pdf": "pub_044/dl_162.pdf",
    "dl_163.pdf": "pub_044/dl_163.pdf",
    "dl_168.pdf": "pub_045/dl_168.pdf",
    "dl_141.pdf": "pub_040/dl_141.pdf",
    "dl_170.pdf": "pub_046/dl_170.pdf",
    "dl_156.pdf": "pub_043/dl_156.pdf",
    "dl_180.pdf": "pub_048/dl_180.pdf",
    "dl_164.pdf": "pub_045/dl_164.pdf",
    "dl_177.pdf": "pub_048/dl_177.pdf",
    "dl_159.pdf": "pub_044/dl_159.pdf",
    "dl_187.pdf": "pub_051/dl_187.pdf",
    "dl_189.pdf": "pub_051/dl_189.pdf",
    "dl_169.pdf": "pub_046/dl_169.pdf",
    "dl_192.pdf": "pub_052/dl_192.pdf",
    "dl_174.pdf": "pub_047/dl_174.pdf",
    "dl_202.pdf": "pub_054/dl_202.pdf",
    "dl_171.pdf": "pub_046/dl_171.pdf",
    "dl_191.pdf": "pub_052/dl_191.pdf",
    "dl_201.pdf": "pub_054/dl_201.pdf",
    "dl_181.pdf": "pub_049/dl_181.pdf",
    "dl_186.pdf": "pub_051/dl_186.pdf",
    "dl_184.pdf": "pub_050/dl_184.pdf",
    "dl_205.pdf": "pub_054/dl_205.pdf",
    "dl_176.pdf": "pub_048/dl_176.pdf",
    "dl_203.pdf": "pub_054/dl_203.pdf",
    "dl_190.pdf": "pub_051/dl_190.pdf",
    "dl_204.pdf": "pub_054/dl_204.pdf",
    "dl_196.pdf": "pub_053/dl_196.pdf",
    "dl_210.pdf": "pub_056/dl_210.pdf",
    "dl_218.pdf": "pub_058/dl_218.pdf",
    "dl_213.pdf": "pub_057/dl_213.pdf",
    "dl_223.pdf": "pub_059/dl_223.pdf",
    "dl_225.pdf": "pub_059/dl_225.pdf",
    "dl_226.pdf": "pub_059/dl_226.pdf",
    "dl_232.pdf": "pub_061/dl_232.pdf",
    "dl_227.pdf": "pub_060/dl_227.pdf",
    "dl_207.pdf": "pub_055/dl_207.pdf",
    "dl_211.pdf": "pub_056/dl_211.pdf",
    "dl_224.pdf": "pub_059/dl_224.pdf",
    "dl_222.pdf": "pub_059/dl_222.pdf",
    "dl_230.pdf": "pub_061/dl_230.pdf",
    "dl_221.pdf": "pub_058/dl_221.pdf",
}


def cleanup_temp_file(file_path: str):
    """Removes the temporary file."""
    try:
        os.unlink(file_path)
        logger.info(f"Successfully cleaned up temporary file: {file_path}")
    except OSError as e:
        logger.error(f"Error cleaning up temporary file {file_path}: {e}")