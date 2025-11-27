

import asyncio
import json
import os
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.streamable_http import streamablehttp_client
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from langchain_openai import ChatOpenAI


TASK_PROMPT = """
你是漏洞专家, 你的任务是完成漏洞验证, 并在可行的情况下生成PoC. 

## 已经可以完成的基础能力
- 使用模拟器运行目标二进制, 并生成一次运行时ICFG
- 能够获取静态分析工具得到的漏洞路径(source -> sink )

## 

请根据提供的漏洞路径, 来验证漏洞是否存在
"""


def parse_text_resource(read_result) -> str | None:
    content = read_result.contents[0]
    if content.mimeType == "text/plain":
        return content.text
    else:
        return None


server_params = StdioServerParameters(
    command="uv",
    args=["--directory", ".", "run", "agent_mcp.py" ],
    # env=None,  # Inherit parent environment instead of using empty dict
    # cwd=os.getcwd(),
    encoding="utf-8",
)

async def main():
    kwargs = {
        "model": "anthropic/claude-sonnet-4",
        "api_key": "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",
        "base_url": "https://openrouter.ai/api/v1", 
        "temperature": 0.3,
        "timeout": 300,
        "max_retries": 3,
    }
    # 创建ChatOpenAI实例
    llm = ChatOpenAI(**kwargs)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            available_tools = [tool.name for tool in tools.tools]
            print(f"Avaliable tools: {available_tools}")

            # List available prompts
            prompts = await session.list_prompts()
            available_prompts = [p.name for p in prompts.prompts]
            print(f"Available prompts: {[p.name for p in prompts.prompts]}")

            # Get a prompt (greet_user prompt from fastmcp_quickstart)
            if "system_prompt" in available_prompts:
                system_prompt = await session.get_prompt("system_prompt")
                system_prompt_content = system_prompt.messages[0].content.text
            else:
                print("`system_prompt` not found")
                return None

            resources = await session.list_resources()
            available_resources = [str(r.uri) for r in resources.resources]
            print(f"Available resources: {[str(r.uri) for r in resources.resources]}")

            if "agent://name" in available_resources and "agent://description" in available_resources and "agent://handoffs":
                agent_name = await session.read_resource("agent://name")
                agent_name = parse_text_resource(agent_name)
                agent_description = await session.read_resource("agent://description")
                agent_description = parse_text_resource(agent_description)
                handoffs = await session.read_resource("agent://handoffs")
                handoffs = parse_text_resource(handoffs)
                handoffs = json.loads(handoffs)
                if not (agent_name and agent_description and handoffs):
                    print("Agent resources value error")
                    return None
            else:
                print("Agent resources not found")
                return None

            tools = await load_mcp_tools(session)

            agent = create_agent(llm, tools=tools, system_prompt=system_prompt_content, name=agent_name)

            config = {
                "recursion_limit": 50,
                "debug": True
            }

            # 测试消息示例：
            # 1. 测试加法工具（原有功能）: "你的昵称是什么" 或 "1 + 2 等于多少"
            # 2. 测试组织资产扫描: "获取庞巴迪公司相关资产" 或 "扫描庞巴迪公司"
            # 3. 测试行业报告: "获取航空行业相关资产" 或 "生成航空行业报告"

            # test_message = "你的昵称是什么"  # 修改此行以测试不同功能
            test_message = "获取洛克希德·马丁公司相关资产"  # 测试无分隔符智能匹配
            # test_message = "获取航空行业相关资产"  # 测试行业报告功能

            async for item in agent.astream(
                {"messages": [HumanMessage(content=test_message)]},
                config=config
            ):
                # Handle nested message structures from langgraph agent
                if isinstance(item, dict):
                    # Handle agent messages
                    if 'model' in item and 'messages' in item['model']:
                        for message in item['model']['messages']:
                            if isinstance(message, AIMessage):
                                if message.content:
                                    print(f"AI: {message.content}")
                                if hasattr(message, 'tool_calls') and message.tool_calls:
                                    for tool_call in message.tool_calls:
                                        tool_name = tool_call.get("name", "unknown")
                                        tool_args = tool_call.get("args", {})
                                        tool_input = ', '.join([f"{key}={value}" for key, value in tool_args.items()])
                                        print(f"Tool call: {tool_name} with input {tool_input}")

                    # Handle tool messages
                    elif 'tools' in item and 'messages' in item['tools']:
                        for message in item['tools']['messages']:
                            if isinstance(message, ToolMessage):
                                print(f"Tool: {message.name}, result: {message.content}")
                    else:
                        print(f"Unknown dict structure: {list(item.keys())}")
                else:
                    print(f"Unknown message type: {type(item).__name__} - {item}")


if __name__ == "__main__":
    asyncio.run(main())

