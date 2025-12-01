"""
LLM-Driven Seed Generator

使用 LLM 智能生成和调整测试输入(seed), 用于漏洞路径覆盖
"""

import json
import logging
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langchain.agents import create_agent
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage

logger = logging.getLogger(__file__)

@dataclass
class Seed:
    """测试种子"""
    content: str  # 种子内容（可以是文件内容、命令行参数、网络请求等）
    input_format: str   # 种子格式 ("args", "env", "stdin")
    env: Optional[Dict[str, str]] = None  # 额外的环境变量
    metadata: Optional[Dict[str, Any]] = None  # 额外的元数据

    generation: int = 0  # 第几代种子
    # coverage_score: float = 0.0  # 覆盖得分

    def to_dict(self) -> dict:
        return asdict(self)


class LLMSeedGenerator:
    """基于 LLM 的智能种子生成器"""

    def __init__(self, llm: ChatOpenAI, mcp_url: str = "http://localhost:13337/mcp"):
        """
        初始化生成器

        Args:
            llm: ChatOpenAI 实例
            mcp_url: MCP服务器的HTTP URL
        """
        self.llm = llm
        self.seed_history: List[Seed] = []
        self.best_seed: Optional[Seed] = None
        self.iteration = 1
        self.mcp_url = mcp_url

        # MCP相关的类成员，用于多轮对话
        self.session: Optional[ClientSession] = None
        self.agent = None
        self.tools = None
        self._client_exit_stack = None  # 保存client的退出方法
        self._session_exit_stack = None  # 保存session的退出方法

    async def initialize(self):
        """
        初始化MCP连接和Agent
        必须在使用generate_seed之前调用一次
        """
        if self.session is not None:
            # 已经初始化过了
            return

        # 手动管理HTTP client的生命周期
        client_context = streamablehttp_client(url=self.mcp_url)
        read, write, _ = await client_context.__aenter__()
        self._client_exit_stack = client_context

        # 手动管理Session的生命周期
        session_context = ClientSession(read, write)
        self.session = await session_context.__aenter__()
        self._session_exit_stack = session_context

        # 初始化session并加载tools
        await self.session.initialize()
        self.tools = await load_mcp_tools(self.session)

        print(f"[*] MCP Session initialized with {len(self.tools)} tools")

    async def close(self):
        """
        关闭MCP连接
        在使用完generator后调用
        """
        if self._session_exit_stack:
            try:
                await self._session_exit_stack.__aexit__(None, None, None)
            except Exception as e:
                print(f"[!] Error closing session: {e}")

        if self._client_exit_stack:
            try:
                await self._client_exit_stack.__aexit__(None, None, None)
            except Exception as e:
                print(f"[!] Error closing client: {e}")

        self.session = None
        self.agent = None
        self.tools = None
        self._client_exit_stack = None
        self._session_exit_stack = None
        print("[*] MCP Session closed")

    async def generate_seed(
        self,
        target_info: Dict[str, Any],
        vuln_info: Dict[str, Any],
        coverage_feedback: Optional[Dict[str, float]] = None,
        history_feedback: Optional[Dict[str, float]] = None,
    ) -> Seed:
        """
        生成初始种子集合

        Args:
            target_info: 目标程序信息（二进制类型、功能描述等）
            vuln_info: 漏洞信息（类型、路径、描述）
            num_seeds: 生成种子数量

        Returns:
            初始种子列表
        """
        system_prompt = f"""你是一个专业的IoT漏洞研究专家。
        ### 主要任务
        结合IDA Pro mcp, 漏洞信息(包含漏洞路径节点)和多轮程序执行的覆盖反馈, 持续为给定的二进制程序调整测试输入(seed), 直至触发该漏洞路径。
        
        ### seed生成策略
        - 针对漏洞类型设计(如 buffer overflow 需要超长输入)
        - 考虑程序接收的外部输入格式(如 命令行参数, 环境变量, 文件输入等)
        ### 变异策略
        1. 如果程序在某个分支点发生了分歧，分析可能的原因（输入值、条件判断等）
        2. 针对性地调整输入，使程序走向目标路径
        3. 考虑常见的绕过技术（如编码、填充、特殊字符等）
        ### 深入洞察
        当变异策略停滞不前时, 分析历史seed数据和覆盖情况:
        1. 哪些节点一直无法覆盖? 可能的原因是什么?
        2. 覆盖率的变化趋势如何? 
        3. 应该采取什么策略使得程序走向目标路径? 若无法实现，则说明该路径不可行。
        
        **目标程序信息：**
        {json.dumps(target_info, indent=2, ensure_ascii=False)}
        **漏洞信息：**
        {json.dumps(vuln_info, indent=2, ensure_ascii=False)}
        """ + \
        """**输出格式要求：**
        请以 JSON 格式返回, 包含以下字段: 
        - content: 测试输入的具体内容, 不可出现 "A"*4这种代码写法, 而必须是"AAAA"这种原始输入
        - input_format: 输入格式("args", "stdin")
        - rationale: 生成该输入的理由(简短说明为什么这个输入可能触发漏洞)
        - analysis: 分析当前问题和调整理由
        - strategy: 简短说明当前调整策略

        示例：
        ```json
        {
            "content": "具体的内容",
            "input_format": "应该以什么方式将输入传递给程序",
            "env": "除了输入内容外, 需要设置哪些环境变量, 若不需要则设为空字典",
            "rationale": "路径遍历攻击，尝试触发目录遍历漏洞",
            "analysis": "为什么这样调整（分析当前问题和调整理由）",
            "strategy": "采用的调整策略（如增加长度、修改编码、添加特殊字符等）"
        }
        ```
        """
        
        prev_seed = self.seed_history[-1] if self.seed_history else None
        prev_seed_desc = f"""**种子 **
        ```
        格式: {prev_seed.input_format}
        内容: {prev_seed.content}
        ``` """ if prev_seed else """"""
        coverage_feedback_desc = json.dumps(coverage_feedback, indent=2, ensure_ascii=False) if coverage_feedback else """"""
        history_feedback_desc = json.dumps(history_feedback, indent=2, ensure_ascii=False) if history_feedback else """"""
        task_prompt = f"""这是第{self.iteration}次为程序生成测试输入: ,
        **前一轮执行情况: **
        {prev_seed_desc}
        **覆盖反馈: **
        {coverage_feedback_desc}
        **最近三轮执行情况(不包含前一轮):
        {history_feedback_desc}
        """

        # 确保已初始化
        if self.session is None or self.tools is None:
            raise RuntimeError("Generator not initialized. Call initialize() first.")

        # 创建或复用agent
        if self.agent is None:
            logger.debug(system_prompt)
            self.agent = create_agent(self.llm, tools=self.tools, system_prompt=system_prompt)

        logger.debug(task_prompt)
        config = {
            "recursion_limit": 50,
            "debug": True
        }
        task_result = None
        async for item in self.agent.astream(
            {"messages": [HumanMessage(content=task_prompt)]},
            config=config
        ):
            if isinstance(item, dict):
                # Handle agent messages
                if 'model' in item and 'messages' in item['model']:
                    for message in item['model']['messages']:
                        if isinstance(message, AIMessage):
                            if message.content:
                                print(f"AI: {message.content}")
                                logger.debug(f"AI: {message.content}")
                                task_result = message.content
                            if hasattr(message, 'tool_calls') and message.tool_calls:
                                for tool_call in message.tool_calls:
                                    tool_name = tool_call.get("name", "unknown")
                                    tool_args = tool_call.get("args", {})
                                    tool_input = ', '.join([f"{key}={value}" for key, value in tool_args.items()])
                                    print(f"Tool call: {tool_name} with input {tool_input}")
                                    logger.debug(f"Tool call: {tool_name} with input {tool_input}")
                # Handle tool messages
                elif 'tools' in item and 'messages' in item['tools']:
                    for message in item['tools']['messages']:
                        if isinstance(message, ToolMessage):
                            print(f"Tool: {message.name}, result: {message.content}")
                            logger.debug(f"Tool: {message.name}, result: {message.content}")
                else:
                    print(f"Unknown dict structure: {list(item.keys())}")
                    logger.debug(f"Unknown dict structure: {list(item.keys())}")
            else:
                print(f"Unknown message type: {type(item).__name__} - {item}")
                logger.debug(f"Unknown message type: {type(item).__name__} - {item}")

        # 解析 LLM 响应
        seed = self._parse_seed_response(task_result, generation=0)
        self.seed_history.append(seed)
        self.iteration += 1

        return seed

    def _parse_seed_response(
        self,
        response_text: str,
        generation: int,
    ) -> Optional[Seed]:
        """
        解析 LLM 返回的种子 JSON

        Args:
            response_text: LLM 响应文本
            generation: 种子代数
            parent_id: 父种子ID

        Returns:
            Seed 对象列表
        """
        seed = None
        # 尝试提取 JSON 代码块
        if response_text.startswith('```json'):
            json_text = response_text[7:-3].strip()
        else:
            # 如果没有代码块，尝试直接解析整个响应
            import re
            json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
            if json_match:
                json_text = json_match.group(1)
            else:
                # 如果没有代码块，尝试直接解析整个响应
                json_text = response_text

        try:
            data = json.loads(json_text)
            seed = Seed(
                content=data.get("content", ""),
                input_format=data.get("input_format", "unknown"),
                metadata={
                    "rationale": data.get("rationale", ""),
                    "analysis": data.get("analysis", ""),
                    "strategy": data.get("strategy", "")
                },
                generation=generation,
            )
        except json.JSONDecodeError as e:
            print(f"Failed to parse LLM response as JSON: {e}")
            print(f"Response text: {response_text[:200]}...")

        return seed

    # def update_seed_score(self, seed: Seed, coverage_score: float):
    #     """更新种子的覆盖得分"""
    #     seed.coverage_score = coverage_score

    #     # 更新最佳种子
    #     if self.best_seed is None or coverage_score > self.best_seed.coverage_score:
    #         self.best_seed = seed

    def export_seed_history(self, output_file: Path):
        """导出种子历史"""
        history_data = {
            "total_seeds": len(self.seed_history),
            "best_seed": self.best_seed.to_dict() if self.best_seed else None,
            "seeds": [seed.to_dict() for seed in self.seed_history]
        }

        with open(output_file, 'w') as f:
            json.dump(history_data, f, indent=2, ensure_ascii=False)


# 示例使用
if __name__ == "__main__":
    from langchain_openai import ChatOpenAI

    async def main():
        # 初始化 LLM
        llm = ChatOpenAI(
            model="kimi-k2-0905-preview",
            temperature=0.7,
            api_key="sk-MkDVKnlqrN7zT4We32elRicls1mZLzLnavy7bBxvICVYM6Jy",
            base_url="https://api.moonshot.cn/v1"
        )

        # 创建生成器
        generator = LLMSeedGenerator(llm)

        try:
            # 初始化MCP连接（只需调用一次）
            await generator.initialize()

            # 目标程序信息
            target_info = {
                "name": "portal.cgi",
                "type": "cgi",
                "description": "cgi程序",
            }

            # 漏洞信息
            vuln_info = {
                "path_node": ["0x41904c", "0x419054", "0x41906c", "0x419084", "0x419134", "0x41913c"],
            }

            # 第一轮：生成初始种子
            seed1 = await generator.generate_seed(target_info, vuln_info)
            print("\n=== Round 1: Generated seed ===")
            print(f"   Format: {seed1.input_format}")
            print(f"   Content: {seed1.content[:100]}...")
            print(f"   Rationale: {seed1.metadata.get('rationale', 'N/A')}")

            # 第二轮：基于覆盖反馈生成新种子
            coverage_feedback = {
                "covered_nodes": ["0x41904c", "0x419054"],
                "uncovered_nodes": ["0x41906c", "0x419084", "0x419134", "0x41913c"],
                "coverage_rate": 0.33
            }
            seed2 = await generator.generate_seed(target_info, vuln_info, coverage_feedback)
            print("\n=== Round 2: Adjusted seed ===")
            print(f"   Format: {seed2.input_format}")
            print(f"   Content: {seed2.content[:100]}...")
            print(f"   Strategy: {seed2.metadata.get('strategy', 'N/A')}")

            # 第三轮：继续调整
            coverage_feedback2 = {
                "covered_nodes": ["0x41904c", "0x419054", "0x41906c"],
                "uncovered_nodes": ["0x419084", "0x419134", "0x41913c"],
                "coverage_rate": 0.50
            }
            seed3 = await generator.generate_seed(target_info, vuln_info, coverage_feedback2)
            print("\n=== Round 3: Further adjusted seed ===")
            print(f"   Format: {seed3.input_format}")
            print(f"   Content: {seed3.content[:100]}...")
            print(f"   Analysis: {seed3.metadata.get('analysis', 'N/A')}")

        finally:
            # 关闭MCP连接
            await generator.close()

    # 运行异步main函数
    asyncio.run(main())
