"""
LLM-Driven Seed Generator

使用 LLM 智能生成和调整测试输入（seed），用于漏洞路径覆盖
"""

import json
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langchain.agents import create_agent
from mcp import ClientSession, StdioServerParameters, stdio_client
from langchain_mcp_adapters.tools import load_mcp_tools


@dataclass
class Seed:
    """测试种子"""
    content: str  # 种子内容（可以是文件内容、命令行参数、网络请求等）
    format: str   # 种子格式 ("file", "args", "http_request", "stdin")
    metadata: Dict[str, Any]  # 额外元数据

    generation: int = 0  # 第几代种子
    parent_id: Optional[str] = None  # 父种子ID
    coverage_score: float = 0.0  # 覆盖得分

    def to_dict(self) -> dict:
        return asdict(self)

server_params = StdioServerParameters(
    command="D:/Program Files/Python312/python.exe",
    args=[
        "D:/Program Files/Python312/Lib/site-packages/ida_pro_mcp/server.py",
        "--ida-rpc",
        "http://127.0.0.1:13337"
    ]
)

class LLMSeedGenerator:
    """基于 LLM 的智能种子生成器"""

    def __init__(self, llm: ChatOpenAI):
        """
        初始化生成器

        Args:
            llm: ChatOpenAI 实例
        """
        self.llm = llm
        self.seed_history: List[Seed] = []
        self.best_seed: Optional[Seed] = None
        self.iteration = 1

    async def generate_initial_seeds(
        self,
        target_info: Dict[str, Any],
        vuln_info: Dict[str, Any],
        prev_seed: Optional[Seed] = None,
        coverage_feedback: Optional[Dict[str, float]] = None,
        history_feedback: Optional[Dict[str, float]] = None,
    ) -> List[Seed]:
        """
        生成初始种子集合

        Args:
            target_info: 目标程序信息（二进制类型、功能描述等）
            vuln_info: 漏洞信息（类型、路径、描述）
            num_seeds: 生成种子数量

        Returns:
            初始种子列表
        """
        system_prompt = f"""你是一个专业的IoT漏洞研究专家和 fuzzer 工程师。
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
        - content: 测试输入的具体内容
        - format: 输入格式("file", "args", "env", "stdin")
        - rationale: 生成该输入的理由(简短说明为什么这个输入可能触发漏洞)
        - analysis: 分析当前问题和调整理由
        - strategy: 简短说明当前调整策略

        示例：
        ```json
        {
            "content": "GET /../../../../etc/passwd HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n",
            "format": "env",
            "rationale": "路径遍历攻击，尝试触发目录遍历漏洞",
            "analysis": "为什么这样调整（分析当前问题和调整理由）",
            "strategy": "采用的调整策略（如增加长度、修改编码、添加特殊字符等）"
        }
        ```
        """
        
        prev_seed_desc = f"""**种子 **
        ```
        格式: {prev_seed.format}
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
        print(system_prompt)
        print("\n")
        print(task_prompt)
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await load_mcp_tools(session)
                agent = create_agent(self.llm, tools=tools, system_prompt=system_prompt)
                config = {
                    "recursion_limit": 50,
                    "debug": True
                }
                # task_result = await agent.ainvoke(
                #     {"messages": [HumanMessage(content=task_prompt)]},
                #     config=config
                # )
                task_result = None
                async for item in agent.astream(
                    {"messages": [HumanMessage(content=task_prompt)]},
                    config=config
                ):
                    print(item)
                    task_result = item
                # print(task_result.content)

                # 解析 LLM 响应
                seeds = self._parse_seed_response(task_result.content, generation=0)
                self.seed_history.extend(seeds)
                return seeds

    def mutate_seed(
        self,
        seed: Seed,
        coverage_feedback: Dict[str, Any],
        target_node: Optional[str] = None
    ) -> Seed:
        """
        根据覆盖反馈变异种子

        Args:
            seed: 要变异的种子
            coverage_feedback: 覆盖反馈信息
            target_node: 下一个目标节点地址

        Returns:
            变异后的新种子
        """
        system_prompt = """你是一个专业的漏洞研究专家。
你需要基于程序执行的覆盖反馈，智能调整测试输入，以便覆盖更多的漏洞路径。

分析策略：
1. 如果程序在某个分支点发生了分歧，分析可能的原因（输入值、条件判断等）
2. 针对性地调整输入，使程序走向目标路径
3. 考虑常见的绕过技术（如编码、填充、特殊字符等）
"""

        user_prompt = f"""基于以下反馈，请调整测试输入：

**当前种子：**
```
格式：{seed.format}
内容：{seed.content}
```

**覆盖反馈：**
{json.dumps(coverage_feedback, indent=2, ensure_ascii=False)}

**目标节点：** {target_node if target_node else "未指定"}

**任务：**
1. 分析为什么当前输入没有覆盖目标路径
2. 提出具体的调整策略
3. 生成新的测试输入

**输出格式：**
```json
{{
  "content": "新的测试输入内容",
  "format": "输入格式",
  "analysis": "为什么这样调整（分析当前问题和调整理由）",
  "strategy": "采用的调整策略（如增加长度、修改编码、添加特殊字符等）"
}}
```
"""

        response = self.llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ])

        # 解析变异结果
        new_seeds = self._parse_seed_response(
            response.content,
            generation=seed.generation + 1,
            parent_id=id(seed)
        )

        if new_seeds:
            new_seed = new_seeds[0]
            self.seed_history.append(new_seed)
            return new_seed
        else:
            # 如果解析失败，返回原种子
            return seed

    def analyze_and_guide(
        self,
        coverage_results: List[Dict[str, Any]],
        vuln_path: Dict[str, Any]
    ) -> str:
        """
        分析多次执行的覆盖结果，给出调整建议

        Args:
            coverage_results: 历史覆盖结果列表
            vuln_path: 漏洞路径信息

        Returns:
            调整建议（自然语言）
        """
        system_prompt = """你是一个专业的漏洞研究专家和程序分析专家。
你需要分析多次程序执行的覆盖情况，找出规律，给出下一步的调整方向。
"""

        user_prompt = f"""请分析以下执行历史，给出调整建议：

**漏洞路径：**
{json.dumps(vuln_path, indent=2, ensure_ascii=False)}

**执行历史（最近 {len(coverage_results)} 次）：**
{json.dumps(coverage_results, indent=2, ensure_ascii=False)}

**请分析：**
1. 哪些节点一直无法覆盖？可能的原因是什么？
2. 覆盖率的变化趋势如何？
3. 应该采取什么策略来提高覆盖率？
4. 具体的下一步行动建议是什么？

请给出简明扼要的分析和建议。
"""

        response = self.llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ])

        return response.content

    def _parse_seed_response(
        self,
        response_text: str,
        generation: int,
        parent_id: Optional[str] = None
    ) -> List[Seed]:
        """
        解析 LLM 返回的种子 JSON

        Args:
            response_text: LLM 响应文本
            generation: 种子代数
            parent_id: 父种子ID

        Returns:
            Seed 对象列表
        """
        seeds = []

        # 尝试提取 JSON 代码块
        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            json_text = json_match.group(1)
        else:
            # 如果没有代码块，尝试直接解析整个响应
            json_text = response_text

        try:
            data = json.loads(json_text)

            # 处理单个对象或数组
            if isinstance(data, dict):
                data = [data]

            for item in data:
                seed = Seed(
                    content=item.get("content", ""),
                    format=item.get("format", "unknown"),
                    metadata={
                        "rationale": item.get("rationale", ""),
                        "analysis": item.get("analysis", ""),
                        "strategy": item.get("strategy", "")
                    },
                    generation=generation,
                    parent_id=parent_id
                )
                seeds.append(seed)

        except json.JSONDecodeError as e:
            print(f"Failed to parse LLM response as JSON: {e}")
            print(f"Response text: {response_text[:200]}...")

        return seeds

    def update_seed_score(self, seed: Seed, coverage_score: float):
        """更新种子的覆盖得分"""
        seed.coverage_score = coverage_score

        # 更新最佳种子
        if self.best_seed is None or coverage_score > self.best_seed.coverage_score:
            self.best_seed = seed

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

    # 初始化 LLM
    llm = ChatOpenAI(
        model="kimi-k2-0905-preview",
        temperature=0.7,
        api_key="sk-MkDVKnlqrN7zT4We32elRicls1mZLzLnavy7bBxvICVYM6Jy",
        base_url="https://api.moonshot.cn/v1"
    )

    # 创建生成器
    generator = LLMSeedGenerator(llm)

    # 目标程序信息
    target_info = {
        "name": "httpd",
        "type": "web_server",
        "description": "Boa HTTP server",
    }

    # 漏洞信息
    vuln_info = {
        "path_node": ["0x1850c", "0x18518", "0x18528", "0x18538"],
    }

    # 生成初始种子
    seeds = asyncio.run(generator.generate_initial_seeds(target_info, vuln_info))

    print("Generated seeds:")
    for i, seed in enumerate(seeds, 1):
        print(f"\n{i}. Format: {seed.format}")
        print(f"   Content: {seed.content[:100]}...")
        print(f"   Rationale: {seed.metadata.get('rationale', 'N/A')}")
