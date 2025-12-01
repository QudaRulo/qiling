"""
Vulnerability Verification Engine

LLM 驱动的漏洞验证引擎，整合路径覆盖分析、种子生成和 Qiling 模拟
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import tempfile
import logging

from langchain_openai import ChatOpenAI

from vperify.path_coverage_analyzer import PathCoverageAnalyzer, VulnPath, CoverageResult
from vperify.seed_generator import LLMSeedGenerator, Seed
from vperify.runtime_icfg_tool import gen_runtime_icfg


@dataclass
class VerificationConfig:
    """验证配置"""
    target_binary: Path  # 目标二进制文件
    rootfs: Path         # 根文件系统路径

    max_iterations: int = 50  # 最大迭代次数
    timeout: int = 300000000  # 单次运行超时（微秒）

    # LLM 配置
    llm_model: str = ""
    llm_temperature: float = 0.7
    llm_base_url: Optional[str] = None
    llm_api_key: Optional[str] = None

    # 输出配置
    output_dir: Path = Path("./vperify_output")
    save_all_icfgs: bool = False  # 是否保存所有 ICFG


@dataclass
class VerificationResult:
    """验证结果"""
    success: bool  # 是否成功验证漏洞
    iterations: int  # 迭代次数
    # final_coverage: float  # 最终覆盖率

    poc_seed: Optional[Seed] = None  # PoC 种子
    poc_command: Optional[str] = None  # PoC 复现命令

    # coverage_history: List[float] = None  # 覆盖率历史
    best_coverage_result: Optional[CoverageResult] = None  # 最佳覆盖结果

    # def __post_init__(self):
    #     if self.coverage_history is None:
    #         self.coverage_history = []


class VulnerabilityVerificationEngine:
    """漏洞验证引擎"""

    def __init__(self, config: VerificationConfig):
        """
        初始化验证引擎

        Args:
            config: 验证配置
        """
        self.config = config
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # 初始化 LLM
        llm_kwargs = {
            "model": config.llm_model,
            "temperature": config.llm_temperature
        }
        if config.llm_base_url:
            llm_kwargs["base_url"] = config.llm_base_url
        if config.llm_api_key:
            llm_kwargs["api_key"] = config.llm_api_key

        self.llm = ChatOpenAI(**llm_kwargs)

        # 初始化种子生成器
        self.seed_generator = LLMSeedGenerator(self.llm)

        # 历史记录
        self.iteration_history: List[Dict[str, Any]] = []

        # 初始化日志记录器
        self.logger = logging.getLogger(__name__)

    async def verify(self, vuln_path: VulnPath) -> VerificationResult:
        """
        验证漏洞路径

        Args:
            vuln_path: 漏洞路径定义

        Returns:
            验证结果
        """
        print(f"\n{'='*70}")
        print(f"漏洞路径: {"->".join(vuln_path.path_nodes)}")
        print(f"{'='*70}\n")

        # 准备目标和漏洞信息
        target_info = self._extract_target_info()
        vuln_info = {
            "path_nodes": vuln_path.path_nodes,
        }

        # 初始化 seed_generator 的 MCP 连接
        await self.seed_generator.initialize()

        try:
            # 迭代验证
            best_result = None
            best_seed = None
            best_coverage = 0
            prev_coverage_feedback = None

            for iteration in range(self.config.max_iterations):
                # print(f"\n[Iteration {iteration + 1}/{self.config.max_iterations}]")
                self.logger.info(f"[Iteration {iteration + 1}/{self.config.max_iterations}]")

                # 生成种子
                current_seed = await self.seed_generator.generate_seed(
                    target_info=target_info,
                    vuln_info=vuln_info,
                    coverage_feedback=prev_coverage_feedback,
                    history_feedback=self.iteration_history[-4:-1] if len(self.iteration_history) > 4 else self.iteration_history[:-1],
                )

                # 执行并分析
                try:
                    coverage_result, program_output = self._run_and_analyze(current_seed, vuln_path, iteration + 1)

                    prev_coverage_feedback = {
                        "covered_nodes": coverage_result.covered_nodes,
                        "missed_nodes": coverage_result.missing_nodes,
                        "ordered_covered_nodes": coverage_result.ordered_covered_nodes,
                        "divergence_point": coverage_result.divergence_point,
                        "next_target": coverage_result.next_target,
                    }
                    coverage_point = len(coverage_result.ordered_covered_nodes)
                    if best_coverage <= coverage_point:
                        best_coverage = coverage_point
                        best_seed = current_seed
                        best_result = coverage_result

                    # 记录历史
                    self.iteration_history.append({
                        "iteration": iteration + 1,
                        "seed": {
                            "content": current_seed.content,
                            "input_format": current_seed.input_format,
                            "env": current_seed.env,
                            "generation": current_seed.generation,
                        },
                        "coverage": prev_coverage_feedback,
                    })

                    # 检查是否完全覆盖
                    if coverage_result.is_covered:
                        print(f"\n{'='*70}")
                        print(f"✓ 漏洞验证成功！")
                        print(f"  迭代次数: {iteration + 1}")
                        print(f"  覆盖点数: {best_coverage}")
                        print(f"{'='*70}\n")

                        self.logger.info(f"验证成功! ")

                        return self._build_success_result(
                            iteration + 1,
                            best_seed,
                            best_result,
                            # best_coverage
                        )

                except Exception as e:
                    error_msg = f"执行出错: {e}"
                    # print(f"  ✗ {error_msg}")
                    self.logger.warning(f"轮次: {iteration + 1}, 执行出错: {e}")
                    continue

                # # 每 10 次迭代分析一次整体趋势
                # if (iteration + 1) % 10 == 0:
                #     self._analyze_progress(vuln_path)

            # 达到最大迭代次数
            print(f"\n{'='*70}")
            print(f"达到最大迭代次数 ({self.config.max_iterations})")
            print(f"最佳覆盖点数: {best_coverage}")
            print(f"{'='*70}\n")

            self.logger.info(f"已到达最大迭代次数, 尚未找到有效输入")

            return self._build_failure_result(
                self.config.max_iterations,
                best_seed,
                best_result,
                best_coverage
            )

        finally:
            # 确保清理 seed_generator 的 MCP 资源
            await self.seed_generator.close()

    def _run_and_analyze(
        self,
        seed: Seed,
        vuln_path: VulnPath,
        iteration: int
    ) -> tuple[CoverageResult, str]:
        """
        运行程序并分析覆盖情况

        Args:
            seed: 测试种子
            vuln_path: 漏洞路径
            iteration: 迭代次数

        Returns:
            tuple[CoverageResult, str]: (覆盖分析结果, 程序输出)
        """
        # 根据种子格式准备参数
        argv, env, stdin_data = self._prepare_execution_args(seed)

        # 生成 ICFG 文件路径
        if self.config.save_all_icfgs:
            icfg_file = self.config.output_dir / f"icfg_iter_{iteration}.json"
        else:
            # 只保留最新的 ICFG
            icfg_file = self.config.output_dir / "current_icfg.json"

        print(f"  运行目标程序...")
        # 执行并生成 ICFG，捕获输出
        success, program_output = gen_runtime_icfg(
            argv=argv,
            output_file=str(icfg_file),
            timeout=self.config.timeout,
            rootfs=str(self.config.rootfs),
            env=env,
            stdin_data=stdin_data
        )

        self.logger.debug(f"本次运行输出: {program_output}")

        if not success:
            raise RuntimeError("Failed to generate ICFG")

        print(f"  分析路径覆盖...")
        # 分析覆盖情况
        analyzer = PathCoverageAnalyzer(icfg_file)
        coverage_result = analyzer.analyze_coverage(vuln_path)

        # print(f"  覆盖率: {coverage_result.coverage_ratio:.2%}")
        # print(f"  已覆盖节点: {len(coverage_result.covered_nodes)}/{len(vuln_path.path_nodes)}")
        self.logger.info(f"已覆盖节点: {len(coverage_result.covered_nodes)}/{len(vuln_path.path_nodes)}")

        if not coverage_result.is_covered:
            # print(f"  下一个目标: {coverage_result.next_target}")
            self.logger.info(f"下一个目标: {coverage_result.next_target}")

        return coverage_result, program_output

    def _prepare_execution_args(self, seed: Seed) -> tuple[List[str], Dict[str, str], Optional[bytes]]:
        """
        根据种子准备执行参数

        Args:
            seed: 测试种子

        Returns:
            (argv, env, stdin_data)
        """
        argv = [str(self.config.target_binary)]
        env = {}
        stdin_data = None

        if seed.input_format == "args":
            # 命令行参数
            argv.extend(seed.content.split())
        elif seed.input_format == "stdin":
            # 将内容作为 stdin 传递
            content_bytes = seed.content.encode('utf-8') if isinstance(seed.content, str) else seed.content
            stdin_data = content_bytes
        else:
            raise RuntimeError("Unsupported input format")

        # 如果 seed 有额外的环境变量，也添加进去（可以覆盖默认值）
        if seed.env:
            for key, value in seed.env.items():
                env[key] = value

        return argv, env, stdin_data

    def _extract_target_info(self) -> Dict[str, Any]:
        """提取目标程序信息"""
        return {
            "name": self.config.target_binary.name,
            "path": str(self.config.target_binary),
            "type": "binary",  # 可以通过文件分析工具获取更详细信息
            "description": "Target binary for vulnerability verification"
        }

    def _build_success_result(
        self,
        iterations: int,
        seed: Seed,
        coverage: CoverageResult,
        # final_coverage: float
    ) -> VerificationResult:
        """构建成功结果"""
        # 生成 PoC 命令
        poc_command = self._generate_poc_command(seed)

        # 保存 PoC
        poc_file = self.config.output_dir / "poc.json"
        with open(poc_file, 'w') as f:
            json.dump({
                "seed": seed.to_dict(),
                "command": poc_command,
                "coverage": coverage.to_dict()
            }, f, indent=2, ensure_ascii=False)

        return VerificationResult(
            success=True,
            iterations=iterations,
            # final_coverage=final_coverage,
            poc_seed=seed,
            poc_command=poc_command,
            # coverage_history=[item["coverage"]["coverage_ratio"] for item in self.iteration_history],
            best_coverage_result=coverage
        )

    def _build_failure_result(
        self,
        iterations: int,
        seed: Optional[Seed],
        coverage: Optional[CoverageResult],
        # final_coverage: float
    ) -> VerificationResult:
        """构建失败结果"""
        return VerificationResult(
            success=False,
            iterations=iterations,
            # final_coverage=final_coverage,
            poc_seed=seed,
            # coverage_history=[item["coverage"]["coverage_ratio"] for item in self.iteration_history],
            best_coverage_result=coverage
        )

    def _generate_poc_command(self, seed: Seed) -> str:
        """生成 PoC 复现命令"""
        if seed.input_format == "args":
            return f"{self.config.target_binary} {seed.content}"
        elif seed.input_format == "stdin":
            return f"echo '{seed.content}' | {self.config.target_binary}"
        else:
            return f"# PoC seed format: {seed.input_format}\n# Content: {seed.content[:100]}..."

    def export_final_report(self, result: VerificationResult, output_file: Path):
        """导出最终报告"""
        report = {
            "verification_result": {
                "success": result.success,
                "iterations": result.iterations,
                "final_coverage": result.final_coverage
            },
            "poc": {
                "command": result.poc_command,
                "seed": result.poc_seed.to_dict() if result.poc_seed else None
            },
            "coverage_history": result.coverage_history,
            "best_coverage": result.best_coverage_result.to_dict() if result.best_coverage_result else None,
            "iteration_details": self.iteration_history
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"\n最终报告已保存: {output_file}")


async def test_verify():
    # 配置
    config = VerificationConfig(
        target_binary=Path("/mnt/d/downloads/web_downloads/AX3200/www/cgi-bin/portal.cgi"),
        rootfs=Path("/mnt/d/downloads/web_downloads/AX3200"),
        max_iterations=20,
        output_dir=Path("./vperify_output"),
        llm_model="kimi-k2-0905-preview",
        llm_api_key="sk-MkDVKnlqrN7zT4We32elRicls1mZLzLnavy7bBxvICVYM6Jy",
        llm_base_url="https://api.moonshot.cn/v1",
        save_all_icfgs=True,
    )

    # 漏洞路径
    vuln_path = VulnPath(
        path_nodes=["0x41904c", "0x419054", "0x41906c", "0x419084", "0x419134", "0x41913c"],
    )

    # 创建引擎
    engine = VulnerabilityVerificationEngine(config)

    # 执行验证
    result = await engine.verify(vuln_path)

    # 导出报告
    engine.export_final_report(result, config.output_dir / "final_report.json")

    # 打印结果
    print(f"\n验证结果: {'成功' if result.success else '失败'}")
    print(f"迭代次数: {result.iterations}")
    print(f"最终覆盖率: {result.final_coverage:.2%}")
    if result.poc_command:
        print(f"\nPoC 命令:\n{result.poc_command}")

# 示例使用
if __name__ == "__main__":
    import asyncio
    from vperify.logger import setup_logging
    setup_logging()
    asyncio.run(test_verify())
