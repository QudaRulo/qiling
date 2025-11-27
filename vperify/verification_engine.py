"""
Vulnerability Verification Engine

LLM 驱动的漏洞验证引擎，整合路径覆盖分析、种子生成和 Qiling 模拟
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import tempfile

from langchain_openai import ChatOpenAI

from .path_coverage_analyzer import PathCoverageAnalyzer, VulnPath, CoverageResult
from .seed_generator import LLMSeedGenerator, Seed
from .runtime_icfg_tool import gen_runtime_icfg


@dataclass
class VerificationConfig:
    """验证配置"""
    target_binary: Path  # 目标二进制文件
    rootfs: Path         # 根文件系统路径

    max_iterations: int = 50  # 最大迭代次数
    timeout: int = 30000000  # 单次运行超时（微秒）

    # LLM 配置
    llm_model: str = "gpt-4"
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
    final_coverage: float  # 最终覆盖率

    poc_seed: Optional[Seed] = None  # PoC 种子
    poc_command: Optional[str] = None  # PoC 复现命令

    coverage_history: List[float] = None  # 覆盖率历史
    best_coverage_result: Optional[CoverageResult] = None  # 最佳覆盖结果

    def __post_init__(self):
        if self.coverage_history is None:
            self.coverage_history = []


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

    def verify(self, vuln_path: VulnPath) -> VerificationResult:
        """
        验证漏洞路径

        Args:
            vuln_path: 漏洞路径定义

        Returns:
            验证结果
        """
        print(f"\n{'='*70}")
        print(f"开始验证漏洞: {vuln_path.vuln_type}")
        print(f"源点: {vuln_path.source} -> 汇点: {vuln_path.sink}")
        print(f"{'='*70}\n")

        # 准备目标和漏洞信息
        target_info = self._extract_target_info()
        vuln_info = {
            "type": vuln_path.vuln_type,
            "source": vuln_path.source,
            "sink": vuln_path.sink,
            "path_nodes": vuln_path.path_nodes,
            "description": vuln_path.description
        }

        # 生成初始种子
        print("[Step 1] 生成初始测试种子...")
        seeds = self.seed_generator.generate_initial_seeds(
            target_info, vuln_info, num_seeds=5
        )
        print(f"  生成了 {len(seeds)} 个初始种子\n")

        # 迭代验证
        best_result = None
        best_seed = None
        best_coverage = 0.0

        for iteration in range(self.config.max_iterations):
            print(f"\n[Iteration {iteration + 1}/{self.config.max_iterations}]")

            # 选择种子（优先选择上一轮最佳种子的变异，否则轮换）
            if iteration < len(seeds):
                current_seed = seeds[iteration]
                print(f"  使用初始种子 #{iteration + 1}")
            elif best_seed:
                print(f"  变异最佳种子（覆盖率 {best_coverage:.2%}）")
                # 使用覆盖反馈变异种子
                coverage_feedback = best_result.to_dict() if best_result else {}
                current_seed = self.seed_generator.mutate_seed(
                    best_seed,
                    coverage_feedback,
                    target_node=best_result.next_target if best_result else None
                )
            else:
                # 如果没有最佳种子，轮换使用初始种子
                current_seed = seeds[iteration % len(seeds)]
                print(f"  轮换使用种子 #{iteration % len(seeds) + 1}")

            # 执行并分析
            try:
                coverage_result = self._run_and_analyze(current_seed, vuln_path, iteration)

                # 更新种子得分
                self.seed_generator.update_seed_score(current_seed, coverage_result.coverage_ratio)

                # 记录历史
                self.iteration_history.append({
                    "iteration": iteration + 1,
                    "seed": current_seed.to_dict(),
                    "coverage": coverage_result.to_dict()
                })

                # 更新最佳结果
                if coverage_result.coverage_ratio > best_coverage:
                    best_coverage = coverage_result.coverage_ratio
                    best_result = coverage_result
                    best_seed = current_seed

                    print(f"  ✓ 新的最佳覆盖率: {best_coverage:.2%}")

                # 检查是否完全覆盖
                if coverage_result.is_covered:
                    print(f"\n{'='*70}")
                    print(f"✓ 漏洞验证成功！")
                    print(f"  迭代次数: {iteration + 1}")
                    print(f"  覆盖率: {best_coverage:.2%}")
                    print(f"{'='*70}\n")

                    return self._build_success_result(
                        iteration + 1,
                        best_seed,
                        best_result,
                        best_coverage
                    )

            except Exception as e:
                print(f"  ✗ 执行出错: {e}")
                continue

            # 每 10 次迭代分析一次整体趋势
            if (iteration + 1) % 10 == 0:
                self._analyze_progress(vuln_path)

        # 达到最大迭代次数
        print(f"\n{'='*70}")
        print(f"达到最大迭代次数 ({self.config.max_iterations})")
        print(f"最佳覆盖率: {best_coverage:.2%}")
        print(f"{'='*70}\n")

        return self._build_failure_result(
            self.config.max_iterations,
            best_seed,
            best_result,
            best_coverage
        )

    def _run_and_analyze(
        self,
        seed: Seed,
        vuln_path: VulnPath,
        iteration: int
    ) -> CoverageResult:
        """
        运行程序并分析覆盖情况

        Args:
            seed: 测试种子
            vuln_path: 漏洞路径
            iteration: 迭代次数

        Returns:
            覆盖分析结果
        """
        # 根据种子格式准备参数
        argv, env = self._prepare_execution_args(seed)

        # 生成 ICFG 文件路径
        if self.config.save_all_icfgs:
            icfg_file = self.config.output_dir / f"icfg_iter_{iteration}.json"
        else:
            # 只保留最新的 ICFG
            icfg_file = self.config.output_dir / "current_icfg.json"

        print(f"  运行目标程序...")
        # 执行并生成 ICFG
        success = gen_runtime_icfg(
            argv=argv,
            output_file=str(icfg_file),
            timeout=self.config.timeout,
            rootfs=str(self.config.rootfs),
            env=env
        )

        if not success:
            raise RuntimeError("Failed to generate ICFG")

        print(f"  分析路径覆盖...")
        # 分析覆盖情况
        analyzer = PathCoverageAnalyzer(icfg_file)
        coverage_result = analyzer.analyze_coverage(vuln_path)

        print(f"  覆盖率: {coverage_result.coverage_ratio:.2%}")
        print(f"  已覆盖节点: {len(coverage_result.covered_nodes)}/{len(vuln_path.path_nodes)}")

        if not coverage_result.is_covered:
            print(f"  下一个目标: {coverage_result.next_target}")

        return coverage_result

    def _prepare_execution_args(self, seed: Seed) -> tuple[List[str], Dict[str, str]]:
        """
        根据种子准备执行参数

        Args:
            seed: 测试种子

        Returns:
            (argv, env)
        """
        argv = [str(self.config.target_binary)]
        env = {}

        if seed.format == "args":
            # 命令行参数
            argv.extend(seed.content.split())

        elif seed.format == "file":
            # 创建临时输入文件
            temp_file = self.config.output_dir / f"input_{seed.generation}.txt"
            temp_file.write_text(seed.content)
            argv.append(str(temp_file))

        elif seed.format == "stdin":
            # 通过环境变量传递（实际实现可能需要修改 Qiling）
            env["STDIN_DATA"] = seed.content

        elif seed.format == "http_request":
            # HTTP 请求（需要特殊处理，可能需要启动服务器后发送请求）
            # 这里简化为将请求保存为文件
            temp_file = self.config.output_dir / f"request_{seed.generation}.http"
            temp_file.write_text(seed.content)
            # 可以通过环境变量告知程序读取该文件
            env["HTTP_REQUEST_FILE"] = str(temp_file)

        return argv, env

    def _extract_target_info(self) -> Dict[str, Any]:
        """提取目标程序信息"""
        return {
            "name": self.config.target_binary.name,
            "path": str(self.config.target_binary),
            "type": "binary",  # 可以通过文件分析工具获取更详细信息
            "description": "Target binary for vulnerability verification"
        }

    def _analyze_progress(self, vuln_path: VulnPath):
        """分析整体进展趋势"""
        print(f"\n  [Progress Analysis]")

        # 获取最近的覆盖结果
        recent_results = [
            item["coverage"] for item in self.iteration_history[-10:]
        ]

        # 使用 LLM 分析
        vuln_info = {
            "type": vuln_path.vuln_type,
            "source": vuln_path.source,
            "sink": vuln_path.sink,
            "path_nodes": vuln_path.path_nodes
        }

        guidance = self.seed_generator.analyze_and_guide(recent_results, vuln_info)
        print(f"  {guidance}\n")

    def _build_success_result(
        self,
        iterations: int,
        seed: Seed,
        coverage: CoverageResult,
        final_coverage: float
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
            final_coverage=final_coverage,
            poc_seed=seed,
            poc_command=poc_command,
            coverage_history=[item["coverage"]["coverage_ratio"] for item in self.iteration_history],
            best_coverage_result=coverage
        )

    def _build_failure_result(
        self,
        iterations: int,
        seed: Optional[Seed],
        coverage: Optional[CoverageResult],
        final_coverage: float
    ) -> VerificationResult:
        """构建失败结果"""
        return VerificationResult(
            success=False,
            iterations=iterations,
            final_coverage=final_coverage,
            poc_seed=seed,
            coverage_history=[item["coverage"]["coverage_ratio"] for item in self.iteration_history],
            best_coverage_result=coverage
        )

    def _generate_poc_command(self, seed: Seed) -> str:
        """生成 PoC 复现命令"""
        if seed.format == "args":
            return f"{self.config.target_binary} {seed.content}"
        elif seed.format == "file":
            return f"echo '{seed.content}' | {self.config.target_binary}"
        elif seed.format == "stdin":
            return f"echo '{seed.content}' | {self.config.target_binary}"
        else:
            return f"# PoC seed format: {seed.format}\n# Content: {seed.content[:100]}..."

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


# 示例使用
if __name__ == "__main__":
    # 配置
    config = VerificationConfig(
        target_binary=Path("/mnt/d/downloads/web_downloads/CC8160-VVTK_output/usr/sbin/httpd"),
        rootfs=Path("/mnt/d/downloads/web_downloads/CC8160-VVTK_output"),
        max_iterations=20,
        output_dir=Path("./vperify_output"),
        llm_model="gpt-4"
    )

    # 漏洞路径
    vuln_path = VulnPath(
        source="0x9a6c",
        sink="0x99d4",
        path_nodes=["0xa76c", "0x9a6c", "0x99d4"],
        vuln_type="buffer_overflow",
        description="Buffer overflow in HTTP request parsing"
    )

    # 创建引擎
    engine = VulnerabilityVerificationEngine(config)

    # 执行验证
    result = engine.verify(vuln_path)

    # 导出报告
    engine.export_final_report(result, config.output_dir / "final_report.json")

    # 打印结果
    print(f"\n验证结果: {'成功' if result.success else '失败'}")
    print(f"迭代次数: {result.iterations}")
    print(f"最终覆盖率: {result.final_coverage:.2%}")
    if result.poc_command:
        print(f"\nPoC 命令:\n{result.poc_command}")
