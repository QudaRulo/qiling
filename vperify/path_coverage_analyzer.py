"""
Path Coverage Analyzer

用于分析运行时 ICFG 是否覆盖了静态分析给出的漏洞路径
"""

import json
from os import PathLike
from pathlib import Path
from typing import Any, List, Set, Tuple, Dict, Optional
from dataclasses import dataclass


@dataclass
class VulnPath:
    """
    漏洞路径定义

    核心是 path_nodes，其他信息都是可选的辅助信息
    """
    path_nodes: List[str]  # 完整路径上的节点地址列表（静态分析给出，可能不是基本块起始地址）


@dataclass
class CoverageResult:
    """路径覆盖分析结果"""
    is_covered: bool  # 是否完整覆盖漏洞路径
    covered_nodes: List[str]  # 已覆盖的节点（无序）
    missing_nodes: List[str]  # 未覆盖的节点
    # coverage_ratio: float  # 覆盖率 (0.0 ~ 1.0)

    # 详细信息
    full_execution_trace: List[str]  # 完整的实际执行路径（包含循环、重复）
    ordered_covered_nodes: List[str]  # 已覆盖节点的有序列表（按执行顺序）
    divergence_point: Optional[str] = None  # 路径分歧点（如果有）
    next_target: Optional[str] = None  # 下一个应该覆盖的节点

    @property
    def execution_trace(self) -> List[str]:
        """为了向后兼容，保留这个属性"""
        return self.ordered_covered_nodes

    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            "is_covered": self.is_covered,
            "covered_nodes": self.covered_nodes,
            "ordered_covered_nodes": self.ordered_covered_nodes,
            "missing_nodes": self.missing_nodes,
            # "coverage_ratio": self.coverage_ratio,
            "divergence_point": self.divergence_point,
            "next_target": self.next_target,
            # "full_execution_trace_length": len(self.full_execution_trace),
            # "ordered_covered_nodes_length": len(self.ordered_covered_nodes)
        }


class PathCoverageAnalyzer:
    """分析运行时 ICFG 与静态漏洞路径的覆盖情况"""

    def __init__(self, icfg_file: PathLike):
        """
        初始化分析器

        Args:
            icfg_file: 运行时 ICFG JSON 文件路径
        """
        self.icfg_file = Path(icfg_file)
        self.icfg_data = self._load_icfg()

        # 提取执行信息
        self.executed_nodes: Set[str] = set(self.icfg_data.get("nodes", {}).keys())
        self.execution_trace: List[str] = self._extract_execution_trace()

        # 构建地址范围映射：任意地址 -> 所属基本块
        self._addr_to_block: Dict[int, str] = self._build_addr_to_block_mapping()

    def _load_icfg(self) -> dict:
        """加载 ICFG JSON 文件"""
        if not self.icfg_file.exists():
            raise FileNotFoundError(f"ICFG file not found: {self.icfg_file}")

        with open(self.icfg_file, 'r') as f:
            return json.load(f)

    def _extract_execution_trace(self) -> List[str]:
        """
        从 ICFG 中提取执行轨迹

        使用 ICFG 导出的真实执行顺序，包含循环和重复执行的基本块
        """
        return self.icfg_data.get("execution_trace", [])

    def _build_addr_to_block_mapping(self) -> Dict[int, str]:
        """
        构建地址到基本块的映射

        静态分析给出的地址可能是基本块内的任意地址，
        需要找到包含该地址的基本块

        Returns:
            {地址: 基本块起始地址(hex string)}
        """
        addr_to_block = {}
        nodes = self.icfg_data.get("nodes", {})

        for block_addr_str, node_info in nodes.items():
            # 基本块起始地址
            block_start = int(block_addr_str, 16)
            block_size = node_info.get("size", 0)
            block_end = block_start + block_size

            # 将该基本块范围内的所有地址都映射到这个基本块
            for addr in range(block_start, block_end):
                addr_to_block[addr] = block_addr_str

        return addr_to_block

    def _normalize_address(self, addr: str) -> str:
        """
        规范化地址：如果地址在某个基本块内部，返回该基本块的起始地址

        Args:
            addr: 地址(hex string, 如 "0x18518")

        Returns:
            规范化后的地址（基本块起始地址）
        """
        # 先检查是否直接匹配基本块起始地址
        if addr in self.executed_nodes:
            return addr

        # 转换为整数并查找所属基本块
        try:
            addr_int = int(addr, 16)
            if addr_int in self._addr_to_block:
                return self._addr_to_block[addr_int]
        except ValueError:
            pass

        # 如果找不到，返回原地址
        return addr

    def _order_covered_nodes(
        self,
        original_nodes: List[str],
        normalized_nodes: List[str]
    ) -> List[str]:
        """
        基于动态执行轨迹对已覆盖节点进行排序，返回原始地址

        Args:
            original_nodes: 原始节点地址列表（可能是基本块内部地址）
            normalized_nodes: 标准化后的节点地址列表（基本块起始地址）

        Returns:
            按执行顺序排列的原始节点地址列表（去重）
        """
        # 建立标准化地址到原始地址的映射（一对多）
        normalized_to_original = {}
        for orig, norm in zip(original_nodes, normalized_nodes):
            if norm not in normalized_to_original:
                normalized_to_original[norm] = []
            normalized_to_original[norm].append(orig)

        # 遍历完整执行轨迹，按顺序记录已覆盖节点
        ordered = []
        seen_normalized = set()

        for addr in self.execution_trace:
            # 如果这个基本块对应了漏洞路径中的节点
            if addr in normalized_to_original and addr not in seen_normalized:
                # 添加该基本块对应的所有原始地址
                # 如果同一个基本块有多个节点，它们顺序是确定的（在同一个基本块内）
                for orig_addr in normalized_to_original[addr]:
                    ordered.append(orig_addr)
                seen_normalized.add(addr)

        return ordered

    def analyze_coverage(self, vuln_path: VulnPath) -> CoverageResult:
        """
        分析漏洞路径覆盖情况

        Args:
            vuln_path: 静态分析得出的漏洞路径

        Returns:
            CoverageResult: 覆盖分析结果
        """
        # 规范化漏洞路径中的所有地址
        normalized_path = [self._normalize_address(addr) for addr in vuln_path.path_nodes]

        # 检查哪些节点被覆盖（保留原始地址和标准化地址）
        covered_original = []  # 原始地址
        covered_normalized = []  # 标准化地址
        missing_nodes = []  # 未覆盖的原始地址

        for original_node, normalized_node in zip(vuln_path.path_nodes, normalized_path):
            if normalized_node in self.executed_nodes:
                covered_original.append(original_node)
                covered_normalized.append(normalized_node)
            else:
                missing_nodes.append(original_node)

        # 完整覆盖需要所有节点都被执行
        is_covered = len(missing_nodes) == 0

        # 基于动态执行轨迹对已覆盖节点排序（返回原始地址）
        ordered_covered_nodes = self._order_covered_nodes(covered_original, covered_normalized)

        # 找到分歧点和下一个目标（使用原始路径和有序的已覆盖节点）
        divergence_point, next_target = self._find_divergence_and_target(
            vuln_path.path_nodes, ordered_covered_nodes, missing_nodes
        )

        return CoverageResult(
            is_covered=is_covered,
            covered_nodes=covered_original,  # 使用原始地址
            missing_nodes=missing_nodes,
            # coverage_ratio=coverage_ratio,
            full_execution_trace=self.execution_trace,
            ordered_covered_nodes=ordered_covered_nodes,
            divergence_point=divergence_point,
            next_target=next_target
        )

    def _find_divergence_and_target(
        self,
        path_nodes: List[str],
        covered: List[str],
        missing: List[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        找到路径分歧点和下一个应该覆盖的目标(使用原始地址)

        Args:
            path_nodes: 漏洞路径节点(原始地址)
            covered: 已覆盖的节点(原始地址, 已排序)
            missing: 未覆盖的节点(原始地址)

        Returns:
            (divergence_point, next_target) - 都是原始地址
        """
        if not missing:
            return None, None

        # 将已覆盖节点转为集合以便快速查找
        covered_set = set(covered)

        # 找到最后一个被覆盖的节点在原始路径中的索引
        last_covered_idx = -1
        for i, node in enumerate(path_nodes):
            if node in covered_set:
                last_covered_idx = i

        # 如果没有节点被覆盖，第一个节点就是目标
        if last_covered_idx == -1:
            return None, path_nodes[0] if path_nodes else None

        # 分歧点是最后一个被覆盖的节点（原始地址）
        divergence_point = path_nodes[last_covered_idx]

        # 下一个目标是紧接着的未覆盖节点（原始地址）
        if last_covered_idx + 1 < len(path_nodes):
            next_target = path_nodes[last_covered_idx + 1]
        else:
            next_target = None

        return divergence_point, next_target

    def export_analysis_report(
        self,
        vuln_path: VulnPath,
        coverage_result: CoverageResult,
        output_file: Path
    ):
        """导出分析报告"""
        report = {
            "vulnerability": {
                "path_nodes": vuln_path.path_nodes,
                "path_length": len(vuln_path.path_nodes)
            },
            "coverage": coverage_result.to_dict(),
            "recommendation": self._generate_recommendation(coverage_result)
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

    def _generate_recommendation(self, result: CoverageResult) -> str:
        """生成调整建议"""
        if result.is_covered:
            return "路径已完全覆盖，漏洞验证成功！当前输入可作为 PoC payload。"

        # 未完全覆盖的情况
        if result.divergence_point:
            return (f"程序在 {result.divergence_point} 处发生路径分歧，"
                   f"需要调整输入使程序继续执行到 {result.next_target}")
        elif result.next_target:
            return f"需要调整输入以到达下一个目标节点 {result.next_target}"
        else:
            return f"路径覆盖不完整, 需要进一步分析。"


# 示例使用
if __name__ == "__main__":
    # 示例漏洞路径
    example_vuln = VulnPath(
        path_nodes=["0x9a6c", "0x99d4"]
    )

    # 分析覆盖情况
    analyzer = PathCoverageAnalyzer(Path("test_icfg_method2.json"))
    result = analyzer.analyze_coverage(example_vuln)

    print("Coverage Analysis:")
    print(f"  Covered: {result.is_covered}")
    # print(f"  Coverage ratio: {result.coverage_ratio:.2%}")
    print(f"  Covered nodes: {len(result.covered_nodes)}/{len(example_vuln.path_nodes)}")
    print(f"  Missing nodes: {result.missing_nodes}")
    print(f"  Next target: {result.next_target}")
    print(f"  Divergence point: {result.divergence_point}")
