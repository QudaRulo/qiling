"""
Path Coverage Analyzer

用于分析运行时 ICFG 是否覆盖了静态分析给出的漏洞路径
"""

import json
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
    covered_nodes: List[str]  # 已覆盖的节点
    missing_nodes: List[str]  # 未覆盖的节点
    coverage_ratio: float  # 覆盖率 (0.0 ~ 1.0)

    # 路径分析
    reached_source: bool  # 是否到达源点
    reached_sink: bool    # 是否到达汇点

    # 详细信息
    execution_trace: List[str]  # 实际执行路径
    divergence_point: Optional[str] = None  # 路径分歧点（如果有）
    next_target: Optional[str] = None  # 下一个应该覆盖的节点

    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            "is_covered": self.is_covered,
            "covered_nodes": self.covered_nodes,
            "missing_nodes": self.missing_nodes,
            "coverage_ratio": self.coverage_ratio,
            "reached_source": self.reached_source,
            "reached_sink": self.reached_sink,
            "divergence_point": self.divergence_point,
            "next_target": self.next_target,
            "execution_trace_length": len(self.execution_trace)
        }


class PathCoverageAnalyzer:
    """分析运行时 ICFG 与静态漏洞路径的覆盖情况"""

    def __init__(self, icfg_file: Path):
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
        self.edges: Dict[str, List[str]] = self._extract_edges()

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

        注意：ICFG 中的 execution_trace 在 ICFG 类中定义但没有导出到 JSON
        这里我们根据 execution_count 重建一个简化版本
        """
        # 按执行次数排序节点（简化方法）
        nodes = self.icfg_data.get("nodes", {})
        trace = []

        # 这是一个简化实现，实际可能需要更复杂的路径重建
        for addr, node_info in sorted(nodes.items(),
                                     key=lambda x: x[1].get("execution_count", 0),
                                     reverse=True):
            trace.append(addr)

        return trace

    def _extract_edges(self) -> Dict[str, List[str]]:
        """提取控制流边"""
        edges = {}
        nodes = self.icfg_data.get("nodes", {})

        for addr, node_info in nodes.items():
            successors = node_info.get("successors", [])
            edges[addr] = successors

        return edges

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
            addr: 地址（hex string，如 "0x18518"）

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
        normalized_source = self._normalize_address(vuln_path.source)
        normalized_sink = self._normalize_address(vuln_path.sink)

        # 检查哪些节点被覆盖
        covered_nodes = []
        missing_nodes = []

        for original_node, normalized_node in zip(vuln_path.path_nodes, normalized_path):
            if normalized_node in self.executed_nodes:
                covered_nodes.append(normalized_node)
            else:
                missing_nodes.append(normalized_node)

        # 计算覆盖率
        coverage_ratio = len(covered_nodes) / len(normalized_path) if normalized_path else 0.0

        # 检查源点和汇点（使用规范化后的地址）
        reached_source = normalized_source in self.executed_nodes
        reached_sink = normalized_sink in self.executed_nodes

        # 完整覆盖需要所有节点都被执行
        is_covered = len(missing_nodes) == 0

        # 找到分歧点和下一个目标（使用规范化后的路径）
        divergence_point, next_target = self._find_divergence_and_target_normalized(
            normalized_path, covered_nodes, missing_nodes
        )

        return CoverageResult(
            is_covered=is_covered,
            covered_nodes=covered_nodes,
            missing_nodes=missing_nodes,
            coverage_ratio=coverage_ratio,
            reached_source=reached_source,
            reached_sink=reached_sink,
            execution_trace=self.execution_trace,
            divergence_point=divergence_point,
            next_target=next_target
        )

    def _find_divergence_and_target_normalized(
        self,
        normalized_path: List[str],
        covered: List[str],
        missing: List[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        找到路径分歧点和下一个应该覆盖的目标（使用规范化后的路径）

        Args:
            normalized_path: 规范化后的漏洞路径（基本块起始地址）
            covered: 已覆盖的节点
            missing: 未覆盖的节点

        Returns:
            (divergence_point, next_target)
        """
        if not missing:
            return None, None

        # 找到最后一个被覆盖的节点
        last_covered_idx = -1
        for i, node in enumerate(normalized_path):
            if node in covered:
                last_covered_idx = i

        # 如果没有节点被覆盖，第一个节点就是目标
        if last_covered_idx == -1:
            return None, normalized_path[0] if normalized_path else None

        # 分歧点是最后一个被覆盖的节点
        divergence_point = normalized_path[last_covered_idx]

        # 下一个目标是紧接着的未覆盖节点
        if last_covered_idx + 1 < len(normalized_path):
            next_target = normalized_path[last_covered_idx + 1]
        else:
            next_target = None

        return divergence_point, next_target

    def check_path_connectivity(self, vuln_path: VulnPath) -> bool:
        """
        检查漏洞路径在运行时 ICFG 中是否连通

        即使所有节点都被执行了，也需要检查它们是否按照预期的顺序连接
        """
        if not vuln_path.path_nodes:
            return False

        # 检查路径中每对相邻节点是否有边连接
        for i in range(len(vuln_path.path_nodes) - 1):
            current = vuln_path.path_nodes[i]
            next_node = vuln_path.path_nodes[i + 1]

            # 检查 current 是否在 ICFG 中
            if current not in self.edges:
                return False

            # 检查 next_node 是否是 current 的后继
            if next_node not in self.edges.get(current, []):
                return False

        return True

    def get_statistics(self) -> dict:
        """获取 ICFG 统计信息"""
        return self.icfg_data.get("statistics", {})

    def export_analysis_report(
        self,
        vuln_path: VulnPath,
        coverage_result: CoverageResult,
        output_file: Path
    ):
        """导出分析报告"""
        report = {
            "vulnerability": {
                "type": vuln_path.vuln_type,
                "description": vuln_path.description,
                "source": vuln_path.source,
                "sink": vuln_path.sink,
                "path_length": len(vuln_path.path_nodes)
            },
            "coverage": coverage_result.to_dict(),
            "icfg_statistics": self.get_statistics(),
            "recommendation": self._generate_recommendation(coverage_result)
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

    def _generate_recommendation(self, result: CoverageResult) -> str:
        """生成调整建议"""
        if result.is_covered:
            return "路径已完全覆盖，漏洞验证成功！当前输入可作为 PoC payload。"

        if not result.reached_source:
            return f"未到达源点，需要调整输入使程序执行到 {result.next_target}"

        if result.reached_source and not result.reached_sink:
            if result.divergence_point:
                return (f"程序在 {result.divergence_point} 处发生路径分歧，"
                       f"需要调整输入使程序继续执行到 {result.next_target}")
            else:
                return f"需要调整输入以到达下一个目标节点 {result.next_target}"

        return "路径覆盖不完整，需要进一步分析。"


# 示例使用
if __name__ == "__main__":
    # 示例漏洞路径
    example_vuln = VulnPath(
        source="0x9a6c",
        sink="0x99d4",
        path_nodes=["0x9a6c", "0x99d4"],
        vuln_type="buffer_overflow",
        description="Buffer overflow in input parsing"
    )

    # 分析覆盖情况
    analyzer = PathCoverageAnalyzer(Path("test_icfg_method2.json"))
    result = analyzer.analyze_coverage(example_vuln)

    print("Coverage Analysis:")
    print(f"  Covered: {result.is_covered}")
    print(f"  Ratio: {result.coverage_ratio:.2%}")
    print(f"  Reached source: {result.reached_source}")
    print(f"  Reached sink: {result.reached_sink}")
    print(f"  Next target: {result.next_target}")
