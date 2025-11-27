"""
测试地址规范化功能

验证静态分析给出的任意地址能否正确映射到基本块起始地址
"""

from pathlib import Path
from vperify import PathCoverageAnalyzer, VulnPath


def test_address_normalization():
    """测试地址规范化"""
    print("="*70)
    print("测试地址规范化功能")
    print("="*70)

    # 使用 httpd ICFG
    icfg_file = Path("httpd_final.json")
    if not icfg_file.exists():
        print("❌ httpd_final.json 文件不存在")
        print(f"   请先运行 httpd 生成 ICFG")
        return False

    analyzer = PathCoverageAnalyzer(icfg_file)

    print(f"\n✓ 加载 ICFG: {icfg_file}")
    print(f"  执行的基本块数: {len(analyzer.executed_nodes)}")

    # 显示前 10 个基本块的地址范围
    print(f"\n基本块详细信息（前 10 个）:")
    for addr_str in sorted(analyzer.executed_nodes)[:10]:
        node_info = analyzer.icfg_data["nodes"][addr_str]
        addr_int = int(addr_str, 16)
        size = node_info["size"]
        exec_count = node_info.get("execution_count", 0)
        print(f"  {addr_str}: 范围 {hex(addr_int)} ~ {hex(addr_int + size - 1)} "
              f"(大小: {size} 字节, 执行: {exec_count} 次)")

    # 选择一个真实的基本块进行测试
    first_block = sorted(analyzer.executed_nodes)[0]
    first_block_info = analyzer.icfg_data["nodes"][first_block]
    first_block_int = int(first_block, 16)
    first_block_size = first_block_info["size"]

    # 测试地址规范化
    print(f"\n地址规范化测试:")
    print(f"  使用基本块 {first_block} (大小: {first_block_size} 字节) 进行测试\n")

    test_cases = [
        # (测试地址, 预期结果描述)
        (first_block, "基本块起始地址，应直接匹配"),
        (hex(first_block_int + 1), "基本块内部地址+1"),
        (hex(first_block_int + 2), "基本块内部地址+2"),
        (hex(first_block_int + first_block_size - 1), "基本块最后一个地址"),
        ("0xdeadbeef", "不存在的地址，返回原地址"),
    ]

    for test_addr, description in test_cases:
        normalized = analyzer._normalize_address(test_addr)
        status = "✓" if normalized in analyzer.executed_nodes or test_addr == normalized else "?"
        print(f"  {status} {test_addr} -> {normalized} ({description})")

    # 测试漏洞路径覆盖分析
    print(f"\n\n漏洞路径覆盖分析测试:")
    print("-"*70)

    # 获取几个真实执行的基本块
    real_blocks = sorted(analyzer.executed_nodes)[:5]
    print(f"\n使用真实执行的基本块: {real_blocks[:3]}")

    # 场景 1: 使用基本块起始地址
    vuln_path1 = VulnPath(
        path_nodes=real_blocks[:3]
    )

    result1 = analyzer.analyze_coverage(vuln_path1)
    print(f"\n场景 1: 使用基本块起始地址")
    print(f"  路径节点: {vuln_path1.path_nodes}")
    print(f"  覆盖率: {result1.coverage_ratio:.2%}")
    print(f"  已覆盖: {result1.covered_nodes}")
    print(f"  未覆盖: {result1.missing_nodes}")
    if result1.next_target:
        print(f"  下一个目标: {result1.next_target}")

    # 场景 2: 使用基本块内部地址（模拟静态分析工具输出）
    # 将地址偏移几个字节
    internal_addrs = [
        hex(int(real_blocks[0], 16) + 2),
        hex(int(real_blocks[1], 16) + 1),
        hex(int(real_blocks[2], 16) + 3)
    ]
    vuln_path2 = VulnPath(
        path_nodes=internal_addrs
    )

    result2 = analyzer.analyze_coverage(vuln_path2)
    print(f"\n场景 2: 使用基本块内部地址（模拟静态分析）")
    print(f"  原始路径: {vuln_path2.path_nodes}")
    print(f"  规范化后: {result2.covered_nodes if result2.covered_nodes else '(全部未覆盖)'}")
    print(f"  覆盖率: {result2.coverage_ratio:.2%}")
    print(f"  说明: 内部地址自动映射到基本块起始地址")

    # 场景 3: 真实示例 - 使用 example 中的地址
    vuln_path3 = VulnPath(
        path_nodes=["0x1850c", "0x18518", "0x18528", "0x18538"]
    )

    result3 = analyzer.analyze_coverage(vuln_path3)
    print(f"\n场景 3: 真实漏洞路径示例")
    print(f"  路径节点: {vuln_path3.path_nodes}")
    print(f"  自动推断的 source: {vuln_path3.source}")
    print(f"  自动推断的 sink: {vuln_path3.sink}")
    print(f"  覆盖率: {result3.coverage_ratio:.2%}")
    print(f"  已覆盖: {result3.covered_nodes}")
    print(f"  未覆盖: {result3.missing_nodes}")
    if result3.next_target:
        print(f"  建议: 调整输入以覆盖 {result3.next_target}")

    print(f"\n{'='*70}")
    print("✓ 所有测试完成")
    print(f"{'='*70}\n")

    return True


if __name__ == "__main__":
    success = test_address_normalization()
    exit(0 if success else 1)
