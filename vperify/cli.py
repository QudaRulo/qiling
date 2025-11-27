"""
VPerify CLI - Command Line Interface for Vulnerability Verification

简单的命令行工具，用于运行漏洞验证
"""

import argparse
import json
import sys
from pathlib import Path

from .verification_engine import (
    VulnerabilityVerificationEngine,
    VerificationConfig
)
from .path_coverage_analyzer import VulnPath


def load_vuln_path_from_file(file_path: Path) -> VulnPath:
    """
    从 JSON 文件加载漏洞路径定义

    JSON 格式示例:
    {
        "source": "0x9a6c",
        "sink": "0x99d4",
        "path_nodes": ["0xa76c", "0x9a6c", "0x99d4"],
        "vuln_type": "buffer_overflow",
        "description": "Buffer overflow in HTTP parsing"
    }
    """
    with open(file_path, 'r') as f:
        data = json.load(f)

    return VulnPath(
        source=data["source"],
        sink=data["sink"],
        path_nodes=data.get("path_nodes", [data["source"], data["sink"]]),
        vuln_type=data["vuln_type"],
        description=data.get("description", "")
    )


def main():
    """主入口"""
    parser = argparse.ArgumentParser(
        description="VPerify - LLM-Driven Vulnerability Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 从文件加载漏洞路径并验证
  %(prog)s -t /path/to/binary -r /path/to/rootfs -v vuln_path.json

  # 指定输出目录和最大迭代次数
  %(prog)s -t ./httpd -r ./rootfs -v vuln.json -o ./output -m 30

  # 使用自定义 LLM API
  %(prog)s -t ./binary -r ./rootfs -v vuln.json \\
           --llm-base-url https://api.openai.com/v1 \\
           --llm-api-key sk-xxx
        """
    )

    # 必需参数
    parser.add_argument(
        "-t", "--target",
        type=Path,
        required=True,
        help="目标二进制文件路径"
    )

    parser.add_argument(
        "-r", "--rootfs",
        type=Path,
        required=True,
        help="根文件系统路径"
    )

    parser.add_argument(
        "-v", "--vuln-path",
        type=Path,
        required=True,
        help="漏洞路径定义文件 (JSON 格式)"
    )

    # 可选参数
    parser.add_argument(
        "-o", "--output-dir",
        type=Path,
        default=Path("./vperify_output"),
        help="输出目录 (默认: ./vperify_output)"
    )

    parser.add_argument(
        "-m", "--max-iterations",
        type=int,
        default=50,
        help="最大迭代次数 (默认: 50)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30000000,
        help="单次执行超时时间（微秒，默认: 30秒）"
    )

    parser.add_argument(
        "--save-all-icfgs",
        action="store_true",
        help="保存所有迭代的 ICFG 文件"
    )

    # LLM 配置
    parser.add_argument(
        "--llm-model",
        type=str,
        default="gpt-4",
        help="LLM 模型名称 (默认: gpt-4)"
    )

    parser.add_argument(
        "--llm-temperature",
        type=float,
        default=0.7,
        help="LLM 温度参数 (默认: 0.7)"
    )

    parser.add_argument(
        "--llm-base-url",
        type=str,
        help="LLM API 基础 URL"
    )

    parser.add_argument(
        "--llm-api-key",
        type=str,
        help="LLM API 密钥"
    )

    args = parser.parse_args()

    # 验证输入
    if not args.target.exists():
        print(f"错误: 目标二进制不存在: {args.target}", file=sys.stderr)
        sys.exit(1)

    if not args.rootfs.exists():
        print(f"错误: rootfs 不存在: {args.rootfs}", file=sys.stderr)
        sys.exit(1)

    if not args.vuln_path.exists():
        print(f"错误: 漏洞路径文件不存在: {args.vuln_path}", file=sys.stderr)
        sys.exit(1)

    # 加载漏洞路径
    try:
        vuln_path = load_vuln_path_from_file(args.vuln_path)
    except Exception as e:
        print(f"错误: 无法加载漏洞路径文件: {e}", file=sys.stderr)
        sys.exit(1)

    # 创建配置
    config = VerificationConfig(
        target_binary=args.target,
        rootfs=args.rootfs,
        max_iterations=args.max_iterations,
        timeout=args.timeout,
        output_dir=args.output_dir,
        save_all_icfgs=args.save_all_icfgs,
        llm_model=args.llm_model,
        llm_temperature=args.llm_temperature,
        llm_base_url=args.llm_base_url,
        llm_api_key=args.llm_api_key
    )

    # 创建验证引擎
    try:
        engine = VulnerabilityVerificationEngine(config)
    except Exception as e:
        print(f"错误: 初始化验证引擎失败: {e}", file=sys.stderr)
        sys.exit(1)

    # 执行验证
    try:
        result = engine.verify(vuln_path)

        # 导出报告
        report_file = config.output_dir / "final_report.json"
        engine.export_final_report(result, report_file)

        # 打印结果
        print(f"\n{'='*70}")
        print("验证完成！")
        print(f"{'='*70}")
        print(f"结果: {'✓ 成功' if result.success else '✗ 失败'}")
        print(f"迭代次数: {result.iterations}")
        print(f"最终覆盖率: {result.final_coverage:.2%}")

        if result.poc_command:
            print(f"\n{'='*70}")
            print("PoC 复现命令:")
            print(f"{'='*70}")
            print(result.poc_command)
            print()

        print(f"详细报告: {report_file}")
        print(f"输出目录: {config.output_dir}")

        sys.exit(0 if result.success else 1)

    except KeyboardInterrupt:
        print("\n\n验证被用户中断", file=sys.stderr)
        sys.exit(130)

    except Exception as e:
        print(f"\n错误: 验证过程中发生异常: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
