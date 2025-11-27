# VPerify - LLM-Driven Vulnerability Verification

VPerify 是一个创新的漏洞验证工具，结合了：
- **动态分析**: Qiling 框架进行二进制模拟
- **路径覆盖分析**: ICFG (Inter-procedural Control Flow Graph) 分析
- **AI 驱动**: LLM 智能生成和调整测试输入

## 核心思路

1. **静态分析输入**: 从静态分析工具获取漏洞路径 (source → sink)
2. **动态验证**: 使用 Qiling 模拟执行，生成运行时 ICFG
3. **路径匹配**: 分析运行时 ICFG 是否覆盖了完整的漏洞路径
4. **智能调整**: 使用 LLM 根据覆盖反馈生成和调整测试输入（seed）
5. **PoC 生成**: 成功覆盖漏洞路径后，生成 PoC

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                    VPerify 架构                               │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐         ┌──────────────┐                  │
│  │ 静态分析工具  │ ───────→│  漏洞路径    │                  │
│  │ (外部)       │         │  定义文件    │                  │
│  └──────────────┘         └──────────────┘                  │
│                                  │                           │
│                                  ▼                           │
│  ┌─────────────────────────────────────────────────┐        │
│  │          Verification Engine                     │        │
│  │  ┌────────────────┐    ┌───────────────────┐   │        │
│  │  │  Seed          │◄───│  LLM Seed        │   │        │
│  │  │  Generator     │    │  Generator       │   │        │
│  │  └────────────────┘    └───────────────────┘   │        │
│  │          │                                       │        │
│  │          ▼                                       │        │
│  │  ┌────────────────┐                             │        │
│  │  │  Qiling        │                             │        │
│  │  │  Emulator      │                             │        │
│  │  └────────────────┘                             │        │
│  │          │                                       │        │
│  │          ▼                                       │        │
│  │  ┌────────────────┐    ┌───────────────────┐   │        │
│  │  │  Runtime ICFG  │───→│  Path Coverage   │   │        │
│  │  │  Generator     │    │  Analyzer        │   │        │
│  │  └────────────────┘    └───────────────────┘   │        │
│  │                                  │               │        │
│  │                                  ▼               │        │
│  │                         ┌──────────────┐        │        │
│  │                         │  Coverage    │        │        │
│  │                         │  Feedback    │        │        │
│  │                         └──────────────┘        │        │
│  └─────────────────────────────────────────────────┘        │
│                                  │                           │
│                                  ▼                           │
│  ┌─────────────────────────────────────────────────┐        │
│  │                   PoC & Report                   │        │
│  └─────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

## 模块说明

### 1. `path_coverage_analyzer.py`
路径覆盖分析器，负责：
- 加载运行时 ICFG
- 分析漏洞路径的覆盖情况
- 计算覆盖率、找到分歧点
- 给出下一步调整建议

### 2. `seed_generator.py`
LLM 驱动的种子生成器，负责：
- 生成初始测试输入（seed）
- 根据覆盖反馈智能变异 seed
- 分析多次执行历史，给出策略建议

### 3. `verification_engine.py`
验证引擎（核心），负责：
- 整合所有模块
- 迭代执行 "生成 seed → 运行 → 分析 → 调整" 循环
- 判断验证成功/失败
- 生成 PoC 和报告

### 4. `runtime_icfg_tool.py`
运行时 ICFG 生成工具，封装 Qiling 调用

### 5. `cli.py`
命令行接口

## 安装依赖

```bash
# 确保已安装 qiling 及相关依赖
uv sync --extra vperify
```

## 使用方法

### 1. 准备漏洞路径定义文件

创建 JSON 文件定义漏洞路径：

```json
{
  "source": "0x9a6c",
  "sink": "0x99d4",
  "path_nodes": ["0xa76c", "0x9a6c", "0x99d4"],
  "vuln_type": "buffer_overflow",
  "description": "Buffer overflow in HTTP request parsing"
}
```

### 2. 运行验证

```bash
python -m vperify.cli \
  --target /path/to/binary \
  --rootfs /path/to/rootfs \
  --vuln-path vuln_path.json \
  --output-dir ./output \
  --max-iterations 30
```

### 3. 查看结果

验证完成后，在输出目录中会生成：
- `final_report.json`: 完整的验证报告
- `poc.json`: PoC 信息（如果验证成功）
- `current_icfg.json`: 最新的运行时 ICFG
- `seed_history.json`: 种子生成历史

## 示例

```bash
# 验证 httpd 的 buffer overflow 漏洞
python -m vperify.cli \
  -t /mnt/d/downloads/web_downloads/CC8160-VVTK_output/usr/sbin/httpd \
  -r /mnt/d/downloads/web_downloads/CC8160-VVTK_output \
  -v example_vuln_path.json \
  -o ./vperify_output \
  -m 20
```

## API 使用

也可以在 Python 代码中直接使用：

```python
from pathlib import Path
from vperify.verification_engine import (
    VulnerabilityVerificationEngine,
    VerificationConfig
)
from vperify.path_coverage_analyzer import VulnPath

# 配置
config = VerificationConfig(
    target_binary=Path("/path/to/binary"),
    rootfs=Path("/path/to/rootfs"),
    max_iterations=30,
    output_dir=Path("./output")
)

# 漏洞路径
vuln_path = VulnPath(
    source="0x9a6c",
    sink="0x99d4",
    path_nodes=["0xa76c", "0x9a6c", "0x99d4"],
    vuln_type="buffer_overflow",
    description="Buffer overflow"
)

# 执行验证
engine = VulnerabilityVerificationEngine(config)
result = engine.verify(vuln_path)

# 导出报告
engine.export_final_report(result, Path("./report.json"))
```

## 优势

相比传统 Fuzzing：
- ✅ **目标明确**: 直接针对静态分析发现的漏洞路径
- ✅ **智能生成**: LLM 理解漏洞类型，生成更有针对性的输入
- ✅ **快速反馈**: 实时覆盖分析，及时调整策略
- ✅ **可解释性**: 清晰的迭代过程和调整理由

相比传统符号执行：
- ✅ **可扩展性**: 不受路径爆炸限制
- ✅ **实际执行**: 真实环境中运行，避免误报
- ✅ **灵活性**: 可以处理复杂的二进制程序

## 未来改进方向

1. **多路径验证**: 同时验证多个漏洞路径
2. **分布式执行**: 并行化多个种子的测试
3. **增量覆盖**: 利用之前的覆盖信息加速验证
4. **混合策略**: 结合传统变异和 LLM 生成
5. **交互式调试**: 实时查看执行状态，手动调整


特性	传统 Fuzzing	符号执行	VPerify (LLM 驱动)
目标明确性	❌ 盲目探索	✅ 路径约束	✅ 直接针对漏洞路径
输入质量	⚠️ 随机/变异	✅ 约束求解	✅ 智能理解
可扩展性	✅ 好	❌ 路径爆炸	✅ 好
可解释性	❌ 弱	⚠️ 中等	✅ 强（LLM 分析）
速度	⚠️ 慢（盲目）	❌ 慢（复杂计算）	✅ 快（有针对性

## 许可证

与 Qiling 框架保持一致 (GPLv2)
