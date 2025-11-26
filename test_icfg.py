#!/usr/bin/env python3
"""
Test script for ICFG coverage plugin.
Demonstrates all usage methods.
"""

from qiling import Qiling
from qiling.extensions.coverage import utils as cov_utils

# Test binary
binary = '/mnt/d/downloads/web_downloads/CC8160-VVTK_output/usr/sbin/httpd'
rootfs = '/mnt/d/downloads/web_downloads/CC8160-VVTK_output'

print("=" * 70)
print("ICFG Coverage Plugin Test")
print("=" * 70)

# Method 1: Using context manager (recommended)
print("\n[Method 1] Using context manager:")
ql = Qiling([binary], rootfs, verbose=0)

with cov_utils.collect_coverage(ql, 'icfg', 'test_icfg_method1.json'):
    try:
        ql.run(timeout=1000)
    except:
        pass

print("  ✓ Generated: test_icfg_method1.json")

# Method 2: Manual control
print("\n[Method 2] Manual control:")
ql = Qiling([binary], rootfs, verbose=0)
cov = cov_utils.factory.get_coverage_collector(ql, 'icfg')

cov.activate()
try:
    ql.run(timeout=1000)
except:
    pass
cov.deactivate()

# Get statistics
stats = cov.get_statistics()
total_edges = (stats['total_internal_edges'] +
              stats['total_lib_call_edges'] +
              stats['total_lib_return_edges'] +
              stats['total_lib_to_lib_edges'])
print(f"  Statistics:")
print(f"    Unique blocks: {stats['total_unique_blocks']}")
print(f"    Total executions: {stats['total_executions']}")
print(f"    Edges: {total_edges} ({stats['total_internal_edges']} internal, {stats['total_lib_call_edges']} lib_call, {stats['total_lib_return_edges']} lib_return, {stats['total_lib_to_lib_edges']} lib_to_lib)")
print(f"    Tracking: {stats['tracking_mode']}")

# Export to both formats
cov.dump_coverage('test_icfg_method2.json')
print("  ✓ Generated: test_icfg_method2.json")

# Export to DOT
with open('test_icfg_method2.dot', 'w') as f:
    f.write(cov.to_dot())
print("  ✓ Generated: test_icfg_method2.dot")

print("\n" + "=" * 70)
print("Test completed successfully!")
print("=" * 70)
print("\nGenerated files:")
print("  - test_icfg_method1.json")
print("  - test_icfg_method2.json")
print("  - test_icfg_method2.dot")
print("\nTo visualize the DOT file:")
print("  dot -Tpng test_icfg_method2.dot -o icfg.png")
print("  # or")
print("  xdot test_icfg_method2.dot")
