#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
ICFG (Inter-procedural Control Flow Graph) coverage format.

This module provides a coverage collector that builds a control flow graph
from executed basic blocks. It only tracks the main binary by default,
filtering out shared libraries to avoid getting lost in library call chains.

Usage with qltool:
    ./qltool run -f binary --rootfs / --coverage-file output.json --coverage-format icfg
    ./qltool run -f binary --rootfs / --coverage-file output.dot --coverage-format icfg

The output format is determined by file extension:
    - .dot: GraphViz DOT format for visualization
    - .json or other: JSON format for programmatic analysis
"""

import json
from os.path import basename
from typing import Dict, List, Optional, Set, Tuple
from bisect import bisect_right

from .base import QlBaseCoverage


class ICFGNode:
    """
    Represents a basic block node in the ICFG.

    Attributes:
    - address: The starting address of the basic block.
    - size: The size of the basic block in bytes.
    - successors: A set of addresses representing the successors (control flow targets).
    - execution_count: The number of times this basic block has been executed.
    """

    def __init__(self, address: int, size: int):
        self.address = address
        self.size = size
        self.successors: Set[int] = set()
        self.execution_count = 0

    def add_successor(self, target_address: int):
        """Add an edge to a successor block (defines control flow)."""
        self.successors.add(target_address)

    def to_dict(self) -> dict:
        """Convert node to dictionary for export."""
        return {
            'address': hex(self.address),
            'size': self.size,
            'execution_count': self.execution_count,
            'successors': [hex(addr) for addr in sorted(self.successors)]
        }


class ICFG:
    """
    Inter-procedural Control Flow Graph.

    Represents the control flow graph of a program with three types of edges:

    1. Internal edges (Node -> Node):
       - Defined by ICFGNode.successors
       - Control flow within the main binary
       - Direction: current -> successor (single direction)
       - Loops are naturally formed by circular paths

    2. Library call edges (Node -> Library):
       - Main binary calls into a shared library
       - Edge: main_block -> library_name

    3. Library return edges (Library -> Node):
       - Library returns to main binary
       - Edge: library_name -> main_block

    4. Library-to-library edges (Library -> Library):
       - One library calls another library
       - Edge: lib1 -> lib2

    Example flow:
        lib1.so -- lib_returns --> ICFG(main) -- lib_calls --> lib2.so -- lib_to_lib --> lib3.so
    """

    def __init__(self, main_image_path: Optional[str] = None):
        self.nodes: Dict[int, ICFGNode] = {}
        self.execution_trace: List[int] = []

        # Library interaction edges
        self.lib_calls: Dict[int, Set[str]] = {}  # node_addr -> {lib_names}
        self.lib_returns: Dict[str, Set[int]] = {}  # lib_name -> {node_addrs}
        self.lib_to_lib: Dict[str, Set[str]] = {}  # lib_name -> {lib_names}

        self.main_image_path = main_image_path

    def add_node(self, address: int, size: int) -> ICFGNode:
        """Add a node to the ICFG or return existing node."""
        if address not in self.nodes:
            self.nodes[address] = ICFGNode(address, size)
        return self.nodes[address]

    def add_edge(self, from_addr: int, to_addr: int):
        """Add an internal control flow edge."""
        if from_addr in self.nodes and to_addr in self.nodes:
            self.nodes[from_addr].add_successor(to_addr)

    def add_lib_call(self, from_addr: int, lib_name: str):
        """Record that a node calls into a library."""
        if from_addr not in self.lib_calls:
            self.lib_calls[from_addr] = set()
        self.lib_calls[from_addr].add(lib_name)

    def add_lib_return(self, lib_name: str, to_addr: int):
        """Record that a library returns to a node."""
        if lib_name not in self.lib_returns:
            self.lib_returns[lib_name] = set()
        self.lib_returns[lib_name].add(to_addr)

    def add_lib_to_lib(self, from_lib: str, to_lib: str):
        """Record that one library calls another."""
        if from_lib not in self.lib_to_lib:
            self.lib_to_lib[from_lib] = set()
        self.lib_to_lib[from_lib].add(to_lib)

    def record_execution(self, address: int):
        """Record that a basic block was executed."""
        if address in self.nodes:
            self.nodes[address].execution_count += 1
            self.execution_trace.append(address)

    def get_statistics(self) -> dict:
        """Get ICFG statistics."""
        total_edges = sum(len(node.successors) for node in self.nodes.values())
        total_lib_calls = sum(len(libs) for libs in self.lib_calls.values())
        total_lib_returns = sum(len(addrs) for addrs in self.lib_returns.values())
        total_lib_to_lib = sum(len(libs) for libs in self.lib_to_lib.values())

        return {
            'total_unique_blocks': len(self.nodes),
            'total_executions': len(self.execution_trace),
            'total_internal_edges': total_edges,
            'total_lib_call_edges': total_lib_calls,
            'total_lib_return_edges': total_lib_returns,
            'total_lib_to_lib_edges': total_lib_to_lib,
            'main_binary': self.main_image_path or 'N/A'
        }

    def to_dict(self) -> dict:
        """Export ICFG to dictionary format."""
        return {
            'statistics': self.get_statistics(),
            'nodes': {hex(addr): node.to_dict() for addr, node in sorted(self.nodes.items())},
            'lib_calls': {hex(addr): sorted(list(libs)) for addr, libs in sorted(self.lib_calls.items())},
            'lib_returns': {lib: [hex(addr) for addr in sorted(addrs)] for lib, addrs in sorted(self.lib_returns.items())},
            'lib_to_lib': {lib: sorted(list(libs)) for lib, libs in sorted(self.lib_to_lib.items())}
        }


class QlICFGCoverage(QlBaseCoverage):
    """
    Qiling coverage collector that builds an ICFG during emulation.

    This collector hooks basic block execution and builds an ICFG object
    representing the control flow graph of the main binary and its interactions
    with shared libraries.

    Output formats:
    - JSON: Structured data with statistics and node details
    - DOT: GraphViz format for visualization (use .dot extension)
    """

    FORMAT_NAME = "icfg"

    def __init__(self, ql, track_main_only: bool = True):
        super().__init__(ql)

        self.track_main_only = track_main_only
        self.prev_block: Optional[int] = None
        self.prev_block_addr: Optional[int] = None  # Track last main block before library
        self.last_library: Optional[str] = None  # Track which library we were in
        self.bb_callback = None

        # Get main binary address range for filtering
        if track_main_only and ql.loader.images:
            self.main_image = ql.loader.images[0]
            main_path = self.main_image.path
        else:
            self.main_image = None
            main_path = None

        # Create the ICFG object
        self.icfg = ICFG(main_image_path=main_path)

        # Build sorted address ranges for O(log n) lookup
        # Format: List of (start_addr, end_addr, library_name)
        self._addr_ranges: List[Tuple[int, int, Optional[str]]] = []
        self._addr_cache: Dict[int, Optional[str]] = {}  # Cache for O(1) repeated lookups
        self._build_address_ranges()

    def _build_address_ranges(self):
        """
        Build sorted list of address ranges for efficient lookup.
        This is called once during initialization and whenever memory mappings change.
        Time complexity: O(n log n) for building, O(log n) for each lookup.
        """
        ranges = []

        # Add loader.images (statically loaded: main binary + interpreter)
        for img in self.ql.loader.images:
            if img == self.main_image:
                ranges.append((img.base, img.end, None))  # Main binary
            else:
                ranges.append((img.base, img.end, basename(img.path)))

        # Add memory mappings (dynamically loaded: shared libraries via mmap)
        for begin, end, _, label, _ in self.ql.mem.map_info:
            if label.startswith('[mmap]'):
                lib_name = label.replace('[mmap]', '').strip()
                # Filter out non-library mappings (only keep .so files)
                if lib_name and '.so' in lib_name:
                    ranges.append((begin, end, lib_name))

        # Sort by start address for binary search
        self._addr_ranges = sorted(ranges, key=lambda x: x[0])

    def _refresh_address_ranges(self):
        """
        Refresh address ranges and clear cache.
        Call this if memory mappings change during execution (e.g., dlopen).
        """
        self._addr_ranges.clear()
        self._addr_cache.clear()
        self._build_address_ranges()

    def is_in_main_binary(self, address: int) -> bool:
        """Check if address is within the main binary's address range."""
        if not self.track_main_only or self.main_image is None:
            return True
        return self.main_image.base <= address < self.main_image.end

    def get_library_name(self, address: int) -> Optional[str]:
        """
        Get the library name for an address, or None if in main binary.

        Time complexity:
        - O(1) for cached addresses (repeated lookups)
        - O(log n) for first-time lookups (binary search)
        - Falls back to O(n) live search if not found in pre-built ranges

        Returns:
        - None: Address is in main binary
        - str: Library name
        - "UNKNOWN": Address not found in any known range
        """
        # Check cache first for O(1) lookup
        if address in self._addr_cache:
            return self._addr_cache[address]

        # Binary search for the range containing this address
        # Find the rightmost range whose start <= address
        idx = bisect_right(self._addr_ranges, address, key=lambda x: x[0]) - 1

        if idx >= 0:
            start, end, lib_name = self._addr_ranges[idx]
            if start <= address < end:
                # Cache the result
                self._addr_cache[address] = lib_name
                return lib_name

        # Not found in pre-built ranges, search live memory mappings
        # This handles dynamically loaded libraries (dlopen/mmap during runtime)
        result = self._search_live_mappings(address)
        self._addr_cache[address] = result
        return result

    def _search_live_mappings(self, address: int) -> Optional[str]:
        """
        Search for address in live memory mappings.
        This is called when address is not found in pre-built ranges,
        typically for dynamically loaded libraries.
        """
        # Check loader.images first (statically loaded)
        for img in self.ql.loader.images:
            if img.base <= address < img.end:
                if img == self.main_image:
                    return None
                return basename(img.path)

        # Check memory mappings (dynamically loaded via mmap)
        for begin, end, _, label, _ in self.ql.mem.map_info:
            if begin <= address < end:
                if label.startswith('[mmap]'):
                    lib_name = label.replace('[mmap]', '').strip()
                    # Filter out non-library mappings (only keep .so files)
                    if lib_name and '.so' in lib_name:
                        return lib_name

        return "UNKNOWN"

    @staticmethod
    def block_callback(ql, address, size, self):
        """Hook callback for each basic block execution."""
        in_main = self.is_in_main_binary(address)
        current_lib = None if in_main else self.get_library_name(address)

        if not in_main:
            # We're in a library
            # Check if we're transitioning from another library to this library
            if self.last_library and self.last_library != current_lib and current_lib:
                # Library-to-library call detected
                self.icfg.add_lib_to_lib(self.last_library, current_lib)

            # If we just left main binary, record the library call
            if self.prev_block is not None and current_lib:
                self.icfg.add_lib_call(self.prev_block, current_lib)
                self.prev_block_addr = self.prev_block  # Remember this for return edge
                self.prev_block = None

            # Update last library
            self.last_library = current_lib
            return

        # We're in main binary
        # Add or update node and record execution
        self.icfg.add_node(address, size)
        self.icfg.record_execution(address)

        # Add edge from previous block to current block
        if self.prev_block is not None:
            # Normal edge between main binary blocks
            self.icfg.add_edge(self.prev_block, address)
        elif self.prev_block_addr is not None and self.last_library is not None:
            # We're returning from a library call
            # Record that this block is returned to from the library
            self.icfg.add_lib_return(self.last_library, address)

        # Update tracking
        self.prev_block = address
        self.prev_block_addr = None  # Clear return tracking
        self.last_library = None  # Clear library tracking

    def activate(self):
        """Start collecting ICFG coverage."""
        self.bb_callback = self.ql.hook_block(self.block_callback, user_data=self)

        if self.main_image:
            self.ql.log.info(f'ICFG: Tracking main binary: {basename(self.main_image.path)}')
            self.ql.log.info(f'ICFG: Address range: {self.main_image.base:#x} - {self.main_image.end:#x}')

    def deactivate(self):
        """Stop collecting ICFG coverage."""
        if self.bb_callback:
            self.ql.hook_del(self.bb_callback)
            self.bb_callback = None

    def get_statistics(self) -> dict:
        """Get ICFG statistics."""
        stats = self.icfg.get_statistics()
        stats['tracking_mode'] = 'main binary only' if self.track_main_only else 'all modules'
        return stats

    def to_dict(self) -> dict:
        """Export ICFG to dictionary format."""
        return self.icfg.to_dict()

    def to_dot(self) -> str:
        """Export ICFG to GraphViz DOT format."""
        lines = ['digraph ICFG {']
        lines.append('  node [shape=box];')

        if self.main_image:
            lines.append(f'  label="ICFG for {basename(self.main_image.path)}";')
            lines.append('  labelloc="t";')

        # Collect libraries that actually have edges (calls or returns)
        used_libraries = set()

        # Get all lib names from lib_calls (node -> {lib_names})
        for libs in self.icfg.lib_calls.values():
            used_libraries.update(libs)

        # Get all lib names from lib_returns (lib_name -> {node_addrs})
        used_libraries.update(self.icfg.lib_returns.keys())

        # Get all lib names from lib_to_lib (lib_name -> {lib_names})
        used_libraries.update(self.icfg.lib_to_lib.keys())
        for libs in self.icfg.lib_to_lib.values():
            used_libraries.update(libs)

        # Add library nodes (only those actually used in this run)
        for lib_name in sorted(used_libraries):
            safe_name = lib_name.replace('.', '_').replace('-', '_')
            lines.append(f'  "LIB_{safe_name}" [label="{lib_name}", shape=ellipse, style=filled, fillcolor=lightyellow];')

        # Add main binary nodes with execution counts (colored by frequency)
        for addr, node in sorted(self.icfg.nodes.items()):
            label = f'{hex(addr)}\\nsize: {node.size}\\nexec: {node.execution_count}'
            if node.execution_count > 100:
                color = 'red'
            elif node.execution_count > 10:
                color = 'orange'
            else:
                color = 'lightblue'
            lines.append(f'  "{hex(addr)}" [label="{label}", style=filled, fillcolor={color}];')

        # Add edges between main binary blocks
        for addr, node in sorted(self.icfg.nodes.items()):
            for succ in sorted(node.successors):
                lines.append(f'  "{hex(addr)}" -> "{hex(succ)}";')

        # Add edges to library calls (dashed gray lines)
        for addr, libs in sorted(self.icfg.lib_calls.items()):
            for lib in sorted(libs):
                safe_name = lib.replace('.', '_').replace('-', '_')
                lines.append(f'  "{hex(addr)}" -> "LIB_{safe_name}" [style=dashed, color=gray];')

        # Add edges from library returns (dashed blue lines)
        for lib, addrs in sorted(self.icfg.lib_returns.items()):
            safe_name = lib.replace('.', '_').replace('-', '_')
            for addr in sorted(addrs):
                lines.append(f'  "LIB_{safe_name}" -> "{hex(addr)}" [style=dashed, color=blue];')

        # Add library-to-library call edges (dashed green lines)
        for src_lib, tgt_libs in sorted(self.icfg.lib_to_lib.items()):
            src_safe = src_lib.replace('.', '_').replace('-', '_')
            for tgt_lib in sorted(tgt_libs):
                tgt_safe = tgt_lib.replace('.', '_').replace('-', '_')
                lines.append(f'  "LIB_{src_safe}" -> "LIB_{tgt_safe}" [style=dashed, color=green];')

        lines.append('}')
        return '\n'.join(lines)

    def dump_coverage(self, coverage_file: str):
        """Export ICFG to files.

        Automatically generates both JSON and DOT files:
        - If coverage_file ends with .json: generates both .json and .dot
        - If coverage_file ends with .dot: generates both .dot and .json
        - Otherwise: generates .json and .dot with the base name
        """
        import os

        stats = self.get_statistics()
        total_edges = (stats["total_internal_edges"] +
                      stats["total_lib_call_edges"] +
                      stats["total_lib_return_edges"] +
                      stats["total_lib_to_lib_edges"])
        self.ql.log.info(f'ICFG: {stats["total_unique_blocks"]} unique blocks, '
                        f'{stats["total_executions"]} executions, '
                        f'{total_edges} edges '
                        f'({stats["total_internal_edges"]} internal, '
                        f'{stats["total_lib_call_edges"]} lib_call, '
                        f'{stats["total_lib_return_edges"]} lib_return, '
                        f'{stats["total_lib_to_lib_edges"]} lib_to_lib)')

        # Determine base filename without extension
        if coverage_file.endswith('.json'):
            base_file = coverage_file[:-5]
            json_file = coverage_file
            dot_file = base_file + '.dot'
        elif coverage_file.endswith('.dot'):
            base_file = coverage_file[:-4]
            json_file = base_file + '.json'
            dot_file = coverage_file
        else:
            base_file = coverage_file
            json_file = base_file + '.json'
            dot_file = base_file + '.dot'

        # Export JSON format
        with open(json_file, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        self.ql.log.info(f'ICFG: Exported JSON format to {json_file}')

        # Export DOT format
        with open(dot_file, 'w') as f:
            f.write(self.to_dot())
        self.ql.log.info(f'ICFG: Exported DOT format to {dot_file}')
