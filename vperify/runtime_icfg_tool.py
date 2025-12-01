# -*- coding: utf-8 -*-

import io
from os import PathLike
from pathlib import Path
from typing import Any, AnyStr, MutableMapping, Optional, Sequence
from qiling import Qiling
from qiling.extensions.coverage import utils as cov_utils


def gen_runtime_icfg(
    argv: Sequence[str],
    output_file: PathLike,
    timeout: Optional[int] = None,
    rootfs: str = r'.',
    env: MutableMapping[AnyStr, AnyStr] = {},
    code: Optional[bytes] = None,
    stdin_data: Optional[bytes] = None,
    **kwargs: Any
) -> tuple[bool, str]:
    """ generate the run time icfg based on qiling. The docstring is sumarized from qiling.

    Args: 
        argv (Sequence[str], optional): pass to Qiling
            Emulated program arguments.
            Note that `code` and `argv` are mutually exclusive.

            Example:
                >>> ql = Qiling([r'myrootfs/path/to/target.bin', 'arg1'], 'myrootfs')
                >>> ql.argv
                ['myrootfs/path/to/target.bin', 'arg1']
        
        output_file (str, optional): 
            when runtime icfg is completed, both of json and dot file will be generated.
            Generally use json file. 
            Example:
                >>> argv = [r'myrootfs/path/to/target.bin', 'arg1'], output_file = 'myrootfs/path/to/target.bin_icfg.json'
        
        timeout (int, optional):
            some binary will on hold, you can set a timeout to stop the binary.(microseconds)
            if not set, default to 30s.
        
        rootfs (str, optional): pass to Qiling
            Path to emulated system root directory, to which the emulated program will be 
            confined to. some libraries may be loaded from the rootfs.
        
        env (MutableMapping[AnyStr, AnyStr], optional):
            The program environment variables.

            Example: {"LC_ALL" : "en_US.UTF-8"}

        code (Optional[bytes], optional):
            The shellcode that was set for execution, or `None` if not set.
            Note that `code` and `argv` are mutually exclusive.

            Example:
                >>> EXIT_SYSCALL = bytes.fromhex(
                    '''31 c0 '''  # xor  eax, eax
                    '''40    '''  # inc  eax
                    '''cd 80 '''  # int  0x80
                )
                >>> ql = Qiling(code=EXIT_SYSCALL, ostype=QL_OS.LINUX, archtype=QL_ARCH.X86)
                >>> ql.code
                b'1\\xc0@\\xcd\\x80'

        stdin_data (Optional[bytes], optional):
            Data to provide as stdin to the emulated program.
            If provided, this data will be available for the program to read from stdin.

            Example:
                >>> stdin_data = b"username=admin&password=secret\\n"
                >>> gen_runtime_icfg(['/path/to/cgi'], 'output.json', stdin_data=stdin_data)
    

    Returns:
        tuple[bool, str]: (success, captured_output)
            - success: True if ICFG was generated successfully
            - captured_output: Combined stdout/stderr output from the execution
    """
    # 创建 BytesIO 对象来捕获输出（Qiling 写入的是二进制数据）
    captured_stdout = io.BytesIO()
    captured_stderr = io.BytesIO()

    ql = Qiling(argv=argv, rootfs=rootfs, env=env, code=code, **kwargs)

    # 如果提供了 stdin 数据，设置 stdin
    if stdin_data is not None:
        stdin_stream = io.BytesIO(stdin_data)
        ql.os.stdin = stdin_stream

    # 重定向 stdout 和 stderr 来捕获输出
    ql.os.stdout = captured_stdout
    ql.os.stderr = captured_stderr

    with cov_utils.collect_coverage(ql, 'icfg', output_file):
        try:
            if timeout:
                ql.run(timeout=timeout)
            else:
                ql.run(timeout=1000000*30)
        except:
            pass

    # 获取捕获的输出并解码为字符串
    try:
        stdout_str = captured_stdout.getvalue().decode('utf-8', errors='replace')
        stderr_str = captured_stderr.getvalue().decode('utf-8', errors='replace')
        output = stdout_str + stderr_str
    except Exception as e:
        output = f"[Error decoding output: {e}]"

    if Path(output_file).exists():
        print("  ✓ Generated: ", output_file)
        return True, output
    else:
        print("  ✗ Failed to generate: ", output_file)
        return False, output
