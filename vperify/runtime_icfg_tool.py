# -*- coding: utf-8 -*-

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
    **kwargs: Any
) -> bool:
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
    
    """
    ql = Qiling(argv=argv, rootfs=rootfs, env=env, code=code, **kwargs)
    with cov_utils.collect_coverage(ql, 'icfg', output_file):
        try:
            if timeout:
                ql.run(timeout=timeout)
            else:
                ql.run(timeout=1000000*30)
        except:
            pass
    if Path(output_file).exists(): 
        print("  ✓ Generated: ", output_file)
        return True
    else:
        print("  ✗ Failed to generate: ", output_file)
        return False
