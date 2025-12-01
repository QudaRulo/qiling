# -*- coding: utf-8 -*-

"""
统一日志配置模块
使用colorlog提供彩色日志输出, 便于区分不同级别的信息
"""

import logging
from logging.handlers import RotatingFileHandler
import time
import colorlog
from pathlib import Path
import os


class LoggerSetup:
    """日志设置类"""
    
    _configured = False
    _logger_cache = {}
    
    @classmethod
    def setup_logging(cls, log_level: str = "INFO", enable_file_logging: bool = False, 
                     rotating: bool=False, module_settings: list = None):
        """
        设置全局日志配置
        
        Args:
            log_level: 日志级别 (DEBUG/INFO/WARNING/ERROR)
            enable_file_logging: 是否启用文件日志
            rotating: 是否使用轮转日志文件
            module_settings: 第三方模块日志级别设置列表
        """
        if cls._configured:
            return
        
        # 设置日志级别
        level = getattr(logging, log_level.upper(), logging.INFO)
        
        # 创建彩色格式化器
        color_formatter = colorlog.ColoredFormatter(
            # "%(log_color)s[%(asctime)s] [%(filename)s:%(lineno)d] [%(levelname)s]: %(message)s",
            "%(log_color)s[%(asctime)s] [%(filename)s::%(funcName)s %(lineno)d] [%(levelname)s]: %(message)s", 
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
        )
        
        # 创建控制台处理器
        console_handler = colorlog.StreamHandler()
        console_handler.setFormatter(color_formatter)
        console_handler.setLevel(level)
        
        # 配置根日志器
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        root_logger.handlers.clear()  # 清除现有处理器
        root_logger.addHandler(console_handler)
        
        # 文件日志配置（可选）
        if enable_file_logging:
            # 1. Set file path
            log_path = Path(os.getcwd()) / "logs"
            if not log_path.exists():
                log_path.mkdir(parents=True, exist_ok=True)

            log_file_path = log_path / f"vperify_{time.strftime('%Y-%m-%d')}.log"

            # 2. Set Formatter
            formatter = logging.Formatter(
                # "[%(asctime)s] [%(filename)s:%(lineno)d] [%(levelname)s]: %(message)s"
                "[%(asctime)s] [%(filename)s::%(funcName)s %(lineno)d] [%(levelname)s]: %(message)s"
            )

            # 3. Set Handler
            if rotating:
                file_handler = RotatingFileHandler(
                    filename=log_file_path,
                    mode="a",
                    maxBytes=1024 * 1024 * 100,
                    backupCount= 5,
                    encoding="utf-8",
                )
            else:
                # 为了调试方便不采用滚动保存
                file_handler = logging.FileHandler(filename=log_file_path, mode="w")

            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)  # 文件记录所有级别
            
            root_logger.addHandler(file_handler)
        
        # 设置第三方库的日志级别
        if module_settings:
            for settings_dict in module_settings:
                if isinstance(settings_dict, dict):
                    for module_name, level_str in settings_dict.items():
                        try:
                            level = getattr(logging, level_str.upper(), logging.WARNING)
                            logging.getLogger(module_name).setLevel(level)
                        except AttributeError:
                            # 如果日志级别字符串无效，使用WARNING作为默认级别
                            logging.getLogger(module_name).setLevel(logging.WARNING)
        
        cls._configured = True
    
    @classmethod
    def get_logger(cls, name: str = None) -> logging.Logger:
        """
        获取日志器实例
        
        Args:
            name: 日志器名称，默认为调用模块名
            
        Returns:
            配置好的日志器实例
        """
        if not cls._configured:
            setup_logging()
        
        if name is None:
            import inspect
            frame = inspect.currentframe()
            caller_frame = frame.f_back
            caller_module = caller_frame.f_globals.get('__name__')
            name = caller_module 
        
        if name not in cls._logger_cache:
            logger = logging.getLogger(name)
            cls._logger_cache[name] = logger
        
        return cls._logger_cache[name]


# 便捷函数
def get_logger(name: str = None) -> logging.Logger:
    """
    便捷函数：获取日志器实例
    
    Args:
        name: 日志器名称
        
    Returns:
        配置好的日志器实例
    """
    return LoggerSetup.get_logger(name)


def setup_logging():
    """从配置文件设置日志"""
    try:        
        LoggerSetup.setup_logging(
            log_level="DEBUG",
            enable_file_logging=True,  # 是否启用文件日志
            module_settings=[
                {"openai": "WARNING"},
                {"urllib3": "WARNING"},
                {"requests": "WARNING"},
                {"httpx": "WARNING"},
                {"httpcore": "WARNING"},  # 添加 httpcore
                {"httpcore._trace": "WARNING"},  # httpcore 的 trace 模块
                {"langchain": "WARNING"},
                {"mcp": "WARNING"},

                ]  # 第三方库日志级别设置
        )
    except Exception as e:
        # 如果配置加载失败，使用默认设置
        LoggerSetup.setup_logging(log_level="INFO")
        logger = get_logger(__file__)
        logger.warning(f"无法从配置文件设置日志，使用默认配置: {e}")
