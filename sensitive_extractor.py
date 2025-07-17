#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
敏感信息提取工具 - 完整项目版本
作者: 慕鸢
版本: 3.0
描述: 扫描指定目录下的文件，提取敏感信息并生成Markdown报告
新增功能:
- 多线程处理 + GUI界面 + 进度显示
- 配置文件分离
- 可执行文件打包
"""

import os
import re
import sys
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Set
import mimetypes
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import webbrowser


class SensitiveInfoExtractor:
    def __init__(self, progress_callback=None, status_callback=None):
        # 进度回调函数
        self.progress_callback = progress_callback
        self.status_callback = status_callback

        # 从配置文件加载规则
        self.patterns = self.load_patterns()

        # 编译正则表达式以提高性能
        self.compiled_patterns = {}
        for name, pattern_info in self.patterns.items():
            try:
                self.compiled_patterns[name] = re.compile(pattern_info["regex"], re.DOTALL)
            except Exception as e:
                print(f"警告: 无法编译正则表达式 '{name}': {e}")

        # 支持的文本文件扩展名
        self.text_extensions = {
            '.txt', '.md', '.py', '.js', '.html', '.htm', '.css', '.xml', '.json',
            '.yml', '.yaml', '.ini', '.cfg', '.conf', '.config', '.properties',
            '.sql', '.sh', '.bat', '.ps1', '.php', '.java', '.cpp', '.c', '.h',
            '.cs', '.go', '.rs', '.rb', '.pl', '.swift', '.kt', '.scala', '.clj',
            '.lua', '.r', '.m', '.dart', '.tsx', '.jsx', '.vue', '.log', '.env',
            '.dockerfile', '.makefile', '.gitignore', '.gitattributes', '.editorconfig'
        }

        # 二进制文件扩展名（需要跳过）
        self.binary_extensions = {
            '.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.db', '.sqlite',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp',
            '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v',
            '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.lzma',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.class', '.jar', '.war', '.ear', '.pyc', '.pyo', '.pyd'
        }

        # 扫描结果存储
        self.results = {}
        self.scanned_files = []
        self.skipped_files = []
        self.error_files = []

        # 多线程控制
        self.is_scanning = False
        self.scan_cancelled = False

        # 统计信息
        self.stats = {
            'total_files': 0,
            'scanned_files': 0,
            'skipped_files': 0,
            'error_files': 0,
            'sensitive_items': 0,
            'start_time': None,
            'end_time': None
        }

    def load_patterns(self) -> Dict:
        """从配置文件加载正则表达式规则"""
        config_file = "patterns.json"

        # 如果配置文件不存在，创建默认配置
        if not os.path.exists(config_file):
            print("首次运行，正在创建默认配置文件...")
            self.create_default_patterns_file(config_file)
            print("配置文件创建完成 - 敏感信息提取工具 by 慕鸢")

        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"加载配置文件失败: {e}")
            return self.get_default_patterns()

    def create_default_patterns_file(self, config_file: str):
        """创建默认的正则表达式配置文件"""
        default_patterns = self.get_default_patterns()

        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(default_patterns, f, ensure_ascii=False, indent=2)
            print(f"已创建默认配置文件: {config_file} - by 慕鸢")
        except Exception as e:
            print(f"创建配置文件失败: {e}")

    def get_default_patterns(self) -> Dict:
        """获取默认的正则表达式规则"""
        return {
            "大陆手机号": {
                "regex": r'\b1[3456789]\d{9}\b',
                "description": "中国大陆手机号码",
                "risk_level": "高",
                "enabled": True
            },
            "身份证": {
                "regex": r'\b\d{17}[\dXx]\b',
                "description": "中国居民身份证号码",
                "risk_level": "高",
                "enabled": True
            },
            "邮箱": {
                "regex": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
                "description": "电子邮箱地址",
                "risk_level": "中",
                "enabled": True
            },
            "银行卡": {
                "regex": r'\b\d{16,19}\b',
                "description": "银行卡号",
                "risk_level": "高",
                "enabled": True
            },
            "域名": {
                "regex": r'(?i)\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|co|edu|gov|mil|biz|info|me|us|ca|uk|de|fr|it|es|au|nz|jp|kr|cn|ru|br|in|mx|nl)\b',
                "description": "域名地址",
                "risk_level": "低",
                "enabled": True
            },
            "路径": {
                "regex": r'(?:https?://|/|\.\./|\./|/[\w-]+)/(?:[\w/.?%&=-]*|[\w-]+)',
                "description": "文件路径",
                "risk_level": "低",
                "enabled": True
            },
            "URL": {
                "regex": r'(?i)\b((?:https?|ftp|file):\/\/[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,63}\b(?:[-a-zA-Z0-9@:%_\+.~#?&\/=]*))\b',
                "description": "网址链接",
                "risk_level": "低",
                "enabled": True
            },
            "JWT": {
                "regex": r'\bey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b',
                "description": "JWT令牌",
                "risk_level": "高",
                "enabled": True
            },
            "JDBC": {
                "regex": r'jdbc:[a-zA-Z]+:\/\/[^\s]*',
                "description": "JDBC数据库连接字符串",
                "risk_level": "高",
                "enabled": True
            },
            "认证头": {
                "regex": r'(?i)\bAuthorization:\s*(?:Bearer|Basic|Digest)\s+(?:[A-Za-z0-9-._~+/]+=*|[\w%]{2}==)\b',
                "description": "HTTP认证头",
                "risk_level": "高",
                "enabled": True
            },
            "账户密码": {
                "regex": r'(?:username|user|account)\s*[:=]\s*[\'\"](.*?)[\'\"]\s*,\s*(?:password|pass)\s*[:=]\s*[\'\"](.*?)[\'\"]',
                "description": "用户名和密码组合",
                "risk_level": "高",
                "enabled": True
            },
            "ticket": {
                "regex": r'\bjsapi_ticket\b',
                "description": "API票据",
                "risk_level": "中",
                "enabled": True
            },
            "加密算法": {
                "regex": r'(?i)\b(AES|DES|3DES|RC4|RSA|ECC|SM2|SM3|SM4|Blowfish|HMAC)\b',
                "description": "加密算法名称",
                "risk_level": "低",
                "enabled": True
            },
            "密钥": {
                "regex": r'(?i)(?:encryption|secret|private|api|auth|access|key)\s*[:=]\s*["\']?([0-9a-fA-F]{32,})["\']?',
                "description": "加密密钥",
                "risk_level": "高",
                "enabled": True
            },
            "偏移量": {
                "regex": r'(?i)(?:iv|offset|init_vector)\s*[:=]\s*["\']?([0-9a-fA-F]{8,})["\']?',
                "description": "加密偏移量",
                "risk_level": "中",
                "enabled": True
            },
            "swagger": {
                "regex": r'(?i)\b((?:https?://)?(?:[a-zA-Z0-9-\.]+)\/(?:v1|v2|v3|docs|swagger|apidocs|api-docs|open-api)?\/?(swagger|api-docs)(?:\.json)?)\b',
                "description": "Swagger API文档地址",
                "risk_level": "中",
                "enabled": True
            },
            "oss": {
                "regex": r'https?://[^\'")\s]*oss[^\'")\s]+',
                "description": "对象存储服务地址",
                "risk_level": "中",
                "enabled": True
            },
            "access_key": {
                "regex": r'(?i)\baccess[_]?key\s*[:=]\s*["\']([^"\']+)["\']',
                "description": "访问密钥",
                "risk_level": "高",
                "enabled": True
            },
            "oss_key": {
                "regex": r'(?i)\boss\s*[_\s]*(?:key)?\s*[=:]\s*[\'"]([A-Z0-9]+)[\'"]',
                "description": "OSS访问密钥",
                "risk_level": "高",
                "enabled": True
            },
            "apikey": {
                "regex": r'(?i)\bapi[_]?key\s*[=:]\s*["\']([^"\']+)["\']',
                "description": "API密钥",
                "risk_level": "高",
                "enabled": True
            },
            "apisecret": {
                "regex": r'(?i)\bapi[_]?secret\s*[=:]\s*["\']([^"\']+)["\']',
                "description": "API秘钥",
                "risk_level": "高",
                "enabled": True
            },
            "app_key": {
                "regex": r'(?i)\bAppKey\s*:\s*["\']([^"\']+)["\']',
                "description": "应用密钥",
                "risk_level": "高",
                "enabled": True
            },
            "app_secret": {
                "regex": r'(?i)\bAPPSECRET\s*:\s*["\']([^"\']+)["\']',
                "description": "应用秘钥",
                "risk_level": "高",
                "enabled": True
            },
            "RSA公钥": {
                "regex": r'-----BEGIN(?:\s+\w+)?\s+PUBLIC\s+KEY-----\s*(.*?)\s*-----END(?:\s+\w+)?\s+PUBLIC\s+KEY-----',
                "description": "RSA公钥",
                "risk_level": "中",
                "enabled": True
            },
            "RSA私钥": {
                "regex": r'-----BEGIN(?:\s+RSA)?\s+PRIVATE\s+KEY-----\s*(.*?)\s*-----END(?:\s+RSA)?\s+PRIVATE\s+KEY-----',
                "description": "RSA私钥",
                "risk_level": "高",
                "enabled": True
            }
        }

    def is_text_file(self, file_path: str) -> bool:
        """判断文件是否为文本文件"""
        file_path = Path(file_path)

        # 检查扩展名
        if file_path.suffix.lower() in self.binary_extensions:
            return False

        if file_path.suffix.lower() in self.text_extensions:
            return True

        # 对于没有扩展名的文件，尝试使用MIME类型判断
        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type:
            return mime_type.startswith('text/') or mime_type in [
                'application/json', 'application/xml', 'application/javascript'
            ]

        # 最后尝试读取文件前几个字节来判断
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\x00' in chunk:  # 包含空字节，可能是二进制文件
                    return False
                try:
                    chunk.decode('utf-8')
                    return True
                except UnicodeDecodeError:
                    try:
                        chunk.decode('gbk')
                        return True
                    except UnicodeDecodeError:
                        return False
        except (IOError, OSError):
            return False

    def read_file_content(self, file_path: str) -> str:
        """读取文件内容，尝试多种编码"""
        encodings = ['utf-8', 'gbk', 'gb2312', 'utf-16', 'latin-1']

        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
            except Exception as e:
                self.error_files.append((file_path, str(e)))
                return ""

        self.error_files.append((file_path, "无法使用任何编码读取文件"))
        return ""

    def scan_file(self, file_path: str) -> Dict[str, List[Tuple[str, int]]]:
        """扫描单个文件中的敏感信息"""
        if self.scan_cancelled:
            return {}

        if not self.is_text_file(file_path):
            self.skipped_files.append(file_path)
            return {}

        content = self.read_file_content(file_path)
        if not content:
            return {}

        self.scanned_files.append(file_path)
        file_results = {}

        # 按行分割内容以获取行号
        lines = content.split('\n')

        for pattern_name, compiled_pattern in self.compiled_patterns.items():
            if self.scan_cancelled:
                break

            # 检查是否启用该规则
            if not self.patterns[pattern_name].get('enabled', True):
                continue

            matches = []

            # 在每一行中查找匹配项
            for line_num, line in enumerate(lines, 1):
                for match in compiled_pattern.finditer(line):
                    matches.append((match.group(0), line_num))

            if matches:
                file_results[pattern_name] = matches

        return file_results

    def get_all_files(self, directory_path: str) -> List[str]:
        """获取目录中所有文件的路径"""
        all_files = []
        directory_path = Path(directory_path)

        for root, dirs, files in os.walk(directory_path):
            # 跳过隐藏目录和常见的二进制目录
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {
                'node_modules', '__pycache__', '.git', '.svn', 'target', 'build',
                'dist', 'bin', 'obj', 'out', '.idea', '.vscode'
            }]

            for file in files:
                if file.startswith('.') and file not in {'.env', '.gitignore', '.gitattributes'}:
                    continue

                file_path = os.path.join(root, file)
                all_files.append(file_path)

        return all_files

    def scan_directory(self, directory_path: str, max_workers: int = 8) -> None:
        """使用多线程扫描目录中的所有文件"""
        directory_path = Path(directory_path)

        if not directory_path.exists():
            raise FileNotFoundError(f"目录 {directory_path} 不存在")

        if not directory_path.is_dir():
            raise NotADirectoryError(f"{directory_path} 不是一个目录")

        self.is_scanning = True
        self.scan_cancelled = False
        self.stats['start_time'] = datetime.now()

        if self.status_callback:
            self.status_callback("正在获取文件列表...")

        # 获取所有文件
        all_files = self.get_all_files(directory_path)
        self.stats['total_files'] = len(all_files)

        if self.status_callback:
            self.status_callback(f"找到 {len(all_files)} 个文件，开始扫描...")

        # 使用线程池执行扫描
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务
            future_to_file = {
                executor.submit(self.scan_file, file_path): file_path
                for file_path in all_files
            }

            completed = 0
            for future in as_completed(future_to_file):
                if self.scan_cancelled:
                    break

                file_path = future_to_file[future]
                completed += 1

                try:
                    file_results = future.result()

                    if file_results:
                        if file_path not in self.results:
                            self.results[file_path] = {}

                        for pattern_name, matches in file_results.items():
                            if pattern_name not in self.results[file_path]:
                                self.results[file_path][pattern_name] = []
                            self.results[file_path][pattern_name].extend(matches)
                            self.stats['sensitive_items'] += len(matches)

                    # 更新进度
                    progress = (completed / len(all_files)) * 100
                    current_file = os.path.basename(file_path)

                    if self.progress_callback:
                        self.progress_callback(progress, current_file)

                    if self.status_callback:
                        self.status_callback(f"扫描进度: {completed}/{len(all_files)} - {current_file}")

                except Exception as e:
                    self.error_files.append((file_path, str(e)))

        # 更新统计信息
        self.stats['scanned_files'] = len(self.scanned_files)
        self.stats['skipped_files'] = len(self.skipped_files)
        self.stats['error_files'] = len(self.error_files)
        self.stats['end_time'] = datetime.now()

        self.is_scanning = False

        if self.status_callback:
            if self.scan_cancelled:
                self.status_callback("扫描已取消")
            else:
                self.status_callback(f"扫描完成！发现 {self.stats['sensitive_items']} 个敏感信息")

    def cancel_scan(self):
        """取消当前扫描"""
        self.scan_cancelled = True

    def generate_report(self, output_path: str = "sensitive_info_report.md") -> None:
        """生成Markdown格式的报告"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        duration = ""

        if self.stats['start_time'] and self.stats['end_time']:
            duration = str(self.stats['end_time'] - self.stats['start_time'])

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"# 🔍 敏感信息扫描报告 - by 慕鸢\n\n")
            f.write(f"**生成时间**: {timestamp}\n")
            if duration:
                f.write(f"**扫描用时**: {duration}\n")
            f.write(f"\n## 📊 统计信息\n\n")
            f.write(f"| 项目 | 数量 |\n")
            f.write(f"|------|------|\n")
            f.write(f"| 总文件数 | {self.stats['total_files']} |\n")
            f.write(f"| 已扫描文件 | {self.stats['scanned_files']} |\n")
            f.write(f"| 跳过文件 | {self.stats['skipped_files']} |\n")
            f.write(f"| 错误文件 | {self.stats['error_files']} |\n")
            f.write(f"| 敏感信息总数 | {self.stats['sensitive_items']} |\n\n")

            # 按敏感信息类型分组
            pattern_summary = {}
            for file_path, file_results in self.results.items():
                for pattern_name, matches in file_results.items():
                    if pattern_name not in pattern_summary:
                        pattern_summary[pattern_name] = []
                    pattern_summary[pattern_name].extend([(file_path, match, line_num) for match, line_num in matches])

            # 生成概览
            f.write("## 🔍 敏感信息概览\n\n")
            if pattern_summary:
                f.write("| 敏感信息类型 | 数量 | 风险等级 | 描述 |\n")
                f.write("|-------------|------|----------|------|\n")
                for pattern_name in sorted(pattern_summary.keys()):
                    count = len(pattern_summary[pattern_name])
                    risk_level = self.patterns[pattern_name]["risk_level"]
                    description = self.patterns[pattern_name]["description"]

                    # 根据风险等级设置表情符号
                    risk_emoji = {"高": "🔴", "中": "🟡", "低": "🟢"}
                    risk_display = f"{risk_emoji.get(risk_level, '⚪')} {risk_level}"

                    f.write(f"| {pattern_name} | {count} | {risk_display} | {description} |\n")
            else:
                f.write("✅ 未发现敏感信息\n")

            f.write("\n---\n\n")

            # 按类型详细列出敏感信息
            for pattern_name in sorted(pattern_summary.keys()):
                risk_level = self.patterns[pattern_name]["risk_level"]
                risk_emoji = {"高": "🔴", "中": "🟡", "低": "🟢"}

                f.write(f"## {risk_emoji.get(risk_level, '⚪')} {pattern_name}\n\n")
                f.write(f"**描述**: {self.patterns[pattern_name]['description']}\n")
                f.write(f"**风险等级**: {risk_level}\n")
                f.write(f"**发现数量**: {len(pattern_summary[pattern_name])}\n\n")

                # 按文件分组
                file_groups = {}
                for file_path, match, line_num in pattern_summary[pattern_name]:
                    if file_path not in file_groups:
                        file_groups[file_path] = []
                    file_groups[file_path].append((match, line_num))

                for file_path in sorted(file_groups.keys()):
                    f.write(f"### 📁 {file_path}\n\n")
                    matches = file_groups[file_path]

                    # 去重并保持行号信息
                    unique_matches = {}
                    for match, line_num in matches:
                        if match not in unique_matches:
                            unique_matches[match] = []
                        unique_matches[match].append(line_num)

                    for match, line_nums in unique_matches.items():
                        line_nums_str = ", ".join(map(str, sorted(set(line_nums))))
                        f.write(f"- **内容**: `{match}`\n")
                        f.write(f"- **行号**: {line_nums_str}\n\n")

                f.write("\n---\n\n")

            # 添加跳过的文件列表
            if self.skipped_files:
                f.write("## 🚫 跳过的文件\n\n")
                f.write("以下文件被识别为二进制文件或不支持的格式，已跳过扫描：\n\n")
                for file_path in sorted(self.skipped_files):
                    f.write(f"- {file_path}\n")
                f.write("\n")

            # 添加错误的文件列表
            if self.error_files:
                f.write("## ❌ 错误的文件\n\n")
                f.write("以下文件在扫描过程中出现错误：\n\n")
                for file_path, error in self.error_files:
                    f.write(f"- **文件**: {file_path}\n")
                    f.write(f"- **错误**: {error}\n\n")

            f.write("\n---\n\n")
            f.write("## 📄 工具信息\n\n")
            f.write("**工具名称**: 敏感信息提取工具 v3.0\n")
            f.write("**作者**: 慕鸢\n")
            f.write("**许可证**: MIT License\n")
            f.write("**说明**: 本工具仅用于安全检测和代码审计，请在合法合规的范围内使用\n\n")
            f.write("---\n\n")
            f.write("*报告由敏感信息提取工具生成 - by 慕鸢*\n")


class SensitiveInfoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 敏感信息提取工具 v3.0 - by 慕鸢")
        self.root.geometry("900x700")

        # 设置应用图标和样式
        self.root.configure(bg='#f0f0f0')

        # 创建样式
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # 配置自定义样式
        self.style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        self.style.configure('Header.TLabel', font=('Arial', 10, 'bold'))
        self.style.configure('Success.TLabel', foreground='green')
        self.style.configure('Error.TLabel', foreground='red')
        self.style.configure('Warning.TLabel', foreground='orange')

        # 变量
        self.scan_directory = tk.StringVar()
        self.output_file = tk.StringVar(value="sensitive_info_report.md")
        self.max_workers = tk.StringVar(value="8")

        # 扫描器实例
        self.scanner = None
        self.scan_thread = None

        # 创建界面
        self.create_widgets()

        # 绑定窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        """创建GUI组件"""
        # 主标题
        title_frame = ttk.Frame(self.root)
        title_frame.pack(fill='x', padx=10, pady=10)

        title_label = ttk.Label(title_frame, text="🔍 敏感信息提取工具 v3.0 - by 慕鸢", style='Title.TLabel')
        title_label.pack()

        subtitle_label = ttk.Label(title_frame, text="扫描目录中的敏感信息并生成详细报告 | 支持多线程 | 配置文件可定制")
        subtitle_label.pack()

        # 创建笔记本控件（标签页）
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # 扫描标签页
        self.scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_frame, text="📁 扫描设置")

        # 结果标签页
        self.result_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.result_frame, text="📊 扫描结果")

        # 配置标签页
        self.config_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.config_frame, text="⚙️ 配置管理")

        # 创建各个界面
        self.create_scan_interface()
        self.create_result_interface()
        self.create_config_interface()

        # 创建状态栏
        self.create_status_bar()

    def create_status_bar(self):
        """创建状态栏"""
        status_bar = ttk.Frame(self.root)
        status_bar.pack(fill='x', side='bottom', padx=5, pady=2)

        # 左侧状态信息
        self.status_info = ttk.Label(status_bar, text="就绪", foreground='green')
        self.status_info.pack(side='left')

        # 右侧版权信息
        copyright_label = ttk.Label(status_bar, text="© 2025 慕鸢 | 敏感信息提取工具 v3.0",
                                    font=('Arial', 8), foreground='gray')
        copyright_label.pack(side='right')

    def create_scan_interface(self):
        """创建扫描设置界面"""
        # 目录选择
        dir_frame = ttk.LabelFrame(self.scan_frame, text="📁 选择扫描目录", padding=10)
        dir_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(dir_frame, text="扫描目录:").pack(anchor='w')
        dir_input_frame = ttk.Frame(dir_frame)
        dir_input_frame.pack(fill='x', pady=5)

        self.dir_entry = ttk.Entry(dir_input_frame, textvariable=self.scan_directory, width=50)
        self.dir_entry.pack(side='left', fill='x', expand=True)

        ttk.Button(dir_input_frame, text="浏览", command=self.browse_directory).pack(side='right', padx=(5, 0))

        # 输出设置
        output_frame = ttk.LabelFrame(self.scan_frame, text="📝 输出设置", padding=10)
        output_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(output_frame, text="输出文件:").pack(anchor='w')
        output_input_frame = ttk.Frame(output_frame)
        output_input_frame.pack(fill='x', pady=5)

        self.output_entry = ttk.Entry(output_input_frame, textvariable=self.output_file, width=50)
        self.output_entry.pack(side='left', fill='x', expand=True)

        ttk.Button(output_input_frame, text="选择", command=self.browse_output_file).pack(side='right', padx=(5, 0))

        # 高级设置
        advanced_frame = ttk.LabelFrame(self.scan_frame, text="⚙️ 高级设置", padding=10)
        advanced_frame.pack(fill='x', padx=10, pady=5)

        workers_frame = ttk.Frame(advanced_frame)
        workers_frame.pack(fill='x', pady=5)

        ttk.Label(workers_frame, text="并发线程数:").pack(side='left')

        # 创建线程数选择下拉框
        self.workers_combo = ttk.Combobox(workers_frame, textvariable=self.max_workers,
                                          values=["2", "4", "8", "16"],
                                          state="readonly", width=10)
        self.workers_combo.pack(side='left', padx=10)

        # 添加说明
        info_label = ttk.Label(workers_frame, text="(推荐: 8线程, 根据CPU核心数调整)")
        info_label.pack(side='left', padx=10)

        # 进度显示
        progress_frame = ttk.LabelFrame(self.scan_frame, text="📈 扫描进度", padding=10)
        progress_frame.pack(fill='x', padx=10, pady=5)

        # 进度条
        self.progress = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.progress.pack(fill='x', pady=5)

        # 状态标签
        self.status_label = ttk.Label(progress_frame, text="准备就绪")
        self.status_label.pack(anchor='w')

        # 当前文件标签
        self.current_file_label = ttk.Label(progress_frame, text="", foreground='blue')
        self.current_file_label.pack(anchor='w')

        # 按钮
        button_frame = ttk.Frame(self.scan_frame)
        button_frame.pack(fill='x', padx=10, pady=10)

        self.start_button = ttk.Button(button_frame, text="🚀 开始扫描", command=self.start_scan)
        self.start_button.pack(side='left', padx=5)

        self.stop_button = ttk.Button(button_frame, text="⏹️ 停止扫描", command=self.stop_scan, state='disabled')
        self.stop_button.pack(side='left', padx=5)

        self.open_report_button = ttk.Button(button_frame, text="📖 查看报告", command=self.open_report,
                                             state='disabled')
        self.open_report_button.pack(side='right', padx=5)

        self.reload_config_button = ttk.Button(button_frame, text="🔄 重新加载配置", command=self.reload_config)
        self.reload_config_button.pack(side='right', padx=5)

        self.about_button = ttk.Button(button_frame, text="ℹ️ 关于", command=self.show_about)
        self.about_button.pack(side='right', padx=5)

    def create_result_interface(self):
        """创建结果显示界面"""
        # 统计信息
        stats_frame = ttk.LabelFrame(self.result_frame, text="📊 统计信息", padding=10)
        stats_frame.pack(fill='x', padx=10, pady=5)

        # 创建统计信息标签
        self.stats_labels = {}
        stats_items = [
            ("总文件数", "total_files"),
            ("已扫描", "scanned_files"),
            ("已跳过", "skipped_files"),
            ("错误文件", "error_files"),
            ("敏感信息", "sensitive_items")
        ]

        for i, (label, key) in enumerate(stats_items):
            row = i // 3
            col = i % 3

            frame = ttk.Frame(stats_frame)
            frame.grid(row=row, column=col, padx=10, pady=5, sticky='w')

            ttk.Label(frame, text=f"{label}:", style='Header.TLabel').pack(side='left')
            self.stats_labels[key] = ttk.Label(frame, text="0")
            self.stats_labels[key].pack(side='left', padx=5)

        # 详细结果
        detail_frame = ttk.LabelFrame(self.result_frame, text="📋 详细结果", padding=10)
        detail_frame.pack(fill='both', expand=True, padx=10, pady=5)

        # 创建树形视图
        columns = ('类型', '数量', '风险等级', '描述')
        self.result_tree = ttk.Treeview(detail_frame, columns=columns, show='headings', height=15)

        # 设置列标题
        for col in columns:
            self.result_tree.heading(col, text=col)
            self.result_tree.column(col, width=150)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(detail_frame, orient='vertical', command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=scrollbar.set)

        # 布局
        self.result_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # 绑定双击事件
        self.result_tree.bind('<Double-1>', self.on_tree_double_click)

    def create_config_interface(self):
        """创建配置管理界面"""
        # 配置文件信息
        info_frame = ttk.LabelFrame(self.config_frame, text="📄 配置文件信息", padding=10)
        info_frame.pack(fill='x', padx=10, pady=5)

        config_file_path = os.path.abspath("patterns.json")
        ttk.Label(info_frame, text=f"配置文件位置: {config_file_path}").pack(anchor='w')

        if os.path.exists("patterns.json"):
            try:
                with open("patterns.json", 'r', encoding='utf-8') as f:
                    patterns = json.load(f)
                enabled_count = sum(1 for p in patterns.values() if p.get('enabled', True))
                ttk.Label(info_frame, text=f"已启用规则: {enabled_count}/{len(patterns)}").pack(anchor='w')
            except:
                ttk.Label(info_frame, text="配置文件读取错误", foreground='red').pack(anchor='w')
        else:
            ttk.Label(info_frame, text="配置文件不存在，将自动创建", foreground='orange').pack(anchor='w')

        # 配置操作按钮
        button_frame = ttk.Frame(info_frame)
        button_frame.pack(fill='x', pady=10)

        ttk.Button(button_frame, text="📝 编辑配置", command=self.edit_config).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🔄 重新加载", command=self.reload_config).pack(side='left', padx=5)
        ttk.Button(button_frame, text="📋 查看示例", command=self.show_config_example).pack(side='left', padx=5)

        # 配置说明
        help_frame = ttk.LabelFrame(self.config_frame, text="📚 配置说明", padding=10)
        help_frame.pack(fill='both', expand=True, padx=10, pady=5)

        help_text = """
🔍 敏感信息提取工具 v3.0 - by 慕鸢

配置文件说明 (patterns.json):

1. 文件格式: JSON格式
2. 每个规则包含以下字段:
   - "regex": 正则表达式字符串
   - "description": 规则描述
   - "risk_level": 风险等级 ("高", "中", "低")
   - "enabled": 是否启用 (true/false)

3. 如何添加新规则:
   - 在配置文件中添加新的键值对
   - 确保正则表达式语法正确
   - 设置合适的风险等级和描述

4. 如何禁用规则:
   - 将规则的 "enabled" 字段设置为 false

5. 配置文件修改后需要重新加载才能生效

---
💡 温馨提示：此工具专为安全检测设计，请合规使用
        """

        help_text_widget = scrolledtext.ScrolledText(help_frame, wrap=tk.WORD, height=12)
        help_text_widget.pack(fill='both', expand=True)
        help_text_widget.insert(tk.END, help_text)
        help_text_widget.config(state='disabled')

    def browse_directory(self):
        """浏览选择目录"""
        directory = filedialog.askdirectory()
        if directory:
            self.scan_directory.set(directory)

    def browse_output_file(self):
        """选择输出文件"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown files", "*.md"), ("All files", "*.*")]
        )
        if filename:
            self.output_file.set(filename)

    def update_progress(self, progress, current_file):
        """更新进度条"""
        self.progress['value'] = progress
        self.current_file_label.config(text=f"当前文件: {current_file}")
        self.root.update_idletasks()

    def update_status(self, status):
        """更新状态标签"""
        self.status_label.config(text=status)
        # 同时更新状态栏
        if hasattr(self, 'status_info'):
            self.status_info.config(text=status)
        self.root.update_idletasks()

    def start_scan(self):
        """开始扫描"""
        if not self.scan_directory.get():
            messagebox.showerror("错误", "请选择扫描目录")
            return

        if not os.path.exists(self.scan_directory.get()):
            messagebox.showerror("错误", "选择的目录不存在")
            return

        # 禁用开始按钮，启用停止按钮
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.open_report_button.config(state='disabled')

        # 清空进度和结果
        self.progress['value'] = 0
        self.current_file_label.config(text="")
        self.clear_results()

        # 创建扫描器
        self.scanner = SensitiveInfoExtractor(
            progress_callback=self.update_progress,
            status_callback=self.update_status
        )

        # 在新线程中运行扫描
        self.scan_thread = threading.Thread(target=self.run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def run_scan(self):
        """运行扫描（在单独线程中）"""
        try:
            workers = int(self.max_workers.get())
            self.scanner.scan_directory(self.scan_directory.get(), workers)

            # 扫描完成后更新GUI
            self.root.after(0, self.scan_completed)

        except Exception as e:
            self.root.after(0, lambda: self.scan_error(str(e)))

    def scan_completed(self):
        """扫描完成后的处理"""
        if not self.scanner.scan_cancelled:
            # 生成报告
            try:
                self.scanner.generate_report(self.output_file.get())
                self.update_status("扫描完成！报告已生成")
                self.open_report_button.config(state='normal')

                # 更新结果显示
                self.update_result_display()

                # 切换到结果标签页
                self.notebook.select(1)

            except Exception as e:
                messagebox.showerror("错误", f"生成报告时出错: {str(e)}")

        # 重置按钮状态
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress['value'] = 100

    def scan_error(self, error_message):
        """扫描出错时的处理"""
        messagebox.showerror("扫描错误", f"扫描过程中发生错误:\n{error_message}")
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.update_status("扫描失败")

    def stop_scan(self):
        """停止扫描"""
        if self.scanner:
            self.scanner.cancel_scan()
            self.update_status("正在停止扫描...")
            self.stop_button.config(state='disabled')

    def open_report(self):
        """打开报告文件"""
        if os.path.exists(self.output_file.get()):
            try:
                # 在默认程序中打开文件
                if sys.platform.startswith('win'):
                    os.startfile(self.output_file.get())
                elif sys.platform.startswith('darwin'):
                    os.system(f'open "{self.output_file.get()}"')
                else:
                    os.system(f'xdg-open "{self.output_file.get()}"')
            except Exception as e:
                messagebox.showerror("错误", f"无法打开报告文件: {str(e)}")
        else:
            messagebox.showerror("错误", "报告文件不存在")

    def reload_config(self):
        """重新加载配置"""
        try:
            # 重新创建扫描器以加载新配置
            test_scanner = SensitiveInfoExtractor()
            messagebox.showinfo("成功", "配置已重新加载")
        except Exception as e:
            messagebox.showerror("错误", f"重新加载配置失败: {str(e)}")

    def edit_config(self):
        """编辑配置文件"""
        config_path = "patterns.json"
        try:
            if sys.platform.startswith('win'):
                os.startfile(config_path)
            elif sys.platform.startswith('darwin'):
                os.system(f'open "{config_path}"')
            else:
                os.system(f'xdg-open "{config_path}"')
        except Exception as e:
            messagebox.showerror("错误", f"无法打开配置文件: {str(e)}")

    def show_config_example(self):
        """显示配置示例"""
        example_window = tk.Toplevel(self.root)
        example_window.title("配置文件示例")
        example_window.geometry("600x400")

        example_text = """{
  "新规则示例": {
    "regex": "\\\\b[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}\\\\b",
    "description": "信用卡号码格式",
    "risk_level": "高",
    "enabled": true
  },
  "IP地址": {
    "regex": "\\\\b(?:[0-9]{1,3}\\\\.){3}[0-9]{1,3}\\\\b",
    "description": "IPv4地址",
    "risk_level": "中",
    "enabled": true
  }
}"""

        text_widget = scrolledtext.ScrolledText(example_window, wrap=tk.WORD)
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, example_text)
        text_widget.config(state='disabled')

    def clear_results(self):
        """清空结果显示"""
        # 清空统计信息
        for label in self.stats_labels.values():
            label.config(text="0")

        # 清空树形视图
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)

    def update_result_display(self):
        """更新结果显示"""
        if not self.scanner:
            return

        # 更新统计信息
        stats = self.scanner.stats
        for key, label in self.stats_labels.items():
            label.config(text=str(stats.get(key, 0)))

        # 更新详细结果
        self.result_tree.delete(*self.result_tree.get_children())

        # 按敏感信息类型分组
        pattern_summary = {}
        for file_path, file_results in self.scanner.results.items():
            for pattern_name, matches in file_results.items():
                if pattern_name not in pattern_summary:
                    pattern_summary[pattern_name] = []
                pattern_summary[pattern_name].extend(matches)

        # 添加到树形视图
        for pattern_name, matches in pattern_summary.items():
            pattern_info = self.scanner.patterns[pattern_name]
            risk_level = pattern_info["risk_level"]
            description = pattern_info["description"]
            count = len(matches)

            # 根据风险等级设置颜色
            if risk_level == "高":
                tags = ('high_risk',)
            elif risk_level == "中":
                tags = ('medium_risk',)
            else:
                tags = ('low_risk',)

            self.result_tree.insert('', 'end', values=(
                pattern_name, count, risk_level, description
            ), tags=tags)

        # 配置标签颜色
        self.result_tree.tag_configure('high_risk', foreground='red')
        self.result_tree.tag_configure('medium_risk', foreground='orange')
        self.result_tree.tag_configure('low_risk', foreground='green')

    def on_tree_double_click(self, event):
        """树形视图双击事件"""
        item = self.result_tree.selection()[0]
        values = self.result_tree.item(item, 'values')
        pattern_name = values[0]

        # 显示详细信息
        self.show_pattern_details(pattern_name)

    def show_pattern_details(self, pattern_name):
        """显示敏感信息详细信息"""
        if not self.scanner or pattern_name not in self.scanner.patterns:
            return

        # 创建详细信息窗口
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"详细信息 - {pattern_name}")
        detail_window.geometry("700x500")

        # 创建文本框显示详细信息
        text_widget = scrolledtext.ScrolledText(detail_window, wrap=tk.WORD)
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)

        # 收集该类型的所有匹配信息
        matches_info = []
        for file_path, file_results in self.scanner.results.items():
            if pattern_name in file_results:
                for match, line_num in file_results[pattern_name]:
                    matches_info.append((file_path, match, line_num))

        # 显示详细信息
        text_widget.insert(tk.END, f"敏感信息类型: {pattern_name}\n")
        text_widget.insert(tk.END, f"描述: {self.scanner.patterns[pattern_name]['description']}\n")
        text_widget.insert(tk.END, f"风险等级: {self.scanner.patterns[pattern_name]['risk_level']}\n")
        text_widget.insert(tk.END, f"发现数量: {len(matches_info)}\n")
        text_widget.insert(tk.END, "-" * 50 + "\n\n")

        # 按文件分组显示
        file_groups = {}
        for file_path, match, line_num in matches_info:
            if file_path not in file_groups:
                file_groups[file_path] = []
            file_groups[file_path].append((match, line_num))

        for file_path, matches in file_groups.items():
            text_widget.insert(tk.END, f"文件: {file_path}\n")
            for match, line_num in matches:
                text_widget.insert(tk.END, f"  行 {line_num}: {match}\n")
            text_widget.insert(tk.END, "\n")

        text_widget.config(state='disabled')

    def show_about(self):
        """显示关于信息"""
        about_window = tk.Toplevel(self.root)
        about_window.title("关于 - 敏感信息提取工具")
        about_window.geometry("500x400")
        about_window.resizable(False, False)

        # 居中显示
        about_window.transient(self.root)
        about_window.grab_set()

        # 标题
        title_label = ttk.Label(about_window, text="🔍 敏感信息提取工具",
                                font=('Arial', 16, 'bold'))
        title_label.pack(pady=20)

        # 版本信息
        version_label = ttk.Label(about_window, text="版本: 3.0.0",
                                  font=('Arial', 12))
        version_label.pack(pady=5)

        # 作者信息
        author_label = ttk.Label(about_window, text="作者: 慕鸢",
                                 font=('Arial', 12, 'bold'),
                                 foreground='#2E86AB')
        author_label.pack(pady=5)

        # 描述信息
        desc_text = """
一个功能强大的敏感信息扫描工具

✨ 主要特性：
• 多线程并发处理，支持2/4/8/16线程
• 友好的GUI界面，实时进度显示
• 配置文件分离，规则可自定义
• 支持多种文件格式和编码
• 风险等级分类，便于问题定位
• 详细的Markdown格式报告

🔒 安全承诺：
• 仅本地处理，不上传任何数据
• 只读取文件内容，不进行修改
• 开源透明，代码可审计

💡 使用建议：
• 请在合法合规的范围内使用
• 建议用于安全检测和代码审计
• 生成的报告请妥善保管
        """

        desc_frame = ttk.Frame(about_window)
        desc_frame.pack(fill='both', expand=True, padx=20, pady=10)

        desc_text_widget = tk.Text(desc_frame, wrap=tk.WORD, height=12, width=50,
                                   font=('Arial', 10), relief='flat',
                                   bg='#f0f0f0', borderwidth=0)
        desc_text_widget.pack(fill='both', expand=True)
        desc_text_widget.insert('1.0', desc_text)
        desc_text_widget.config(state='disabled')

        # 底部信息
        bottom_frame = ttk.Frame(about_window)
        bottom_frame.pack(fill='x', padx=20, pady=10)

        license_label = ttk.Label(bottom_frame, text="许可证: MIT License",
                                  font=('Arial', 9))
        license_label.pack(side='left')

        copyright_label = ttk.Label(bottom_frame, text="© 2025 慕鸢",
                                    font=('Arial', 9))
        copyright_label.pack(side='right')

        # 关闭按钮
        close_button = ttk.Button(about_window, text="关闭",
                                  command=about_window.destroy)
        close_button.pack(pady=10)

        # 居中显示窗口
        about_window.update_idletasks()
        x = (about_window.winfo_screenwidth() // 2) - (about_window.winfo_width() // 2)
        y = (about_window.winfo_screenheight() // 2) - (about_window.winfo_height() // 2)
        about_window.geometry(f"+{x}+{y}")

    def on_closing(self):
        """窗口关闭事件"""
        if self.scanner and self.scanner.is_scanning:
            if messagebox.askokcancel("退出", "扫描正在进行中，确定要退出吗？"):
                self.scanner.cancel_scan()
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    """主函数"""
    print("🔍 敏感信息提取工具 v3.0 - by 慕鸢")
    print("=" * 40)
    print("正在启动GUI界面...")

    root = tk.Tk()
    app = SensitiveInfoGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()