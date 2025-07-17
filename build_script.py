#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
敏感信息提取工具打包脚本
支持Windows、Linux、macOS多平台打包
"""

import os
import sys
import shutil
import subprocess
import platform
from pathlib import Path


def check_pyinstaller():
    """检查是否安装了PyInstaller"""
    try:
        import PyInstaller
        return True
    except ImportError:
        return False


def install_pyinstaller():
    """安装PyInstaller"""
    print("正在安装PyInstaller...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("PyInstaller安装完成")
        return True
    except subprocess.CalledProcessError:
        print("PyInstaller安装失败")
        return False


def get_platform_info():
    """获取平台信息"""
    system = platform.system().lower()
    arch = platform.machine().lower()

    if system == "windows":
        return "windows", "exe"
    elif system == "darwin":
        return "macos", "app"
    elif system == "linux":
        return "linux", ""
    else:
        return system, ""


def create_spec_file():
    """创建PyInstaller spec文件"""
    spec_content = """
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['sensitive_extractor.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('patterns.json', '.'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SensitiveInfoExtractor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico' if os.path.exists('icon.ico') else None,
)
"""

    with open('sensitive_extractor.spec', 'w', encoding='utf-8') as f:
        f.write(spec_content)

    print("已创建spec文件")


def build_executable():
    """构建可执行文件"""
    platform_name, ext = get_platform_info()

    print(f"正在为 {platform_name} 平台构建可执行文件...")

    # 创建spec文件
    create_spec_file()

    # 构建命令
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--onefile",
        "--windowed" if platform_name != "linux" else "--console",
        "--name", "SensitiveInfoExtractor",
        "--add-data", "patterns.json:." if platform_name != "windows" else "patterns.json;.",
    ]

    # 添加图标（如果存在）
    if os.path.exists("icon.ico"):
        cmd.extend(["--icon", "icon.ico"])

    cmd.append("sensitive_extractor.py")

    try:
        subprocess.check_call(cmd)
        print(f"构建完成！可执行文件位于 dist/ 目录")
        return True
    except subprocess.CalledProcessError as e:
        print(f"构建失败: {e}")
        return False


def create_release_package():
    """创建发布包"""
    platform_name, ext = get_platform_info()

    # 创建发布目录
    release_dir = Path(f"release/{platform_name}")
    release_dir.mkdir(parents=True, exist_ok=True)

    # 复制可执行文件
    dist_dir = Path("dist")
    if dist_dir.exists():
        for file in dist_dir.glob("*"):
            if file.is_file():
                shutil.copy2(file, release_dir)

    # 复制配置文件
    shutil.copy2("patterns.json", release_dir)

    # 复制说明文件
    if os.path.exists("README.md"):
        shutil.copy2("README.md", release_dir)

    print(f"发布包已创建在 {release_dir}")


def clean_build():
    """清理构建文件"""
    dirs_to_remove = ["build", "dist", "__pycache__"]
    files_to_remove = ["*.spec"]

    for dir_name in dirs_to_remove:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"已删除 {dir_name}")

    import glob
    for pattern in files_to_remove:
        for file in glob.glob(pattern):
            os.remove(file)
            print(f"已删除 {file}")


def main():
    """主函数"""
    print("=" * 50)
    print("🔍 敏感信息提取工具打包脚本")
    print("=" * 50)

    # 检查必要文件
    if not os.path.exists("sensitive_extractor.py"):
        print("❌ 错误: 找不到 sensitive_extractor.py")
        sys.exit(1)

    if not os.path.exists("patterns.json"):
        print("❌ 错误: 找不到 patterns.json")
        sys.exit(1)

    # 检查PyInstaller
    if not check_pyinstaller():
        print("⚠️  PyInstaller未安装")
        if input("是否安装PyInstaller? (y/N): ").lower() in ['y', 'yes']:
            if not install_pyinstaller():
                sys.exit(1)
        else:
            sys.exit(1)

    # 获取平台信息
    platform_name, ext = get_platform_info()
    print(f"🔧 检测到平台: {platform_name}")

    # 清理之前的构建
    print("🧹 清理之前的构建文件...")
    clean_build()

    # 构建可执行文件
    print("🔨 开始构建...")
    if build_executable():
        print("✅ 构建成功！")

        # 创建发布包
        print("📦 创建发布包...")
        create_release_package()

        print("🎉 打包完成！")
        print(f"📁 发布包位置: release/{platform_name}/")

        # 显示文件大小
        dist_dir = Path("dist")
        if dist_dir.exists():
            for file in dist_dir.glob("*"):
                if file.is_file():
                    size = file.stat().st_size / 1024 / 1024  # MB
                    print(f"📄 {file.name}: {size:.2f} MB")
    else:
        print("❌ 构建失败")
        sys.exit(1)


if __name__ == "__main__":
    main()