# -*- coding: utf-8 -*-
"""
PawnIO 读取层 - 替代 WinRing0 的监控读取
只读取白名单内的寄存器，不会蓝屏
写操作仍然走 WinRing0（msr.py 里的 wrmsr）
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import threading
import time

# 全局状态
_pawnio = None
_pawnio_lock = threading.RLock()
_init_failed = False
_init_error = ""


class PawnIOError(Exception):
    pass


def _get_resource_path(filename):
    """获取资源文件路径（兼容 PyInstaller 打包和源码模式）"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


class _PawnIO:
    """PawnIO 用户态 DLL 封装"""

    def __init__(self, dll_path=None, bin_path=None):
        if dll_path is None:
            dll_path = _get_resource_path("pawnio.dll")
        if bin_path is None:
            bin_path = _get_resource_path("IntelMSR.bin")

        if not os.path.exists(dll_path):
            raise PawnIOError(f"pawnio.dll 不存在: {dll_path}")

        self.lib = ctypes.WinDLL(dll_path)

        # 函数原型
        self.lib.pawnio_version.argtypes = [ctypes.POINTER(wt.ULONG)]
        self.lib.pawnio_open.argtypes = [ctypes.POINTER(wt.HANDLE)]
        self.lib.pawnio_load.argtypes = [
            wt.HANDLE,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_size_t
        ]
        self.lib.pawnio_execute.argtypes = [
            wt.HANDLE,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t)
        ]
        self.lib.pawnio_close.argtypes = [wt.HANDLE]

        # 打开驱动
        self.handle = wt.HANDLE()
        ret = self.lib.pawnio_open(ctypes.byref(self.handle))
        if not self.handle:
            raise PawnIOError(f"pawnio_open 失败 (ret={ret})，驱动未安装")

        # 加载 IntelMSR 模块
        if not os.path.exists(bin_path):
            raise PawnIOError(f"IntelMSR.bin 不存在: {bin_path}")
        with open(bin_path, "rb") as f:
            mod_data = f.read()
        mod_buf = (ctypes.c_ubyte * len(mod_data))(*mod_data)
        ret = self.lib.pawnio_load(self.handle, mod_buf, len(mod_data))
        if ret != 0:
            raise PawnIOError(f"pawnio_load 失败 (ret={ret})")

    def read_msr(self, reg):
        """读单个 MSR 寄存器，返回 64 位整数值"""
        in_array = (ctypes.c_uint64 * 1)(reg)
        out_array = (ctypes.c_uint64 * 1)()
        return_size = ctypes.c_size_t()

        ret = self.lib.pawnio_execute(
            self.handle,
            b"ioctl_read_msr",
            in_array, 1,
            out_array, 1,
            ctypes.byref(return_size)
        )
        if ret != 0:
            raise PawnIOError(f"ioctl_read_msr(0x{reg:X}) 失败 ret={ret}")
        return out_array[0]

    def close(self):
        if hasattr(self, 'handle') and self.handle:
            self.lib.pawnio_close(self.handle)
            self.handle = None


def _try_install_driver():
    """尝试静默安装 PawnIO 驱动。成功返回 True。"""
    setup_path = _get_resource_path("PawnIO_setup.exe")
    if not os.path.exists(setup_path):
        return False
    try:
        # PawnIO 静默安装参数：-install -silent
        subprocess.run(
            [setup_path, "-install", "-silent"],
            timeout=60,
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        time.sleep(3)  # 等驱动服务启动
        return True
    except Exception:
        return False


def init():
    """初始化 PawnIO。成功返回 True，失败返回 False。"""
    global _pawnio, _init_failed, _init_error
    if _pawnio is not None:
        return True
    if _init_failed:
        return False

    # 第一次尝试
    try:
        _pawnio = _PawnIO()
        return True
    except Exception as e:
        _init_error = str(e)

    # 第一次失败，尝试自动安装驱动
    if _try_install_driver():
        try:
            _pawnio = _PawnIO()
            _init_error = ""
            return True
        except Exception as e:
            _init_error = f"驱动安装后仍失败: {e}"

    _init_failed = True
    return False


def is_available():
    """PawnIO 是否可用"""
    return _pawnio is not None


def get_error():
    """获取初始化错误信息"""
    return _init_error


def read_msr(reg):
    """读 MSR，优先用 PawnIO，失败抛异常"""
    with _pawnio_lock:
        if _pawnio is None:
            raise PawnIOError("PawnIO 未初始化")
        return _pawnio.read_msr(reg)


def try_read_msr(reg):
    """尝试读 MSR，失败返回 None（不抛异常）"""
    try:
        return read_msr(reg)
    except Exception:
        return None


# ---------- 白名单判断 ----------
# 这些寄存器 PawnIO IntelMSR.bin 支持读取
PAWNIO_READABLE = {
    0x198,  # PERF_STATUS
    0x19C,  # THERM_STATUS
    0x606,  # RAPL_POWER_UNIT
    0x611,  # PKG_ENERGY_STATUS
    0x1A2,  # TEMPERATURE_TARGET
    0x0CE,  # PLATFORM_INFO
    0x1AD,  # TURBO_RATIO_LIMIT (P核)
    0x150,  # FIVR / PLATFORM_INFO
    0x1B1,  # TEMPERATURE_TARGET_1B1
}


def can_use_pawnio(reg):
    """判断该寄存器能否用 PawnIO 读"""
    return reg in PAWNIO_READABLE


def close():
    global _pawnio
    if _pawnio:
        _pawnio.close()
        _pawnio = None
