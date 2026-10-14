# -*- coding: utf-8 -*-
"""
WinRing0 驱动封装（直接 IOCTL，不依赖 WinRing0x64.dll 的自动安装）
- 自行安装/启动 WinRing0x64.sys 内核驱动（sc create/start）
- 打开设备句柄 \\\\.\\WinRing0_1_2_0
- 通过 DeviceIoControl 读写 MSR

IOCTL 定义（来自 OpenLibSys OlsIoctl.h）：
  OLS_TYPE = 40000
  IOCTL_OLS_READ_MSR  = CTL_CODE(40000, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x9C402084
  IOCTL_OLS_WRITE_MSR = CTL_CODE(40000, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x9C402088
"""
import ctypes
import ctypes.wintypes as wt
import filecmp
import os
import shutil
import struct
import subprocess
import sys

DRIVER_ID = "IntelUndervoltWinRing0"
DRIVER_FILE_NAME = "IntelUndervoltWinRing0x64.sys"
PACKAGED_DRIVER_FILE_NAME = "WinRing0x64.sys"
DEVICE_NAME = r"\\.\WinRing0_1_2_0"
IOCTL_READ_MSR = 0x9C402084
IOCTL_WRITE_MSR = 0x9C402088

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_h = None  # device handle
_managed_service_active = False


class WinRing0Error(Exception):
    pass


def _base_dir():
    if getattr(sys, "frozen", False):
        # onefile 模式下打包的附加文件在 _MEIPASS 临时目录
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass and os.path.exists(
                os.path.join(meipass, PACKAGED_DRIVER_FILE_NAME)):
            return meipass
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def sys_path():
    return os.path.join(_base_dir(), PACKAGED_DRIVER_FILE_NAME)


def _driver_destination():
    return os.path.join(
        os.environ.get("WINDIR", r"C:\Windows"),
        "System32", "drivers", DRIVER_FILE_NAME,
    )


def is_loaded():
    return _h is not None


def _run_sc(*args):
    """调用 SCM；参数列表避免 shell 引号和本地化输出造成误判。"""
    kwargs = {
        "capture_output": True,
        "text": True,
        "errors": "replace",
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    r = subprocess.run(["sc.exe", *args], **kwargs)
    return r.returncode, (r.stdout + r.stderr).strip()


def _driver_installed():
    rc, _ = _run_sc("query", DRIVER_ID)
    return rc == 0


def _driver_running():
    rc, out = _run_sc("query", DRIVER_ID)
    if rc != 0:
        return False
    normalized = out.upper()
    return "RUNNING" in normalized or "运行" in out


def _files_match(src, dst):
    return os.path.isfile(dst) and filecmp.cmp(src, dst, shallow=False)


def _sc_error(action, rc, output, driver_path):
    detail = output or "sc.exe 未返回详细信息"
    hint = ""
    if rc == 2 or "失败 2" in detail or "FAILED 2" in detail.upper():
        hint = ("\nWindows 仍报告文件不存在；请检查安全软件是否隔离了驱动：%s"
                % driver_path)
    return WinRing0Error(
        "%s失败（sc.exe 返回码 %d）: %s%s" % (action, rc, detail, hint))


def _ensure_driver():
    """确保 WinRing0x64.sys 已复制到 drivers 目录并作为服务运行。"""
    src = sys_path()
    if not os.path.isfile(src):
        raise WinRing0Error("未找到 WinRing0x64.sys（请与程序放在同一目录）")

    dst = _driver_destination()
    try:
        # 比较完整内容，避免同尺寸的旧版或损坏文件被误认为有效。
        if not _files_match(src, dst):
            shutil.copyfile(src, dst)
    except Exception as e:
        raise WinRing0Error("复制驱动到 %s 失败: %s" % (dst, e))
    if not os.path.isfile(dst):
        raise WinRing0Error("驱动复制后仍不存在: %s" % dst)

    if not _driver_installed():
        rc, out = _run_sc(
            "create", DRIVER_ID,
            "type=", "kernel", "start=", "demand", "binPath=", dst,
        )
        # 另一进程可能恰好先完成创建；用查询结果判断，不依赖中英文提示。
        if rc != 0 and not _driver_installed():
            raise _sc_error("创建驱动服务", rc, out, dst)

    # 即使服务已经存在，也必须修正 ImagePath。旧版 onefile 程序可能把它
    # 留在已删除的 _MEI 临时目录，随后 StartService 就会返回错误 2。
    rc, out = _run_sc(
        "config", DRIVER_ID,
        "type=", "kernel", "start=", "demand", "binPath=", dst,
    )
    if rc != 0:
        raise _sc_error("校正驱动服务路径", rc, out, dst)

    if not _driver_running():
        rc, out = _run_sc("start", DRIVER_ID)
        if rc != 0 and not _driver_running():
            raise _sc_error("启动驱动服务", rc, out, dst)


def _open_device():
    global _h
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, wt.DWORD, wt.DWORD, ctypes.c_void_p,
        wt.DWORD, wt.DWORD, ctypes.c_void_p,
    ]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    h = kernel32.CreateFileW(
        DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 3, None,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None,
    )
    if h == INVALID_HANDLE_VALUE or not h:
        err = ctypes.get_last_error()
        raise WinRing0Error("打开驱动设备 %s 失败 (错误码 %d)" % (DEVICE_NAME, err))
    _h = h


def _ioctl(ioctl_code, inbuf, out_size=0):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.DeviceIoControl.restype = wt.BOOL
    kernel32.DeviceIoControl.argtypes = [
        ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, wt.DWORD,
        ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p,
    ]
    returned = wt.DWORD(0)
    outbuf = ctypes.create_string_buffer(max(out_size, 1))
    ok = kernel32.DeviceIoControl(
        _h, ioctl_code, inbuf, len(inbuf) if inbuf else 0,
        outbuf, out_size, ctypes.byref(returned), None,
    )
    if not ok:
        raise WinRing0Error("DeviceIoControl(0x%X) 失败" % ioctl_code)
    return outbuf.raw[:returned.value]


def load():
    """安装/启动驱动并打开设备句柄。"""
    global _h, _managed_service_active
    if _h is not None:
        return True

    # 其他硬件工具可能已经加载了兼容 WinRing0。先复用现有设备，避免
    # 修改或停止第三方的同名服务；仅管理本程序自己的独立服务。
    try:
        _open_device()
        _managed_service_active = _driver_running()
        return True
    except WinRing0Error:
        _h = None

    _ensure_driver()
    _managed_service_active = True
    _open_device()
    return True


def unload():
    """关闭句柄并停止驱动服务（与应用退出保持同步，减小反作弊检测面）。"""
    global _h, _managed_service_active
    if _h is not None:
        try:
            ctypes.WinDLL("kernel32").CloseHandle(_h)
        except Exception:
            pass
        _h = None
    # 只停止本程序管理的独立服务，不干预其他软件加载的 WinRing0。
    if _managed_service_active:
        try:
            _run_sc("stop", DRIVER_ID)
        except Exception:
            pass
    _managed_service_active = False


def rdmsr(reg):
    """读取 64 位 MSR。"""
    if _h is None:
        raise WinRing0Error("WinRing0 尚未加载")
    inbuf = struct.pack("<I", reg)
    out = _ioctl(IOCTL_READ_MSR, inbuf, 8)
    return struct.unpack("<Q", out[:8])[0]


def wrmsr(reg, value):
    """写入 64 位 MSR。"""
    if _h is None:
        raise WinRing0Error("WinRing0 尚未加载")
    inbuf = struct.pack("<IQ", reg, value & 0xFFFFFFFFFFFFFFFF)
    _ioctl(IOCTL_WRITE_MSR, inbuf, 0)
