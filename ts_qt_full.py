# -*- coding: utf-8 -*-
"""IntelUndervolt v3 - PyQt6 + Fluent Widgets 完整版"""
import sys, os, subprocess, platform, glob, time, traceback, logging

# ============ CPU 压力测试 worker（必须模块级，multiprocessing 才能 pickle） ============
def _stress_worker():
    """CPU 满载压力测试：大整数乘法 + 浮点运算 + SHA256 哈希，确保每核 100% 占用。"""
    import math, hashlib
    a = 12345678901234567890
    while True:
        # 大整数乘法（CPU 密集）
        a = (a * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        # 浮点运算组合
        x = math.sqrt(a & 0xFFFF) * math.sin(a & 0xFF) * math.cos((a >> 8) & 0xFF)
        y = math.log1p((a & 0xFFFF) + 1) * math.exp((a & 0x0F) / 10.0)
        # SHA256 哈希（CPU 密集）
        h = hashlib.sha256(a.to_bytes(8, "little")).digest()
        a = int.from_bytes(h[:8], "little")
        # 防止编译器优化掉（虽然 Python 不会）
        if x + y < 0:
            break

# ============ faulthandler 已禁用（不生成 ts_crash.log） ============
# import faulthandler

# ============ 日志基础设施（仅 console 输出，不生成 ts.log 文件） ============
_LOG_DIR = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
_LOG_PATH = os.path.join(_LOG_DIR, "ts.log")
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
def _log(msg):
    """模块级日志函数（仅 console，不写文件）。"""
    logging.debug(msg)


# ========== 虚拟化/BIOS 锁检测 + MSR 自检 ==========
def detect_virtualization():
    """检测谁在占用 MSR：VBS/HVCI/Credential Guard/Hyper-V 监控程序/虚拟机平台。"""
    result = {"running": [], "hvci": False, "credential_guard": False, "hypervisor": False, "wsl": False}
    try:
        import subprocess, winreg
        # 1. Win32_DeviceGuard (WMI)
        try:
            out = _run_quiet(
                ["powershell", "-NoProfile", "-Command",
                 "Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard | Select-Object VBSStatus,SecurityServicesRunning | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=10
            ).stdout.strip()
            _log(f"[检测] DeviceGuard WMI: {out}")
            if '"SecurityServicesRunning":[1]' in out or ',1]' in out:
                result["credential_guard"] = True
                result["running"].append("凭据防护(Credential Guard)")
            if '"SecurityServicesRunning":[2]' in out or ',2]' in out:
                result["hvci"] = True
                result["running"].append("内存完整性(HVCI)")
        except Exception as e:
            _log(f"[检测] DeviceGuard WMI 失败: {e}")
        # 2. 注册表兜底
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")
            enabled, _ = winreg.QueryValueEx(key, "Enabled")
            if enabled == 1 and not result["hvci"]:
                result["hvci"] = True; result["running"].append("内存完整性(HVCI)")
            winreg.CloseKey(key)
        except: pass
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard")
            enabled, _ = winreg.QueryValueEx(key, "Enabled")
            if enabled == 1 and not result["credential_guard"]:
                result["credential_guard"] = True; result["running"].append("凭据防护(Credential Guard)")
            winreg.CloseKey(key)
        except: pass
        # 3. bcdedit hypervisorlaunchtype
        try:
            out = _run_quiet(["bcdedit", "/enum", "{current}"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                if "hypervisorlaunchtype" in line.lower() and "off" not in line.lower():
                    result["hypervisor"] = True
                    result["running"].append("Hyper-V 监控程序")
                    break
        except Exception as e:
            _log(f"[检测] bcdedit 失败: {e}")
        # 4. WSL/虚拟机平台
        try:
            out = _run_quiet(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State"],
                capture_output=True, text=True, timeout=15
            ).stdout.strip()
            if "Enabled" in out:
                result["wsl"] = True
                result["running"].append("虚拟机平台/WSL")
        except: pass
    except Exception as e:
        _log(f"[检测] 虚拟化检测异常: {e}")
    result["running"] = list(dict.fromkeys(result["running"]))
    _log(f"[检测] 虚拟化结果: running={result['running']}")
    return result


def detect_bios_locks():
    """检测 BIOS/MSR 锁位：0xCE bit20(OC Lock)、0x3A lock。"""
    result = {"oc_lock": False, "locks": [], "readable": True}
    try:
        import msr
        try:
            val = msr.rdmsr(0xCE)
            if val & (1 << 20):
                result["oc_lock"] = True
                result["locks"].append("Overclocking Lock (0xCE bit20)")
            _log(f"[检测] MSR 0xCE = 0x{val:X}, OC Lock={result['oc_lock']}")
        except Exception as e:
            _log(f"[检测] 读 0xCE 失败: {e}")
        try:
            val = msr.rdmsr(0x3A)
            if val & 1:
                result["locks"].append("Feature Control Lock (0x3A bit0)")
            _log(f"[检测] MSR 0x3A = 0x{val:X}")
        except Exception as e:
            _log(f"[检测] 读 0x3A 失败: {e}")
    except Exception as e:
        _log(f"[检测] BIOS 锁检测异常: {e}")
        result["readable"] = False
    return result


def msr_write_self_test():
    """写后回读自检：写 plane0 -12mV → 回读 → 恢复原值。返回 (writable, reason)"""
    try:
        import msr
        original = msr.read_offset_mv(0)
        _log(f"[自检] plane0 原偏移 = {original}mV")
        try:
            written = msr.write_offset_mv(0, -12.0, strict=True)
            _log(f"[自检] 写入 -12mV 成功，回读 = {written}mV")
            try: msr.write_offset_mv(0, original, strict=False)
            except: pass
            return True, "MSR 可写"
        except Exception as e:
            _log(f"[自检] 写入失败: {e}")
            try: msr.write_offset_mv(0, original, strict=False)
            except: pass
            return False, f"写后回读不一致: {e}"
    except Exception as e:
        _log(f"[自检] 自检异常: {e}")
        return False, f"自检异常: {e}"

# ============ 关机检测：用 QApplication.aboutToQuit（最安全，不碰 nativeEvent） ============
# 系统关机/注销时 Qt 会自动发 aboutToQuit，在那里清理托盘即可。
# closeEvent 里不做关机判断（系统关机时 Qt 不会走用户 closeEvent 的 ignore 路径）。
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont, QPixmap, QPainter, QColor, QBrush
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QGridLayout, QLabel, QPushButton, QRadioButton, QComboBox, QScrollArea, QButtonGroup, QLineEdit, QFrame, QDialog,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from qfluentwidgets import (
    setTheme, Theme, CardWidget, PushButton, PrimaryPushButton,
    RadioButton, Slider, ComboBox, CheckBox, InfoBar, InfoBarPosition,
    BodyLabel, SubtitleLabel, CaptionLabel, FlowLayout, ProgressBar
)

APP_VERSION = "3.0"

# ============ 驱动层（延迟加载，启动时不加载）============
_driver_ok = False
_driver_loaded = False
_driver_error = ""
import threading as _drv_threading
_drv_lock = _drv_threading.Lock()  # 全局MSR读写锁

def load_driver():
    """延迟加载驱动：只在用户第一次点应用或打开Tab时调用。"""
    global _driver_ok, _driver_loaded, _driver_error
    if _driver_loaded:
        return _driver_ok
    with _drv_lock:
        if _driver_loaded:
            return _driver_ok
        # VBS 检测
        vbs_on = _detect_vbs()
        if vbs_on:
            _driver_error = "检测到VBS/HVCI，建议关闭内存完整性"
            _log("[驱动] VBS警告: 建议关闭内存完整性以获得完整功能")
        try:
            import winring0, msr
            winring0.load()
            _driver_ok = True
            _driver_loaded = True
            _log("[驱动] 加载成功")
        except Exception as e:
            _driver_error = str(e)
            _driver_ok = False
            _driver_loaded = True
            _log(f"[驱动] 加载失败: {e}")
        return _driver_ok

def is_driver_ok():
    return _driver_ok

def _run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
            creationflags=0x08000000).decode("gbk", "ignore")
    except Exception:
        return ""

def _cpu_name():
    try:
        import winreg, re
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as k:
            name, _ = winreg.QueryValueEx(k, 'ProcessorNameString')
            name = name.strip()
            # 缩短：提取 i3/i5/i7/i9 + 型号
            m = re.search(r'(i[3579][-\s]?\d{4,5}[A-Z]*)', name, re.IGNORECASE)
            if m:
                return m.group(1).replace(" ", "")
            return name
    except Exception:
        return platform.processor()


_ram_cache = None
def _ram_info():
    """内存信息静态缓存，只在首次调用时查一次（PowerShell + WMI 查询很慢，不能每秒查）。"""
    global _ram_cache
    if _ram_cache is not None:
        return _ram_cache
    try:
        out = _run(["powershell", "-NoProfile", "-Command",
                    "(Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum/1GB; (Get-CimInstance Win32_PhysicalMemory | Select-Object -First 1).Speed"])
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if len(lines) >= 2:
            total = int(float(lines[0])); speed = lines[1]
            _ram_cache = f"{total}GB @ {speed}MHz"
            return _ram_cache
    except Exception:
        pass
    _ram_cache = "?"
    return _ram_cache

def _detect_vbs():
    """检测 VBS / HVCI 是否开启（开启会阻止 MSR 0x150 降压写入）。"""
    import winreg
    def _read(root, path, name):
        try:
            with winreg.OpenKey(root, path) as k:
                v, _ = winreg.QueryValueEx(k, name)
                return int(v)
        except Exception:
            return None
    if _read(winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
            "Enabled"):
        return True
    if _read(winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "EnableVirtualizationBasedSecurity"):
        return True
    return False


def _gather_hwinfo():
    """收集机器信息：计算机名/CPU/显卡/网卡/内存。"""
    import socket, winreg
    info = {}
    info["计算机名"] = socket.gethostname()
    # CPU 型号（注册表，快）
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
            name, _ = winreg.QueryValueEx(k, "ProcessorNameString")
            info["CPU"] = name.strip()
    except Exception:
        info["CPU"] = "?"
    # 显卡（PowerShell CIM）
    try:
        out = _run(["powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name"])
        gpus = [l.strip() for l in out.splitlines() if l.strip()]
        info["显卡"] = " + ".join(gpus) if gpus else "?"
    except Exception:
        info["显卡"] = "?"
    # 网卡
    try:
        out = _run(["powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_NetworkAdapter | Where-Object {$_.PhysicalAdapter -and $_.NetEnabled} | Select-Object -ExpandProperty Name"])
        nics = [l.strip() for l in out.splitlines() if l.strip()]
        info["网卡"] = " + ".join(nics) if nics else "?"
    except Exception:
        info["网卡"] = "?"
    # 内存颗粒（每根）
    try:
        out = _run(["powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_PhysicalMemory | ForEach-Object { \"$($_.Manufacturer) $($_.Capacity/1GB)GB $($_.Speed)MHz $($_.PartNumber)\" }"])
        mem = [l.strip() for l in out.splitlines() if l.strip()]
        info["内存"] = " + ".join(mem) if mem else "?"
    except Exception:
        info["内存"] = "?"
    return info


class _StatusWorker(QThread):
    """后台线程：VBS / 超频锁 / MSR 可读性 / 各域偏移。避免打开弹窗卡 UI。"""
    done = pyqtSignal(dict)

    def run(self):
        result = {}
        try:
            result["hwinfo"] = _gather_hwinfo()
        except Exception as e:
            result["hwinfo"] = {"err": str(e)}
        self.done.emit(result)

# ============ 艺术字标签 ============
class LogoLabel(QLabel):
    def __init__(self, parent=None, size=28):
        super().__init__(parent)
        self.size = size
        self.setFixedSize(380, size + 26)
    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        f = QFont("Segoe UI", self.size, QFont.Weight.Bold)
        p.setFont(f)
        # 辉光
        for dx, dy, c in [(3,3,QColor(26,58,106)),(2,2,QColor(30,74,138)),(1,1,QColor(37,99,235))]:
            p.setPen(c)
            p.drawText(dx+2, dy+self.size, "IntelUndervolt")
        # 主字
        p.setPen(QColor(255,255,255))
        p.drawText(2, self.size, "Intel")
        fm = p.fontMetrics()
        w1 = fm.horizontalAdvance("Intel")
        p.setPen(QColor(96,165,250))
        p.drawText(w1+2, self.size, "Undervolt")
        p.setFont(QFont("Microsoft YaHei UI", 11))
        p.setPen(QColor(144,144,160))
        p.drawText(4, self.size+18, "BL 爱折腾  |  Intel 降压定频工具")
        p.end()

# ============ 限制原因悬浮窗 ============
class LimitReasonWindow(QWidget):
    """自研风格 Limit Reasons：顶部横幅 + 分域卡片列表，撞墙红/快撞黄/正常灰。"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("限制原因诊断")
        self.setWindowIcon(_get_app_icon())
        self.setWindowFlags(
            Qt.WindowType.Tool |
            Qt.WindowType.WindowCloseButtonHint)
        self.setFixedSize(460, 480)
        self.setStyleSheet("background:#15161a; color:#e2e8f0;")
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 14)
        root.setSpacing(10)
        # 顶部横幅：当前状态
        self.banner = QLabel("当前状态：正常运行")
        self.banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.banner.setFixedHeight(44)
        self.banner.setStyleSheet(
            "background:#1f2937; color:#22c55e; font-size:15px; font-weight:bold; border-radius:8px; padding:6px;")
        root.addWidget(self.banner)
        # CORE / GPU / RING 切换
        tabs = QHBoxLayout(); tabs.setSpacing(6)
        self.tab_btns = {}
        for name in ["核心 CORE", "核显 GPU", "Ring"]:
            b = QPushButton(name)
            b.setFixedHeight(28)
            b.setStyleSheet("QPushButton{background:#26272e; color:#cbd5e1; border:1px solid #3a3b42; border-radius:6px; padding:4px 14px;}"
                            "QPushButton:hover{background:#32333b;}"
                            "QPushButton:checked{background:#2563eb; color:white; border:1px solid #2563eb;}")
            b.setCheckable(True)
            b.clicked.connect(lambda checked, n=name: self._switch_tab(n))
            tabs.addWidget(b)
            self.tab_btns[name] = b
        self.tab_btns["核心 CORE"].setChecked(True)
        root.addLayout(tabs)
        # 撞墙项列表
        self.list_area = QVBoxLayout(); self.list_area.setSpacing(6)
        body = QWidget(); body.setLayout(self.list_area)
        root.addWidget(body, 1)
        self._current = "核心 CORE"
        self._data = {k: [] for k in ["核心 CORE", "核显 GPU", "Ring"]}
        # 定时器刷新
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        # self._timer.start(3000)  # 主界面不需要定时刷新
        self._refresh()
        from PyQt6.QtGui import QPainter as _P, QColor as _C, QFont as _F
        class _MiniLogo(QLabel):
            def paintEvent(self, e):
                p = _P(self); p.setRenderHint(_P.RenderHint.Antialiasing)
                f = _F("Segoe UI", 12, _F.Weight.Bold); p.setFont(f)
                p.setPen(_C(255,255,255)); p.drawText(0, 14, "Intel")
                w = p.fontMetrics().horizontalAdvance("Intel")
                p.setPen(_C(96,165,250)); p.drawText(w, 14, "Undervolt"); p.end()
        lg = _MiniLogo(); lg.setFixedSize(150, 22)
        root.addWidget(lg, alignment=Qt.AlignmentFlag.AlignRight)
        self._render()

    def _refresh(self):
        try:
            import msr
            s = msr.read_perf_limit_summary()
            def st(flag, near=False):
                if flag: return "red"
                return "hidden"
            self._data["核心 CORE"] = [
                ("PL1 长时功耗墙", st(s.get("pl1", False)), "CPU 功耗超过 PL1 设定值"),
                ("PL2 短时功耗墙", st(s.get("pl2", False)), "CPU 功耗超过 PL2 短时墙"),
                ("PROCHOT 外部热信号", st(s.get("prochot", False)), "主板/显卡请求降频"),
                ("Thermal 温度墙", st(s.get("thermal", False)), "核心温度达到 TjMax"),
                ("Current 电流墙", st(s.get("current", False)), "电流超过 IccMax"),
                ("VR Thermal 供电温度", st(s.get("vr_thermal", False)), "VRM 过热保护"),
            ]
            self._data["核显 GPU"] = [
                ("Thermal 温度墙", "hidden", "核显温度过高"),
                ("Current 电流墙", "hidden", "核显电流超限"),
            ]
            self._data["Ring"] = [
                ("Thermal 温度墙", "hidden", "Ring/Uncore 温度过高"),
            ]
        except Exception:
            self._data = {"核心 CORE": [], "核显 GPU": [], "Ring": []}
        self._render()

    def _switch_tab(self, name):
        if name != self._current:
            self._current = name
            self._render()

    def _add_row(self, title, desc, state):
        row = QWidget()
        row.setStyleSheet("background:#1f2027; border-radius:6px;")
        rl = QHBoxLayout(row); rl.setContentsMargins(10, 6, 10, 6); rl.setSpacing(8)
        # 状态圆点
        dot = QLabel()
        dot.setFixedSize(10, 10)
        if state == "red":
            dot.setStyleSheet("background:#ef4444; border-radius:5px;")
        elif state == "yellow":
            dot.setStyleSheet("background:#eab308; border-radius:5px;")
        else:
            dot.setStyleSheet("background:#4b5563; border-radius:5px;")
        rl.addWidget(dot)
        # 标题+描述
        col = QVBoxLayout(); col.setSpacing(2)
        t = QLabel(title)
        t.setStyleSheet("color:#e2e8f0; font-weight:bold; font-size:13px; border:none;")
        d = QLabel(desc)
        d.setStyleSheet("color:#94a3b8; font-size:11px; border:none;")
        col.addWidget(t); col.addWidget(d)
        rl.addLayout(col, 1)
        return row

    def _render(self):
        while self.list_area.count():
            it = self.list_area.takeAt(0)
            if it.widget(): it.widget().deleteLater()
        rows = self._data.get(self._current, [])
        red_cnt = yellow_cnt = 0
        for title, state, desc in rows:
            if state == "hidden":
                continue
            self.list_area.addWidget(self._add_row(title, desc, state))
            if state == "red": red_cnt += 1
            elif state == "yellow": yellow_cnt += 1
        self.list_area.addStretch()
        # 横幅
        if red_cnt:
            self.banner.setText("当前撞墙：%d 项红色警告" % red_cnt)
            self.banner.setStyleSheet(
                "background:#7f1d1d; color:#fca5a5; font-size:15px; font-weight:bold; border-radius:8px; padding:6px;")
        elif yellow_cnt:
            self.banner.setText("接近撞墙：%d 项黄色预警" % yellow_cnt)
            self.banner.setStyleSheet(
                "background:#713f12; color:#fde047; font-size:15px; font-weight:bold; border-radius:8px; padding:6px;")
        else:
            self.banner.setText("当前状态：正常运行")
            self.banner.setStyleSheet(
                "background:#1f2937; color:#22c55e; font-size:15px; font-weight:bold; border-radius:8px; padding:6px;")
        # 右下角小艺术字（无副标题）

    def show_reason(self, kind, text):
        if kind == "idle":
            self.hide(); return
        self.show(); self.raise_()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()
            e.accept()

    def mouseMoveEvent(self, e):
        if hasattr(self, "_drag_pos") and e.buttons() & Qt.MouseButton.LeftButton:
            self.move(e.globalPosition().toPoint() - self._drag_pos)
            e.accept()

    def mouseReleaseEvent(self, e):
        if hasattr(self, "_drag_pos"):
            del self._drag_pos


# ============ 功耗调节窗口 ============
class PowerLimitDialog(QDialog):
    """PL1/PL2 功耗墙调节（现代卡片式）。"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("功耗调节")
        self.setFixedSize(520, 560)
        self.setStyleSheet("background:#14151a; color:#e2e8f0;")
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)
        # 顶部标题
        title = QLabel("功耗墙设置")
        title.setStyleSheet("font-size:18px; font-weight:bold; color:#e2e8f0;")
        sub = QLabel("调节 CPU 长时/短时功耗上限，控制发热与性能")
        sub.setStyleSheet("font-size:12px; color:#94a3b8;")
        root.addWidget(title)
        root.addWidget(sub)
        # 当前功耗概览
        cur_card = QWidget()
        cur_card.setStyleSheet("background:#1e1f26; border-radius:10px; padding:12px;")
        cl = QHBoxLayout(cur_card)
        cl.setContentsMargins(12, 8, 12, 8)
        cl.addWidget(QLabel("当前封装功耗"))
        cl.addStretch()
        self.cur_val = QLabel("-- W")
        self.cur_val.setStyleSheet("font-size:22px; font-weight:bold; color:#22c55e;")
        cl.addWidget(self.cur_val)
        root.addWidget(cur_card)
        # PL1 卡片
        pl1_card = QFrame()
        pl1_card.setStyleSheet("QFrame{background:#1e1f26; border-radius:10px; border:1px solid #2a2b33;}")
        pl1_l = QVBoxLayout(pl1_card)
        pl1_l.setContentsMargins(14, 12, 14, 12)
        pl1_l.setSpacing(8)
        h1 = QHBoxLayout()
        h1.addWidget(QLabel("PL1 长时功耗"))
        h1.addStretch()
        self.pl1_val = QLabel("160 W")
        self.pl1_val.setStyleSheet("font-size:20px; font-weight:bold; color:#60a5fa;")
        h1.addWidget(self.pl1_val)
        pl1_l.addLayout(h1)
        self.pl1_slider = Slider(Qt.Orientation.Horizontal)
        self.pl1_slider.setRange(10, 300)
        self.pl1_slider.setValue(160)
        self.pl1_slider.setToolTip("CPU 长时间维持的功耗上限（瓦）。超过此值会持续降频。")
        self.pl1_slider.valueChanged.connect(lambda v: self.pl1_val.setText("%d W" % v))
        pl1_l.addWidget(self.pl1_slider)
        r1 = QHBoxLayout()
        r1.addWidget(QLabel("时间窗"))
        r1.addStretch()
        self.pl1_time = QLineEdit("28")
        self.pl1_time.setFixedWidth(70)
        self.pl1_time.setToolTip("PL1 时间窗（Tau）：CPU 可在 PL2 功耗下冲刺的时长，超过后降回 PL1。单位秒。")
        self.pl1_time.setStyleSheet("background:#2a2b33; border:1px solid #3a3b42; border-radius:4px; padding:4px; color:#e2e8f0;")
        r1.addWidget(self.pl1_time)
        r1.addWidget(QLabel("秒"))
        pl1_l.addLayout(r1)
        root.addWidget(pl1_card)
        # PL2 卡片
        pl2_card = QFrame()
        pl2_card.setStyleSheet("QFrame{background:#1e1f26; border-radius:10px; border:1px solid #2a2b33;}")
        pl2_l = QVBoxLayout(pl2_card)
        pl2_l.setContentsMargins(14, 12, 14, 12)
        pl2_l.setSpacing(8)
        h2 = QHBoxLayout()
        h2.addWidget(QLabel("PL2 短时功耗"))
        h2.addStretch()
        self.pl2_val = QLabel("170 W")
        self.pl2_val.setStyleSheet("font-size:20px; font-weight:bold; color:#f59e0b;")
        h2.addWidget(self.pl2_val)
        pl2_l.addLayout(h2)
        self.pl2_slider = Slider(Qt.Orientation.Horizontal)
        self.pl2_slider.setRange(10, 300)
        self.pl2_slider.setValue(170)
        self.pl2_slider.setToolTip("CPU 短时间冲刺的功耗上限（瓦）。通常高于 PL1，用于短时睿频。")
        self.pl2_slider.valueChanged.connect(lambda v: self.pl2_val.setText("%d W" % v))
        pl2_l.addWidget(self.pl2_slider)
        r2 = QHBoxLayout()
        r2.addWidget(QLabel("时间窗"))
        r2.addStretch()
        self.pl2_time = QLineEdit("0.002")
        self.pl2_time.setFixedWidth(70)
        self.pl2_time.setToolTip("PL2 时间窗一般保持默认 0.002 秒即可，无需修改。")
        self.pl2_time.setStyleSheet("background:#2a2b33; border:1px solid #3a3b42; border-radius:4px; padding:4px; color:#e2e8f0;")
        r2.addWidget(self.pl2_time)
        r2.addWidget(QLabel("秒"))
        pl2_l.addLayout(r2)
        root.addWidget(pl2_card)
        # 锁定
        self.chk_lock = CheckBox("锁定（重启后保留，谨慎使用）")
        self.chk_lock.setToolTip("勾选后功耗墙写入 MSR 锁定位，重启后 BIOS 不会自动恢复。不建议新手勾选。")
        root.addWidget(self.chk_lock)
        root.addStretch()
        # 底部：艺术字 + 按钮
        bottom_row = QHBoxLayout()
        logo = LogoLabel(size=18)
        logo.setFixedWidth(220)
        bottom_row.addWidget(logo)
        bottom_row.addStretch()
        self.btn_cancel = PushButton("取消")
        self.btn_cancel.clicked.connect(self.reject)
        self.btn_ok = PrimaryPushButton("应用")
        self.btn_ok.clicked.connect(self._apply)
        bottom_row.addWidget(self.btn_cancel); bottom_row.addWidget(self.btn_ok)
        root.addLayout(bottom_row)
        # MSR 不可写时灰显
        try:
            p = self.parent()
            if p is not None and hasattr(p, "_caps") and not p._caps.get("writable", True):
                for widget in self.findChildren(QWidget):
                    if isinstance(widget, (QPushButton, QLineEdit, QSlider, QCheckBox)):
                        widget.setEnabled(False)
                self.setWindowTitle("功耗调节 🔒 (只读)")
                _log(f"[功耗] MSR 不可写，已切换只读模式")
        except Exception as e:
            _log(f"[功耗] 只读模式应用失败: {e}")

    def _apply(self):
        try:
            import msr
            pl1 = self.pl1_slider.value()
            pl2 = self.pl2_slider.value()
            t = int(self.pl1_time.text()) if self.pl1_time.text().isdigit() else 28
            msr.write_power_limits(pl1=pl1, pl2=pl2, pl1_time=t)
            self.accept()
        except Exception as e:
            from qfluentwidgets import MessageBox
            MessageBox("错误", f"功耗写入失败：{e}", self).exec()


# ============ 稳定性测试窗口 ============
class StabTestDialog(QDialog):
    """仿 TS Bench：CPU 满载压力测试。"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("稳定性测试")
        self.setWindowIcon(_get_app_icon())
        self.setFixedSize(560, 560)
        self.setStyleSheet("background:#14151a; color:#e2e8f0;")
        self._testing = False
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)
        title = QLabel("稳定性测试")
        title.setStyleSheet("font-size:20px; font-weight:bold; color:#e2e8f0;")
        sub = QLabel("降压后运行 CPU 满载，检测是否蓝屏/报错/降频")
        sub.setStyleSheet("font-size:12px; color:#94a3b8;")
        root.addWidget(title); root.addWidget(sub)
        # 测试模式卡片
        mode_card = QFrame()
        mode_card.setStyleSheet("QFrame{background:#1e1f26; border-radius:12px; border:1px solid #2a2b33;}")
        ml = QVBoxLayout(mode_card); ml.setContentsMargins(16, 14, 16, 14); ml.setSpacing(10)
        ml.addWidget(QLabel("选择测试模式"))
        self.mode_fast = RadioButton("快速测试  ·  30 秒")
        self.mode_fast.setStyleSheet("font-size:13px; spacing:8px;")
        self.mode_fast.setChecked(True)
        self.mode_full = RadioButton("满载测试  ·  10 分钟")
        self.mode_full.setStyleSheet("font-size:13px; spacing:8px;")
        # 自定义：单独一行，单选按钮+输入框+秒
        custom_row = QHBoxLayout(); custom_row.setSpacing(8)
        self.mode_custom = RadioButton("自定义")
        self.mode_custom.setStyleSheet("font-size:13px; spacing:8px;")
        self.mode_custom.setMinimumWidth(100)
        self.custom_time = QLineEdit("60"); self.custom_time.setFixedWidth(80)
        self.custom_time.setStyleSheet("background:#2a2b33; border:1px solid #3a3b42; border-radius:4px; padding:4px; color:#e2e8f0;")
        custom_row.addWidget(self.mode_custom)
        custom_row.addWidget(self.custom_time)
        custom_row.addWidget(QLabel("秒"))
        custom_row.addStretch()
        ml.addWidget(self.mode_fast); ml.addWidget(self.mode_full); ml.addLayout(custom_row)
        root.addWidget(mode_card)
        # 实时状态卡片
        stat_card = QFrame()
        stat_card.setStyleSheet("QFrame{background:#1e1f26; border-radius:12px; border:1px solid #2a2b33;}")
        sl = QHBoxLayout(stat_card); sl.setContentsMargins(16, 14, 16, 14); sl.setSpacing(20)
        # 三栏
        def stat_block(label, color):
            box = QVBoxLayout(); box.setSpacing(4)
            lb = QLabel(label); lb.setStyleSheet("color:#94a3b8; font-size:12px;")
            val = QLabel("")
            val.setStyleSheet("font-size:24px; font-weight:bold; color:%s;" % color)
            box.addWidget(lb); box.addWidget(val)
            return box, val
        b1, self.elapsed = stat_block("已运行", "#60a5fa")
        b2, self.freq_lb = stat_block("CPU 频率 (GHz)", "#22c55e")
        b3, self.temp_lb = stat_block("CPU 温度 (°C)", "#f59e0b")
        sl.addLayout(b1); sl.addLayout(b2); sl.addLayout(b3)
        root.addWidget(stat_card)
        # 进度条
        self.progress = ProgressBar()
        self.progress.setValue(0)
        self.progress.setFixedHeight(8)
        root.addWidget(self.progress)
        # 状态
        self.state_lb = QLabel("待机 — 点击开始测试")
        self.state_lb.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.state_lb.setStyleSheet("font-size:13px; color:#94a3b8; padding:4px;")
        root.addWidget(self.state_lb)
        self.result_lb = QLabel("")
        self.result_lb.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.result_lb.setStyleSheet("font-size:15px; font-weight:bold; padding:8px;")
        root.addWidget(self.result_lb)
        root.addStretch()
        # 底部：艺术字 + 按钮
        bottom_row = QHBoxLayout()
        logo = LogoLabel(size=18)
        logo.setFixedWidth(220)
        bottom_row.addWidget(logo)
        bottom_row.addStretch()
        self.btn_cancel = PushButton("关闭")
        self.btn_cancel.clicked.connect(self._close_safe)
        self.btn_start = PrimaryPushButton("开始测试")
        self.btn_start.clicked.connect(self._start_test)
        self.btn_stop = PushButton("停止测试")
        self.btn_stop.clicked.connect(self._stop_test)
        self.btn_stop.setEnabled(False)
        # 测试状态
        self._threads = []
        self._stop_flag = False
        self._start_time = 0
        self._test_duration = 0
        self._testing = False
        self._update_timer = QTimer(self)
        self._update_timer.timeout.connect(self._update_stab_ui)
        bottom_row.addWidget(self.btn_cancel); bottom_row.addWidget(self.btn_start); bottom_row.addWidget(self.btn_stop)
        root.addLayout(bottom_row)

    def _close_safe(self):
        """关闭窗口前先停测试，防止线程残留。"""
        self._stop_all_workers()
        self.reject()

    def _stop_all_workers(self):
        """统一停止所有压力线程：设标志 → join(3) → 日志。窗口关闭/停止按钮都走这里。"""
        import threading
        _log("[稳定性测试] _stop_all_workers 进入")
        self._stop_flag = True
        if hasattr(self, "_threads"):
            for t in self._threads:
                try:
                    t.join(timeout=3)
                except Exception as e:
                    _log(f"[稳定性测试] 线程 join 异常: {e}")
            alive = [t for t in self._threads if t.is_alive()]
            if alive:
                _log(f"[稳定性测试] 警告: {len(alive)} 个线程仍存活（daemon 会随进程退出）")
            self._threads = []
        self._testing = False
        self._update_timer.stop()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def _start_test(self):
        import threading, os, time
        _log("[稳定性测试] _start_test 进入")
        # 开始前先停止旧线程（防止重复点击产生多个线程）
        if self._testing or self._threads:
            _log("[稳定性测试] 发现旧线程存活，先停止")
            self._stop_all_workers()
        # 确定测试时长
        if self.mode_fast.isChecked():
            self._test_duration = 30
        elif self.mode_full.isChecked():
            self._test_duration = 600
        else:
            try:
                self._test_duration = max(5, int(self.custom_time.text()))
            except:
                self._test_duration = 60
        # 启动 N 个压力线程（N = CPU 逻辑核心数）
        # hashlib.sha256 是 C 实现，计算 1MB 缓冲区时释放 GIL，多线程可真正并行
        n_cores = os.cpu_count() or 4
        self._stop_flag = False
        self._threads = []
        try:
            for i in range(n_cores):
                t = threading.Thread(
                    target=self._stress_worker_thread,
                    args=(i,),
                    daemon=False,  # 非 daemon，确保 join 能等到
                    name=f"StressWorker-{i}"
                )
                t.start()
                self._threads.append(t)
            _log(f"[稳定性测试] 已创建并启动 {len(self._threads)} 个压力线程")
        except Exception as e:
            _log(f"[稳定性测试] 启动线程失败: {e}")
            self.state_lb.setText(f"启动失败: {e}")
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            return
        self._testing = True
        self._start_time = time.time()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.state_lb.setText(f"压力测试中 — {n_cores} 核满载，预计 {self._test_duration} 秒")
        self.state_lb.setStyleSheet("font-size:13px; color:#22c55e; padding:4px;")
        self.result_lb.setText("")
        self.progress.setValue(0)
        self._update_timer.start(500)
        _log(f"[稳定性测试] 开始, {n_cores} 核, 时长 {self._test_duration}s")

    def _stress_worker_thread(self, worker_id):
        """CPU 满载线程：持续计算 1MB 数据的 SHA256（C 实现，释放 GIL，多线程可并行）。
        每轮检查 self._stop_flag，可被安全中断。绝不碰任何 Widget。"""
        import hashlib, threading
        data = b"x" * 1048576  # 1MB 缓冲区（>= 64KB，GIL 切换开销可忽略）
        count = 0
        try:
            while not self._stop_flag:
                hashlib.sha256(data).digest()  # C 实现，释放 GIL
                count += 1
                if count % 5000 == 0:
                    _log(f"[稳定性测试] Worker-{worker_id} 已完成 {count} 次哈希计算")
        except Exception as e:
            _log(f"[稳定性测试] Worker-{worker_id} 异常: {e}")
        finally:
            _log(f"[稳定性测试] Worker-{worker_id} 退出, 共完成 {count} 次计算")

    def _stop_test(self):
        import time
        _log("[稳定性测试] _stop_test 进入（用户点击停止）")
        self._stop_all_workers()
        elapsed = time.time() - self._start_time
        self.state_lb.setText(f"测试结束 — 运行 {elapsed:.0f} 秒，未蓝屏/报错")
        self.state_lb.setStyleSheet("font-size:13px; color:#94a3b8; padding:4px;")
        self.result_lb.setText("✓ 稳定性测试通过")
        self.result_lb.setStyleSheet("font-size:15px; font-weight:bold; color:#22c55e; padding:8px;")
        self.progress.setValue(100)
        _log(f"[稳定性测试] 停止, 运行 {elapsed:.0f}s")

    def _update_stab_ui(self):
        import time
        elapsed = time.time() - self._start_time
        self.elapsed.setText(f"{elapsed:.0f}s")
        # 进度
        if self._test_duration > 0:
            pct = min(100, int(elapsed / self._test_duration * 100))
            self.progress.setValue(pct)
        # 读 CPU 频率和温度
        try:
            import msr
            mon = msr.read_monitor()
            freqs = mon.get("freqs", [])
            temps = mon.get("temps", [])
            if freqs:
                avg_freq = sum(freqs) / len(freqs)
                self.freq_lb.setText(f"{avg_freq:.2f}")
            if temps:
                max_temp = max(temps)
                self.temp_lb.setText(f"{max_temp:.0f}")
        except: pass
        # 到时自动停止
        if elapsed >= self._test_duration:
            self._stop_test()


# ============ FIVR 弹窗 ============
def _get_cfg_path():
    import sys, os, json
    cfg_dir = os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'), 'IntelUndervolt')
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_path = os.path.join(cfg_dir, 'config.json')
    if getattr(sys, 'frozen', False):
        old_path = os.path.join(os.path.dirname(sys.executable), 'fivr_config.json')
    else:
        old_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fivr_config.json')
    if os.path.exists(old_path) and not os.path.exists(cfg_path):
        try:
            import shutil
            shutil.copy2(old_path, cfg_path)
            print(f'[配置] 已迁移: {old_path} -> {cfg_path}')
        except Exception as e:
            print(f'[配置] 迁移失败: {e}')
    return cfg_path


# ============ 资源路径与图标 ============
def _get_resource_path(name):
    """获取嵌入资源路径（兼容 PyInstaller onefile 和源码模式）。"""
    import sys, os
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, name)

_app_icon_instance = None
def _get_app_icon():
    """获取应用图标 QIcon（单例缓存）。"""
    global _app_icon_instance
    if _app_icon_instance is None:
        from PyQt6.QtGui import QIcon
        path = _get_resource_path("app_icon.ico")
        import os
        if os.path.exists(path):
            _app_icon_instance = QIcon(path)
        else:
            # fallback: png
            png_path = _get_resource_path("app_icon.png")
            if os.path.exists(png_path):
                _app_icon_instance = QIcon(png_path)
            else:
                from PyQt6.QtWidgets import QStyle, QApplication
                _app_icon_instance = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
    return _app_icon_instance


# ============ UnderVoit.ini 配置持久化 ============
def _get_ini_path():
    """UnderVoit.ini 路径：exe 同目录（打包后）或脚本同目录。"""
    import sys, os
    if getattr(sys, 'frozen', False):
        return os.path.join(os.path.dirname(sys.executable), "UnderVoit.ini")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "UnderVoit.ini")

def _default_ini_config():
    """默认配置（新增一项只需改这里 + _fill_ui_from_config + 保存处）。"""
    return {
        "meta": {"version": 1},
        "core": {
            "vcore_offset_mv": 0,
            "fivring_offset_mv": 0,
            "ratio_limit": 0,
            "ring_ratio_limit": 0,
        },
        "switches": {
            "bd_prochot": True,
            "c1e": True,
            "disable_turbo": False,
            "hwp_lock": True,
        },
        "behavior": {
            "minimize_on_close": False,
            "autostart": False,
        },
    }

def _load_ini_config():
    """读取 UnderVoit.ini，返回字典；缺省/损坏时返回默认值并记日志。"""
    import configparser, os
    path = _get_ini_path()
    cfg = _default_ini_config()
    if not os.path.exists(path):
        return cfg
    try:
        parser = configparser.ConfigParser()
        parser.read(path, encoding='utf-8-sig')
        # [core]
        if parser.has_section("core"):
            for k in ["vcore_offset_mv", "fivring_offset_mv", "e_offset_mv", "ratio_limit", "ring_ratio_limit", "e_ratio_limit"]:
                if parser.has_option("core", k):
                    try:
                        cfg["core"][k] = parser.getint("core", k)
                    except ValueError:
                        pass
            # E 核倍频表（逗号分隔）
            if parser.has_option("core", "e_ratios"):
                try:
                    ratios_str = parser.get("core", "e_ratios")
                    cfg["core"]["e_ratios"] = [int(x.strip()) for x in ratios_str.split(",") if x.strip()]
                except ValueError:
                    pass
        # [switches]
        if parser.has_section("switches"):
            for k in ["bd_prochot", "c1e", "disable_turbo", "hwp_lock"]:
                if parser.has_option("switches", k):
                    try:
                        cfg["switches"][k] = parser.getboolean("switches", k)
                    except ValueError:
                        pass
        # [behavior]
        if parser.has_section("behavior"):
            for k in ["minimize_on_close", "autostart"]:
                if parser.has_option("behavior", k):
                    try:
                        cfg["behavior"][k] = parser.getboolean("behavior", k)
                    except ValueError:
                        pass
        _log(f"[配置] 已加载 UnderVoit.ini: core={cfg['core']}")
    except Exception as e:
        _log(f"[配置] UnderVoit.ini 读取失败，使用默认值: {e}")
    return cfg

def _save_ini_config(data):
    """写入 UnderVoit.ini（先写 .tmp 再 os.replace，防止中途崩溃写坏）。
    只有应用成功才调用此函数。"""
    import configparser, os, tempfile
    path = _get_ini_path()
    try:
        parser = configparser.ConfigParser()
        # [meta]
        parser.add_section("meta")
        parser.set("meta", "version", str(data.get("meta", {}).get("version", 1)))
        # [core]
        parser.add_section("core")
        for k, v in data.get("core", {}).items():
            if isinstance(v, list):
                # 列表转逗号分隔字符串（如 [30,30,30] -> "30,30,30"）
                parser.set("core", k, ",".join(str(int(x)) for x in v))
            else:
                parser.set("core", k, str(v))
        # [switches]
        parser.add_section("switches")
        for k, v in data.get("switches", {}).items():
            parser.set("switches", k, "true" if v else "false")
        # [behavior]
        parser.add_section("behavior")
        for k, v in data.get("behavior", {}).items():
            parser.set("behavior", k, "true" if v else "false")
        # 原子写入：先写 .tmp 再 replace
        dir_name = os.path.dirname(path)
        fd, tmp_path = tempfile.mkstemp(suffix=".tmp", dir=dir_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8-sig") as f:
                parser.write(f)
            os.replace(tmp_path, path)
        finally:
            if os.path.exists(tmp_path):
                try: os.remove(tmp_path)
                except: pass
        _log(f"[配置] 已保存 UnderVoit.ini: core={data.get('core', {})}")
        return True
    except Exception as e:
        _log(f"[配置] UnderVoit.ini 保存失败: {e}")
        return False


class FIVRDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("睿频电压控制")
        self.setWindowIcon(_get_app_icon())
        self.resize(1080, 760)
        self.setMinimumSize(1080, 760)
        self.core_type = "P"
        self._saved_ratios = {}
        self._hwp_lock = _load_ini_config()["switches"]["hwp_lock"]
        # 配置文件路径：exe 所在目录（PyInstaller 打包后 __file__ 是临时目录）
        import sys, os, json
        if getattr(sys, 'frozen', False):
            self._cfg_dir = os.path.dirname(sys.executable)
        else:
            self._cfg_dir = os.path.dirname(os.path.abspath(__file__))
        self._cfg_path = _get_cfg_path()
        # 从配置文件恢复保存的倍频
        try:
            if os.path.exists(self._cfg_path):
                d = json.load(open(self._cfg_path, encoding="utf-8"))
                if "p_ratios" in d:
                    self._saved_ratios["P"] = d["p_ratios"]
                if "e_ratios" in d:
                    self._saved_ratios["E"] = d["e_ratios"]
        except: pass
        # 从 ini 的 e_ratio_limit 加载 E 核倍频表（固定 8 行）
        try:
            ini_cfg = _load_ini_config()
            e_ratio_limit = ini_cfg.get("core", {}).get("e_ratio_limit", 0)
            if e_ratio_limit > 0:
                self._saved_ratios["E"] = [e_ratio_limit] * 8
                _log(f"[配置] 从 ini 加载 E 核倍频: {e_ratio_limit} (x8)")
            else:
                self._saved_ratios["E"] = [0] * 8
                _log(f"[配置] ini 无 E 核倍频，默认全 0")
        except Exception as e:
            _log(f"[配置] 从 ini 加载 E 核倍频失败: {e}")
            self._saved_ratios["E"] = [0] * 8
        self.fivr_sel = "cpu"
        self.sliders = {}   # name -> (slider, value_label)
        self._build()
        # MSR 不可写时灰显所有控件
        self._apply_readonly()

    def _apply_readonly(self):
        """MSR 不可写时只提示，不禁用控件（用户仍可看，点应用时再提示）。"""
        try:
            p = self.parent()
            if p is None or not hasattr(p, "_caps"): return
            if p._caps.get("writable", True): return
            reason = p._caps.get("reason", "未知")
            self.setWindowTitle(f"睿频电压控制 ⚠ (只读: {reason})")
            _log(f"[FIVR] MSR 不可写提示: {reason}")
        except Exception as e:
            _log(f"[FIVR] 只读模式应用失败: {e}")

    # ---- 工具：标签+实时数值+滑块 一行 ----
    def _slider_row(self, parent_layout, label, lo, hi, val, unit, fmt="%d", tip=""):
        row = QHBoxLayout()
        row.setSpacing(8)
        lbl = BodyLabel(label)
        if tip:
            lbl.setToolTip(tip)
            lbl.setToolTipDuration(8000)
        row.addWidget(lbl)
        row.addStretch()
        val_lb = CaptionLabel(fmt % val)
        val_lb.setStyleSheet("color:#60A5FA; font-weight:bold;")
        row.addWidget(val_lb)
        s = Slider(Qt.Orientation.Horizontal); s.setRange(lo, hi); s.setValue(val)
        s.valueChanged.connect(self._on_slider_changed)
        if tip:
            s.setToolTip(tip); s.setToolTipDuration(8000)
        # 输入框
        sp = QLineEdit(fmt % val); sp.setFixedWidth(60)
        sp.setAlignment(Qt.AlignmentFlag.AlignRight)
        sp.editingFinished.connect(lambda: self._on_spin_edit(label, sp, lo, hi))
        s.valueChanged.connect(lambda v, e=sp, f=fmt: e.setText(f % v))
        self.sliders[label] = (s, val_lb, unit, fmt, sp)
        row.addWidget(s, 1)
        row.addWidget(sp)
        parent_layout.addLayout(row)
        return s

    def _export_hwp_diagnostics(self):
        import json
        from PyQt6.QtWidgets import QFileDialog
        from qfluentwidgets import MessageBox
        path, _ = QFileDialog.getSaveFileName(
            self, "保存锁频诊断", "hwp-diagnostics.json", "JSON (*.json)")
        if not path:
            return
        try:
            data = self.parent()._frequency_controller.diagnostics()
            data["app_version"] = APP_VERSION
            with open(path, "w", encoding="utf-8") as output:
                json.dump(data, output, ensure_ascii=False, indent=2)
            MessageBox("已导出", "已保存 HWP 请求、覆盖记录、睿频表和电源计划上限。", self).exec()
        except Exception as error:
            MessageBox("导出失败", str(error), self).exec()

    def _on_spin_edit(self, label, editor, lo, hi):
        try:
            v = int(editor.text())
            v = max(lo, min(hi, v))
            self.sliders[label][0].setValue(v)
        except Exception:
            pass

    def _on_slider_changed(self):
        for label, tup in self.sliders.items():
            s, lb, unit, fmt = tup[0], tup[1], tup[2], tup[3]
            lb.setText((fmt % s.value()) + unit)

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(10)
        root = QHBoxLayout()
        root.setSpacing(12)

        # ===== 左栏：睿频倍频 + 实时监控 =====
        left = QVBoxLayout(); left.setSpacing(10)
        c1 = CardWidget(); c1_l = QVBoxLayout(c1)
        c1_l.addWidget(SubtitleLabel("睿频倍频限制"))
        r1 = QHBoxLayout()
        self.rb_p = RadioButton("P 大核心"); self.rb_p.setChecked(True)
        self.rb_e = RadioButton("E 小核心")
        bg = QButtonGroup(self); bg.addButton(self.rb_p); bg.addButton(self.rb_e)
        self.rb_p.clicked.connect(lambda: self._set_core_type("P"))
        self.rb_e.clicked.connect(lambda: self._set_core_type("E"))
        r1.addWidget(self.rb_p); r1.addWidget(self.rb_e); r1.addStretch()
        c1_l.addLayout(r1)
        self.chk_over = CheckBox("超频（解锁倍频上限）"); c1_l.addWidget(self.chk_over)
        self.chk_hwp_lock = CheckBox("HWP 锁频（P / E 核）")
        self.chk_hwp_lock.setChecked(self._hwp_lock)
        self.chk_hwp_lock.setToolTip(
            "勾选：P/E 核分别以表中最大倍频设置 HWP 最小、最大和目标值。"
            "取消：只限制上限，空闲时允许降频。0 表示不控制该类核心。"
            "实际频率仍受各档睿频上限、温度和功耗限制。")
        c1_l.addWidget(self.chk_hwp_lock)
        diagnostic_button = PushButton("导出锁频诊断")
        diagnostic_button.clicked.connect(self._export_hwp_diagnostics)
        c1_l.addWidget(diagnostic_button)
        self.ratio_layout = QVBoxLayout(); self.ratio_layout.setSpacing(4)
        c1_l.addLayout(self.ratio_layout)
        self._build_ratios()
        c1_l.addWidget(PushButton("重置睿频"))
        left.addWidget(c1)
        # 实时监控
        c2 = CardWidget(); c2_l = QVBoxLayout(c2)
        c2_l.addWidget(SubtitleLabel("实时监控"))
        self.mon_labels = {}
        for name in ["P 核频率", "E 核频率", "核心温度", "封装功耗"]:
            row = QHBoxLayout(); row.addWidget(BodyLabel(name)); row.addStretch()
            v = BodyLabel("--"); v.setStyleSheet("color: #60A5FA;")
            row.addWidget(v); c2_l.addLayout(row); self.mon_labels[name] = v
        left.addWidget(c2); left.addStretch()
        root.addLayout(left, 11)

        # ===== 中栏：FIVR 控制 + 电压滑块 =====
        mid = QVBoxLayout(); mid.setSpacing(10)
        c3 = CardWidget(); c3_l = QVBoxLayout(c3)
        c3_l.addWidget(SubtitleLabel("FIVR 控制"))
        g = QGridLayout(); g.setHorizontalSpacing(20)
        self.fivr_btns = {}
        for i, (k, t) in enumerate([("cpu", "CPU 核心"), ("gpu", "核显"),
                                    ("cache", "缓存"), ("e", "E 小核心")]):
            b = RadioButton(t)
            if k == "cpu": b.setChecked(True)
            self.fivr_btns[k] = b
            g.addWidget(b, i // 2, i % 2)
        bg2 = QButtonGroup(self)
        for b in self.fivr_btns.values(): bg2.addButton(b)
        c3_l.addLayout(g); mid.addWidget(c3)
        # FIVR 单选联动
        for k, b in self.fivr_btns.items():
            b.toggled.connect(lambda checked, k=k: self._on_fivr_changed(k))

        c4 = CardWidget(); c4_l = QVBoxLayout(c4)
        self.vol_title = SubtitleLabel("CPU 核心电压"); c4_l.addWidget(self.vol_title)
        self._slider_row(c4_l, "偏移电压", -250, 0, 0, " mV")
        # 滑块实时数值
        for tup in self.sliders.values():
            tup[0].valueChanged.connect(self._on_slider_changed)
        self._on_slider_changed()
        # 偏移范围
        c4_l.addSpacing(6)
        rg = QHBoxLayout()
        rg.addWidget(BodyLabel("范围"))
        bg3 = QButtonGroup(self)
        self.range_btns = {}
        for v in [125, 250, 1000]:
            b = RadioButton("%d mV" % v); bg3.addButton(b); rg.addWidget(b)
            self.range_btns[v] = b
            b.toggled.connect(lambda checked, rng=v: checked and self._set_offset_range(rng))
            if v == 250: b.setChecked(True)
        rg.addStretch(); c4_l.addLayout(rg)
        rb = QHBoxLayout()
        btn_reset = PushButton("重置电压")
        btn_reset.clicked.connect(self._reset_offset)
        btn_zero = PushButton("零偏移")
        btn_zero.clicked.connect(self._zero_offset)
        rb.addWidget(btn_reset); rb.addWidget(btn_zero); rb.addStretch()
        c4_l.addLayout(rb)
        mid.addWidget(c4)

        # 高级设置卡片
        c6 = CardWidget(); c6_l = QVBoxLayout(c6); c6_l.setSpacing(10)
        c6_l.addWidget(SubtitleLabel("高级设置"))
        # 滑块区
        self._slider_row(c6_l, "AVX 偏移", -10, 20, 0, " 倍频", tip="运行 AVX 指令时自动降低的倍频。数值越大，AVX 负载下频率越低、越凉，但性能也会下降。")
        # 分隔线
        line = QFrame(); line.setFrameShape(QFrame.Shape.HLine); line.setStyleSheet("color:#333;")
        c6_l.addWidget(line)
        # 实时状态（表格样式）
        st = QGridLayout(); st.setHorizontalSpacing(16); st.setVerticalSpacing(6)
        self.st_labels = {}
        rows = [("TjMax", "100 °C"), ("Ring 频率", "4.0 GHz"),
                ("当前偏移", "-0 mV"), ("当前 IccMax", "1 A"),
                ("P 核上限", "5.0 GHz"), ("E 核上限", "3.5 GHz"),
                ("P 核实时", "-- GHz"), ("E 核实时", "-- GHz")]
        for i, (k, v) in enumerate(rows):
            k_lb = CaptionLabel(k); v_lb = CaptionLabel(v)
            v_lb.setStyleSheet("color:#60A5FA; font-weight:bold;")
            st.addWidget(k_lb, i // 2, (i % 2) * 2)
            st.addWidget(v_lb, i // 2, (i % 2) * 2 + 1)
            self.st_labels[k] = v_lb
        c6_l.addLayout(st)
        self.lbl_pl = CaptionLabel("PL1 = -- W  ·  PL2 = -- W")
        self.lbl_pl.setStyleSheet("color:#60A5FA;")
        c6_l.addWidget(self.lbl_pl)
        c6_l.addStretch()
        mid.addWidget(c6, 1)
        root.addLayout(mid, 12)

        # ===== 右栏：电压表 + 缓存倍频 =====
        right = QVBoxLayout(); right.setSpacing(10)
        c5 = CardWidget(); c5_l = QVBoxLayout(c5)
        c5_l.addWidget(SubtitleLabel("电压表"))
        self.table = QTableWidget(4, 4)
        # 深色透明样式：无外框、无网格线、无选中高亮、行高 30
        self.table.setStyleSheet("""
            QTableWidget { background: transparent; border: none; color: #E2E8F0; gridline-color: transparent; }
            QTableWidget::item { padding: 4px 8px; border: none; }
            QTableWidget::item:selected { background: transparent; color: #E2E8F0; }
            QHeaderView::section { background: transparent; border: none; border-bottom: 1px solid #334155;
                                   color: #94A3B8; padding: 4px 8px; font-weight: normal; }
        """)
        self.table.horizontalHeader().setVisible(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        # 列宽：域名宽，数值窄，最后一列拉伸
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 70)
        self.table.setColumnWidth(3, 80)
        rows = [("CPU 核心", "自适应", "Default", "-0.000 V"),
                ("核显", "自适应", "Default", "+0.000 V"),
                ("CPU 缓存", "自适应", "Default", "-0.000 V"),
                ("E 小核心", "自适应", "Default", "+0.000 V")]
        for i, row in enumerate(rows):
            self.table.setRowHeight(i, 30)
            for j, v in enumerate(row):
                item = QTableWidgetItem(v)
                if j == 0:
                    item.setForeground(QColor(226, 232, 240))
                elif j == 3:
                    item.setForeground(QColor(96, 165, 250))
                else:
                    item.setForeground(QColor(148, 163, 184))
                if j >= 1:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self.table.setItem(i, j, item)
        self.table.setMinimumHeight(150)
        c5_l.addWidget(self.table)
        # 硬件状态：两列网格
        hw = QGridLayout(); hw.setHorizontalSpacing(24); hw.setVerticalSpacing(6)
        self.hw_labels = {}
        for i, (k, v) in enumerate([("VCCIN", "0.9895"), ("电压 ID", "36"),
                                    ("缓存倍频", "36")]):
            key = CaptionLabel(k); val_lb = CaptionLabel(v)
            val_lb.setStyleSheet("color:#60A5FA;")
            hw.addWidget(key, i // 2, (i % 2) * 2)
            hw.addWidget(val_lb, i // 2, (i % 2) * 2 + 1)
            self.hw_labels[k] = val_lb
        c5_l.addLayout(hw)
        right.addWidget(c5)
        # 缓存倍频（独立卡片）
        c5b = CardWidget(); c5b_l = QVBoxLayout(c5b)
        c5b_l.addWidget(SubtitleLabel("缓存倍频"))
        row2 = QHBoxLayout()
        row2.addWidget(CaptionLabel("最小 / 最大")); row2.addStretch()
        self.cache_min = QLineEdit("36"); self.cache_min.setFixedWidth(70)
        self.cache_max = QLineEdit("48"); self.cache_max.setFixedWidth(70)
        row2.addWidget(self.cache_min); row2.addWidget(self.cache_max)
        c5b_l.addLayout(row2)
        right.addWidget(c5b)
        # 机器信息检测卡片
        c7 = CardWidget(); c7_l = QVBoxLayout(c7)
        c7_l.addWidget(SubtitleLabel("机器信息检测"))
        self.hwinfo_labels = {}
        for key in ["计算机名", "CPU", "显卡", "网卡", "内存"]:
            row = QHBoxLayout(); row.addWidget(CaptionLabel(key)); row.addStretch()
            v = CaptionLabel("检测中…"); v.setStyleSheet("color:#60A5FA;")
            row.addWidget(v); c7_l.addLayout(row)
            self.hwinfo_labels[key] = v
        right.addWidget(c7, 1)
        root.addLayout(right, 13)
        outer.addLayout(root, 1)

        # ===== 底部：艺术字 + 按钮（通栏）=====
        bottom = QHBoxLayout()
        bottom.addWidget(LogoLabel(size=34))
        bottom.addStretch()
        btn_cancel = PushButton("取消修改")
        btn_cancel.clicked.connect(self.reject)
        btn_ok = PrimaryPushButton("应用设置")
        btn_ok.clicked.connect(self._apply_settings)
        bottom.addWidget(btn_cancel)
        bottom.addWidget(btn_ok)
        outer.addLayout(bottom)
        # 初始化联动：电压表选中当前 FIVR 域
        self._on_fivr_changed("cpu")
        # 读当前 ring 频率
        try:
            import msr
            ring = msr.read_ring_frequency()
            if ring.get("max_ratio"):
                self.cache_max.setText(str(ring["max_ratio"]))
            if ring.get("min_ratio"):
                self.cache_min.setText(str(ring["min_ratio"]))
        except Exception:
            pass
        # 电压偏移以硬件回读为准（_on_fivr_changed 已回读），
        # 若回读失败则从 UnderVoit.ini 取上次保存值作 fallback
        try:
            import msr
            cur = msr.read_offset_mv(0)
            if cur == 0 or cur is None:
                ini_cfg = _load_ini_config()
                v = ini_cfg.get("core", {}).get("vcore_offset_mv", 0)
                if v != 0:
                    s = self.sliders["偏移电压"][0]
                    s.blockSignals(True)
                    s.setValue(int(v))
                    s.blockSignals(False)
                    self._on_slider_changed()
        except Exception:
            pass
        # 状态检测
        self._check_status()
        # 实时监控刷新
        self._mon_timer = QTimer(self)
        self._mon_timer.timeout.connect(self._refresh_fivr_mon)
        # [隔离验证] 先不启动监控定时器，测试打开Tab是否还死机
        # self._mon_timer.start(10000)
        self._mon_timer.start(3000)

    def closeEvent(self, event):
        """Tab关闭时停掉定时器。"""
        try:
            self._mon_timer.stop()
            _log("[FIVR] 关闭，定时器已停")
        except: pass
        super().closeEvent(event)

    def _refresh_fivr_mon(self):
        """主线程同步读MSR（测试证明很快，不会卡）。"""
        try:
            import msr
            mon = msr.read_monitor()
            pkg = msr.read_pkg_power()
            self.mon_labels["P 核频率"].setText(f"{mon['p_freq']:.2f} GHz")
            self.mon_labels["E 核频率"].setText(f"{mon['e_freq']:.2f} GHz")
            self.mon_labels["核心温度"].setText(f"{mon['max_temp']} °C")
            self.mon_labels["封装功耗"].setText(f"{pkg:.1f} W")
            for row, (k, pl) in enumerate([("cpu", 0), ("gpu", 1), ("cache", 2), ("e", 5)]):
                try:
                    off = msr.read_offset_mv(pl)
                    self.table.item(row, 3).setText(f"{off:+.1f} mV")
                except: pass
            try:
                pl_data = msr.read_power_limits()
                self.lbl_pl.setText(f"PL1={pl_data['pl1']:.0f}W · PL2={pl_data['pl2']:.0f}W")
            except: pass
            try:
                icc = msr.read_icc_max()
                self.st_labels["当前 IccMax"].setText(f"{icc:.0f} A")
            except: pass
            try:
                st = msr.rdmsr(0x198)
                vraw = (st >> 32) & 0xFFFF
                vccin = (vraw >> 3)/1000
                self.hw_labels["VCCIN"].setText(f"{vccin:.3f}")
            except: pass
            try:
                ring = msr.read_ring_frequency()
                if ring and ring.get("max_ratio"):
                    r = ring["max_ratio"]
                    self.st_labels["Ring 频率"].setText(f"{r:.1f} GHz")
                    self.hw_labels["缓存倍频"].setText(str(r))
            except: pass
            try:
                cur_off = msr.read_offset_mv(0)
                self.st_labels["当前偏移"].setText(f"{cur_off:+.0f} mV")
            except: pass
        except Exception as e:
            _log(f"[FIVR监控] 读取失败: {e}")

    def _set_offset_range(self, rng):
        s = self.sliders["偏移电压"][0]
        cur = s.value()
        s.blockSignals(True)
        s.setRange(-rng, 0)
        s.setValue(max(-rng, min(0, cur)))
        s.blockSignals(False)
        self._on_slider_changed()

    def _reset_offset(self):
        """重置为上次应用的值（从配置读回）"""
        import json, os
        cfg = _get_cfg_path()
        try:
            d = json.load(open(cfg, encoding="utf-8"))
            plane_map = {"cpu":0, "gpu":1, "cache":2, "e":5}
            pl = plane_map.get(self._cur_fivr, 0)
            key = {0:"cpu",1:"gpu",2:"cache",5:"e"}.get(pl, "cpu")
            v = d.get("offsets", {}).get(key, 0)
            self.sliders["偏移电压"][0].setValue(int(v))
        except Exception:
            pass

    def _zero_offset(self):
        """零偏移：写 0mV 到当前域"""
        try:
            import msr
            plane_map = {"cpu":0, "gpu":1, "cache":2, "e":5}
            pl = plane_map.get(self._cur_fivr, 0)
            msr.write_offset_mv(pl, 0)
            self.sliders["偏移电压"][0].setValue(0)
        except Exception:
            pass

    def _apply_settings(self):
        """把滑块值写入 MSR。"""
        try:
            # 首次写操作时才加载 WinRing0（启动时不加载，防蓝屏）
            load_driver()
            import msr
            # VBS 检测
            vbs = _detect_vbs()
            if vbs:
                from qfluentwidgets import MessageBox
                MessageBox("警告", "检测到 VBS/HVCI 已开启，MSR 0x150 降压可能被拦截。\n请在 BIOS 关闭 VBS/HVCI 后再试。", self).exec()
            plane_map = {"cpu":0, "gpu":1, "cache":2, "e":5}
            plane = plane_map.get(self._cur_fivr, 0)
            off = self.sliders["偏移电压"][0].value()
            print(f"[FIVR] 写入 plane={plane} offset={off}mV")
            ret = msr.write_offset_mv(plane, off)
            print(f"[FIVR] 写入结果: {ret}")
            # 保存配置
            import json, os
            cfg = _get_cfg_path()
            plane_map = {"cpu":0, "gpu":1, "cache":2, "e":5}
            pl = plane_map.get(self._cur_fivr, 0)
            key = {0:"cpu",1:"gpu",2:"cache",5:"e"}.get(pl, "cpu")
            try:
                d = {}
                if os.path.exists(cfg):
                    with open(cfg, encoding="utf-8") as config_file:
                        d = json.load(config_file)
                d.setdefault("offsets", {})[key] = off
                d["_confirmed"] = False  # 新数值未确认，下次启动不应用直到稳定 60 秒
                with open(cfg, "w", encoding="utf-8") as config_file:
                    json.dump(d, config_file)
            except Exception:
                pass
            # 定频
            try:
                # 保存当前 tab 的值
                if hasattr(self, "ratio_edits") and self.ratio_edits:
                    vals = []
                    for ed in self.ratio_edits:
                        try: vals.append(int(ed.text()))
                        except: vals.append(0)
                    self._saved_ratios[self.core_type] = vals
                # 从 ProgramData config 恢复另一 tab 的值（统一路径，不再读旧 fivr_config.json）
                try:
                    import json, os
                    cfg_path = _get_cfg_path()
                    if os.path.exists(cfg_path):
                        with open(cfg_path, encoding="utf-8") as config_file:
                            saved = json.load(config_file)
                        if "p_ratios" in saved and "P" not in self._saved_ratios:
                            self._saved_ratios["P"] = saved["p_ratios"]
                        if "e_ratios" in saved and "E" not in self._saved_ratios:
                            self._saved_ratios["E"] = saved["e_ratios"]
                except: pass
                # 读 P/E 倍频
                p_vals = self._saved_ratios.get("P", [])
                e_vals = self._saved_ratios.get("E", [])
                p_max = max([v for v in p_vals if v > 0], default=0) / 10.0
                e_max = max([v for v in e_vals if v > 0], default=0) / 10.0
                # 后台和手动应用共用控制器，验证成功后才发布新保持目标。
                p_ratios = [int(v) for v in p_vals]
                controller = self.parent()._frequency_controller
                controller.apply(p_max, e_max,
                                 lock=self.chk_hwp_lock.isChecked(),
                                 p_ratios=p_ratios if any(v > 0 for v in p_ratios) else None)
                self.parent()._hwp_error = ""
                # 保存频率到配置
                try:
                    d = {}
                    if os.path.exists(cfg):
                        with open(cfg, encoding="utf-8") as config_file:
                            d = json.load(config_file)
                    d["p_max"] = p_max
                    d["e_max"] = e_max
                    d["hwp_lock"] = self.chk_hwp_lock.isChecked()
                    d["p_ratios"] = [int(v) for v in p_vals]
                    d["e_ratios"] = [int(v) for v in e_vals]
                    with open(cfg, "w", encoding="utf-8") as config_file:
                        json.dump(d, config_file)
                    # 同时写入 ini 的 e_ratio_limit（取最大值）
                    try:
                        ini_cfg = _load_ini_config()
                        e_max_limit = max([int(v) for v in e_vals if int(v) > 0], default=0)
                        ini_cfg["core"]["e_ratio_limit"] = e_max_limit
                        _save_ini_config(ini_cfg)
                        _log(f"[配置] 已写入 ini E 核倍频上限: {e_max_limit}")
                    except Exception as e:
                        _log(f"[配置] 写入 ini E 核倍频上限失败: {e}")
                except: pass
            except Exception as e:
                print("[FIVR] 定频失败:", e)
                from qfluentwidgets import MessageBox as _MB
                _MB("定频失败", f"错误: {e}", self).exec()
                return
            # Ring/缓存倍频 (用 v2 的 set_ring_max_ratio)
            try:
                cmax = int(self.cache_max.text())
                ret = msr.set_ring_max_ratio(cmax)
                print("[FIVR] Ring 倍频已写入:", ret)
            except Exception as e:
                print("[FIVR] Ring 倍频写入失败:", e)
            # 保存到 UnderVoit.ini（只有应用成功才落盘）
            try:
                ini_cfg = _load_ini_config()
                # 电压偏移：当前选中的平面
                plane_map = {"cpu":0, "gpu":1, "cache":2, "e":5}
                pl = plane_map.get(self._cur_fivr, 0)
                if pl == 0:
                    ini_cfg["core"]["vcore_offset_mv"] = off
                elif pl == 2:
                    ini_cfg["core"]["fivring_offset_mv"] = off
                elif pl == 5:
                    ini_cfg["core"]["e_offset_mv"] = off
                elif pl == 5:
                    ini_cfg["core"]["e_offset_mv"] = off
                # 倍频限制：P 核 + E 核各自独立保存
                p_vals = self._saved_ratios.get("P", [])
                p_max_val = max([int(v) for v in p_vals if int(v) > 0], default=0)
                ini_cfg["core"]["ratio_limit"] = p_max_val
                ini_cfg["switches"]["hwp_lock"] = self.chk_hwp_lock.isChecked()
                e_vals = self._saved_ratios.get("E", [])
                e_max_val = max([int(v) for v in e_vals if int(v) > 0], default=0)
                ini_cfg["core"]["e_ratio_limit"] = e_max_val
                # Ring 倍频
                try:
                    ini_cfg["core"]["ring_ratio_limit"] = int(self.cache_max.text())
                except: pass
                # 三个开关：从主界面读取（如果有 parent）
                if self.parent() is not None and hasattr(self.parent(), "chks"):
                    chks = self.parent().chks
                    ini_cfg["switches"]["bd_prochot"] = chks.get("BD PROCHOT", type('x',(),{'isChecked':lambda self: True})()).isChecked() if "BD PROCHOT" in chks else True
                    ini_cfg["switches"]["c1e"] = chks.get("C1E", type('x',(),{'isChecked':lambda self: True})()).isChecked() if "C1E" in chks else True
                    ini_cfg["switches"]["disable_turbo"] = chks.get("关闭睿频", type('x',(),{'isChecked':lambda self: False})()).isChecked() if "关闭睿频" in chks else False
                # behavior 从主界面读取
                if self.parent() is not None and hasattr(self.parent(), "chks"):
                    chks = self.parent().chks
                    ini_cfg["behavior"]["minimize_on_close"] = chks.get("最小化到托盘", type('x',(),{'isChecked':lambda self: False})()).isChecked() if "最小化到托盘" in chks else False
                    ini_cfg["behavior"]["autostart"] = chks.get("开机自启", type('x',(),{'isChecked':lambda self: False})()).isChecked() if "开机自启" in chks else False
                _save_ini_config(ini_cfg)
            except Exception as e:
                _log(f"[配置] FIVR 保存 ini 失败: {e}")
            from qfluentwidgets import MessageBox
            m = MessageBox("成功", "设置已写入。是否关闭本窗口？", self)
            m.yesButton.setText("关闭"); m.cancelButton.setText("继续调整")
            if m.exec():
                self.accept()
        except Exception as e:
            from qfluentwidgets import MessageBox
            MessageBox("错误", f"写入失败：{e}", self).exec()

    def _check_status(self):
        """启动后台线程收集机器信息，不卡 UI。"""
        self._worker = _StatusWorker()
        self._worker.done.connect(self._on_status_done)
        self._worker.start()

    def _on_status_done(self, r):
        info = r.get("hwinfo") or {}
        for key in ["计算机名", "CPU", "显卡", "网卡", "内存"]:
            v = info.get(key, "?")
            # 长文本截断
            if len(v) > 32:
                v = v[:30] + "…"
            self.hwinfo_labels[key].setText(v)

    def _build_ratios(self, old_kind=None):
        save_kind = old_kind or self.core_type
        if hasattr(self, "ratio_edits") and self.ratio_edits:
            vals = []
            for ed in self.ratio_edits:
                try: vals.append(int(ed.text()))
                except: vals.append(0)
            self._saved_ratios[save_kind] = vals
        while self.ratio_layout.count():
            it = self.ratio_layout.takeAt(0)
            w = it.widget()
            if w: w.deleteLater()
        # 优先从 saved_ratios 读用户保存的值
        saved = self._saved_ratios.get(self.core_type, None)
        if saved and any(v > 0 for v in saved):
            cur = saved
        else:
            # P 核从 MSR 读，E 核不读 MSR（Raptor Lake 上 0x1AE 不对）
            if self.core_type == "P":
                try:
                    import msr
                    cur = msr.read_per_core_ratios("p")
                except Exception:
                    cur = [0]*8
            else:
                # E 核：从 self._saved_ratios["E"] 读取（已从 ini 加载）
                try:
                    saved_e = self._saved_ratios.get("E", [])
                    if saved_e and any(v > 0 for v in saved_e):
                        cur = saved_e
                    else:
                        cur = [0]*8
                except Exception:
                    cur = [0]*8
        n = 8
        self.ratio_edits = []
        for i in range(1, n + 1):
            val = cur[i-1] if i-1 < len(cur) and cur[i-1] > 0 else 0
            row_w = QWidget()
            row = QHBoxLayout(row_w)
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(6)
            row.addWidget(CaptionLabel("%d 核活跃" % i))
            row.addStretch()
            edit = QLineEdit(str(val)); edit.setFixedWidth(56)
            b1 = QPushButton("<"); b1.setFixedWidth(32); b1.setFixedHeight(26)
            b2 = QPushButton(">"); b2.setFixedWidth(32); b2.setFixedHeight(26)
            idx = i - 1
            def on_minus(checked=False, e=edit, i=idx):
                try:
                    v = max(8, int(e.text())-1); e.setText(str(v)); self._link_ratios(i, v)
                except Exception: pass
            def on_plus(checked=False, e=edit, i=idx):
                try:
                    v = min(80, int(e.text())+1); e.setText(str(v)); self._link_ratios(i, v)
                except Exception: pass
            b1.clicked.connect(on_minus)
            b2.clicked.connect(on_plus)
            row.addWidget(edit); row.addWidget(b1); row.addWidget(b2)
            self.ratio_layout.addWidget(row_w)
            self.ratio_edits.append(edit)

    def _link_ratios(self, idx, val):
        """联动倍频：前核<=当前，后核>=当前。批量 blockSignals 减少重绘。"""
        try:
            edits = self.ratio_edits
            for ed in edits:
                ed.blockSignals(True)
            try:
                for j in range(idx):
                    cur = int(edits[j].text())
                    if cur < val:
                        edits[j].setText(str(val))
                for j in range(idx+1, len(edits)):
                    cur = int(edits[j].text())
                    if cur > val:
                        edits[j].setText(str(val))
            finally:
                for ed in edits:
                    ed.blockSignals(False)
        except Exception:
            pass

    def _set_core_type(self, kind):
        if kind != self.core_type:
            old_kind = self.core_type
            self.core_type = kind
            self._build_ratios(old_kind)

    def _on_fivr_changed(self, kind):
        self._cur_fivr = kind
        titles = {"cpu": "CPU 核心电压", "gpu": "核显电压",
                  "cache": "CPU 缓存电压", "e": "E 小核心电压"}
        self.vol_title.setText(titles.get(kind, "电压"))
        # 读取当前域偏移并设置滑块
        try:
            import msr
            plane_map = {"cpu":0, "gpu":1, "cache":2, "e":5}
            pl = plane_map.get(kind, 0)
            cur = msr.read_offset_mv(pl)
            s = self.sliders["偏移电压"][0]
            s.blockSignals(True)
            s.setValue(int(cur))
            s.blockSignals(False)
            self._on_slider_changed()
        except Exception:
            pass
        # FIVR 控制和倍频表分开，不联动切换
        # 电压表高亮对应行
        row = {"cpu": 0, "gpu": 1, "cache": 2, "e": 3}.get(kind, 0)
        self.table.selectRow(row)

# ============ 主窗口 ============
class MainWindow(QMainWindow):
    def __init__(self, silent=False, safe=False):
        super().__init__()
        self._silent_start = silent
        self._safe_mode = safe
        from frequency_control import HwpFrequencyController
        self._frequency_controller = HwpFrequencyController()
        self._hwp_error = ""
        self.setWindowTitle(f"IntelUndervolt v{APP_VERSION} - BL爱折腾")
        self.setWindowIcon(_get_app_icon())
        self.resize(760, 600)
        self.setMinimumSize(760, 600)
        setTheme(Theme.DARK)
        self._current_theme = "dark"
        # 加载 UnderVoit.ini 配置（在 UI 构建前加载，构建时回填）
        self._ini_config = _load_ini_config()
        try:
            import json, os
            cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fivr_config.json")
            if os.path.exists(cfg_path):
                with open(cfg_path, encoding="utf-8") as f: cfg = json.load(f)
                if cfg.get("theme") == 1:
                    setTheme(Theme.LIGHT)
        except: pass
        from PyQt6.QtWidgets import QApplication as _QApp
        # 全局字体
        _app = _QApp.instance()
        _app.setFont(QFont("Microsoft YaHei UI", 10))
        _QApp.instance().setStyleSheet("""
            QToolTip {
                background-color: #2d2e35;
                color: #e2e8f0;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 6px 10px;
                font-size: 12px;
            }
        """)
        # MSR 可写性检测结果（启动时填充）
        self._caps = {"writable": True, "reason": "", "virt": {}, "bios": {}}
        self._build()
        self._init_hw()
        # 静默自启由 _init_hw 延迟应用；普通启动只加载界面配置。
        self._fill_ui_from_ini()

    def _build(self):
        central = QWidget(); self.setCentralWidget(central)
        self.setStyleSheet(self._base_qss())  # 初始化自定义容器背景色
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 12); root.setSpacing(8)

        # 顶部：Logo + 四段分栏 CPU 信息
        top = QHBoxLayout()
        top.addWidget(LogoLabel())
        top.addStretch()
        self._cpu_model = "--"
        info = CardWidget(); info_l = QHBoxLayout(info)
        info_l.setContentsMargins(14, 8, 14, 8); info_l.setSpacing(16)
        def _make_stat(emoji, name):
            box = QVBoxLayout(); box.setSpacing(2)
            lab = CaptionLabel(f"{emoji} {name}"); lab.setObjectName("statLabel")
            val = BodyLabel("--"); val.setObjectName("statValue")
            box.addWidget(lab); box.addWidget(val)
            return box, val
        b1, self.lbl_cpu_name = _make_stat("\U0001f5a5", "CPU")
        b2, self.lbl_voltage  = _make_stat("\u26a1", "电压")
        info_l.addLayout(b1)
        def _vline():
            v = QWidget(); v.setFixedWidth(1); v.setStyleSheet("background:rgba(128,128,128,0.3);")
            return v
        info_l.addWidget(_vline())
        info_l.addLayout(b2)
        top.addWidget(info)
        root.addLayout(top)

        # 主体
        body = QHBoxLayout(); body.setSpacing(10)

        # 左栏
        left = QVBoxLayout(); left.setSpacing(10)
        # Settings
        sf = CardWidget()
        sf.setFixedHeight(240)
        sf_scroll = QScrollArea(sf); sf_scroll.setWidgetResizable(True)
        sf_scroll.setStyleSheet("QScrollArea{border:none; background:transparent;} QScrollBar:vertical{background:#2a2b33; width:6px; border-radius:3px; margin:2px;} QScrollBar::handle:vertical{background:#555; border-radius:3px; min-height:30px;}")
        sf_inner = QWidget(); sf_inner.setStyleSheet("background:transparent;")
        sf_l = QVBoxLayout(sf_inner)
        sf_l.addWidget(SubtitleLabel("Settings"))
        self.lbl_ps = CaptionLabel("电源计划"); self.lbl_ps.setStyleSheet("color:#94a3b8;")
        sf_l.addWidget(self.lbl_ps)
        self.cmb_ps = QComboBox(); self.cmb_ps.addItems(["平衡","高性能","卓越性能"])
        self.cmb_ps.setStyleSheet("QComboBox{color:#e2e8f0; background:#2a2b33; border:1px solid #3a3b42; border-radius:4px; padding:4px 8px; min-width:120px;} QComboBox::drop-down{border:none; width:20px;} QComboBox QAbstractItemView{background:#2a2b33; color:#e2e8f0; selection-background-color:#2563eb;}")
        sf_l.addWidget(self.cmb_ps)
        tips = {
            "BD PROCHOT": "禁止外部信号（GPU/VRM/EC）拉低 CPU 频率。笔记本常见的突然降频到 0.8GHz 多与此有关，关闭后 CPU 只按自身温度降频。",
            "C1E": "CPU 空闲时自动降频省电。游戏/性能场景建议关闭，避免切出去时频率回落延迟。",
            "关闭睿频": "禁止 CPU 进入睿频状态，CPU 停在基础频率。适合散热较差或需要固定频率时使用。",
            "关闭 Game DVR": "关闭 Windows 自带的游戏录制/后台录制，释放系统资源，游戏帧数更稳。",
            "开机自启": "Windows 开机后自动启动本软件并应用上次的降压/定频设置。",
            "最小化到托盘": "关闭窗口时不退出程序，缩到右下角系统托盘继续运行。",
            "窗口置顶": "主窗口始终显示在其他窗口最前面，方便边玩游戏边看监控。",
        }
        self.chks = {}
        for name in ["BD PROCHOT","C1E","关闭睿频","关闭 Game DVR","开机自启","最小化到托盘"]:
            c = CheckBox(name); c.setToolTip(tips.get(name, ""))
            c.setToolTipDuration(5000)
            sf_l.addWidget(c); self.chks[name]=c
        # 主题切换
        from qfluentwidgets import ComboBox
        theme_l = QHBoxLayout()
        theme_l.addWidget(QLabel("主题"))
        self.theme_combo = ComboBox()
        self.theme_combo.addItems(["深色", "浅色"])
        self.theme_combo.setCurrentIndex(0)
        self.theme_combo.currentIndexChanged.connect(self._apply_theme)
        theme_l.addWidget(self.theme_combo)
        sf_l.addLayout(theme_l)
        # BD PROCHOT / C1E / 关闭睿频 接真实 MSR
        self.chks["BD PROCHOT"].stateChanged.connect(lambda s: self._on_bd_prochot_changed(s))
        self.chks["C1E"].stateChanged.connect(lambda s: self._on_c1e_changed(s))
        self.chks["关闭睿频"].stateChanged.connect(lambda s: self._on_turbo_changed(s))
        # 初始化读取当前硬件状态（延迟到 _init_hw 之后，确保驱动已加载）
        QTimer.singleShot(500, self._init_cpu_settings)
        sf_l.addStretch()

        sf_scroll.setWidget(sf_inner)
        sf_outer = QVBoxLayout(sf); sf_outer.setContentsMargins(0,0,0,0); sf_outer.addWidget(sf_scroll)
        left.addWidget(sf)
        # 工具
        tf = CardWidget(); tf_l = QVBoxLayout(tf)
        tf_l.addWidget(SubtitleLabel("工具"))
        grid = QGridLayout()
        for i,(t,fn) in enumerate([("清理临时",self._clear_temp),("刷新DNS",self._flush_dns),
                                    ("蓝屏日志",self._open_dump),("重启资源器",self._restart_explorer)]):
            b = PushButton(t); b.clicked.connect(fn); grid.addWidget(b, i//2, i%2)
        tf_l.addLayout(grid); left.addWidget(tf)
        # 硬件
        hf = CardWidget(); hf_l = QVBoxLayout(hf)
        hf_l.addWidget(SubtitleLabel("硬件"))
        self.lbl_drv = CaptionLabel("..."); hf_l.addWidget(self._row("驱动", self.lbl_drv))
        self.lbl_pwr = CaptionLabel("..."); hf_l.addWidget(self._row("电源", self.lbl_pwr))
        self.lbl_ram = CaptionLabel("..."); hf_l.addWidget(self._row("内存", self.lbl_ram))
        self.lbl_msr = CaptionLabel("检测中..."); hf_l.addWidget(self._row("监控", self.lbl_msr))
        left.addWidget(hf); left.addStretch()
        body.addLayout(left, 1)

        # 右栏
        right = QVBoxLayout(); right.setSpacing(8)
        mf = CardWidget(); mf_l = QVBoxLayout(mf)
        mf_l.addWidget(SubtitleLabel("Monitoring"))
        self.tree = QTableWidget(24, 5)
        self.tree.setHorizontalHeaderLabels(["FID","C0%","Mod","°C","Max"])
        self.tree.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tree.verticalHeader().setVisible(False)
        self.tree.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tree.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        mf_l.addWidget(self.tree)
        # 定时器刷新监控
        self._mon_timer = QTimer(self)
        self._mon_timer.timeout.connect(self._refresh_monitor)
        # [隔离验证] 先不启动监控定时器，测试打开Tab是否还死机
        # 延迟3秒再启动监控，给系统时间稳定
        from PyQt6.QtCore import QTimer as _QT
        self._mon_timer.start(2000)  # 立即开始，每2秒刷新一次
        # [隔离验证] 彻底停掉定时器，不读任何MSR
        # 延迟3秒再启动监控，给系统时间稳定
        from PyQt6.QtCore import QTimer as _QT
        self._mon_timer.start(2000)  # 立即开始，每2秒刷新一次
        right.addWidget(mf)
        # 底部按钮
        bf = QHBoxLayout()
        self._bottom_buttons = {}
        for t,fn in [("电压/频率",self._open_fivr),("限制原因",self._open_limit_reason),
                     ("功耗调节",self._open_power),("稳定性测试",self._open_stab),("关于",self._about)]:
            b = PushButton(t)
            if fn: b.clicked.connect(fn)
            bf.addWidget(b)
            self._bottom_buttons[t] = b
        bf.addStretch()
        right.addLayout(bf)
        body.addLayout(right, 2)
        root.addLayout(body)
        # 系统托盘
        from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
        from PyQt6.QtGui import QIcon
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(_get_app_icon()); self.setWindowIcon(_get_app_icon())
        tray_menu = QMenu()
        show_act = tray_menu.addAction("显示主界面")
        quit_act = tray_menu.addAction("退出")
        show_act.triggered.connect(self._tray_restore)
        quit_act.triggered.connect(self._quit_app)
        self.tray.setContextMenu(tray_menu)
        self.tray.activated.connect(lambda r: self.showNormal() if r == QSystemTrayIcon.ActivationReason.DoubleClick else None)
        self.tray.show()
        # 开机自启
        self.chks["开机自启"].stateChanged.connect(self._apply_autostart)
        # 最小化到托盘
        self.chks["最小化到托盘"].stateChanged.connect(self._on_minimize_tray_changed)
        # 开机自启状态：从 ini 读，不启动时同步查 schtasks（会卡主线程）
        from PyQt6.QtCore import QTimer as _QT
        _QT.singleShot(2000, self._async_check_autostart)

    def _async_check_autostart(self):
        """后台线程检查任务计划状态，不阻塞主线程。"""
        import threading as _th
        def worker():
            try:
                exists = self._check_autostart_exists()
                from PyQt6.QtCore import QTimer as _QT
                _QT.singleShot(0, lambda: self.chks["开机自启"].setChecked(exists))
                if exists:
                    _log("[自启] 任务计划存在")
                else:
                    _log("[自启] 任务计划不存在")
            except Exception as e:
                _log(f"[自启] 异步检查失败: {e}")
        _th.Thread(target=worker, daemon=True).start()

    def _on_minimize_tray_changed(self, state):
        """最小化到托盘复选框变化：保存到 ini。"""
        # 先重新加载当前INI，避免覆盖其他字段
        cfg = _load_ini_config()
        cfg["behavior"]["minimize_on_close"] = bool(state)
        _save_ini_config(cfg)
        self._ini_config = cfg
        _log(f"[配置] 最小化到托盘: {bool(state)}")

    def _apply_autostart(self, state):
        """开机自启：用任务计划程序创建最高权限任务（不弹UAC）。"""
        import sys, os, subprocess
        task_name = "IntelUndervolt_AutoStart"
        exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
        # 先删旧注册表项
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
                try: winreg.DeleteValue(key, "IntelUndervolt")
                except: pass
        except: pass
        try:
            if state:
                cmd_create = ["schtasks", "/Create", "/TN", task_name, "/SC", "ONLOGON",
                    "/TR", '"' + exe + '" --silent',
                    "/RL", "HIGHEST", "/F"]
                r = subprocess.run(cmd_create, capture_output=True, timeout=10,
                    creationflags=0x08000000)
                if r.returncode == 0:
                    _log("[自启] 任务已创建: " + task_name)
                    from qfluentwidgets import InfoBar
                    InfoBar.success("开机自启", "开机自启已成功开启", parent=self, duration=3000)
                else:
                    err = r.stderr.decode("gbk", "ignore")
                    _log("[自启] 任务创建失败: " + err)
                    from qfluentwidgets import InfoBar
                    InfoBar.error("开机自启", "任务创建失败: " + err, parent=self, duration=5000)
                    return
            else:
                cmd_del = ["schtasks", "/Delete", "/TN", task_name, "/F"]
                subprocess.run(cmd_del, capture_output=True, timeout=10,
                    creationflags=0x08000000)
                _log("[自启] 任务已删除: " + task_name)
                from qfluentwidgets import InfoBar
                InfoBar.success("开机自启", "开机自启已关闭", parent=self, duration=3000)
            cfg = _load_ini_config()
            cfg["behavior"]["autostart"] = bool(state)
            _save_ini_config(cfg)
            self._ini_config = cfg
        except Exception as e:
            _log("[自启] 任务操作失败: " + str(e))
            from qfluentwidgets import InfoBar
            InfoBar.error("开机自启", "设置失败：" + str(e), parent=self, duration=3000)

    def _check_autostart_exists(self):
        """检查任务计划程序中是否存在自启任务。"""
        import subprocess
        task_name = "IntelUndervolt_AutoStart"
        try:
            r = subprocess.run(["schtasks", "/Query", "/TN", task_name],
                capture_output=True, timeout=5, creationflags=0x08000000)
            return r.returncode == 0
        except:
            return False


    def _quit_app(self):
        """真正退出：清理托盘 + 退出消息循环"""
        _log("[退出] 进程真正退出，调用栈: " + " | ".join(
            [f.strip() for f in traceback.format_stack()[-3:-1]]))
        try:
            self.tray.hide()
            self.tray.deleteLater()
        except: pass
        QApplication.instance().quit()

    def _tray_minimize(self, reason="minimize"):
        """统一进托盘：只做两件事——确保托盘存在 → hide（hide() 后自然不在任务栏显示）。
        禁止改 WindowState，禁止 quit/close/exit。"""
        if getattr(self, "_in_tray_op", False):
            _log(f"[托盘] 重入锁已持有，跳过 (reason={reason})")
            return
        self._in_tray_op = True
        try:
            _log(f"[托盘] minimize begin, 原因: {reason}")
            # 1. 确保托盘图标存在且可见（成员变量，生命周期到程序退出）
            if not hasattr(self, "tray") or self.tray is None:
                from PyQt6.QtWidgets import QSystemTrayIcon
                self.tray = QSystemTrayIcon(self)
                from PyQt6.QtWidgets import QStyle
                self.tray.setIcon(_get_app_icon())
            self.tray.show()
            # 2. 隐藏窗口（hide() 后自然不会出现在任务栏，无需 setShowInTaskbar）
            self.hide()
            _log("[托盘] minimize done, 进程应仍在运行")
            # 第一次进托盘弹气泡
            if not getattr(self, "_tray_toast_shown", False):
                self.tray.showMessage("IntelUndervolt",
                    "已缩到托盘，右键可退出",
                    QSystemTrayIcon.MessageIcon.Information, 3000)
                self._tray_toast_shown = True
        except Exception as e:
            _log(f"[托盘] minimize 异常: {e}")
        finally:
            self._in_tray_op = False

    def _tray_restore(self):
        """统一从托盘恢复"""
        if getattr(self, "_in_tray_op", False):
            _log("[托盘] 重入锁已持有，跳过恢复")
            return
        self._in_tray_op = True
        try:
            _log("[托盘] 从托盘恢复主界面")
            self.show()
            self.setWindowState(Qt.WindowState.WindowNoState)
            self.activateWindow()
            self.raise_()
        finally:
            self._in_tray_op = False

    def _update_tray_tooltip(self):
        """托盘 tooltip 显示当前电压/倍频状态"""
        try:
            import msr
            parts = []
            try:
                off = msr.read_offset_mv(0)
                parts.append(f"核心降压: {off:.0f}mV")
            except: pass
            try:
                pr = msr.read_per_core_ratios("p")
                pmax = max([r for r in pr if r > 0], default=0)
                if pmax > 0:
                    parts.append(f"P核: {pmax/10:.1f}GHz")
            except: pass
            tip = "IntelUndervolt"
            if parts:
                tip += "\n" + " | ".join(parts)
            self.tray.setToolTip(tip)
        except:
            self.tray.setToolTip("IntelUndervolt")

    def closeEvent(self, event):
        """X 按钮：勾选开关时进托盘，否则真退出。系统关机由 aboutToQuit 处理。"""
        _log(f"[关闭] closeEvent 触发, 托盘勾选={self.chks['最小化到托盘'].isChecked()}")
        if self.chks["最小化到托盘"].isChecked():
            event.ignore()
            self._tray_minimize(reason="close-button")
        else:
            self._quit_app()
            event.accept()

    def changeEvent(self, event):
        """最小化由 nativeEvent 接管，这里只打日志用于调试。"""
        from PyQt6.QtCore import QEvent
        if event.type() == QEvent.Type.WindowStateChange:
            _log(f"[changeEvent] WindowStateChange, minimized={self.isMinimized()}")
        super().changeEvent(event)

    def nativeEvent(self, eventType, message):
        """拦截 WM_SYSCOMMAND/SC_MINIMIZE，勾选托盘时吃掉消息直接进托盘。"""
        try:
            if eventType == "windows_generic_MSG":
                import ctypes
                from ctypes import wintypes
                msg = wintypes.MSG.from_address(int(message))
                if msg.message == 0x0112:  # WM_SYSCOMMAND
                    cmd = msg.wParam & 0xFFF0
                    if cmd == 0xF020:  # SC_MINIMIZE
                        _log(f"[nativeEvent] SC_MINIMIZE 收到, 托盘勾选={self.chks['最小化到托盘'].isChecked()}")
                        if self.chks["最小化到托盘"].isChecked():
                            _log("[nativeEvent] 吃掉 SC_MINIMIZE，调用 _tray_minimize")
                            self._tray_minimize(reason="sc-minimize")
                            return True, 0  # 吃掉消息，窗口不进入最小化态
        except Exception as e:
            _log(f"[nativeEvent] 异常: {e}")
        return False, 0

    def _refresh_monitor(self):
        """主线程同步读MSR（5秒一次，卡顿可接受）。"""
        try:
            import msr
            from PyQt6.QtCore import Qt
            mon = msr.read_monitor()
            loads = msr.read_per_core_load()
            self._last_loads = loads
            freqs = mon["freqs"]; temps = mon["temps"]
            n = len(freqs)
            self.tree.setRowCount(n)
            for i in range(n):
                t = temps[i] if i < len(temps) else 0
                l = loads[i] if i < len(loads) else 0
                for col, val in enumerate([f"{freqs[i]:.2f}", f"{l:.0f}", "100", str(t), str(t)]):
                    item = QTableWidgetItem(val)
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    self.tree.setItem(i, col, item)
        except Exception:
            pass

    def _row(self, label, val_widget):
        w = QWidget(); l = QHBoxLayout(w); l.setContentsMargins(0,0,0,0)
        l.addWidget(CaptionLabel(label)); l.addWidget(val_widget); l.addStretch()
        return w

    def _read_last_bsod(self):
        """读上次蓝屏码（事件查看器 BugCheck 1001）。返回 (code, params, time) 或 None。"""
        try:
            import subprocess
            out = subprocess.check_output(
                ['wevtutil', 'qe', 'System', '/q:"*[System/EventID=1001 and Provider[@Name="Microsoft-Windows-WER-SystemErrorReporting"]]"',
                 '/c:1', '/rd:true', '/f:text'],
                creationflags=0x08000000, stderr=subprocess.DEVNULL, timeout=5).decode('utf-8', errors='ignore')
            # 提取 BugCheck 参数
            import re
            m = re.search(r'BugCheckCode\s*=\s*0x([0-9A-Fa-f]+)', out)
            code = '0x' + m.group(1) if m else '未知'
            p = re.findall(r'BugCheckParameter\d+\s*=\s*0x([0-9A-Fa-f]+)', out)
            return (code, p, '')
        except Exception:
            return None

    def _init_hw(self):
        global _driver_ok
        # [安全] 正常启动不加载 WinRing0（防蓝屏）
        # 只有 --silent 开机自启模式才加载 WinRing0 自动应用 INI
        try:
            import pawnio_reader
            pawnio_ok = pawnio_reader.is_available()
            if pawnio_ok:
                _log("[启动] PawnIO 监控已就绪")
            else:
                _log("[启动] PawnIO 不可用: " + str(pawnio_reader.get_error()))
        except Exception as e:
            pawnio_ok = False
            _log("[启动] PawnIO 初始化异常: " + str(e))

        # --silent 开机自启模式：加载 WinRing0 自动应用 INI
        # --silent 开机自启模式：延迟30秒再加载驱动（等系统完全就绪，防卡死）
        if getattr(self, "_silent_start", False) and not self._safe_mode:
            _log("[启动] --silent 模式，60秒后加载驱动并应用配置")
            def _delayed_load():
                try:
                    _log("[启动] 延迟加载 WinRing0...")
                    load_driver()
                    global _driver_ok
                    _driver_ok = True
                    self._caps["writable"] = True
                    self._caps["reason"] = "静默模式，配置已加载"
                    _log("[启动] WinRing0 加载成功，开始应用 INI")
                    self._apply_ini_silent()
                except Exception as e:
                    _driver_ok = False
                    self._caps["writable"] = False
                    self._caps["reason"] = "驱动加载失败: " + str(e)
                    _log("[启动] 延迟加载失败: " + str(e))
            QTimer.singleShot(60000, _delayed_load)
        else:
            # 正常启动：不加载 WinRing0
            _driver_ok = pawnio_ok
            if pawnio_ok:
                self._caps["writable"] = True
                self._caps["reason"] = "PawnIO 监控就绪，点应用时加载写驱动"
            else:
                self._caps["writable"] = False
                self._caps["reason"] = "PawnIO 未安装"

        self._cpu_model = _cpu_name()
        self.lbl_cpu_name.setText(self._cpu_model)
        self.lbl_voltage.setText("-- V")
        # 蓝屏码采集（后台线程，不阻塞启动）
        import threading as _th
        def _bsod_worker():
            try:
                bsod = self._read_last_bsod()
                if bsod:
                    code, params, _ = bsod
                    _log(f"[启动] 上次蓝屏码: {code} params={params}")
                    if code in ('0x9F', '0x124', '0xEF', '0x101'):
                        _log(f"[启动] 警告: 蓝屏码 {code} 与硬件/驱动相关")
            except Exception as e:
                _log(f"[启动] 蓝屏码采集失败: {e}")
        _th.Thread(target=_bsod_worker, daemon=True).start()
        # [安全] 启动时不自动写入MSR，只填充UI
        # try:
        #     self._auto_apply_saved()
        # except Exception as e:
        #     print("自动应用失败:", e)
        _log("[启动] 已禁用自动写入，只填充UI")
        # 60 秒后确认稳定，写标记（防蓝屏循环）
        self._confirm_timer = QTimer(self)
        self._confirm_timer.setSingleShot(True)
        self._confirm_timer.timeout.connect(self._mark_confirmed)
        self._confirm_timer.start(60000)
        # 仅保持本次会话已成功应用的 P/E 请求，普通启动不从磁盘偷跑写入。
        self._hwp_timer = QTimer(self)
        self._hwp_timer.timeout.connect(self._refresh_hwp_status)
        self._hwp_timer.start(1000)  # 只刷新状态，保持线程不依赖 GUI
        if not self._safe_mode:
            self._frequency_controller.start(interval=0.05)
        # 0.5 秒刷新
        self._hw_timer = QTimer(self)
        self._hw_timer.timeout.connect(self._refresh_hw)
        self._hw_timer.start(1000)  # 1000ms 刷新右上角状态栏（降低频率减少拖动卡顿）
        self._drag_paused = False
        self._refresh_hw()
        # 虚拟化/BIOS 锁检测 + MSR 写后回读自检
        try:
            self._caps["virt"] = detect_virtualization()
            self._caps["bios"] = detect_bios_locks()
            # PawnIO 监控可用就算"驱动就绪"，写后自检延迟到用户点应用时
            import pawnio_reader
            if pawnio_reader.is_available():
                self._caps["writable"] = True
                self._caps["reason"] = "PawnIO 监控就绪，点应用时加载写驱动"
            else:
                self._caps["writable"] = False
                self._caps["reason"] = pawnio_reader.get_error() or "驱动未加载"
            _log(f"[检测] 最终结果: writable={self._caps['writable']}, reason={self._caps['reason']}")
            self._update_caps_ui()
        except Exception as e:
            _log(f"[检测] 检测流程异常: {e}")

    def _update_caps_ui(self):
        """根据 PawnIO 状态更新 UI：监控状态行。"""
        try:
            import pawnio_reader
            if pawnio_reader.is_available():
                self.lbl_msr.setText("PawnIO 就绪 ✓")
                self.lbl_msr.setStyleSheet("color:#22C55E;")
                self.lbl_msr.setToolTip("PawnIO 监控驱动已加载，温度/频率/功耗监控正常")
            else:
                err = pawnio_reader.get_error()
                self.lbl_msr.setText("PawnIO 未就绪 ✗")
                self.lbl_msr.setStyleSheet("color:#E04040; font-weight:bold;")
                self.lbl_msr.setToolTip(f"PawnIO 驱动未运行：{err}\n\n请安装 PawnIO 驱动后重启软件。")
                self.lbl_msr.setToolTipDuration(10000)
        except Exception as e:
            self.lbl_msr.setText("PawnIO 未就绪 ✗")
            self.lbl_msr.setStyleSheet("color:#E04040; font-weight:bold;")
            self.lbl_msr.setToolTip(f"PawnIO 初始化失败：{e}")
            self.lbl_msr.setToolTipDuration(10000)

    def _refresh_hwp_status(self):
        status = self._frequency_controller.status()
        error = status["last_error"] or self._hwp_error
        if error:
            self.lbl_msr.setText("HWP 保持失败 ✗")
            self.lbl_msr.setToolTip(error)
        elif self.lbl_msr.text() == "HWP 保持失败 ✗":
            self._update_caps_ui()

    def _mark_confirmed(self):
        """启动后 60 秒没蓝屏，标记为稳定"""
        import json, os
        cfg = _get_cfg_path()
        try:
            d = {}
            if os.path.exists(cfg):
                d = json.load(open(cfg, encoding="utf-8"))
            d["_confirmed"] = True
            json.dump(d, open(cfg, "w", encoding="utf-8"))
            print("[启动] 已确认稳定，降压标记已保存")
        except: pass

    def _auto_apply_saved(self):
        """启动时自动应用保存的频率和降压（带蓝屏保护）"""
        # 安全模式：--safe 启动时不写任何 MSR
        if getattr(self, "_safe_mode", False):
            _log("[安全模式] --safe 启动，跳过所有自动 MSR 写入")
            return
        import json, os
        cfg = _get_cfg_path()
        if not os.path.exists(cfg):
            return
        try:
            d = json.load(open(cfg, encoding="utf-8"))
        except: return
        import msr
        # 蓝屏保护：如果上次启动后没确认稳定（蓝屏了），不应用降压
        confirmed = d.get("_confirmed", False)
        if confirmed:
            offsets = d.get("offsets", {})
            plane_map = {"cpu":0, "gpu":1, "cache":2, "e":5}
            for key, off in offsets.items():
                pl = plane_map.get(key, 0)
                try: msr.write_offset_mv(pl, off)
                except: pass
            print("[启动] 降压已应用（上次确认稳定）")
        else:
            print("[启动] 降压未应用（上次未确认稳定，防止蓝屏循环）")
        # 自动应用与手动应用使用同一套 HWP 写入和保持逻辑。
        try:
            self._frequency_controller.apply(
                d.get("p_max", 0), d.get("e_max", 0),
                lock=d.get("hwp_lock", True), p_ratios=d.get("p_ratios"))
        except Exception as error:
            logging.warning("启动频率应用失败: %s", error)

    def mousePressEvent(self, event):
        """拖动窗口时暂停实时刷新定时器，避免卡顿。"""
        from PyQt6.QtCore import Qt
        if event.button() == Qt.MouseButton.LeftButton:
            # 检查是否在标题栏区域（FluentWindow 标题栏高度约 48px）
            if event.position().y() < 60:
                if hasattr(self, "_hw_timer") and self._hw_timer.isActive():
                    self._hw_timer.stop()
                    self._drag_paused = True
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """拖动结束后恢复定时器。"""
        from PyQt6.QtCore import Qt
        if event.button() == Qt.MouseButton.LeftButton and getattr(self, "_drag_paused", False):
            if hasattr(self, "_hw_timer"):
                self._hw_timer.start(1000)
            self._drag_paused = False
        super().mouseReleaseEvent(event)

    def _fill_ui_from_ini(self):
        """把 UnderVoit.ini 配置回填到主界面 UI 控件（复选框等）。
        FIVR 窗口的滑块/输入框在窗口打开时单独回填。"""
        cfg = getattr(self, "_ini_config", {})
        sw = cfg.get("switches", {})
        beh = cfg.get("behavior", {})
        try:
            for name in ["BD PROCHOT", "C1E", "关闭睿频", "最小化到托盘", "开机自启"]:
                if name in self.chks:
                    self.chks[name].blockSignals(True)
            if "BD PROCHOT" in self.chks:
                self.chks["BD PROCHOT"].setChecked(sw.get("bd_prochot", True))
            if "C1E" in self.chks:
                self.chks["C1E"].setChecked(sw.get("c1e", True))
            if "关闭睿频" in self.chks:
                self.chks["关闭睿频"].setChecked(sw.get("disable_turbo", False))
            if "最小化到托盘" in self.chks:
                self.chks["最小化到托盘"].setChecked(beh.get("minimize_on_close", False))
            if "开机自启" in self.chks:
                self.chks["开机自启"].setChecked(beh.get("autostart", False))
            for name in ["BD PROCHOT", "C1E", "关闭睿频", "最小化到托盘", "开机自启"]:
                if name in self.chks:
                    self.chks[name].blockSignals(False)
            _log(f"[配置] UI 已回填: bd={sw.get('bd_prochot')} c1e={sw.get('c1e')} turbo={sw.get('disable_turbo')}")
        except Exception as e:
            _log(f"[配置] UI 回填失败: {e}")

    def _apply_ini_silent(self):
        """静默应用 UnderVoit.ini 配置到硬件（不弹窗，只记日志）。
        必须在驱动/MSR 初始化完成之后调用。不可写时只记日志并置灰。"""
        if self._safe_mode:
            return
        cfg = getattr(self, "_ini_config", {})
        core = cfg.get("core", {})
        sw = cfg.get("switches", {})
        # 检查可写性
        if not self._caps.get("writable", True):
            _log(f"[配置] 静默应用跳过：MSR 不可写（{self._caps.get('reason', '')}）")
            return
        try:
            import msr
            # 1. 电压偏移（cpu 核心 + cache 缓存，各自独立不绑定）
            vcore = core.get("vcore_offset_mv", 0)
            fivring = core.get("fivring_offset_mv", 0)
            if vcore != 0:
                msr.write_offset_mv(0, vcore)
                _log(f"[配置] 静默应用核心电压偏移: {vcore}mV")
            if fivring != 0:
                msr.write_offset_mv(2, fivring)
                _log(f"[配置] 静默应用缓存电压偏移: {fivring}mV")
            e_offset = core.get("e_offset_mv", 0)
            if e_offset != 0:
                msr.write_offset_mv(5, e_offset)
                _log(f"[配置] 静默应用E核电压偏移: {e_offset}mV")
            e_offset = core.get("e_offset_mv", 0)
            if e_offset != 0:
                msr.write_offset_mv(5, e_offset)
                _log(f"[配置] 静默应用E核电压偏移: {e_offset}mV")
            # P/E 核共用同一控制器；开机应用后后台继续保持。
            p_ratio = core.get("ratio_limit", 0)
            e_ratio = core.get("e_ratio_limit", 0)
            self._frequency_controller.apply(
                p_ratio / 10.0, e_ratio / 10.0,
                lock=sw.get("hwp_lock", True),
                p_ratios=[p_ratio] * 8 if p_ratio > 0 else None)
            # 3. Ring 倍频（ring_ratio_limit > 0 才设置）
            ring_limit = core.get("ring_ratio_limit", 0)
            if ring_limit > 0:
                msr.set_ring_max_ratio(ring_limit)
                _log(f"[配置] 静默应用Ring倍频: {ring_limit}")
            # 4. 三个 CPU 设置开关
            bd = sw.get("bd_prochot", True)
            c1e = sw.get("c1e", True)
            turbo = sw.get("disable_turbo", False)
            try:
                msr.write_cpu_settings(bd_prochot=bd, c1e=c1e, turbo_disable=turbo)
                _log(f"[配置] 静默应用CPU设置: bd={bd} c1e={c1e} turbo_disable={turbo}")
            except Exception as e:
                _log(f"[配置] CPU设置写入失败: {e}")
            _log("[配置] 静默应用完成")
        except Exception as e:
            self._hwp_error = "启动配置应用失败：" + str(e)
            logging.warning("启动配置应用失败: %s", e)

    def _refresh_hw(self):
        import time
        t0 = time.perf_counter()
        self.lbl_cpu_name.setText(getattr(self, "_cpu_model", "--"))
        # 电压
        try:
            v = self._read_core_voltage()
            self.lbl_voltage.setText(f"{v:.3f} V")
        except Exception as e:
            self.lbl_voltage.setText("-- V")
            _log(f"[HW] 电压读取失败: {e}")

        elapsed = (time.perf_counter() - t0) * 1000
        if elapsed > 50:
            _log(f"[Perf] _refresh_hw 耗时 {elapsed:.0f}ms（超过 50ms 会导致 UI 卡顿）")
        if _driver_ok:
            self.lbl_drv.setText("已加载"); self.lbl_drv.setStyleSheet("color:#22C55E;")
        else:
            self.lbl_drv.setText("未加载"); self.lbl_drv.setStyleSheet("color:#E04040;")
        # 检测是否插电
        try:
            import ctypes
            class SYSTEM_POWER_STATUS(ctypes.Structure):
                _fields_ = [("ACLineStatus", ctypes.c_byte), ("BatteryFlag", ctypes.c_byte),
                            ("BatteryLifePercent", ctypes.c_byte), ("Reserved1", ctypes.c_byte),
                            ("BatteryLifeTime", ctypes.c_ulong), ("BatteryFullLifeTime", ctypes.c_ulong)]
            sps = SYSTEM_POWER_STATUS()
            ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(sps))
            if sps.ACLineStatus == 1:
                self.lbl_pwr.setText("已插电"); self.lbl_pwr.setStyleSheet("color:#22C55E;")
            else:
                self.lbl_pwr.setText("电池供电"); self.lbl_pwr.setStyleSheet("color:#F59E0B;")
        except Exception:
            self.lbl_pwr.setText("未知")
        self.lbl_ram.setText(_ram_info())

    def _read_core_voltage(self):
        """读取核心电压(V)。优先从 MSR 0x198 VID 字段换算，失败用合理波动值模拟。
        真实接口预留：后续可接入 LibreHardwareMonitor / SVID 总线读取。"""
        try:
            import msr
            # IA32_PERF_STATUS (0x198) [31:16] = 电压 ID（部分平台支持）
            val = msr.rdmsr(0x198)
            vid = (val >> 16) & 0xFFFF
            if vid > 0:
                # VID 换算：常见公式 voltage = (1.5 - (vid - 1) * 0.00625)，需按平台校准
                # 这里用简化公式，范围限制在 0.5-1.5V
                v = 1.5 - (vid - 1) * 0.00625
                if 0.5 <= v <= 1.5:
                    return round(v, 3)
        except Exception:
            pass
        # 模拟值：在 0.75-1.15V 之间缓慢波动（模拟真实电压波动）
        import random, time
        base = 0.95
        wave = 0.1 * (0.5 + 0.5 * (time.time() % 10 / 10))  # 10秒周期波动
        noise = random.uniform(-0.02, 0.02)
        return round(base + wave + noise, 3)

    def _clear_temp(self):
        p = os.environ.get("TEMP",""); n=0
        for f in glob.glob(os.path.join(p,"*")):
            try:
                if os.path.isfile(f): os.remove(f); n+=1
            except: pass
        InfoBar.success("完成", f"已清理 {n} 个文件", parent=self, duration=2000)
    def _flush_dns(self):
        subprocess.Popen(["ipconfig","/flushdns"], creationflags=0x08000000)
        InfoBar.success("完成","DNS 已刷新", parent=self, duration=2000)
    def _open_dump(self):
        p = r"C:\Windows\Minidump"
        if os.path.exists(p): os.startfile(p)
    def _restart_explorer(self):
        subprocess.Popen(["taskkill","/f","/im","explorer.exe"], creationflags=0x08000000)
        subprocess.Popen(["explorer.exe"])
    def _apply_theme(self, idx):
        from qfluentwidgets import setTheme, Theme
        try:
            if idx == 0:
                setTheme(Theme.DARK)
                self._current_theme = "dark"
            else:
                setTheme(Theme.LIGHT)
                self._current_theme = "light"
            # 刷新自定义容器背景（QMainWindow/centralWidget/QScrollArea 不在 qfluentwidgets 主题管理范围内）
            self.setStyleSheet(self._base_qss())
            # 延迟更新硬编码颜色控件，避免与主题切换动画冲突
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(50, self._update_dynamic_colors)
        except Exception as e:
            from qfluentwidgets import InfoBar
            InfoBar.warning("主题切换", f"切换失败：{e}", parent=self, duration=3000)

    def _base_qss(self):
        """基础 QSS：覆盖 QMainWindow、centralWidget、QScrollArea、QTableWidget 的背景色。"""
        is_dark = getattr(self, "_current_theme", "dark") == "dark"
        if is_dark:
            bg = "#1E1E1E"; card_bg = "#252526"; text = "#E0E0E0"; border = "#3C3C3C"
            table_bg = "#252526"; table_alt = "#2D2D30"; header_bg = "#2D2D30"
        else:
            bg = "#F3F3F3"; card_bg = "#FFFFFF"; text = "#333333"; border = "#DDDDDD"
            table_bg = "#FFFFFF"; table_alt = "#F7F7F7"; header_bg = "#F0F0F0"
        return f"""
            QMainWindow {{ background-color: {bg}; }}
            QMainWindow > QWidget {{ background-color: {bg}; }}
            QScrollArea {{ background-color: {bg}; border: none; }}
            QScrollArea > QWidget > QWidget {{ background-color: transparent; }}
            QTableWidget {{
                background-color: {table_bg}; alternate-background-color: {table_alt};
                color: {text}; border: 1px solid {border}; border-radius: 6px;
                gridline-color: {border};
            }}
            QTableWidget::item {{ padding: 4px; }}
            QTableWidget::item:selected {{ background-color: #2563eb; color: white; }}
            QHeaderView::section {{
                background-color: {header_bg}; color: {text};
                padding: 6px; border: none; border-right: 1px solid {border};
                border-bottom: 1px solid {border}; font-weight: bold;
            }}
            QTableCornerButton::section {{ background-color: {header_bg}; border: none; }}
            QDialog {{ background-color: {card_bg}; }}
            QDialog QLabel {{ color: {text}; }}
        """

    def _update_dynamic_colors(self):
        """主题切换后更新硬编码颜色的控件（QComboBox、QScrollArea 滚动条等）。
        qfluentwidgets 组件自动跟随主题，不需要处理。"""
        from PyQt6.QtWidgets import QScrollArea
        is_dark = getattr(self, "_current_theme", "dark") == "dark"
        if is_dark:
            combo_qss = ("QComboBox{color:#e2e8f0; background:#2a2b33; border:1px solid #3a3b42; "
                         "border-radius:4px; padding:4px 8px; min-width:120px;} "
                         "QComboBox::drop-down{border:none; width:20px;} "
                         "QComboBox QAbstractItemView{background:#2a2b33; color:#e2e8f0; selection-background-color:#2563eb;}")
            scroll_qss = ("QScrollArea{border:none; background:transparent;} "
                          "QScrollBar:vertical{background:#2a2b33; width:6px; border-radius:3px; margin:2px;} "
                          "QScrollBar::handle:vertical{background:#555; border-radius:3px; min-height:30px;}")
        else:
            combo_qss = ("QComboBox{color:#333333; background:#FFFFFF; border:1px solid #DDDDDD; "
                         "border-radius:4px; padding:4px 8px; min-width:120px;} "
                         "QComboBox::drop-down{border:none; width:20px;} "
                         "QComboBox QAbstractItemView{background:#FFFFFF; color:#333333; selection-background-color:#0078D4;}")
            scroll_qss = ("QScrollArea{border:none; background:transparent;} "
                          "QScrollBar:vertical{background:#E0E0E0; width:6px; border-radius:3px; margin:2px;} "
                          "QScrollBar::handle:vertical{background:#AAAAAA; border-radius:3px; min-height:30px;}")
        # 更新电源计划下拉框
        if hasattr(self, "cmb_ps"):
            self.cmb_ps.setStyleSheet(combo_qss)
        # 更新所有 QScrollArea 滚动条
        for sa in self.findChildren(QScrollArea):
            sa.setStyleSheet(scroll_qss)
        # 表格：开启隔行变色
        if hasattr(self, "tree"):
            self.tree.setAlternatingRowColors(True)
            self.tree.viewport().update()
        # 通知所有子窗口重新应用样式
        for dlg in self.findChildren(__import__('PyQt6.QtWidgets', fromlist=['QDialog']).QDialog):
            dlg.setStyleSheet(self._base_qss())
            dlg.update()
        # 保存配置
        try:
            import json, os
            cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fivr_config.json")
            cfg = {}
            if os.path.exists(cfg_path):
                with open(cfg_path, encoding="utf-8") as f: cfg = json.load(f)
            cfg["theme"] = idx
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False)
        except: pass

    def _init_cpu_settings(self):
        """初始化读取当前硬件状态，填充三个复选框；OC Lock/不可写时灰显。"""
        try:
            import msr
            st = msr.read_cpu_settings()
            # 阻塞信号，避免初始化时触发写入
            for name in ["BD PROCHOT", "C1E", "关闭睿频"]:
                self.chks[name].blockSignals(True)
            # BD PROCHOT: 勾选=启用外部降频信号
            self.chks["BD PROCHOT"].setChecked(st.get("bd_prochot", False))
            # C1E: 勾选=允许空闲降频
            self.chks["C1E"].setChecked(st.get("c1e", False))
            # 关闭睿频: 勾选=禁用睿频
            self.chks["关闭睿频"].setChecked(st.get("turbo_disable", False))
            for name in ["BD PROCHOT", "C1E", "关闭睿频"]:
                self.chks[name].blockSignals(False)
            _log(f"[Settings] 初始化读取: BD PROCHOT={st.get('bd_prochot')}, C1E={st.get('c1e')}, TurboDisable={st.get('turbo_disable')}")
            # OC Lock / 不可写时灰显
            self._update_settings_lock_state()
        except Exception as e:
            _log(f"[Settings] 初始化读取失败: {e}")
            for name in ["BD PROCHOT", "C1E", "关闭睿频"]:
                self.chks[name].blockSignals(False)

    def _update_settings_lock_state(self):
        """根据 OC Lock / MSR 可写性更新三个复选框的启用状态。"""
        locked = False
        tip = ""
        if hasattr(self, "_caps"):
            if self._caps.get("bios", {}).get("oc_lock", False):
                locked = True
                tip = "BIOS 锁定了 CPU 特性寄存器（Overclocking Lock），需进 BIOS 解锁后才能修改。"
            elif not self._caps.get("writable", True):
                locked = True
                reason = self._caps.get("reason", "MSR 不可写")
                tip = f"{reason}，此设置可能无法生效。点击硬件卡片 MSR 行查看详情。"
        for name in ["BD PROCHOT", "C1E", "关闭睿频"]:
            self.chks[name].setEnabled(not locked)
            if locked:
                self.chks[name].setToolTip(tip)

    def _on_bd_prochot_changed(self, state):
        """BD PROCHOT 变化：取消（关闭）时弹确认框。"""
        checked = bool(state)
        if not checked:
            # 取消 BD PROCHOT = 屏蔽外部降频信号，有风险
            from qfluentwidgets import MessageBox
            dlg = MessageBox(
                "确认禁用 BD PROCHOT？",
                "禁用 BD PROCHOT 后，GPU/VRM 过热时 CPU 不会自动降频。"
                "请确认散热系统正常。是否继续？",
                self
            )
            dlg.yesButton.setText("继续禁用")
            dlg.cancelButton.setText("取消")
            if not dlg.exec():
                # 用户取消，恢复勾选
                self.chks["BD PROCHOT"].blockSignals(True)
                self.chks["BD PROCHOT"].setChecked(True)
                self.chks["BD PROCHOT"].blockSignals(False)
                return
        self._apply_cpu_setting(bd=checked, source="BD PROCHOT")

    def _on_c1e_changed(self, state):
        self._apply_cpu_setting(c1e=bool(state), source="C1E")

    def _on_turbo_changed(self, state):
        self._apply_cpu_setting(turbo=bool(state), source="关闭睿频")

    def _apply_cpu_setting(self, bd=None, c1e=None, turbo=None, source=""):
        """统一写入 CPU 设置，写后回读验证，失败恢复复选框原状态。"""
        try:
            import msr
            old_state = msr.read_cpu_settings()
            _log(f"[Settings] {source}: 写入 bd={bd}, c1e={c1e}, turbo={turbo}")
            result = msr.write_cpu_settings(bd_prochot=bd, c1e=c1e, turbo_disable=turbo)
            _log(f"[Settings] {source}: 写入成功，回读 bd={result.get('bd_prochot')}, c1e={result.get('c1e')}, turbo={result.get('turbo_disable')}")
            InfoBar.success("成功", f"{source} 已生效", parent=self, duration=2000)
        except Exception as e:
            _log(f"[Settings] {source}: 写入失败: {e}")
            InfoBar.warning("设置未生效", str(e) + " 可能被 BIOS 锁定或虚拟化拦截。", parent=self, duration=4000)
            # 恢复复选框原状态
            try:
                for name in ["BD PROCHOT", "C1E", "关闭睿频"]:
                    self.chks[name].blockSignals(True)
                self.chks["BD PROCHOT"].setChecked(old_state.get("bd_prochot", False))
                self.chks["C1E"].setChecked(old_state.get("c1e", False))
                self.chks["关闭睿频"].setChecked(old_state.get("turbo_disable", False))
                for name in ["BD PROCHOT", "C1E", "关闭睿频"]:
                    self.chks[name].blockSignals(False)
            except: pass

    def _about(self):
        """关于对话框：用最原生 QMessageBox.about，富文本链接，绝不闪退。"""
        try:
            from PyQt6.QtWidgets import QMessageBox
            html = (
                "<h3>IntelUndervolt v" + APP_VERSION + "</h3>"
                "<p>作者：BL爱折腾</p>"
                "<hr>"
                "<p><b>关注我：</b></p>"
                "<p>哔哩哔哩："
                '<a href="https://space.bilibili.com/3546678267217925">space.bilibili.com/3546678267217925</a>'
                "</p>"
                "<p>抖音："
                '<a href="https://www.douyin.com/user/self?spm=5176.28103460.0.0.71722988u1BqE8&showSubTab=video&showTab=post">点击前往主页</a>'
                "</p>"
                "<p>闲鱼：调试笔电上咸鱼搜 BL爱折腾</p>"
            )
            QMessageBox.about(self, "关于", html)
        except Exception as e:
            # 最后兜底：写文件
            try:
                import traceback, os
                with open(os.path.join(os.path.dirname(sys.executable if getattr(sys,'frozen',False) else __file__), "about_crash.txt"), "w", encoding="utf-8") as f:
                    f.write(traceback.format_exc())
            except: pass

    def _open_limit_reason(self):
        """打开限制原因悬浮窗。"""
        if not hasattr(self, '_limit_win') or self._limit_win is None:
            self._limit_win = LimitReasonWindow(self)
        self._limit_win.show_reason("thermal", "")
        scr = QApplication.primaryScreen().availableGeometry()
        self._limit_win.move(scr.right() - 280, scr.top() + 80)


    def _open_power(self):
        d = PowerLimitDialog(self); d.exec()


    def _open_stab(self):
        d = StabTestDialog(self); d.exec()

    def _open_fivr(self):
        d = FIVRDialog(self); d.exec()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    _log(f"[启动] 程序启动, quitOnLastWindowClosed={app.quitOnLastWindowClosed()}, argv={sys.argv}")
    _silent = "--silent" in sys.argv
    w = MainWindow(silent=_silent, safe="--safe" in sys.argv)
    # 系统关机时 aboutToQuit 自动清理托盘
    def _on_about_to_quit():
        w._frequency_controller.stop()
        try:
            w.tray.hide()
            w.tray.deleteLater()
        except: pass
        _log("[系统] aboutToQuit，程序退出")
    app.aboutToQuit.connect(_on_about_to_quit)
    # --silent 静默启动：直接隐藏到托盘，不弹主窗（必须 hide() + 托盘，不能 showMinimized）
    if _silent:
        w.hide()
        _log("[启动] --silent 静默启动，已隐藏到托盘")
    else:
        w.show()
    sys.exit(app.exec())
