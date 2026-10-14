# -*- coding: utf-8 -*-
"""
Intel CPU 核心逻辑（电压偏移 / 监控 / 功耗墙 / Windows P/E限频 / TjMax）

MSR 参考：
  0x150  IA VR 电压偏移邮箱（核心/缓存/核显平面）
  0x1A2  TEMPERATURE_TARGET (TjMax / TjOffset)
  0x19C  IA32_THERM_STATUS 逐核温度
  0x198  IA32_PERF_STATUS 逐核频率
  0x606  RAPL_POWER_UNIT 功耗/时间单位
  0x611  MSR_PKG_ENERGY_STATUS 封装能耗计数器
  0x610  MSR_PKG_POWER_LIMIT  PL1/PL2 功耗墙
  0x1AD/0x1AE/0x1AF 睿频倍频（读显示用）
  0x620  MSR_UNCORE_RATIO_LIMIT  Ring/Uncore(环形总线+LLC)倍频上限/下限
  0x621  MSR_UNCORE_PERF_STATUS  当前 Ring/Uncore 倍频
  Windows 电源计划 PROCFREQMAX/PROCFREQMAX1  大小核最大频率（MHz）
"""
import ctypes
import ctypes.wintypes as wt
import os
import struct
import threading
import time
import uuid

from winring0 import WinRing0Error, wrmsr as _raw_wrmsr
import threading as _msr_threading
_msr_lock = _msr_threading.RLock()  # 全局MSR读写锁

# PawnIO 读取层（唯一安全路径，不回退 WinRing0 防止蓝屏）
_pawnio_ok = False
_pawnio_error = ""
try:
    import pawnio_reader
    pawnio_reader.init()
    _pawnio_ok = pawnio_reader.is_available()
    if not _pawnio_ok:
        _pawnio_error = "PawnIO 驱动未安装或未运行"
except Exception as e:
    _pawnio_error = f"PawnIO 初始化失败: {e}"


def pawnio_status():
    """返回 (是否可用, 错误信息)"""
    return _pawnio_ok, _pawnio_error


def rdmsr(reg):
    """读 MSR：全部走 PawnIO，读失败返回 None"""
    with _msr_lock:
        if not _pawnio_ok:
            return None
        try:
            return pawnio_reader.read_msr(reg)
        except Exception:
            return None


_winring0_loaded = False


def _ensure_winring0():
    """懒加载 WinRing0：第一次写时才加载"""
    global _winring0_loaded
    if _winring0_loaded:
        return
    from winring0 import load as _wr_load
    _wr_load()
    _winring0_loaded = True


def wrmsr(reg, value):
    """写 MSR：用 WinRing0（懒加载）"""
    with _msr_lock:
        _ensure_winring0()
        return _raw_wrmsr(reg, value)

# ---------- 电压偏移 (0x150) ----------
MSR_VOLTAGE = 0x150
PLANES = {"core": 0, "igpu": 1, "cache": 2, "sa": 3, "igpu_unslice": 4, "l2_ecore": 5}
# 极限偏移 -249mV（仅极限玩家；普通降压建议 -30 ~ -150mV）
MAX_OFFSET = -249
MAX_OVERVOLT = 0


# ---------- IccMax 电流限制 (0x150 plane 14) ----------
PLANE_ICC = 14


def read_icc_max():
    """读取 IA VR IccMax 电流限制（A）。单位 0.125A。读失败返回 0。"""
    try:
        val = _mailbox_read(PLANE_ICC)
        raw = (val >> 32) & 0xFFFF
        if raw == 0 or raw == 0xFFFF:
            return 0.0
        return round(raw * 0.125, 1)
    except Exception:
        return 0.0


def write_icc_max(amps):
    """写入 IccMax（A）。读-改-写保留其它字段；成功后读回验证。"""
    amps = float(amps)
    if amps < 8 or amps > 1024:
        raise WinRing0Error("IccMax 范围 8~1024A")
    raw = int(round(amps / 0.125))
    rdval = 0x8000001000000000 | (PLANE_ICC << 40)
    cur = _mailbox_read(PLANE_ICC)
    cur = (cur & ~(0xFFFF << 32)) | ((raw & 0xFFFF) << 32)
    wrval = rdval | 0x100000000 | (cur & 0xFFFFFFFF)
    wrmsr(MSR_VOLTAGE, wrval)
    wrmsr(MSR_VOLTAGE, rdval)
    back = rdmsr(MSR_VOLTAGE)
    if (back & 0xFFFFFFFF) != (wrval & 0xFFFFFFFF):
        raise WinRing0Error("IccMax 写入读回不一致（电流墙可能被 BIOS 锁定）")
    return read_icc_max()


def encode_offset(mv):
    mask = 0x800
    return (int(mask - abs(mv) * 1.024 + 0.5) << 21) & 0xFFFFFFFF


def _mailbox_read(plane):
    rdval = 0x8000001000000000 | (plane << 40)
    wrmsr(MSR_VOLTAGE, rdval)
    return rdmsr(MSR_VOLTAGE)


def read_offset_mv(plane):
    val = _mailbox_read(plane)
    decoded = ((0x800 - ((val >> 21) & 0x7FF)) & 0x7FF) / 1.024
    return round(-decoded, 2)


def write_offset_mv(plane, mv, strict=True):
    mv = float(mv)
    if mv > MAX_OVERVOLT:
        raise WinRing0Error("禁止加压：偏移值必须 <= 0 mV")
    if mv < MAX_OFFSET:
        raise WinRing0Error("偏移过深（超过 %d mV），已拒绝写入" % MAX_OFFSET)
    uvint = encode_offset(mv)
    rdval = 0x8000001000000000 | (plane << 40)
    wrval = rdval | 0x100000000 | uvint
    wrmsr(MSR_VOLTAGE, wrval)
    wrmsr(MSR_VOLTAGE, rdval)
    cur = rdmsr(MSR_VOLTAGE)
    if (cur & 0xFFFFFFFF) != (wrval & 0xFFFFFFFF):
        if not strict:
            # 宽松模式：读回不一致只返回 None，不抛错（用于未确认 plane）
            return None
        raise WinRing0Error("MSR 0x150 读回不一致（电压控制可能被 BIOS 锁定）")
    return read_offset_mv(plane)


def apply_undervolt(core_mv, cache_mv=None, igpu_mv=0, sync_core_cache=True,
                    l2_ecore_mv=None):
    if cache_mv is None or sync_core_cache:
        cache_mv = core_mv
    result = {}
    result["core"] = write_offset_mv(PLANES["core"], core_mv)
    result["cache"] = write_offset_mv(PLANES["cache"], cache_mv)
    if igpu_mv:
        result["igpu"] = write_offset_mv(PLANES["igpu"], igpu_mv)
    if l2_ecore_mv is not None:
        result["l2_ecore"] = write_offset_mv(
            PLANES["l2_ecore"], l2_ecore_mv)
    return result


def reset_all():
    result = {}
    for name in PLANES:
        try:
            result[name] = write_offset_mv(PLANES[name], 0)
        except WinRing0Error:
            result[name] = None
    return result


def read_all():
    result = {}
    for name, idx in PLANES.items():
        try:
            result[name] = read_offset_mv(idx)
        except WinRing0Error:
            result[name] = None
    return result


def scan_all_planes():
    """遍历 MSR 0x150 所有 plane (0~25)，读回电压偏移值。
    用于定位 L2 E-core 等未知 plane 号。返回 {plane: mv} dict。"""
    results = {}
    for plane in range(26):
        try:
            val = _mailbox_read(plane)
            decoded = ((0x800 - ((val >> 21) & 0x7FF)) & 0x7FF) / 1.024
            results[plane] = round(-decoded, 2)
        except WinRing0Error:
            results[plane] = None
    return results


# ---------- 拓扑检测 (GetLogicalProcessorInformationEx) ----------
def _get_topology():
    """按 Windows EfficiencyClass 返回 P/E 核逻辑处理器拓扑。"""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetLogicalProcessorInformationEx.restype = wt.BOOL
    kernel32.GetLogicalProcessorInformationEx.argtypes = [
        wt.DWORD, ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]

    size = wt.DWORD(0)
    kernel32.GetLogicalProcessorInformationEx(0, None, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if not kernel32.GetLogicalProcessorInformationEx(0, buf, ctypes.byref(size)):
        raise WinRing0Error("GetLogicalProcessorInformationEx 失败 (错误码 %d)"
                            % ctypes.get_last_error())
    raw = buf.raw
    cores = []
    off = 0
    while off + 8 <= len(raw):
        rel, sz = struct.unpack_from("<II", raw, off)
        if sz < 8 or off + sz > len(raw):
            break
        if rel == 0:  # RelationProcessorCore（每个条目 = 一个物理核心）
            efficiency_class = raw[off + 9]
            group_count = struct.unpack_from("<H", raw, off + 30)[0]
            lps = []
            for group_index in range(group_count):
                group_off = off + 32 + group_index * 16
                if group_off + 16 > off + sz:
                    break
                mask = struct.unpack_from("<Q", raw, group_off)[0]
                group = struct.unpack_from("<H", raw, group_off + 8)[0]
                lps.extend(group * 64 + i for i in range(64)
                           if (mask >> i) & 1)
            if lps:
                cores.append((efficiency_class, lps))
        off += sz
    return _classify_cores(cores)


def _classify_cores(cores):
    """将 [(EfficiencyClass, [LP...]), ...] 归类为 P/E 核。"""
    if not cores:
        raise WinRing0Error("Windows 未返回可用的处理器核心拓扑")
    classes = sorted(set(item[0] for item in cores))
    performance_class = max(classes)
    is_hybrid = len(classes) > 1
    p_lps, e_lps = [], []
    p_cores, e_cores = 0, 0
    for efficiency_class, lps in cores:
        # 异构处理器中数值最高的 EfficiencyClass 为性能更强的 P 核。
        # 非异构处理器只有一个类别，统一作为 P 核展示。
        if not is_hybrid or efficiency_class == performance_class:
            p_lps.extend(lps)
            p_cores += 1
        else:
            e_lps.extend(lps)
            e_cores += 1
    total_lps = len(p_lps) + len(e_lps)
    return {"p_lps": sorted(p_lps), "e_lps": sorted(e_lps),
            "p_cores": p_cores, "e_cores": e_cores,
            "total_lps": total_lps,
            "efficiency_classes": classes}


TOPOLOGY = None


def get_topology(refresh=False):
    global TOPOLOGY
    if TOPOLOGY is None or refresh:
        TOPOLOGY = _get_topology()
    return TOPOLOGY


def get_tjmax():
    return (rdmsr(0x1A2) >> 16) & 0xFF


# ---------- 亲和性 (逐逻辑CPU读取) ----------
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.GetCurrentThread.restype = ctypes.c_void_p
_kernel32.SetThreadAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_ulonglong]
_kernel32.SetThreadAffinityMask.restype = ctypes.c_ulonglong
_hThread = _kernel32.GetCurrentThread()
_aff_lock = threading.Lock()


def _pinned(lp, func):
    """亲和性设置失败时绝不在错误的逻辑处理器上继续写入。"""
    if lp is None:
        return func()
    if not 0 <= int(lp) < 64:
        raise WinRing0Error("暂不支持跨 processor group 的 LP%d" % lp)
    h = _kernel32.GetCurrentThread()
    old = _kernel32.SetThreadAffinityMask(h, 1 << int(lp))
    if not old:
        raise WinRing0Error("无法绑定 LP%d，已停止 MSR 操作" % lp)
    try:
        return func()
    finally:
        _kernel32.SetThreadAffinityMask(h, old)


def _lp_freq_ratio(lp):
    def sample():
        value = rdmsr(0x198)
        if value is None:
            raise WinRing0Error("LP%d PERF_STATUS 读取失败" % lp)
        return (value >> 8) & 0xFF
    return _pinned(lp, sample)

def _lp_temp(lp):
    def f():
        reading = (rdmsr(0x19C) >> 16) & 0x7F
        return get_tjmax() - reading
    return _pinned(lp, f)


# ---------- 监控 ----------
def read_monitor():
    """逐 LP 读取 PERF_STATUS 瞬时频率和温度；不是 C0 加权有效频率。"""
    topo = get_topology()
    ordered_lps = topo["p_lps"] + topo["e_lps"]
    temps, freqs = [], []
    freq_by_lp = {}
    for lp in ordered_lps:
        try:
            freq = round(_lp_freq_ratio(lp) * 0.1, 1)
            freqs.append(freq)
            freq_by_lp[lp] = freq
        except Exception:
            freqs.append(0.0)
            freq_by_lp[lp] = 0.0
        # 温度：用 PawnIO 读
        try:
            temps.append(_lp_temp(lp))
        except Exception:
            temps.append(0)
    return {
        "freqs": freqs, "temps": temps,
        "p_freq": round(max([freq_by_lp[lp] for lp in topo["p_lps"]]
                            or [0]), 1),
        "e_freq": round(max([freq_by_lp[lp] for lp in topo["e_lps"]]
                            or [0]), 1),
        "max_temp": max(temps) if temps else 0,
    }


# ---------- 每核负载（无依赖，NtQuerySystemInformation） ----------
class _SysProcPerfInfo(ctypes.Structure):
    _fields_ = [
        ("IdleTime", ctypes.c_int64),
        ("KernelTime", ctypes.c_int64),
        ("UserTime", ctypes.c_int64),
        ("DpcTime", ctypes.c_int64),
        ("InterruptTime", ctypes.c_int64),
        ("InterruptCount", ctypes.c_uint32),
    ]


_per_core_prev = None
_per_core_order = None


def _per_core_times():
    info_p = ctypes.POINTER(_SysProcPerfInfo)
    n = ctypes.c_ulong()
    ctypes.windll.ntdll.NtQuerySystemInformation(
        8, None, 0, ctypes.byref(n))
    count = n.value // ctypes.sizeof(_SysProcPerfInfo)
    if count <= 0:
        return []
    buf = (_SysProcPerfInfo * count)()
    ctypes.windll.ntdll.NtQuerySystemInformation(
        8, buf, ctypes.sizeof(buf), ctypes.byref(n))
    return [(i.IdleTime, i.KernelTime, i.UserTime) for i in buf]


def read_per_core_load():
    """返回与 read_monitor 顺序一致的每核负载（%）。首轮采样返回全 0。"""
    global _per_core_prev, _per_core_order
    try:
        topo = get_topology()
        ordered = topo["p_lps"] + topo["e_lps"]
        cur = _per_core_times()
    except Exception:
        return []
    if len(cur) != len(ordered):
        _per_core_prev = None
        return [0.0] * len(ordered)
    if _per_core_prev is None:
        _per_core_prev = cur
        return [0.0] * len(cur)
    loads = []
    for prev, now in zip(_per_core_prev, cur):
        total = (now[1] - prev[1]) + (now[2] - prev[2])
        idle = now[0] - prev[0]
        if total <= 0:
            loads.append(0.0)
        else:
            loads.append(round(100.0 * max(0.0, 1.0 - idle / float(total)), 0))
    _per_core_prev = cur
    return loads


# ---------- RAPL 封装功耗 ----------
_pkg_energy = {"t": None, "e": 0}


def _power_unit():
    """返回 (功率单位 2^exp, 时间单位 2^exp, 能量单位 2^exp)。"""
    v = rdmsr(0x606)
    pu = 1 << (v & 0xF)            # bits[3:0] 功率单位
    tu = 1 << ((v >> 16) & 0xF)    # bits[19:16] 时间单位
    eu = 1 << ((v >> 8) & 0x1F)    # bits[12:8] 能量单位 (J per count = 1/eu)
    return pu, tu, eu


def read_pkg_power():
    """返回封装功耗(W)。首次调用返回 0（需两次采样）。"""
    _, _, eu = _power_unit()
    e = rdmsr(0x611) & 0xFFFFFFFF
    now = time.time()
    global _pkg_energy
    if _pkg_energy["t"] is None:
        _pkg_energy = {"t": now, "e": e}
        return 0.0
    dt = now - _pkg_energy["t"]
    if dt <= 0:
        return 0.0
    dcount = (e - _pkg_energy["e"]) & 0xFFFFFFFF
    dj = dcount / float(eu)  # 每个计数 = 1/eu 焦耳
    power = dj / dt
    _pkg_energy = {"t": now, "e": e}
    return round(power, 1)


# ---------- TPL 功耗墙 (0x610) ----------
MSR_PKG_PL4_LIMIT = 0x601


def read_power_limits():
    """读取 PL1(长时)/PL2(短时)/PL4(瞬时) 功耗墙。"""
    pu, _, _ = _power_unit()
    v = rdmsr(0x610)
    pl1 = (v & 0x7FFF) / float(pu)
    pl1_en = (v >> 15) & 1
    pl2 = ((v >> 32) & 0x7FFF) / float(pu)
    pl2_en = (v >> 47) & 1
    result = {"pl1": round(pl1, 1), "pl2": round(pl2, 1),
              "pl1_en": bool(pl1_en), "pl2_en": bool(pl2_en)}
    try:
        v4 = rdmsr(MSR_PKG_PL4_LIMIT)
        result["pl4"] = round((v4 & 0x7FFF) / float(pu), 1)
        result["pl4_en"] = bool((v4 >> 15) & 1)
    except Exception:
        result["pl4"] = None
        result["pl4_en"] = None
    return result


def write_pl4(pl4=None):
    """写 PL4(瞬时功耗, W)。pl4=0 关闭 PL4（TS 里常用 0 解除 EDP 限流）。"""
    pu, _, _ = _power_unit()
    v = rdmsr(MSR_PKG_PL4_LIMIT)
    if pl4 is not None:
        raw = max(0, min(int(pl4 * pu), 0x7FFF))
        v = (v & 0xFFFFFFFFFFFF8000) | raw
        v = (v | (1 << 15)) if raw > 0 else (v & ~(1 << 15))
    wrmsr(MSR_PKG_PL4_LIMIT, v)
    return read_power_limits()


def write_power_limits(pl1=None, pl2=None, pl1_time=None, pl2_time=None):
    """写 PL1/PL2 功耗墙(W)。保留未指定的字段。"""
    pu, tu, _ = _power_unit()
    v = rdmsr(0x610)

    def clamp(p):
        return max(0, min(int(p * pu), 0x7FFF))

    # bits[14:0]=PL1功率, bit[15]=PL1使能
    if pl1 is not None:
        v = (v & 0xFFFFFFFFFFFF8000) | (clamp(pl1) & 0x7FFF) | (1 << 15)
    # bits[46:32]=PL2功率, bit[47]=PL2使能
    if pl2 is not None:
        v = (v & 0xFFFF8000FFFFFFFF) | ((clamp(pl2) & 0x7FFF) << 32) | (1 << 47)
    # bits[23:17]=PL1时间窗口
    if pl1_time is not None:
        t = _power_from_seconds(pl1_time, tu)
        v = (v & 0xFFFFFFFFFF01FFFF) | ((t & 0x7F) << 17)
    # bits[54:49]=PL2时间窗口
    if pl2_time is not None:
        t = _power_from_seconds(pl2_time, tu)
        v = (v & 0xF81FFFFFFFFFFFFF) | ((t & 0x3F) << 49)
    wrmsr(0x610, v)
    return read_power_limits()


def _power_to_seconds(value, time_unit):
    multiplier = 1 + ((value >> 6) & 0x3) / 4.0
    exponent = (value >> 1) & 0x1F
    return (2 ** exponent) * multiplier / time_unit


def _power_from_seconds(seconds, time_unit):
    import math
    if math.log2(seconds * time_unit / 1.75) >= 0x1F:
        return 0xFE
    last_diff, last_result = 1.0, 0
    for i in range(4):
        multiplier = 1 + i / 4.0
        value = seconds * time_unit / multiplier
        exponent = math.log2(value)
        ei = int(exponent)
        diff = exponent - ei
        if ei < 0x19 and diff > 0.5:
            ei += 1
            diff = 1 - diff
        if ei < 0x20 and diff < last_diff:
            last_diff, last_result = diff, (i << 6) | (ei << 1)
    return last_result


# ---------- TjMax 偏移 (0x1A2) ----------
def read_tjoffset():
    return (rdmsr(0x1A2) >> 24) & 0x3F


def write_tjoffset(offset):
    offset = max(-15, min(int(offset), 15))
    v = rdmsr(0x1A2)
    v = (v & 0xFFFFFFFFC0FFFFFF) | ((offset & 0x3F) << 24)
    wrmsr(0x1A2, v)
    return read_tjoffset()


# ---------- Windows 电源计划大小核最大频率（单位 MHz） ----------
# Windows CPU Sets 通常使用较高 EfficiencyClass 表示性能核、较低值表示能效核。
PROCESSOR_POWER_SUBGROUP = "54533251-82be-4824-96c1-47b60b740d00"
E_CORE_MAX_FREQ = "75b0ae3f-bce0-45a7-8c89-c9611c25e100"
P_CORE_MAX_FREQ = "75b0ae3f-bce0-45a7-8c89-c9611c25e101"
_FREQ_TRANSITION_DELAY_SECONDS = 1.2


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD),
                ("Data2", wt.WORD),
                ("Data3", wt.WORD),
                ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def parse(cls, value):
        return cls.from_buffer_copy(uuid.UUID(str(value)).bytes_le)

    def text(self):
        raw = ctypes.string_at(ctypes.byref(self), ctypes.sizeof(self))
        return str(uuid.UUID(bytes_le=raw))


_powrprof = ctypes.WinDLL("powrprof.dll", use_last_error=True)
_powrprof.PowerGetActiveScheme.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_GUID))]
_powrprof.PowerGetActiveScheme.restype = wt.DWORD
_powrprof.PowerSetActiveScheme.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(_GUID)]
_powrprof.PowerSetActiveScheme.restype = wt.DWORD
for _name in ("PowerReadACValueIndex", "PowerReadDCValueIndex"):
    _func = getattr(_powrprof, _name)
    _func.argtypes = [ctypes.c_void_p, ctypes.POINTER(_GUID),
                      ctypes.POINTER(_GUID), ctypes.POINTER(_GUID),
                      ctypes.POINTER(wt.DWORD)]
    _func.restype = wt.DWORD
for _name in ("PowerWriteACValueIndex", "PowerWriteDCValueIndex"):
    _func = getattr(_powrprof, _name)
    _func.argtypes = [ctypes.c_void_p, ctypes.POINTER(_GUID),
                      ctypes.POINTER(_GUID), ctypes.POINTER(_GUID), wt.DWORD]
    _func.restype = wt.DWORD


def _power_error(code, action):
    raise WinRing0Error("%s失败（Windows 错误 %d）" % (action, code))


def _get_active_power_scheme():
    pointer = ctypes.POINTER(_GUID)()
    code = _powrprof.PowerGetActiveScheme(None, ctypes.byref(pointer))
    if code:
        _power_error(code, "读取当前电源计划")
    try:
        return pointer.contents.text()
    finally:
        ctypes.windll.kernel32.LocalFree(pointer)


def _power_value(scheme, setting, ac=True):
    scheme_guid = _GUID.parse(scheme)
    subgroup_guid = _GUID.parse(PROCESSOR_POWER_SUBGROUP)
    setting_guid = _GUID.parse(setting)
    value = wt.DWORD()
    func = (_powrprof.PowerReadACValueIndex if ac else
            _powrprof.PowerReadDCValueIndex)
    code = func(None, ctypes.byref(scheme_guid), ctypes.byref(subgroup_guid),
                ctypes.byref(setting_guid), ctypes.byref(value))
    if code:
        _power_error(code, "读取%s频率上限" % ("AC" if ac else "DC"))
    return int(value.value)


def _write_power_value(scheme, setting, value, ac=True):
    scheme_guid = _GUID.parse(scheme)
    subgroup_guid = _GUID.parse(PROCESSOR_POWER_SUBGROUP)
    setting_guid = _GUID.parse(setting)
    func = (_powrprof.PowerWriteACValueIndex if ac else
            _powrprof.PowerWriteDCValueIndex)
    code = func(None, ctypes.byref(scheme_guid), ctypes.byref(subgroup_guid),
                ctypes.byref(setting_guid), wt.DWORD(int(value)))
    if code:
        _power_error(code, "写入%s频率上限" % ("AC" if ac else "DC"))


def _activate_power_scheme(scheme):
    scheme_guid = _GUID.parse(scheme)
    code = _powrprof.PowerSetActiveScheme(None, ctypes.byref(scheme_guid))
    if code:
        _power_error(code, "激活电源计划")


def _read_frequency_values_mhz(scheme=None):
    scheme = scheme or _get_active_power_scheme()
    return {
        "scheme": scheme,
        "p": {"ac": _power_value(scheme, P_CORE_MAX_FREQ, True),
              "dc": _power_value(scheme, P_CORE_MAX_FREQ, False)},
        "e": {"ac": _power_value(scheme, E_CORE_MAX_FREQ, True),
              "dc": _power_value(scheme, E_CORE_MAX_FREQ, False)},
    }


def _write_frequency_values_mhz(scheme, values):
    for kind, setting in (("p", P_CORE_MAX_FREQ), ("e", E_CORE_MAX_FREQ)):
        _write_power_value(scheme, setting, values[kind]["ac"], True)
        _write_power_value(scheme, setting, values[kind]["dc"], False)


def _ghz_to_mhz(value):
    value = float(value or 0)
    if value <= 0:
        return 0
    mhz = int(round(value * 1000))
    if mhz < 800 or mhz > 7000:
        raise WinRing0Error("频率上限只接受 0.0 或 0.8～7.0 GHz")
    return mhz


def _as_ghz(values):
    return {
        "scheme": values["scheme"],
        "p": {"ac": round(values["p"]["ac"] / 1000.0, 1),
              "dc": round(values["p"]["dc"] / 1000.0, 1)},
        "e": {"ac": round(values["e"]["ac"] / 1000.0, 1),
              "dc": round(values["e"]["dc"] / 1000.0, 1)},
    }


def set_core_freq_ghz(p_ghz, e_ghz):
    """事务式设置当前电源计划的 P/E 核 AC/DC 最大频率。"""
    scheme = _get_active_power_scheme()
    original = _read_frequency_values_mhz(scheme)
    target = {
        "scheme": scheme,
        "p": {"ac": _ghz_to_mhz(p_ghz), "dc": _ghz_to_mhz(p_ghz)},
        "e": {"ac": _ghz_to_mhz(e_ghz), "dc": _ghz_to_mhz(e_ghz)},
    }
    transition = {"scheme": scheme,
                  "p": {"ac": 0, "dc": 0},
                  "e": {"ac": 0, "dc": 0}}
    try:
        # 先切换到“不限制”，让 Windows PPM 清除旧版程序留下的 HWP 限制。
        _write_frequency_values_mhz(scheme, transition)
        _activate_power_scheme(scheme)
        transition_actual = _read_frequency_values_mhz(scheme)
        if transition_actual["p"] != transition["p"] or \
                transition_actual["e"] != transition["e"]:
            raise WinRing0Error("过渡频率写入后回读不一致")
        time.sleep(_FREQ_TRANSITION_DELAY_SECONDS)
        _write_frequency_values_mhz(scheme, target)
        _activate_power_scheme(scheme)
        actual = _read_frequency_values_mhz(scheme)
        if actual["p"] != target["p"] or actual["e"] != target["e"]:
            raise WinRing0Error("频率上限写入后回读不一致")
        return _as_ghz(actual)
    except Exception as error:
        try:
            _write_frequency_values_mhz(scheme, original)
            _activate_power_scheme(scheme)
        except Exception as rollback_error:
            raise WinRing0Error("%s；回滚失败：%s" % (error, rollback_error))
        if isinstance(error, WinRing0Error):
            raise
        raise WinRing0Error(str(error))


def read_core_freq_ghz():
    """读取当前电源计划中的 P/E 核 AC/DC 最大频率。"""
    return _as_ghz(_read_frequency_values_mhz())


# ---------- ThrottleStop 风格的 HWP / Turbo Ratio 直接控制 ----------
MSR_PM_ENABLE = 0x770
MSR_HWP_CAPABILITIES = 0x771
MSR_HWP_REQUEST = 0x774
MSR_POWER_CTL = 0x1FC
MSR_PLATFORM_INFO = 0xCE
MSR_TURBO_RATIO_LIMIT = 0x1AD
MSR_TURBO_RATIO_LIMIT2 = 0x1AE
MSR_CORE_PERF_LIMIT_REASONS = 0x64F
# 频率通路开关（TS 同样会处理这三层，否则 HWP max 可能被上层无视）
MSR_MISC_ENABLE = 0x1A0
MISC_TURBO_DISABLE_BIT = 38      # 1=禁用睿频，定频上限>基频时必须为 0
MSR_CLOCK_MODULATION = 0x19A
CLOCK_MODULATION_ENABLE_BIT = 4  # 1=占空比门控开启（周期性停钟），需关闭
HWP_PACKAGE_CONTROL_BIT = 42
# IA32_HWP_REQUEST (0x774) / IA32_HWP_REQUEST_PKG (0x777) valid 位
MSR_HWP_REQUEST_PKG = 0x777
# HWP 使能位在 IA32_PM_ENABLE[0]，不在 IA32_HWP_REQUEST 中。
# REQUEST[41:32] 是 Activity Window；valid 位 [63:59] 只在 package
# control=1 时选择字段来源。独立控制每个 LP 时清 bit42 即可。
HWP_ACTIVITY_WINDOW_MASK = 0x3FF << 32
HWP_REQUEST_MANAGED_MASK = (0xFFFFFFFF | HWP_ACTIVITY_WINDOW_MASK |
                            (1 << HWP_PACKAGE_CONTROL_BIT))
POWER_CTL_BD_PROCHOT_BIT = 0
POWER_CTL_C1E_BIT = 1
POWER_CTL_MANAGED_MASK = ((1 << POWER_CTL_BD_PROCHOT_BIT) |
                          (1 << POWER_CTL_C1E_BIT))

HWP_DEFAULT_SCALING_KHZ = 100000
# 与 Linux intel_pstate 的 intel_hybrid_scaling_factor 保持一致。
# 不使用可写的 Turbo Ratio 表校准，否则限频后再次应用会改变标尺。
HWP_P_SCALING_BY_MODEL = {
    0x97: 78741, 0x9A: 78741,  # Alder Lake
    0xB7: 78741, 0xBA: 78741, 0xBF: 78741,  # Raptor Lake / refresh
    0xD7: 78741,  # Bartlett Lake
    0xAA: 80000,  # Meteor Lake mobile
    0xBD: 86957,  # Lunar Lake
    0xC6: 80000,  # Arrow Lake-HX (Ultra 200HX)
}
# E 核倍率表（0x1AE）槽位有效性下限：< 1.6 GHz（<16x）的槽视为未初始化
# 或垃圾值（部分平台 0x1AE 出厂就是 1..8 递增的占位序列），
# 绝不把这类表当作真实 E 核倍率去写入，否则会把表写坏或误报失败。
E_CORE_RATIO_MIN = 16

# Intel SDM MSR_CORE_PERF_LIMIT_REASONS (0x64F) 低 32 位=当前状态，
# 高 32 位=历史日志。位定义见 SDM 表 2-12（桌面/移动平台）。
_PERF_LIMIT_BITS = (
    (0, "外部 PROCHOT"),
    (1, "核心温度"),
    (3, "驻留状态限制"),
    (4, "平均温度限制 RATL"),
    (5, "供电温度"),
    (6, "供电电流 TDC"),
    (7, "其他供电电流"),
    (8, "MAX_VID 电压上限"),
    (9, "低于最小电压"),
    (10, "EDP 电流限制"),
    (11, "PMAX/其他电气限制"),
    (12, "最大效率限制"),
    (13, "睿频倍率上限限制"),
    (15, "功耗限制 PL1/PL2"),
    (16, "电流限制 IccMax"),
    (17, "温度限制 TjMax"),
)


def _read_control_msr(register):
    # 只为已使用的控制寄存器选择 WinRing0；监控仍使用 PawnIO。
    if register in (MSR_PM_ENABLE, MSR_HWP_CAPABILITIES, MSR_HWP_REQUEST,
                    MSR_HWP_REQUEST_PKG, MSR_POWER_CTL, MSR_MISC_ENABLE,
                    MSR_CLOCK_MODULATION):
        from winring0 import rdmsr as read_control
        _ensure_winring0()
        value = read_control(register)
    else:
        value = rdmsr(register)
    if value is None:
        raise WinRing0Error("读取 MSR 0x%X 失败" % register)
    return int(value)


def _read_msr_on_lp(lp, register):
    with _msr_lock:
        return _pinned(lp, lambda: _read_control_msr(register))


def _crash_log(msg):
    """逐条落盘日志，蓝屏后可追溯最后一次写入。"""
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crash.txt")
        with open(log_path, "a", encoding="utf-8") as f:
            from datetime import datetime
            f.write(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}\n")
    except:
        pass


def _write_msr_on_lp(lp, register, value, log=True):
    """在同一 LP、同一临界区写入并从可用的通道回读。"""
    def action():
        if log:
            _crash_log(f"[WRMSR] LP{lp} reg=0x{register:X} value=0x{value:016X}")
        wrmsr(register, value)
        after = _read_control_msr(register)
        if log:
            _crash_log(f"[WRMSR] LP{lp} reg=0x{register:X} after=0x{after:016X} match={after==value}")
        return after
    with _msr_lock:
        return _pinned(lp, action)


def _hwp_capabilities(lp):
    value = _read_msr_on_lp(lp, MSR_HWP_CAPABILITIES)
    caps = {"highest": value & 0xFF,
            "guaranteed": (value >> 8) & 0xFF,
            "efficient": (value >> 16) & 0xFF,
            "lowest": (value >> 24) & 0xFF}
    if not 0 < caps["lowest"] <= caps["guaranteed"] <= caps["highest"] <= 255:
        raise WinRing0Error("LP%d HWP 能力值异常：0x%X" % (lp, value))
    return caps


def _cpu_name():
    if os.name == "nt":
        try:
            import winreg
            path = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                value, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                return " ".join(str(value).split())
        except Exception:
            pass
    return "Intel CPU"


def _e_core_ratios(lp=None):
    """读 0x1AE（E 核倍率表）的有效倍率槽与锁定位。

    返回 (ratios, locked)。布局因平台而异（Raptor Lake 上低字节为 E 核
    1～4 核倍率，bit63=锁定位）；无法读取或没有有效槽时返回 ([], True)。
    """
    if lp is None:
        try:
            topo = get_topology()
            lp = (topo.get("e_lps") or topo.get("p_lps") or [None])[0]
        except Exception:
            lp = None
    if lp is None:
        return [], True
    try:
        value = _read_msr_on_lp(lp, MSR_TURBO_RATIO_LIMIT2)
    except Exception:
        return [], True
    locked = bool((value >> 63) & 1)
    ratios = [(int(value) >> (8 * index)) & 0xFF
              for index in range(8)]
    valid = [r for r in ratios
             if _valid_ratio(r) and r >= E_CORE_RATIO_MIN]
    return valid, locked


def _cpu_family_model():
    """Windows 注册表中的 CPUID family/model，避免按营销型号猜测。"""
    try:
        import re, winreg
        path = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            identifier, _ = winreg.QueryValueEx(key, "Identifier")
        match = re.search(r"Family\s+(\d+)\s+Model\s+(\d+)", identifier)
        if match:
            return tuple(map(int, match.groups()))
    except (ImportError, OSError):
        pass
    return None, None


def _hwp_scaling_khz(kind, highest=None, turbo_ratios=None, topology=None):
    """GHz 与 HWP performance 是不同单位，标尺不能来自可写睿频表。"""
    family, model = _cpu_family_model()
    if family == 6 and model in HWP_P_SCALING_BY_MODEL:
        return (HWP_DEFAULT_SCALING_KHZ if kind == "e"
                else HWP_P_SCALING_BY_MODEL[model])
    topology = topology or get_topology()
    if topology.get("e_lps") or (family == 6 and model in (0x4F, 0x56)):
        raise WinRing0Error("尚未确认此 CPU 的 HWP 频率标尺，已停止写入")
    return HWP_DEFAULT_SCALING_KHZ


def _hwp_perf_to_ratio(performance, scaling_khz):
    """按 Intel P-state 的向下对齐规则把 HWP 级别换算成 100 MHz 倍频。"""
    performance = max(0, int(performance))
    scaling_khz = max(1, int(scaling_khz))
    return int(performance * scaling_khz // 100000)


def _ratio_to_hwp_perf(ratio, scaling_khz, capabilities=None):
    """把 100 MHz 物理倍频向上换算成能达到目标的 HWP 性能级别。"""
    ratio = max(0, int(ratio))
    scaling_khz = max(1, int(scaling_khz))
    performance = int((ratio * 100000 + scaling_khz - 1) // scaling_khz)
    if not 1 <= performance <= 255:
        raise WinRing0Error("HWP 性能级别必须在 1～255 之间")
    if capabilities:
        lowest = int(capabilities["lowest"])
        highest = int(capabilities["highest"])
        # 标尺有整数舍入；硬件最高级别对应显示的最高 100 MHz 档。
        if ratio == int(round(highest * scaling_khz / 100000.0)):
            performance = highest
        if performance < lowest or performance > highest:
            raise WinRing0Error(
                "目标 %dx 换算为 HWP %d 级，超出硬件范围 %d～%d" %
                (ratio, performance, lowest, highest))
    return performance


def _ratio_bytes(value, count=8):
    """解析 0x1AD 的 1..8 个活跃 P 核倍率槽。"""
    count = max(0, min(int(count), 8))
    return [(int(value) >> (index * 8)) & 0xFF
            for index in range(count)]


def _valid_ratio(value):
    return 8 <= int(value) <= 85


def _turbo_ratio_target(current, ratio, core_count):
    """把有效的 1..N 活跃 P 核倍率槽统一设为目标，并保留未知位。"""
    ratio = int(ratio)
    if not _valid_ratio(ratio):
        raise WinRing0Error("Turbo Ratio 目标倍率无效：%d" % ratio)
    core_count = max(1, min(int(core_count), 8))
    value = int(current)
    changed_slots = 0
    for index, existing in enumerate(_ratio_bytes(current, core_count)):
        if not _valid_ratio(existing):
            continue
        mask = 0xFF << (index * 8)
        value = (value & ~mask) | (ratio << (index * 8))
        changed_slots += 1
    if not changed_slots:
        raise WinRing0Error("Turbo Ratio 表没有可用倍率槽")
    return value & 0xFFFFFFFFFFFFFFFF


def _parse_saved_msr(value):
    if value in (None, ""):
        return None
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def read_frequency_capabilities(topology=None, p_turbo_original=None):
    """读取 HWP 原始范围，并换算成真正的 100 MHz 物理倍频范围。"""
    topology = topology or get_topology()
    cpu_name = _cpu_name()
    result = {"cpu_name": cpu_name, "p": {}, "e": {}}

    raw_capabilities = {}
    for kind in ("p", "e"):
        capabilities = [_hwp_capabilities(lp)
                        for lp in topology[kind + "_lps"]]
        raw_capabilities[kind] = capabilities

    p_lps = topology.get("p_lps", [])
    ratios = []
    if p_lps:
        current = _read_msr_on_lp(p_lps[0], MSR_TURBO_RATIO_LIMIT)
        platform_info = _read_msr_on_lp(p_lps[0], MSR_PLATFORM_INFO)
        reference = _parse_saved_msr(p_turbo_original)
        if reference is None:
            reference = current
        ratios = [r for r in _ratio_bytes(reference,
                                            topology.get("p_cores", 8))
                  if _valid_ratio(r)]
        result["p_turbo_current_raw"] = current
        result["p_turbo_reference_raw"] = reference
        result["p_turbo_ratios"] = ratios
        # Intel SDM: 0x1AD is R/W only when MSR_PLATFORM_INFO[28] == 1.
        result["p_turbo_programmable"] = bool((platform_info >> 28) & 1)
        result["p_turbo_locked"] = not result["p_turbo_programmable"]

    e_ratios, e_locked = _e_core_ratios(
        (topology.get("e_lps") or p_lps or [None])[0])
    result["e_turbo_ratios"] = e_ratios
    result["e_turbo_locked"] = e_locked

    for kind in ("p", "e"):
        capabilities = raw_capabilities[kind]
        if not capabilities:
            result[kind] = {"present": False, "min_ratio": 0,
                            "max_ratio": 0, "hwp": [],
                            "hwp_scaling_khz": HWP_DEFAULT_SCALING_KHZ}
            continue
        raw_low = max(item["lowest"] for item in capabilities)
        raw_high = min(item["highest"] for item in capabilities)
        scaling = _hwp_scaling_khz(
            kind, raw_high, ratios if kind == "p" else e_ratios, topology)
        low = max(8, (raw_low * scaling + 99999) // 100000)
        high = int(round(raw_high * scaling / 100000.0))
        if high < low or high > 85:
            raise WinRing0Error("%s 核 HWP 频率范围异常，已停止换算" % kind.upper())
        result[kind] = {
            "present": True,
            "min_ratio": low,
            "max_ratio": high,
            "hwp": capabilities,
            "hwp_lowest": raw_low,
            "hwp_highest": raw_high,
            "hwp_scaling_khz": scaling,
        }

    if p_lps and ratios:
        result["p"]["max_ratio"] = min(
            result["p"]["max_ratio"], max(ratios))
        result["p"]["single_core_ratio"] = ratios[0]
        result["p"]["all_core_ratio"] = ratios[
            min(len(ratios), topology.get("p_cores", len(ratios))) - 1]
    return result


def _direct_ratio(value, kind=None, limits=None):
    value = float(value or 0)
    if value <= 0:
        raise WinRing0Error("直接锁频需要填写大于 0 的 P/E 核频率")
    ratio = int(round(value * 10))
    if ratio < 8 or ratio > 80:
        raise WinRing0Error("直接锁频只接受 0.8～8.0 GHz")
    if kind and limits:
        item = limits.get(kind, {})
        low = int(item.get("min_ratio", 8))
        high = int(item.get("max_ratio", low))
        if ratio < low:
            raise WinRing0Error("%s 核目标低于当前下限 %.1f GHz" %
                                (kind.upper(), low / 10.0))
        if ratio > high:
            raise WinRing0Error("%s 核目标 %.1f GHz 超过当前上限 %.1f GHz" %
                                (kind.upper(), ratio / 10.0, high / 10.0))
    return ratio


def validate_direct_profile(p_ghz, e_ghz, p_turbo_original=None,
                            topology=None):
    """只读校验直接倍率配置，供启动迁移和 UI 确认使用。"""
    topology = topology or get_topology()
    limits = read_frequency_capabilities(topology, p_turbo_original)
    ratios = {"p": 0, "e": 0}
    hwp_levels = {"p": 0, "e": 0}
    for kind, ghz in (("p", p_ghz), ("e", e_ghz)):
        if limits.get(kind, {}).get("present"):
            ratios[kind] = _direct_ratio(ghz, kind, limits)
            # 在 CPU 允许范围内调节：超出硬件能力由 _direct_ratio 拒绝
            hwp_levels[kind] = _ratio_to_hwp_perf(
                ratios[kind], limits[kind]["hwp_scaling_khz"],
                {"lowest": limits[kind]["hwp_lowest"],
                 "highest": limits[kind]["hwp_highest"]})
    return {"limits": limits, "ratios": ratios,
            "hwp_levels": hwp_levels}


def _compose_hwp_request(current, capabilities, ratio, epp, lock,
                         cap_only=False):
    """独立 LP 请求：锁频设置 min=max=desired；限频只设置 max。

    Package_Control=0 时不受 0x777 控制，valid 位也不参与选择。
    Activity Window 设为 0（硬件自动），清除旧版误写的 bits[36:32]。
    保留其余位；使能由 IA32_PM_ENABLE[0] 表达。
    """
    lowest, highest = int(capabilities["lowest"]), int(capabilities["highest"])
    if not 0 < lowest <= highest <= 255:
        raise WinRing0Error("HWP 能力范围无效")
    if lock or cap_only:
        if not lowest <= int(ratio) <= highest:
            raise WinRing0Error("HWP 目标 %s 超出硬件范围 %d～%d" %
                                (ratio, lowest, highest))
        maximum = int(ratio)
        minimum = maximum if lock else lowest
        desired = maximum if lock else 0
    else:
        minimum, maximum, desired = lowest, highest, 0
    value = int(current) & ~HWP_REQUEST_MANAGED_MASK
    return (value | minimum | (maximum << 8) | (desired << 16) |
            (max(0, min(int(epp), 255)) << 24))


def _compose_hwp_package_request(current, max_level, min_level, epp, active):
    """兼容旧调用；独立 LP 控制路径不应修改整个封装的请求。"""
    if not active:
        return current
    caps = {"lowest": int(min_level), "highest": int(max_level)}
    return _compose_hwp_request(current, caps, max_level, epp, False,
                                cap_only=True)


def _decode_hwp_request(value):
    return {
        "minimum": value & 0xFF,
        "maximum": (value >> 8) & 0xFF,
        "desired": (value >> 16) & 0xFF,
        "epp": (value >> 24) & 0xFF,
        "package_control": bool((value >> HWP_PACKAGE_CONTROL_BIT) & 1),
    }


def _compose_power_ctl(current, c1e, bd_prochot):
    """保留 IA32_POWER_CTL 其他位，只设置 C1E 与双向 PROCHOT。"""
    value = int(current) & ~POWER_CTL_MANAGED_MASK
    if bool(bd_prochot):
        value |= 1 << POWER_CTL_BD_PROCHOT_BIT
    if bool(c1e):
        value |= 1 << POWER_CTL_C1E_BIT
    return value & 0xFFFFFFFFFFFFFFFF


def _verify_power_ctl(value, c1e, bd_prochot, lp):
    """核对硬件回读的两个受管位，防止固件静默拒绝写入。"""
    actual = int(value) & POWER_CTL_MANAGED_MASK
    expected = _compose_power_ctl(0, c1e, bd_prochot)
    if actual != expected:
        raise WinRing0Error(
            "LP%d POWER_CTL 写入后回读不一致（C1E=%s，BD PROCHOT=%s）" %
            (lp, "开" if c1e else "关",
             "开" if bd_prochot else "关"))


def _direct_targets(p_ghz, e_ghz, epp, lock, topology=None,
                    p_turbo_original=None, cap_only=False,
                    out_warnings=None):
    topology = topology or get_topology()
    active = lock or cap_only
    ratios = {"p": 0, "e": 0}
    if active:
        validation = validate_direct_profile(
            p_ghz, e_ghz, p_turbo_original, topology)
        limits, ratios = validation["limits"], validation["ratios"]
    else:
        limits = read_frequency_capabilities(topology, p_turbo_original)
    targets = {}
    for kind in ("p", "e"):
        for lp in topology[kind + "_lps"]:
            pm_before = _read_msr_on_lp(lp, MSR_PM_ENABLE)
            if not (pm_before & 1):
                if active:
                    raise WinRing0Error("LP%d 未启用 Intel Speed Shift/HWP" % lp)
                continue
            caps = _hwp_capabilities(lp)
            ratio = ratios[kind]
            scaling = limits[kind].get(
                "hwp_scaling_khz", HWP_DEFAULT_SCALING_KHZ)
            hwp_level = (_ratio_to_hwp_perf(ratio, scaling, caps)
                         if active else 0)
            if active and hwp_level < caps["lowest"]:
                raise WinRing0Error(
                    "%s核 %.1f GHz 换算为 HWP %d 级，低于 LP%d 下限 %d，"
                    "已停止写入（防止核心被压到异常低频）" %
                    (kind.upper(), ratio / 10.0, hwp_level, lp,
                     caps["lowest"]))
            # Highest 已包含睿频能力，不能与 Guaranteed 混淆。
            if active:
                # 反算保护：HWP 级别映射回物理倍频，与目标偏差超过 1×
                # （0.1 GHz）即视为标尺换算异常，立即停止，绝不写入会把
                # 核心压到 0.1 GHz 以下的极端级别。
                back_ratio = _hwp_perf_to_ratio(hwp_level, scaling)
                if abs(back_ratio - ratio) > 1:
                    raise WinRing0Error(
                        "%s核 %.1f GHz 换算 HWP %d 级后对应 %.1f GHz，"
                        "标尺换算异常，已停止写入（未触碰硬件）" %
                        (kind.upper(), ratio / 10.0, hwp_level,
                         back_ratio / 10.0))
            current = _read_msr_on_lp(lp, MSR_HWP_REQUEST)
            # 0x1A0/0x19A 在个别虚拟/老平台可能读不到：容错为 None，
            # 该通路自动跳过，绝不因此阻断 HWP(0x774) 主路径。
            try:
                misc_before = _read_msr_on_lp(lp, MSR_MISC_ENABLE)
            except Exception:
                misc_before = None
            try:
                clk_before = _read_msr_on_lp(lp, MSR_CLOCK_MODULATION)
            except Exception:
                clk_before = None
            if active:
                # 主动启用 HWP；清睿频禁用位；清时钟门控——三层通路全打开
                pm_target = pm_before | 1
                misc_target = (
                    misc_before & ~(1 << MISC_TURBO_DISABLE_BIT)
                    & 0xFFFFFFFFFFFFFFFF) if misc_before is not None else None
                clk_target = (
                    clk_before & ~(1 << CLOCK_MODULATION_ENABLE_BIT)
                    & 0xFFFFFFFFFFFFFFFF) if clk_before is not None else None
            else:
                # 释放：全部恢复进入时的原值
                pm_target = pm_before
                misc_target = misc_before
                clk_target = clk_before
            targets[lp] = {
                "kind": kind,
                "caps": caps,
                "ratio": ratio,
                "hwp_level": hwp_level,
                "hwp_scaling_khz": scaling,
                "hwp_before": current,
                "hwp_target": _compose_hwp_request(
                    current, caps, hwp_level, epp, bool(lock),
                    cap_only=cap_only),
                "power_before": _read_msr_on_lp(lp, MSR_POWER_CTL),
                "pkg_before": None,
                "pkg_target": None,
                "pm_before": pm_before, "pm_target": pm_target,
                "misc_before": misc_before, "misc_target": misc_target,
                "clk_before": clk_before, "clk_target": clk_target,
            }
    if not targets:
        raise WinRing0Error("没有检测到可控制的逻辑处理器")
    # 每个 LP 清 Package_Control，无需探测或改写可选的 0x777。
    return targets, limits, ratios


def _write_path_guards(item, lp, strict=False):
    """写入三层频率通路开关（HWP 使能 / 睿频使能 / 关门控）。

    这些是“尽力而为”的辅助动作：部分平台锁定 0x1A0/0x19A，写失败
    不应阻断 HWP(0x774) 主路径，故默认静默；strict=True 时抛错。
    """
    guards = (
        (MSR_PM_ENABLE, "pm_target", "pm_before"),
        (MSR_MISC_ENABLE, "misc_target", "misc_before"),
        (MSR_CLOCK_MODULATION, "clk_target", "clk_before"),
    )
    for msr, tk, bk in guards:
        target = item.get(tk)
        before = item.get(bk)
        if target is None or target == before:
            continue
        try:
            _write_msr_on_lp(lp, msr, target)
        except Exception:
            if strict:
                raise


def _decode_perf_limit_reasons(value):
    current = [name for bit, name in _PERF_LIMIT_BITS if (value >> bit) & 1]
    logged = [name for bit, name in _PERF_LIMIT_BITS
              if (value >> (bit + 16)) & 1]
    return {"raw": int(value), "current": current, "logged": logged}


def read_perf_limit_reasons(topology=None):
    """只读性能受限原因；不清除历史日志位。"""
    topology = topology or get_topology()
    lps = topology.get("p_lps") or topology.get("e_lps") or []
    if not lps:
        raise WinRing0Error("没有可读取性能限制原因的逻辑处理器")
    return _decode_perf_limit_reasons(
        _read_msr_on_lp(lps[0], MSR_CORE_PERF_LIMIT_REASONS))


def read_perf_limit_summary(topology=None):
    """汇总所有 P/E 逻辑处理器当前生效的性能限制原因（并集）。

    撞墙检测用：任一核心正在被 PL1/PL2/电流/温度等限制，立即反映到
    返回的 current 列表；logged 为历史累计（采样期间被触碰过的墙）。
    """
    topology = topology or get_topology()
    lps = (topology.get("p_lps") or []) + (topology.get("e_lps") or [])
    if not lps:
        raise WinRing0Error("没有可读取性能限制原因的逻辑处理器")
    current = []
    logged = []
    seen_current = set()
    seen_logged = set()
    for lp in lps:
        try:
            raw = _read_msr_on_lp(lp, MSR_CORE_PERF_LIMIT_REASONS)
        except Exception:
            continue  # 个别核心读失败（如 C 状态离线）跳过，不中断汇总
        for bit, name in _PERF_LIMIT_BITS:
            if (raw >> bit) & 1:
                if name not in seen_current:
                    current.append(name)
                    seen_current.add(name)
            if (raw >> (bit + 16)) & 1 and name not in seen_logged:
                logged.append(name)
                seen_logged.add(name)
    return {"current": current, "logged": logged}


def _wr_rdmsr_on_lp(lp, register):
    """兼容旧调用名，共用有锁的控制寄存器读取通道。"""
    return _read_msr_on_lp(lp, register)


def build_hwp_frequency_targets(p_ghz, e_ghz, lock=True, epp=0):
    """只读构建 P/E HWP 目标；0 表示该类核心不参与控制。"""
    topology = get_topology()
    targets = {}
    for kind, ghz in (("p", p_ghz), ("e", e_ghz)):
        if float(ghz) == 0:
            continue
        ratio = _direct_ratio(ghz)
        lps = topology.get(kind + "_lps", [])
        if not lps:
            raise WinRing0Error("未检测到 %s 核" % kind.upper())
        scaling = _hwp_scaling_khz(kind, topology=topology)
        for lp in lps:
            # 不尝试通过 REQUEST 中的虚构 enable 位启用 HWP。
            # PM_ENABLE 的启用通常不可撤销，要求 BIOS/Windows 已启用。
            if not (_read_msr_on_lp(lp, MSR_PM_ENABLE) & 1):
                raise WinRing0Error("LP%d 未启用 Intel Speed Shift/HWP" % lp)
            caps = _hwp_capabilities(lp)
            level = _ratio_to_hwp_perf(ratio, scaling, caps)
            current = _read_msr_on_lp(lp, MSR_HWP_REQUEST)
            targets[lp] = {
                "kind": kind, "ratio": ratio, "hwp_level": level,
                "hwp_scaling_khz": scaling, "hwp_before": current,
                "hwp_target": _compose_hwp_request(
                    current, caps, level, epp, lock, cap_only=not lock),
            }
    return targets


def _verify_hwp_request(lp, actual, expected):
    if actual is None or ((int(actual) ^ int(expected)) & HWP_REQUEST_MANAGED_MASK):
        actual_text = "读取失败" if actual is None else "0x%016X" % actual
        raise WinRing0Error(
            "LP%d HWP 回读不一致：目标=0x%016X，实际=%s" %
            (lp, expected, actual_text))


def apply_hwp_frequency_targets(targets):
    """先快照所有 LP，再写入；任何拒写/回读失败均回滚并报告。"""
    with _msr_lock:
        before = {lp: _read_msr_on_lp(lp, MSR_HWP_REQUEST) for lp in targets}
        written = []
        try:
            for lp, item in targets.items():
                # 只接管已声明的字段，保留刚刚读到的其余位。
                target = ((before[lp] & ~HWP_REQUEST_MANAGED_MASK) |
                          (item["hwp_target"] & HWP_REQUEST_MANAGED_MASK))
                if target == before[lp]:
                    continue
                written.append(lp)  # 回读失败也必须回滚这一 LP。
                actual = _write_msr_on_lp(lp, MSR_HWP_REQUEST, target)
                _verify_hwp_request(lp, actual, target)
        except Exception as error:
            rollback_errors = []
            for lp in reversed(written):
                try:
                    actual = _write_msr_on_lp(lp, MSR_HWP_REQUEST, before[lp])
                    _verify_hwp_request(lp, actual, before[lp])
                except Exception as rollback_error:
                    rollback_errors.append("LP%d: %s" % (lp, rollback_error))
            detail = ("；回滚失败：" + "; ".join(rollback_errors)
                      if rollback_errors else "；已回滚本次 HWP 修改")
            raise WinRing0Error(str(error) + detail) from error
        return before


def maintain_hwp_frequency_targets(targets, observations=None):
    """核对全部受管字段，仅修复被 Windows 改写的 LP。"""
    changed, errors = 0, []
    with _msr_lock:
        for lp, item in targets.items():
            try:
                current = _read_msr_on_lp(lp, MSR_HWP_REQUEST)
                target = ((current & ~HWP_REQUEST_MANAGED_MASK) |
                          (item["hwp_target"] & HWP_REQUEST_MANAGED_MASK))
                if current != target:
                    observation = {"lp": lp, "before": hex(current),
                                   "target": hex(target), "verified": False}
                    if observations is not None:
                        observations.append(observation)
                    actual = _write_msr_on_lp(lp, MSR_HWP_REQUEST, target, log=False)
                    observation["after"] = hex(actual) if actual is not None else None
                    _verify_hwp_request(lp, actual, target)
                    observation["verified"] = True
                    changed += 1
            except Exception as error:
                errors.append("LP%d: %s" % (lp, error))
    if errors:
        raise WinRing0Error("HWP 保持失败：" + "; ".join(errors))
    return changed


def read_hwp_diagnostics(targets):
    """诊断快照；未被驱动支持的读取记录错误，不回退探测未知 MSR。"""
    result = {"cpu": _cpu_name(), "family_model": _cpu_family_model(),
              "frequency_source": "IA32_PERF_STATUS instantaneous (not effective clock)",
              "lps": []}
    for lp, item in targets.items():
        row = {"lp": lp, "kind": item["kind"], "target_ratio": item["ratio"],
               "target_request": hex(item["hwp_target"]), "errors": {}}
        for name, reg in (("request", MSR_HWP_REQUEST), ("capabilities", MSR_HWP_CAPABILITIES),
                          ("pm_enable", MSR_PM_ENABLE), ("power_ctl", MSR_POWER_CTL),
                          ("misc_enable", MSR_MISC_ENABLE), ("perf_status", 0x198),
                          ("therm_status", 0x19C), ("perf_limit_reasons", 0x64F)):
            try:
                value = _read_msr_on_lp(lp, reg)
                row[name] = hex(value)
                if name == "request":
                    row["request_matches"] = not ((value ^ item["hwp_target"]) & HWP_REQUEST_MANAGED_MASK)
                    row["request_fields"] = _decode_hwp_request(value)
                elif name == "perf_status":
                    row["sample_ghz"] = ((value >> 8) & 0xFF) / 10.0
                elif name == "power_ctl":
                    row["c1e"] = bool(value & (1 << POWER_CTL_C1E_BIT))
                elif name == "misc_enable":
                    row["turbo_disabled"] = bool(value & (1 << MISC_TURBO_DISABLE_BIT))
                    row["cpuid_limited"] = bool(value & (1 << 22))
            except Exception as error:
                row["errors"][name] = str(error)
        result["lps"].append(row)
    try:
        result["p_turbo_ratios"] = read_per_core_ratios("p")
    except Exception as error:
        result["p_turbo_error"] = str(error)
    try:
        result["windows_frequency_caps"] = read_core_freq_ghz()
    except Exception as error:
        result["windows_frequency_caps_error"] = str(error)
    return result


def apply_e_only(e_ghz, epp=0, lock=False):
    """仅设置 E 核请求；失败抛出异常，不再返回被 UI 忽略的 False。"""
    targets = build_hwp_frequency_targets(0, e_ghz, lock=lock, epp=epp)
    apply_hwp_frequency_targets(targets)
    return True


def apply_direct_profile(p_ghz, e_ghz, epp=0, c1e=False, lock=True,
                         p_turbo_original=None, bd_prochot=True,
                         cap_only=False):
    """事务式设置 HWP、Turbo Ratio、EPP、C1E 与 BD PROCHOT。

    cap_only=True 时以“频率上限”方式写入：HWP max=目标、min 交由硬件
    控制，满载最高只能跑到设定值、空闲自动降频；Turbo Ratio 表同步设
    为目标（与 lock 相同的写入路径）。
    """
    topology = get_topology()
    warnings = []
    targets, limits, ratios = _direct_targets(
        p_ghz, e_ghz, epp, lock, topology, p_turbo_original,
        cap_only=cap_only, out_warnings=warnings)
    p_lps = topology.get("p_lps", [])
    turbo_before = (_read_msr_on_lp(p_lps[0], MSR_TURBO_RATIO_LIMIT)
                    if p_lps else None)
    saved_turbo = _parse_saved_msr(p_turbo_original)
    turbo_reference = saved_turbo if saved_turbo is not None else turbo_before
    # v2.14.7：不再写入 Turbo Ratio 表（0x1AD/0x1AE），频率上限只由
    # HWP（0x774）承担——Turbo 表在部分平台只读/被固件覆盖，写入反而
    # 可能引发回读不一致或中断保持；HWP max 已是 Intel 推荐的上限路径。
    e_turbo_written = False
    e_turbo_reason = "Turbo 表写入已移除（仅 HWP 上限）"
    written = []
    try:
        for lp, item in targets.items():
            written.append(lp)
            _write_path_guards(item, lp)  # 先打通 HWP/睿频/门控三层通路
            hwp_after = _write_msr_on_lp(lp, MSR_HWP_REQUEST,
                                         item["hwp_target"])
            _verify_hwp_request(lp, hwp_after, item["hwp_target"])
            if item.get("pkg_target") is not None:
                try:
                    pkg_after = _write_msr_on_lp(
                        lp, MSR_HWP_REQUEST_PKG, item["pkg_target"])
                    if pkg_after != item["pkg_target"]:
                        print(f"[警告] LP{lp} PKG HWP 回读不一致（忽略）")
                except Exception as e:
                    print(f"[警告] LP{lp} PKG HWP 写入失败: {e}")
            power_target = _compose_power_ctl(
                item["power_before"], c1e, bd_prochot)
            try:
                power_after = _write_msr_on_lp(lp, MSR_POWER_CTL, power_target)
                _verify_power_ctl(power_after, c1e, bd_prochot, lp)
            except Exception as e:
                print(f"[警告] LP{lp} POWER_CTL 写入失败（BIOS 锁定）: {e}")
            item["power_target"] = power_target
    except Exception as error:
        rollback_errors = []
        for lp in reversed(written):
            item = targets[lp]
            try:
                _write_msr_on_lp(lp, MSR_HWP_REQUEST, item["hwp_before"])
                if item.get("pkg_before") is not None:
                    _write_msr_on_lp(
                        lp, MSR_HWP_REQUEST_PKG, item["pkg_before"])
                # 恢复三层通路开关原值
                for msr, bk in (
                        (MSR_PM_ENABLE, "pm_before"),
                        (MSR_MISC_ENABLE, "misc_before"),
                        (MSR_CLOCK_MODULATION, "clk_before")):
                    if item.get(bk) is not None:
                        try:
                            _write_msr_on_lp(lp, msr, item[bk])
                        except Exception:
                            pass
                _write_msr_on_lp(lp, MSR_POWER_CTL, item["power_before"])
            except Exception as rollback_error:
                rollback_errors.append("LP%d=%s" % (lp, rollback_error))
        if rollback_errors:
            raise WinRing0Error("%s；回滚失败：%s" %
                                (error, ", ".join(rollback_errors)))
        if isinstance(error, WinRing0Error):
            raise
        raise WinRing0Error(str(error))
    result = read_direct_profile(p_turbo_original=turbo_reference)
    result["p_turbo_original"] = turbo_reference
    result["p_turbo_before"] = turbo_before
    result["p_turbo_after"] = turbo_before
    result["e_turbo_written"] = e_turbo_written
    result["e_turbo_reason"] = e_turbo_reason
    result["warnings"] = warnings
    return result


def maintain_direct_profile(p_ghz, e_ghz, epp=0, c1e=False, lock=True,
                            p_turbo_original=None, bd_prochot=True,
                            force=False, cap_only=False):
    """保持直接控制：仅在值被系统改写时恢复，或 force=True 时无条件重写。

    Windows PPM / 厂商电源软件 / EC 固件会周期性重写 HWP_REQUEST 与
    Turbo Ratio 表（尤其切换电源计划、性能模式或高负载时）。保持线程
    必须以高频无条件重写才能压住这些覆盖，否则频率上限会被短暂突破。
    cap_only=True 时按“频率上限”方式保持（max=目标，min 硬件控制）。
    """
    topology = get_topology()
    warnings = []
    targets, limits, ratios = _direct_targets(
        p_ghz, e_ghz, epp, lock, topology, p_turbo_original,
        cap_only=cap_only, out_warnings=warnings)
    changed = 0
    # v2.14.7：Turbo Ratio 表不再参与保持，频率上限只由 HWP 承担。
    for lp, item in targets.items():
        _write_path_guards(item, lp)
        if force or item["hwp_before"] != item["hwp_target"]:
            actual = _write_msr_on_lp(lp, MSR_HWP_REQUEST, item["hwp_target"])
            _verify_hwp_request(lp, actual, item["hwp_target"])
            changed += 1
        if item.get("pkg_target") is not None:
            _write_msr_on_lp(lp, MSR_HWP_REQUEST_PKG, item["pkg_target"])
        power_target = _compose_power_ctl(
            item["power_before"], c1e, bd_prochot)
        if power_target != item["power_before"]:
            power_after = _write_msr_on_lp(
                lp, MSR_POWER_CTL, power_target)
            _verify_power_ctl(power_after, c1e, bd_prochot, lp)
            changed += 1
    return changed


def build_direct_targets(p_ghz, e_ghz, epp=0, c1e=False, lock=True,
                        p_turbo_original=None, bd_prochot=True,
                        cap_only=False):
    """构建 HWP/POWER_CTL 写入目标缓存（应用时计算一次，保持线程直接复用）。

    TS 风格定频的核心：目标值在写入时锁定，保持循环直接写缓存，不重新
    计算 HWP 标尺——避免运行中标尺校准波动导致的目标漂移或写入中断
    （"定频过一会儿失效"的根因）。
    """
    topology = get_topology()
    targets, limits, ratios = _direct_targets(
        p_ghz, e_ghz, epp, lock, topology, p_turbo_original,
        cap_only=cap_only)
    for lp, item in targets.items():
        item["power_target"] = _compose_power_ctl(
            item["power_before"], c1e, bd_prochot)
    return targets


def maintain_direct_targets(targets, c1e=False, bd_prochot=True):
    """无条件重写缓存目标（TS 风格保持）。

    - 直接写 apply 时算好的 hwp_target，不做任何重新换算；
    - 单个 LP 写入失败不中断其它核心，错误汇总抛出后由保持线程继续
      重试——绝不因一次瞬时错误停止定频保持（防止"定频失效"）。
    """
    errors = []
    for lp, item in targets.items():
        try:
            _write_path_guards(item, lp)
            actual = _write_msr_on_lp(lp, MSR_HWP_REQUEST, item["hwp_target"])
            _verify_hwp_request(lp, actual, item["hwp_target"])
            if item.get("pkg_target") is not None:
                _write_msr_on_lp(
                    lp, MSR_HWP_REQUEST_PKG, item["pkg_target"])
        except Exception as error:
            errors.append("LP%d HWP=%s" % (lp, error))
        try:
            power_target = item.get("power_target")
            if power_target is not None and \
                    power_target != item["power_before"]:
                _write_msr_on_lp(lp, MSR_POWER_CTL, power_target)
        except Exception as error:
            errors.append("LP%d POWER_CTL=%s" % (lp, error))
    if errors:
        raise WinRing0Error("; ".join(errors))
    return len(targets)


def read_direct_profile(p_turbo_original=None):
    """读取请求、能力、当前倍率和限频原因，不把请求值当作实际频率。"""
    topology = get_topology()
    result = {"p": {}, "e": {}, "c1e": None, "bd_prochot": None,
              "limits": read_frequency_capabilities(
                  topology, p_turbo_original)}
    c1e_values = []
    bd_prochot_values = []
    for kind in ("p", "e"):
        scaling = result["limits"].get(kind, {}).get(
            "hwp_scaling_khz", HWP_DEFAULT_SCALING_KHZ)
        for lp in topology[kind + "_lps"]:
            request = _read_msr_on_lp(lp, MSR_HWP_REQUEST)
            decoded = _decode_hwp_request(request)
            decoded.update({
                "hwp_scaling_khz": scaling,
                "minimum_ratio": _hwp_perf_to_ratio(
                    decoded["minimum"], scaling),
                "maximum_ratio": _hwp_perf_to_ratio(
                    decoded["maximum"], scaling),
                "desired_ratio": _hwp_perf_to_ratio(
                    decoded["desired"], scaling),
            })
            result[kind][lp] = decoded
            power_ctl = _read_msr_on_lp(lp, MSR_POWER_CTL)
            c1e_values.append(bool(
                power_ctl & (1 << POWER_CTL_C1E_BIT)))
            bd_prochot_values.append(bool(
                power_ctl & (1 << POWER_CTL_BD_PROCHOT_BIT)))
    if c1e_values:
        result["c1e"] = (c1e_values[0] if len(set(c1e_values)) == 1
                         else "mixed")
    if bd_prochot_values:
        result["bd_prochot"] = (
            bd_prochot_values[0]
            if len(set(bd_prochot_values)) == 1 else "mixed")
    try:
        result["actual"] = read_monitor()
    except Exception:
        result["actual"] = {}
    try:
        result["perf_limits"] = read_perf_limit_reasons(topology)
    except Exception:
        result["perf_limits"] = {"raw": None, "current": [], "logged": []}
    try:
        result["power_limits"] = read_power_limits()
    except Exception:
        result["power_limits"] = {}
    return result


# ---------- 睿频倍频信息（显示用，不写入） ----------
def read_turbo_info():
    info = {}
    try:
        v = rdmsr(MSR_TURBO_RATIO_LIMIT)
        info["p_ratios"] = _ratio_bytes(v, 8)
        info["p_lock"] = not bool((rdmsr(MSR_PLATFORM_INFO) >> 28) & 1)
        info["p_raw"] = v
    except WinRing0Error:
        info["p_ratios"], info["p_lock"] = [], None
    try:
        v = rdmsr(0x1AE)
        info["e_ratios"] = [(v >> (8 * i)) & 0xFF for i in range(8)]
        info["e_lock"] = (v >> 63) & 1
    except WinRing0Error:
        info["e_ratios"], info["e_lock"] = [], None
    return info


# ---------- Ring / Uncore 频率 (0x620 / 0x621) ----------
# MSR_UNCORE_RATIO_LIMIT (0x620)：Ring/Uncore（环形总线 + LLC）频率上限。
#   bits[6:0]    = 最大倍频（ratio × 100MHz）
#   bits[14:8]   = 最小倍频
# MSR_UNCORE_PERF_STATUS (0x621)：当前 Ring/Uncore 倍频。
# 硬件只允许把上限降到默认值以下，不允许超过默认上限（BIOS 也可能锁定写入）。
MSR_UNCORE_RATIO_LIMIT = 0x620
MSR_UNCORE_PERF_STATUS = 0x621


def _ring_fields(v, current_ratio=None):
    """拆出 0x620 两个倍频字段，并识别哪个是上限字段。

    返回 (max_ratio, min_ratio, max_is_high)。
    max_is_high=True 表示上限字段在高位（bits[14:8]）。

    布局说明：Intel 文档/Linux 内核定义 MAX=bits[6:0]、MIN=bits[14:8]
    （服务器/旧平台）；实测 Raptor Lake HX 等客户端平台相反（高位=上限）。
    优先用当前频率(0x621)判断：上限字段应 >= 当前频率、下限字段应 <= 当前频率；
    无法区分（如两字段相等）时按客户端习惯取高位为上限。
    """
    lo = v & 0x7F
    hi = (v >> 8) & 0x7F
    if current_ratio:
        if lo >= current_ratio and hi < current_ratio:
            return lo, hi, False   # 低位是上限（服务器/旧平台布局）
        if hi >= current_ratio and lo < current_ratio:
            return hi, lo, True    # 高位是上限（客户端布局）
    if hi >= lo:
        return hi, lo, True
    return lo, hi, False


def read_ring_frequency():
    """读取 Ring/Uncore 频率限制与当前值。

    返回 dict：
      max_ratio / min_ratio / current_ratio  倍频（×100MHz）
      max_ghz / min_ghz / current_ghz        换算 GHz（无值时为 None）
      ok                                     0x620 是否可读

    字段布局说明：Intel 文档/Linux 内核定义 MAX_RATIO=bits[6:0]、
    MIN_RATIO=bits[14:8]（服务器/旧平台），但实测 Raptor Lake HX 等客户端
    平台两者互换（高位=上限、低位=下限）。为避免再次出现“上限<下限”的错乱，
    这里结合当前频率自动识别上限字段，显示与写入统一按此。
    """
    result = {
        "max_ratio": None, "min_ratio": None, "current_ratio": None,
        "max_ghz": None, "min_ghz": None, "current_ghz": None,
        "ok": False,
    }
    current = 0
    try:
        current = rdmsr(MSR_UNCORE_PERF_STATUS) & 0x7F
        if current:
            result["current_ratio"] = current
            result["current_ghz"] = round(current / 10.0, 1)
    except WinRing0Error:
        pass
    try:
        v = rdmsr(MSR_UNCORE_RATIO_LIMIT)
        max_ratio, min_ratio, _ = _ring_fields(v, current)
        result["max_ratio"] = max_ratio
        result["min_ratio"] = min_ratio
        if max_ratio:
            result["max_ghz"] = round(max_ratio / 10.0, 1)
        if min_ratio:
            result["min_ghz"] = round(min_ratio / 10.0, 1)
        result["ok"] = True
    except WinRing0Error:
        pass
    return result


def set_ring_max_ratio(ratio, original_max_ratio=None):
    """设置 Ring/Uncore 最大倍频（只能降低，硬件不允许超过默认上限）。

    ratio <= 0 时恢复为 original_max_ratio（或当前读取到的默认上限）。
    自动识别上限字段所在位置（高位或低位，结合当前频率判断），把目标倍频
    写入正确的字段，并保证另一个（下限）字段不超过目标倍频，避免 min>max。
    写入后立即回读校验；若被 BIOS 锁定、写入未生效则抛 WinRing0Error。
    返回回读后的 read_ring_frequency() 状态。
    """
    ratio = int(round(ratio))
    if ratio < 0:
        raise WinRing0Error("Ring 倍频不能为负")
    state = read_ring_frequency()
    current_max = state.get("max_ratio")
    if not current_max:
        raise WinRing0Error("无法读取 Ring/Uncore 倍频上限（MSR 0x620），"
                            "可能被 BIOS 锁定或本机不支持")
    # 硬件允许的"出厂默认上限"：优先用保存的原始值，其次当前读到的值。
    # 若以当前值（已被降低过）作上限，会导致无法调回出厂范围。
    hw_default = (int(original_max_ratio) if original_max_ratio
                  else current_max)
    target = ratio
    if target <= 0:
        target = hw_default
    # 硬件不允许超过出厂默认上限：超限自动截断
    if target > hw_default:
        target = hw_default
    if target < 8:
        target = 8  # 避免写入异常值
    v = rdmsr(MSR_UNCORE_RATIO_LIMIT)
    current = 0
    try:
        current = rdmsr(MSR_UNCORE_PERF_STATUS) & 0x7F
    except WinRing0Error:
        pass
    _, _, max_is_high = _ring_fields(v, current)
    lo = v & 0x7F
    hi = (v >> 8) & 0x7F
    if max_is_high:
        new_hi = target
        new_lo = lo if lo <= target else target
    else:
        new_lo = target
        new_hi = hi if hi <= target else target
    new = (new_lo & 0x7F) | ((new_hi & 0x7F) << 8)
    wrmsr(MSR_UNCORE_RATIO_LIMIT, new)
    back = read_ring_frequency()
    if back.get("max_ratio") != target:
        raise WinRing0Error(
            "Ring 倍频写入未生效（MSR 0x620 可能被 BIOS 锁定）。"
            "当前上限仍为 %s" % back.get("max_ratio"))
    return back


def restore_ring_max_ratio(original_max_ratio):
    """恢复 Ring/Uncore 最大倍频到原始值。"""
    return set_ring_max_ratio(int(original_max_ratio),
                              int(original_max_ratio))


# ---------- Per-Core 倍频表（0x1AD / 0x1AE） ----------
# 0x1AD = IA32_PER_CORE_TURBO_RATIO（P 核，每核 8 bits，最多 8 槽）
# 0x1AE = IA32_PER_CORE_TURBO_RATIO2（E 核，每核 8 bits，最多 8 槽）
MSR_PER_CORE_P = 0x1AD
MSR_PER_CORE_E = 0x1AE


def _ratio_register_and_lp(kind):
    if kind not in ("p", "e"):
        raise WinRing0Error("核心类型只能为 p 或 e")
    lps = get_topology().get(kind + "_lps", [])
    if not lps:
        raise WinRing0Error("未检测到 %s 核" % kind.upper())
    return (MSR_PER_CORE_P if kind == "p" else MSR_PER_CORE_E), lps[0]


def _decode_ratio_table(value, kind):
    return [r if _valid_ratio(r) and (kind != "e" or r >= E_CORE_RATIO_MIN)
            else 0 for r in _ratio_bytes(value)]


def read_per_core_ratios(kind="p"):
    """按核心类型绑定 LP 后读取睿频表；槽位表示活跃核数，不是 LP 编号。"""
    reg, lp = _ratio_register_and_lp(kind)
    return _decode_ratio_table(_read_msr_on_lp(lp, reg), kind)


def write_per_core_ratios(kind, ratios):
    """在同一目标 LP 上读取、修改、回读，保留无效/保留槽。"""
    reg, lp = _ratio_register_and_lp(kind)
    with _msr_lock:
        value = _read_msr_on_lp(lp, reg)
        existing = _decode_ratio_table(value, kind)
        cleaned = []
        for slot, ratio in enumerate(list(ratios)[:8]):
            r = int(round(float(ratio)))
            if r == 0 or not existing[slot]:
                continue
            # 跳过第1档（slot 0）：Arrow Lake 等新型号该位由硬件管理，软件写入不生效
            if slot == 0:
                continue
            if not 8 <= r <= 80:
                raise WinRing0Error("睿频表倍频只接受 0 或 8～80")
            cleaned.append((slot, r))
        target = value
        for slot, ratio in cleaned:
            target = (target & ~(0xFF << (slot * 8))) | (ratio << (slot * 8))
        actual = (_write_msr_on_lp(lp, reg, target) if target != value else value)
        return _decode_ratio_table(actual, kind)


# ========== BD PROCHOT / C1E / Turbo Disable 设置 ==========
# C1E = MSR_POWER_CTL[1]；IA32_MISC_ENABLE[22] 是 Limit CPUID Maxval。
# 不能通过 C1E 开关修改 CPUID 可见性。


def read_cpu_settings():
    """读取一个实际存在的 LP；读取失败保留 None，避免把失败伪装为关闭。"""
    lps = get_topology().get("p_lps") or get_topology().get("e_lps") or []
    result = {"bd_prochot": None, "c1e": None, "turbo_disable": None}
    if not lps:
        return result
    try:
        power_ctl = _read_msr_on_lp(lps[0], MSR_POWER_CTL)
        result["bd_prochot"] = bool(power_ctl & (1 << POWER_CTL_BD_PROCHOT_BIT))
        result["c1e"] = bool(power_ctl & (1 << POWER_CTL_C1E_BIT))
    except Exception:
        pass
    try:
        misc = _read_msr_on_lp(lps[0], MSR_MISC_ENABLE)
        result["turbo_disable"] = bool(misc & (1 << MISC_TURBO_DISABLE_BIT))
    except Exception:
        pass
    return result


def write_cpu_settings(bd_prochot=None, c1e=None, turbo_disable=None):
    """只修改显式指定的字段；逐 LP 校验，失败回滚。

    C1E 不等于全部 C-state：关闭它不保证空闲核心永远处于 C0。
    """
    topology = get_topology()
    lps = topology.get("p_lps", []) + topology.get("e_lps", [])
    if not lps:
        raise WinRing0Error("未检测到可控制的逻辑处理器")
    fields = ((MSR_POWER_CTL, ((POWER_CTL_BD_PROCHOT_BIT, bd_prochot),
                              (POWER_CTL_C1E_BIT, c1e))),
              (MSR_MISC_ENABLE, ((MISC_TURBO_DISABLE_BIT, turbo_disable),)))
    with _msr_lock:
        changes = []
        # 全部预读成功后才开始写入。
        for lp in lps:
            for reg, items in fields:
                requested = [(bit, flag) for bit, flag in items if flag is not None]
                if not requested:
                    continue
                before = _read_msr_on_lp(lp, reg)
                target, mask = before, 0
                for bit, flag in requested:
                    mask |= 1 << bit
                    target = (target | (1 << bit)) if flag else (target & ~(1 << bit))
                if target != before:
                    changes.append((lp, reg, before, target, mask))
        written = []
        try:
            for lp, reg, before, target, mask in changes:
                written.append((lp, reg, before, mask))
                actual = _write_msr_on_lp(lp, reg, target)
                if (actual ^ target) & mask:
                    raise WinRing0Error("LP%d MSR 0x%X 设置回读不一致" % (lp, reg))
        except Exception as error:
            failures = []
            for lp, reg, before, mask in reversed(written):
                try:
                    current = _read_msr_on_lp(lp, reg)
                    restore = (current & ~mask) | (before & mask)
                    actual = _write_msr_on_lp(lp, reg, restore)
                    if (actual ^ before) & mask:
                        raise WinRing0Error("回读不一致")
                except Exception as rollback_error:
                    failures.append("LP%d: %s" % (lp, rollback_error))
            suffix = "；回滚失败：" + "; ".join(failures) if failures else "；已回滚"
            raise WinRing0Error(str(error) + suffix) from error
    return read_cpu_settings()
