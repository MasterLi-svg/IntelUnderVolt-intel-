# IntelUndervolt v3.0 — 软件使用与开发说明

> CPU 降压 / 定频 / 睿频控制工具，由 **BL爱折腾** 开发。
> 平台：Windows（Intel CPU） · 界面框架：PyQt6 + qfluentwidgets · 打包：PyInstaller

---

## 目录

1. [软件概述](#1-软件概述)
2. [技术架构](#2-技术架构)
3. [驱动方案（核心）](#3-驱动方案核心)
4. [界面说明](#4-界面说明)
5. [功能详解](#5-功能详解)
6. [配置持久化（UnderVoit.ini）](#6-配置持久化undervoitini)
7. [开机自启与静默启动](#7-开机自启与静默启动)
8. [系统安全与异常防护](#8-系统安全与异常防护)
9. [源码结构](#9-源码结构)
10. [打包方法](#10-打包方法)
11. [常见问题与注意事项](#11-常见问题与注意事项)

---

## 1. 软件概述

IntelUndervolt 是一款面向 Intel CPU（尤其是带 E-core 的大小核处理器）的**降压、定频、睿频控制**工具，功能与界面仿照 ThrottleStop 设计。

**核心能力**

| 能力 | 说明 |
|------|------|
| 核心/缓存电压偏移 | 通过 FIVR 邮箱（MSR 0x150）降低核心与缓存电压，减少发热与功耗 |
| P核 / E核 睿频倍频限制 | 分别限制大核与小核的最大倍频（Turbo Ratio Limit） |
| HWP 频率锁定 | 通过 IA32_HWP_REQUEST 锁频，让 CPU 顶着设定频率跑 |
| 功耗墙调节 | PL1 / PL2 / PL4 功耗限制写入 |
| 温度 / 频率 / 功耗监控 | 实时读取各核心温度、频率、功耗、负载 |
| C1E / BD PROCHOT / 睿频开关 | 切换节能状态、处理器热保护、Turbo Boost |
| 稳定性压力测试 | 多线程满载 CPU，验证降压/定频后稳定性 |
| 开机自启 + 静默启动 | 以最高权限任务随系统登录启动，静默应用配置 |

**版本信息**：`APP_VERSION = "3.0"`，窗口标题 `IntelUndervolt v3.0 - BL爱折腾`

---

## 2. 技术架构

```
┌─────────────────────────────────────────────┐
│  ts_qt_full.py  (UI 层, PyQt6 + qfluentwidgets) │
│   MainWindow / FIVRDialog / StabTestDialog   │
├─────────────────────────────────────────────┤
│  frequency_control.py  (HWP 频率控制线程)        │
├─────────────────────────────────────────────┤
│  msr.py  (驱动封装核心)                          │
│   读取 → pawnio_reader.py (PawnIO)            │
│   写入 → winring0.py (WinRing0)               │
├─────────────────────────────────────────────┤
│  WinRing0x64.sys / pawnio.dll + IntelMSR.bin   │
│  (内核驱动, 以管理员权限访问 MSR)               │
└─────────────────────────────────────────────┘
```

**分层职责**

| 层 | 文件 | 职责 |
|----|------|------|
| 界面层 | `ts_qt_full.py` | 窗口、控件、交互、配置读写、自启管理 |
| 控制层 | `frequency_control.py` | HWP 频率的守护线程（保持频率不弹回） |
| 驱动封装层 | `msr.py` | 所有 MSR 读写的统一入口，含校验、日志、锁 |
| 读取实现 | `pawnio_reader.py` | 通过 PawnIO 驱动读取 MSR（有微软签名，不被 Defender 拦截） |
| 写入实现 | `winring0.py` | 通过 WinRing0 驱动写入 MSR（延迟懒加载，仅应用时启用） |

---

## 3. 驱动方案（核心）

本项目采用**混合驱动方案**，这是多次死机/蓝屏问题后收敛的最终架构：

### 3.1 读取 vs 写入分离

| 操作 | 驱动 | 理由 |
|------|------|------|
| **所有 MSR 读取**（温度/频率/功耗/电压/睿频表） | **PawnIO**（`pawnio.dll` + `IntelMSR.bin`） | 有微软签名，Windows Defender 不拦截，分发给他人安全 |
| **所有 MSR 写入**（降压/定频/功耗墙/开关） | **WinRing0**（`WinRing0x64.sys`） | 懒加载，只在点"应用设置"时启用 |

### 3.2 关键设计

- **WinRing0 懒加载**：程序启动时不加载 WinRing0，只有用户点击"应用设置"或打开"睿频电压控制"时通过 `load_driver()` 动态加载。避免开机即加载驱动导致卡死。
- **VBS/HVCI 检测**：`detect_virtualization()` / `_detect_vbs()` 启动时检测"基于虚拟化的安全性"和"内存完整性"，开启时提示但**不强制阻断**（只 warn 不 block），把决定权交给用户。
- **MSR 可写自检**：`msr_write_self_test()` 写后回读，检测 OC Lock / 虚拟化接管 / 未知 OEM 锁。
- **全局读写锁**：`_drv_lock = threading.Lock()`，所有 MSR 读写串行化，防止多线程并发调用驱动导致内核死锁。

### 3.3 可读 MSR 白名单（PawnIO 实测支持）

| 寄存器 | 用途 | 状态 |
|--------|------|------|
| 0x198 | PERF_STATUS（频率/倍频/VID） | ✅ |
| 0x19C | THERM_STATUS（温度） | ✅ |
| 0x606 | RAPL_POWER_UNIT（功耗单位） | ✅ |
| 0x611 | PKG_ENERGY_STATUS（封装能量） | ✅ |
| 0x1A2 | TEMPERATURE_TARGET（温度墙） | ✅ |
| 0x0CE | PLATFORM_INFO（平台信息） | ✅ |
| 0x1AD | TURBO_RATIO_LIMIT（P核睿频表） | ✅ |
| 0x150 | FIVR（电压控制） | ✅ |
| 0x1B1 | TEMPERATURE_TARGET_1B1 | ✅ |

> 注：0x1A0 / 0x771 / 0x774 / 0x777 / 0x1FC 不在 PawnIO 白名单，相关功能（C1E/BD PROCHOT/睿频开关、HWP）读取走 WinRing0。

---

## 4. 界面说明

主窗口（`MainWindow`，760×600，可调最小尺寸）

```
┌──────────────────────────────────────────────────────────────┐
│  [Logo]  CPU: i7-14650HX │ ⚡ 电压: 0.842V │ 🔥 功耗 │ 📊 CPU%  │  ← 顶部状态栏
├──────────────────────────────┬───────────────────────────────┤
│  左栏（设置）                 │  右栏（Monitoring 数据表格）      │
│  - Settings 分组              │   核心 │ 温度 │ 频率 │ 负载 │ 功耗│
│    · BD PROCHOT 开关          │   0    │ 72° │ 4.4 │ 12% │ 16W│
│    · C1E 开关                 │   1    │ ... │     │     │     │
│    · 关闭睿频                 │   ...  │ ... │     │     │     │
│    · HWP 锁定                 │        │     │     │     │     │
│  - 工具 分组                  │        │     │     │     │     │
│    · 睿频电压控制 → FIVR       │        │     │     │     │     │
│    · 功耗调节                 │        │     │     │     │     │
│    · 稳定性测试               │        │     │     │     │     │
│  - 硬件 分组                  │        │     │     │     │     │
│    · 驱动/电源/内存/MSR锁 状态 │        │     │     │     │     │
├──────────────────────────────┴───────────────────────────────┤
│  底部按钮区：应用设置 │ 刷新 │ 恢复默认 │ ...                    │
└──────────────────────────────────────────────────────────────┘
```

- **主题**：默认深色（`Theme.DARK`），支持浅色/深色切换，可持久化到 ini/fivr_config。
- **右侧表格**：实时刷新各核心温度、频率、负载等，条件着色（温度 <70°C 绿 / 70~85°C 橙 / >85°C 红）。

### 4.1 FIVR 睿频电压控制窗口（`FIVRDialog`，1080×760）

| 区域 | 功能 |
|------|------|
| P核 / E核 切换 | 切换编辑大核 / 小核的睿频表 |
| 核心/缓存电压滑块 | 调整 CPU 核心、缓存电压偏移（mV） |
| 睿频倍频表 | 每个活跃核心的倍频限制（1核~N核） |
| 倍频 < / > 按钮 | 调整选中核心的倍频值 |
| 应用设置 | 批量写入所有 MSR |
| 读回当前值 | 从硬件读取当前实际生效的值回填 |

### 4.2 稳定性测试窗口（`StabTestDialog`）

- 多线程满载（默认 CPU 核心数）跑 hashlib 哈希循环，验证降压后稳定性。
- 支持"开始/停止"，测试中"开始"禁用、可随时停止。
- Worker 线程独立运行，不阻塞 UI，退出时强制清理。

---

## 5. 功能详解

### 5.1 降压（Undervolt）

- **寄存器**：MSR 0x150（FIVR 邮箱）
- **电压平面**：`core`(0) / `igpu`(1) / `cache`(2) / `sa`(3) / `igpu_unslice`(4) / `l2_ecore`(5)
- **范围**：`MAX_OFFSET = -249` mV 至 `MAX_OVERVOLT = 0` mV
- **实现**：`write_offset_mv(plane, mv)` 通过邮箱写偏移，写后回读验证。
- **全部核心**：降压对每个逻辑处理器（LP）逐一写入（`-a` 模式），不只写核 0。

### 5.2 P/E 核睿频限制

- **寄存器**：P核 = MSR 0x1AD（`MSR_PER_CORE_P`），E核 = MSR 0x1AE（`MSR_PER_CORE_E`）
- **写表**：`write_per_core_ratios(kind, ratios)`，按每个核心写入对应倍频字节。
- **Arrow Lake 适配**：跳过 slot 0（第1档由硬件管理，软件写入不生效）；回读不一致时已移除报错（只写入不检查）。
- **HWP 换算**：`_hwp_scaling_khz()` 用白名单按 CPU model 取 scaling（如 78741/80000），再换算成 HWP performance 级别。不在白名单的型号会提示"尚未确认此 CPU 的 HWP 频率标尺"。

### 5.3 HWP 频率锁定（锁频）

- **寄存器**：MSR 0x774（`MSR_HWP_REQUEST`）
- **实现**：`build_hwp_frequency_targets()` + `apply_hwp_frequency_targets()`
- **锁频**：min = max = 目标性能级别（`lock=True`），让 CPU 顶着设定频率跑。
- **EPP**：只写 EPP=0（最高性能偏好），不锁死 Min/Max（之前锁 255 导致锁在 0.4GHz 的问题已修复）。
- **守护**：`frequency_control.py` 的 `HwpFrequencyController` 周期性检查，若频率被系统/固件改回则重新写入（读回比对后再写）。

### 5.4 C1E / BD PROCHOT / 睿频开关

| 功能 | 寄存器 | 位 | 说明 |
|------|--------|----|------|
| BD PROCHOT | MSR 0x1FC (POWER_CTL) | bit 0 | 勾选=启用外部降频信号，取消=屏蔽外部降频信号 |
| C1E | MSR 0x1A0 (MISC_ENABLE) | bit 22 | 勾选=允许空闲降频降压 |
| 关闭睿频 | MSR 0x1A0 (MISC_ENABLE) | bit 38 | 勾选=禁用 Intel Turbo Boost |
| 关闭 Game DVR | — | — | 额外系统优化 |

- **写后回读验证**：写入后读回确认位已翻转，失败弹窗"设置未生效（可能被 BIOS 锁定）"并恢复原状态。
- **与 OC Lock 联动**：检测到 OC Lock 启用时，这些开关全部禁用并提示需进 BIOS 解锁。
- **取消 BD PROCHOT 风险确认**：取消时弹确认框提示散热风险。

### 5.5 功耗墙调节（`PowerLimitDialog`）

- **寄存器**：PL1/PL2（0x610/0x611 相关）、PL4（0x601 相关）
- **实现**：`write_power_limits(pl1, pl2, ...)` / `write_pl4(pl4)`
- 支持设置功耗上限（W）和持续时间。

### 5.6 实时监控

- 通过 `read_monitor()` 读取每个逻辑处理器的温度、频率、负载、功耗。
- **温度**：MSR 0x19C（THERM_STATUS）
- **频率**：MSR 0x198（PERF_STATUS）
- **功耗**：MSR 0x611 能量计数器差分计算
- **CPU 占用**：`psutil.cpu_percent()` 或 `_per_core_times()`
- 后台 QTimer/线程刷新，避免阻塞 UI。

### 5.7 频率/功耗限制原因诊断

- **寄存器**：MSR 0x64F（`MSR_CORE_PERF_LIMIT_REASONS`）
- **实现**：`read_perf_limit_reasons()` / `read_perf_limit_summary()`，解码每个核心频率被限制的原因（热、功耗、电流、VRM 等），帮助用户判断为什么频率上不去。

### 5.8 环形总线频率（Ring/Uncore）

- **寄存器**：MSR 0x620（Uncore Ratio Limit）
- **实现**：`set_ring_max_ratio()` / `read_ring_frequency()`，可限制缓存/环形总线频率。

---

## 6. 配置持久化（UnderVoit.ini）

**位置**：exe 同目录（打包后）或脚本同目录，文件名固定 `UnderVoit.ini`。
**编码**：`utf-8-sig`（中文不乱码）。

### 6.1 结构

```ini
[meta]
version = 1

[core]
vcore_offset_mv = -75        ; 核心电压偏移 (mV)
fivring_offset_mv = -60      ; 缓存电压偏移 (mV)
e_offset_mv = 0              ; E核电压偏移 (mV)
ratio_limit = 44             ; P核睿频倍频上限（0=未限制）
e_ratio_limit = 33           ; E核睿频倍频上限（0=未限制）
ring_ratio_limit = 0         ; 环形总线倍频上限（0=恢复默认）
e_ratios = 33,33,33,33,33,33,33,33   ; E核倍频表（8行，逗号分隔）

[switches]
bd_prochot = true            ; BD PROCHOT
c1e = true                   ; C1E
disable_turbo = false        ; 关闭睿频
hwp_lock = true              ; HWP 锁定

[behavior]
minimize_on_close = false    ; 关闭时最小化到托盘
autostart = false            ; 开机自启
```

### 6.2 读写逻辑

- **保存**：点"应用设置"成功后 `_save_ini_config()` 写入。**先写 .tmp 再 `os.replace`**，防止中途崩溃写坏文件。
- **加载**：`_load_ini_config()` 启动时读取，缺省/损坏时返回默认值并记日志，不崩溃。
- **回填**：启动时读取后回填到 UI 控件（滑块/输入框/复选框显示 ini 状态）。
- **应用**：`--silent` 开机自启模式延迟 60 秒后静默应用（读→回填→静默应用，不弹成功提示）。
- 只有"应用成功"才落盘；应用失败不写入错误状态。

### 6.3 其他配置

- **config.json**：位于 `%ProgramData%\IntelUndervolt\config.json`，保存睿频表（p_ratios/e_ratios）与主题等。
- **fivr_config.json**：旧版配置，存在时自动迁移到 config.json。

---

## 7. 开机自启与静默启动

### 7.1 开机自启实现

- **方式**：任务计划程序（`schtasks`），**不用 Startup 文件夹**（权限不够拿不到最高权限）。
- **任务名**：固定 `IntelUndervolt_AutoStart`，便于精准定位删除。
- **属性**：
  - 触发器：`/SC ONLOGON`（用户登录时）
  - 操作：`"exe路径" --silent`
  - 权限：`/RL HIGHEST`（以最高权限运行）
- **勾选**：先删旧注册表项（`HKCU\...\Run` 的 IntelUndervolt），再创建 schtasks 任务。
- **取消**：`schtasks /Delete /TN IntelUndervolt_AutoStart /F` 删除任务（幂等，不存在也静默成功）。
- **状态回写**：操作结果写入 ini 的 `[behavior] autostart`。
- **界面提示**：开启/关闭均弹 InfoBar 成功提示。

### 7.2 静默启动（--silent）

- 开机自启任务带 `--silent` 参数。
- 主入口 `if "--silent" in sys.argv`：`MainWindow(silent=True)`，`w.hide()` 直接隐藏到托盘（**必须 hide() + 托盘，不能 showMinimized**，否则任务栏会留按钮）。
- 静默模式延迟 **60 秒**加载 WinRing0 驱动并自动应用 ini 配置（等系统完全就绪，防卡死）。
- 提供 `--safe` 参数（安全模式，不自动应用）。

### 7.3 托盘（系统托盘图标）

- 关闭时最小化到托盘（`minimize_on_close = true`）：拦截 closeEvent → `hide()`，任务栏不显示，托盘保留图标。
- 托盘右键"退出" → 真正退出；双击/打开 → 恢复窗口。
- 程序退出时 `tray.hide()` + `deleteLater()`，防止幽灵图标残留。

---

## 8. 系统安全与异常防护

本项目经历过多轮"蓝屏/死机"问题的修复，沉淀了以下关键防护：

### 8.1 防止蓝屏/死机的设计

| 措施 | 说明 |
|------|------|
| 驱动延迟加载 | WinRing0 只在点"应用设置"时加载，启动不加载 |
| VBS/HVCI 检测 | 检测到内存完整性开启时提示，不强制阻断 |
| MSR 全局锁 | `threading.Lock()` 串行化所有读写，防止驱动并发死锁 |
| 写后回读验证 | 写入后读回确认，失败即报错并回滚，不继续写 |
| 反算保护 | HWP 级别换算回物理倍频，偏差超过 1× 立即停止写入 |
| 合法性校验 | 倍频范围、P/E 大小关系、保留位清零，异常值拦截 |
| 写入前暂停守护 | 写频率前暂停 HWP 守护线程，写完恢复，防止竞态覆盖 |
| 50~100ms 写间隔 | 连续写多个核心之间加间隔，避免连击触发固件保护 |

### 8.2 异常兜底

- 所有 MSR 调用包 `try/except`，失败写日志 + 弹窗提示，不 re-raise 到进程外。
- `faulthandler` 兜底 native 崩溃（C 层崩溃也能留下堆栈）。
- 启动主入口 `try/except`，未捕获异常写日志再退出，避免闪退无痕。

### 8.3 环境检测

- `detect_virtualization()`：检测虚拟化层（HVCI / Credential Guard / Hyper-V / VBS）
- `detect_bios_locks()`：检测 OC Lock、CFG Lock 等 BIOS 锁
- `msr_write_self_test()`：写后回读自检 MSR 可写性

---

## 9. 源码结构

```
hwp-fix2-analyze/
├── ts_qt_full.py              # 主程序（UI + 配置 + 自启 + 入口）
├── msr.py                     # 驱动封装核心（所有 MSR 读写）
├── pawnio_reader.py           # PawnIO 读取层
├── winring0.py                # WinRing0 写入层
├── frequency_control.py       # HWP 频率守护控制器
├── IntelUndervolt-v3bh.spec   # PyInstaller 打包配置
├── app_icon.ico / app_icon.png # 应用图标
├── IntelMSR.bin               # PawnIO 脚本模块
├── pawnio.dll                 # PawnIO 驱动 DLL
├── PawnIO_setup.exe           # PawnIO 驱动安装程序
└── WinRing0x64.sys            # WinRing0 内核驱动
```

### 9.1 主程序 `ts_qt_full.py` 主要类/函数

| 位置 | 类型 | 说明 |
|------|------|------|
| `_stress_worker()` | 函数 | 稳定性测试哈希负载线程 |
| `_log()` | 函数 | 日志输出（时间戳） |
| `detect_virtualization()` | 函数 | 虚拟化检测 |
| `detect_bios_locks()` | 函数 | BIOS 锁检测 |
| `msr_write_self_test()` | 函数 | MSR 可写自检 |
| `load_driver()` | 函数 | 延迟加载 WinRing0 |
| `_get_ini_path()` | 函数 | UnderVoit.ini 路径 |
| `_default_ini_config()` | 函数 | 默认配置 |
| `_load_ini_config()` / `_save_ini_config()` | 函数 | ini 读写 |
| `_StatusWorker` | 类(QThread) | 后台状态刷新线程 |
| `PowerLimitDialog` | 类(QDialog) | 功耗墙调节窗口 |
| `StabTestDialog` | 类(QDialog) | 稳定性测试窗口 |
| `FIVRDialog` | 类(QDialog) | 睿频电压控制窗口 |
| `MainWindow` | 类(QMainWindow) | 主窗口 |

### 9.2 驱动层 `msr.py` 主要函数

| 函数 | 说明 |
|------|------|
| `rdmsr(reg)` / `wrmsr(reg, value)` | 基础读/写（默认走 WinRing0） |
| `apply_undervolt(core_mv, cache_mv, ...)` | 应用降压 |
| `read_offset_mv(plane)` / `write_offset_mv(plane, mv)` | 单平面电压偏移读写 |
| `read_monitor()` | 读全部核心监控数据 |
| `read_pkg_power()` | 读封装功耗 |
| `write_power_limits()` / `write_pl4()` | 功耗墙写入 |
| `read_turbo_info()` / `read_frequency_capabilities()` | 睿频能力读取 |
| `write_per_core_ratios(kind, ratios)` | P/E 核睿频表写入 |
| `build_hwp_frequency_targets()` / `apply_hwp_frequency_targets()` | HWP 锁频 |
| `maintain_hwp_frequency_targets()` | HWP 守护 |
| `apply_direct_profile()` / `maintain_direct_profile()` | 直接定频配置 |
| `read_perf_limit_reasons()` | 频率限制原因诊断 |
| `set_ring_max_ratio()` | 环形总线倍频限制 |
| `write_cpu_settings(bd_prochot, c1e, turbo_disable)` | C1E/BD PROCHOT/睿频开关 |

---

## 10. 打包方法

### 10.1 打包配置（IntelUndervolt-v3bh.spec）

- 输出名：`IntelUndervolt-v3.exe`
- `console=False`（无控制台窗口）
- onefile 模式（资源通过 `_MEIPASS` 解压）
- 包含资源：图标、WinRing0 驱动、PawnIO 驱动、IntelMSR.bin

### 10.2 打包命令

```bash
cd C:\Users\123\Desktop\源码\hwp-fix2-analyze
pyinstaller IntelUndervolt-v3bh.spec --noconfirm
```

输出在 `dist\IntelUndervolt-v3.exe`。

### 10.3 分发注意事项

- **PawnIO 驱动**：需在目标机器安装（`PawnIO_setup.exe`），否则读取功能不可用。
- **WinRing0**：仅写入时懒加载，被 Defender 拦截时写入不可用。
- **管理员权限**：读写 MSR 需要管理员权限运行。

---

## 11. 常见问题与注意事项

### 11.1 为什么会出现"定频失败：尚未确认此 CPU 的 HWP 频率标尺"

- 原因：当前 CPU model 不在 `HWP_P_SCALING_BY_MODEL` 白名单中，且没有自动校准逻辑。
- 解决：在 `msr.py` 的 `HWP_P_SCALING_BY_MODEL` 字典中新增该 CPU 的 model 和对应 scaling 值。

### 11.2 为什么设置倍频后实际频率不一致（如设44跑34）

- 原因：HWP scaling 值不准。不同 CPU 代际的 scaling 不同（如 Raptor Lake 78741、Arrow Lake 约60000）。
- 排查：查看日志中该 CPU 的 scaling 值，调整 `HWP_P_SCALING_BY_MODEL` 中对应 model 的值。

### 11.3 为什么给其他人后打开就死机/蓝屏

- 常见原因：对方机器开启了 VBS/内存完整性（HVCI），或驱动加载时机不对。
- 应对：本项目已采用 PawnIO（签名驱动）读取 + WinRing0 懒加载写入 + VBS 检测提示，尽量规避。

### 11.4 开机自启后闪退/卡死

- 原因：开机即加载驱动或自动应用写入，系统未完全就绪。
- 应对：静默模式延迟 60 秒加载驱动并应用配置。

### 11.5 电压/温度/频率读取不准

- 0x198 VID 换算公式在不同 CPU 代际有差异（Raptor Lake 等不适用）。
- E 核频率 Windows 默认不暴露，用 WMI 读取可能不准。

---

*文档由 BL爱折腾 · IntelUndervolt v3.0 源码整理生成*
