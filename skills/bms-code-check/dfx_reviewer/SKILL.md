---
name: dfx_reviewer
description: Bundle Framework DFX 代码审查技能，专注于 HiLog API、HiSysEvent 和 HiTrace 组件的审查，包含日志基础规范、常见模式日志打印检查
version: 2.1.0
author: DFX Team
tags:
  - dfx
  - hilog
  - hisysevent
  - hitrace
  - diagnostic
  - event logging
  - performance tracing
  - log pattern
triggers:
  - dfx review
  - dfx 检视
  - hisysevent
  - hitrace
  - hilog
  - 事件日志
  - event logging
  - 性能追踪
  - performance tracing
  - 诊断
  - diagnostic
  - 日志规范
  - log pattern
---

# Bundle Framework DFX Code Review Skill

## Purpose
This skill provides specialized guidance for reviewing DFX (Diagnostic Facilities) code in the Bundle Framework subsystem (BMS - Bundle Manager Service), focusing on HiSysEvent and HiTrace components.

## DFX Components Overview
The DFX facility in bundle_framework does **not** maintain a separate adapter directory (unlike some other subsystems). Instead, DFX is integrated directly via the `EventReport` utility class:

- **EventReport**: Static utility class providing all HiSysEvent reporting APIs (`services/bundlemgr/include/event_report.h`)
- **InnerEventReport**: Internal implementation detail (`services/bundlemgr/include/inner_event_report.h`)
- **HiTrace**: Standard `HITRACE_METER_NAME_EX` macros from `hisysevent.h`, no adapter layer
- **HiSysEvent config**: `hisysevent.yaml` at the project root defines all event domain/names/params

## Key Files and Locations

### DFX Entry Files
```
services/bundlemgr/include/
├── event_report.h                     # EventReport class - public DFX API
├── inner_event_report.h               # InnerEventReport - internal helpers

services/bundlemgr/src/
├── event_report.cpp                   # EventReport implementation
├── inner_event_report.cpp             # InnerEventReport implementation

hisysevent.yaml                         # Event domain/names/params definition (project root)
```

### Core Service Files Using DFX
```
services/bundlemgr/src/bundle_mgr_service.cpp           # BMS lifecycle, boot scan
services/bundlemgr/src/base_bundle_installer.cpp        # Install/uninstall/update flow
services/bundlemgr/src/bundle_data_mgr.cpp              # bundleInfos_ / DB / state machine
services/bundlemgr/src/bundle_mgr_host_impl.cpp         # IDL host entry (IPC boundary)
services/bundlemgr/src/installd/installd_host_impl.cpp  # installd daemon client
services/bundlemgr/src/shared/inner_shared_bundle_installer.cpp  # HSP install flow
```

## Review Guidelines

### 1. HiSysEvent Review

#### Available Report Functions

**EventReport static API** (`services/bundlemgr/include/event_report.h`):
```cpp
class EventReport {
public:
    // Bundle lifecycle behavior events (install/uninstall/update)
    static void SendBundleSystemEvent(BundleEventType bundleEventType, const EventInfo& eventInfo);

    // Boot scan behavior/fault events
    static void SendScanSysEvent(BMSEventType bMSEventType);

    // Generic system event (covers fault + behavior + statistic)
    static void SendSystemEvent(BMSEventType eventType, const EventInfo& eventInfo);

    // User lifecycle (create/remove user)
    static void SendUserSysEvent(UserEventType userEventType, int32_t userId);

    // Specific scenarios
    static void SendCleanCacheSysEvent(const std::string &bundleName, int32_t userId,
        bool isCleanCache, bool exception, int32_t callingUid, const std::string &callingBundleName);
    static void SendComponentStateSysEvent(const std::string &bundleName, const std::string &abilityName,
        int32_t userId, bool isEnable, int32_t appIndex, const std::string &callingName);
    static void SendDiskSpaceEvent(const std::string &fileName, int64_t freeSize, int32_t operationType);
    static void SendAppControlRuleEvent(const EventInfo& eventInfo);
    static void SendDbErrorEvent(const std::string &dbName, int32_t operationType, int32_t errorCode);
    static void SendDefaultAppEvent(DefaultAppActionType actionType, int32_t userId, int32_t appIndex,
        const std::string& callingName, const std::string& want, const std::string& utd);
    static void SendDynamicShortcutEvent(const std::string &bundleName, int32_t userId,
        const std::vector<std::string> &shortcutIds, const std::string &operationType, int32_t callingUid);
    static void SendDesktopShortcutEvent(const std::string &operationType, int32_t userId,
        const std::string &bundleName, int32_t appIndex, const std::string &shortcutId,
        int32_t callingUid, int32_t result);
    static void SendHighRiskEvent(const EventInfo& eventInfo);
    static void SendTriggerFallbackEvent(HighRiskOperationType operation, const std::string &bundleName,
        int32_t userId, const std::vector<std::string> &path);
    static void SendScanTimeoutEvent(HighRiskOperationType operation, int64_t startTime, int64_t endTime);
};
```

**Event Types** (`BMSEventType`, fault events first then behavior events):
```cpp
enum class BMSEventType : uint8_t {
    // FAULT events
    BUNDLE_INSTALL_EXCEPTION,
    BUNDLE_UNINSTALL_EXCEPTION,
    BUNDLE_UPDATE_EXCEPTION,
    PRE_BUNDLE_RECOVER_EXCEPTION,
    BUNDLE_STATE_CHANGE_EXCEPTION,
    BUNDLE_CLEAN_CACHE_EXCEPTION,
    // BEHAVIOR events
    BOOT_SCAN_START,
    BOOT_SCAN_END,
    BUNDLE_INSTALL,
    BUNDLE_UNINSTALL,
    BUNDLE_UPDATE,
    PRE_BUNDLE_RECOVER,
    BUNDLE_STATE_CHANGE,
    BUNDLE_CLEAN_CACHE,
    BMS_USER_EVENT,
    APPLY_QUICK_FIX,
    CPU_SCENE_ENTRY,
    AOT_COMPILE_SUMMARY,
    AOT_COMPILE_RECORD,
    QUERY_OF_CONTINUE_TYPE,
    FREE_INSTALL_EVENT,
    BMS_DISK_SPACE,
    APP_CONTROL_RULE,
    DB_ERROR,
    DEFAULT_APP,
    DATA_PARTITION_USAGE_EVENT,
    QUERY_BUNDLE_INFO,
    BUNDLE_DYNAMIC_SHORTCUTINFO,
    DESKTOP_SHORTCUT,
    APP_STATUS_CHANGE,
    HIGH_RISK_EVENT,
    BUNDLE_LOCAL_PLUGIN_OPERATION,
};

enum class BundleEventType : uint8_t {
    INSTALL,
    UNINSTALL,
    UPDATE,
    RECOVER,
    QUICK_FIX
};

enum class InstallScene : uint8_t {
    NORMAL = 0,
    BOOT,         // first boot scan
    REBOOT,       // reboot scan
    CREATE_USER,  // create new user
    REMOVE_USER   // remove user
};
```

**EventInfo payload** (`event_report.h`): carries `bundleName`, `userId`, `versionCode`, `errCode`, `callingUid`, `appIndex`, `preBundleScene`, `filePath`, `hashValue`, `fingerprint`, `appDistributionType`, etc. Call `eventInfo.Reset()` before reuse.

#### ⚠️ 架构原则：客户端禁止直接打点

**🔴 重要规则：客户端代码不允许直接进行 HiSysEvent 打点**

**定义**：
- **服务端（Server）**: System Ability 实现，位于 `services/bundlemgr/`，如 `BundleMgrService`、`BaseBundleInstaller`、`BundleDataMgr`
- **客户端（Client）**: SDK、Kit、Proxy、包装类等，如 `BundleMgrProxy`、`BundleMgrClient`、NAPI 接口

**为什么客户端不能打点？**

1. **统一管理**: 所有事件在服务端统一打点，便于管理和分析
2. **避免重复**: 同一个操作可能在多个客户端调用，服务端打点可以避免重复事件
3. **权限控制**: HiSysEvent 打点需要系统权限，客户端可能没有足够权限
4. **数据一致性**: 服务端可以确保事件参数的准确性和一致性
5. **性能考虑**: 减少客户端到 HiSysEvent 服务的跨进程调用
6. **安全性**: 防止恶意应用伪造或滥用事件系统

**代码位置规则**：

| 代码位置 | 是否允许 HiSysEvent 打点 | 说明 |
|----------|------------------------|------|
| `services/bundlemgr/src/` | ✅ **允许** | 服务端实现 |
| `services/bundlemgr/include/` | ✅ **允许** | 服务端接口 |
| `services/bundlemgr/src/event_report.cpp` | ✅ **允许** | DFX 实现本身 |
| `interfaces/inner_api/appexecfwk_core/` | ❌ **禁止** | Inner API 客户端 |
| `interfaces/kits/appkit/` | ❌ **禁止** | 应用侧 Kit 客户端 |
| `interfaces/kits/js/`、`ndk/`、`cj/` | ❌ **禁止** | JS/NDK/CJ 接口客户端 |

**正确做法示例**：

```cpp
// ❌ 错误：客户端代码直接打点
// 文件: interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_proxy.cpp
ErrCode BundleMgrProxy::Install(const std::string &bundlePath, const InstallParam &installParam,
    const sptr<IStatusReceiver> &statusReceiver)
{
    ErrCode ret = SendRequest(IBundleMgr::Message::INSTALL, data, reply, option);
    if (ret != ERR_OK) {
        // 客户端不应该直接调用 EventReport
        EventInfo eventInfo;
        eventInfo.bundleName = bundlePath;
        EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);  // ❌ 错误
    }
    return ret;
}

// ✅ 正确：客户端只调用服务端，不打点
ErrCode BundleMgrProxy::Install(const std::string &bundlePath, const InstallParam &installParam,
    const sptr<IStatusReceiver> &statusReceiver)
{
    // 客户端只负责透传 IPC，不进行 HiSysEvent 打点
    return SendRequest(IBundleMgr::Message::INSTALL, data, reply, option);  // ✅ 正确
}

// ✅ 正确：服务端进行打点
// 文件: services/bundlemgr/src/base_bundle_installer.cpp
ErrCode BaseBundleInstaller::ProcessBundleInstall(...)
{
    ErrCode result = InnerProcessBundleInstall(...);
    if (result != ERR_OK) {
        EventInfo eventInfo;
        eventInfo.bundleName = bundleName_;
        eventInfo.errCode = result;
        eventInfo.userId = userId_;
        EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);  // ✅ 正确
        return result;
    }
    return ERR_OK;
}
```

**检查方法**：

```bash
# 检查客户端代码是否有 HiSysEvent 打点
grep -rn "EventReport::\|HiSysEventWrite\|SendBundleSystemEvent\|SendSystemEvent" \
    interfaces/inner_api/ interfaces/kits/ --include="*.cpp" --include="*.h"

# 如果有输出，说明违反了规则，需要修复
```

**自动化检查脚本**：

```bash
#!/bin/bash
# check_client_hisysevent.sh
# 检查 bundle_framework 客户端代码是否违规进行 HiSysEvent 打点

echo "=== 检查 bundle_framework 客户端 HiSysEvent 打点 ==="
echo ""

CLIENT_DIRS="interfaces/inner_api/appexecfwk_core/ interfaces/kits/appkit/ interfaces/kits/js/ interfaces/kits/ndk/ interfaces/kits/cj/"
VIOLATIONS=0

for dir in $CLIENT_DIRS; do
    if [ ! -d "$dir" ]; then
        continue
    fi

    echo "检查目录: $dir"

    # 检查 EventReport 调用
    FOUND=$(grep -r "EventReport::" "$dir" --include="*.cpp" --include="*.h" 2>/dev/null | wc -l)
    if [ $FOUND -gt 0 ]; then
        echo "  ❌ 发现 $FOUND 处 EventReport 调用"
        grep -rn "EventReport::" "$dir" --include="*.cpp" --include="*.h" 2>/dev/null | head -5
        VIOLATIONS=$((VIOLATIONS + FOUND))
    fi

    # 检查 HiSysEventWrite
    FOUND=$(grep -r "HiSysEventWrite" "$dir" --include="*.cpp" --include="*.h" 2>/dev/null | wc -l)
    if [ $FOUND -gt 0 ]; then
        echo "  ❌ 发现 $FOUND 处 HiSysEventWrite 调用"
        grep -rn "HiSysEventWrite" "$dir" --include="*.cpp" --include="*.h" 2>/dev/null | head -5
        VIOLATIONS=$((VIOLATIONS + FOUND))
    fi
done

echo ""
if [ $VIOLATIONS -eq 0 ]; then
    echo "✅ 未发现客户端违规打点"
    exit 0
else
    echo "❌ 发现 $VIOLATIONS 处违规，需要修复"
    exit 1
fi
```

**例外情况**：

极少数特殊情况下，客户端可能需要打点，但必须满足以下条件：

**例外类型 1: 底层工具类（需架构团队批准）**

```cpp
// 例外：底层工具类打点
// 文件: common/log/src/bundle_util.cpp （如果被多模块共享）

// 这是一个底层工具类，被多个模块使用
// 由于它是通用工具，不知道调用者是服务端还是客户端
// 因此允许其进行基础的事件打点

bool BundleUtil::CheckFilePath(const std::vector<std::string> &paths, std::vector<std::string> &validPaths)
{
    // ... 文件检查逻辑 ...
    if (ret != ERR_OK) {
        // 允许：底层工具类只记录基础操作失败
        // 但 bundle_framework 中通常不允许，建议仅打 LOG
        APP_LOGE("check file path failed, errCode=%{public}d", ret);
        return false;
    }
    return true;
}
```

**底层工具类的条件**：
1. ✅ 被多个模块使用（服务端和客户端）
2. ✅ 只记录基础操作（文件操作、网络操作等）
3. ✅ 不包含业务语义（不记录"安装应用"、"卸载应用"等）
4. ✅ 使用通用的操作类型
5. ✅ 经过架构团队评审批准

**例外类型 2: 客户端生命周期事件（需架构团队批准）**

bundle_framework 通常不需要此例外。如果确需追踪客户端初始化状态，应通过 LOG 而非 HiSysEvent。

**代码审查清单**：

在审查代码时，检查以下项目：

- [ ] 确认代码所在位置（服务端 vs 客户端）
- [ ] 客户端代码不包含 `EventReport::Send*` 调用
- [ ] 客户端代码不包含 `HiSysEventWrite` 直接调用
- [ ] 所有业务操作的事件都在服务端打点
- [ ] 如有例外，已添加明确说明并获得批准

**常见错误示例**：

```cpp
// ❌ 错误 1: Proxy 客户端直接打点
class BundleMgrProxy {
public:
    ErrCode GetBundleInfo(const std::string &bundleName, int32_t flags, BundleInfo &info, int32_t userId) {
        ErrCode ret = SendRequest(...);
        if (ret != ERR_OK) {
            EventInfo eventInfo;
            eventInfo.bundleName = bundleName;
            EventReport::SendSystemEvent(BMSEventType::QUERY_BUNDLE_INFO, eventInfo);  // ❌
        }
        return ret;
    }
};

// ❌ 错误 2: NAPI 接口直接打点
static napi_value Install(napi_env env, napi_callback_info info) {
    // ...
    ErrCode ret = proxy_->Install(...);
    if (ret != ERR_OK) {
        EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);  // ❌
    }
    // ...
}

// ✅ 正确：客户端只调用，不打点
class BundleMgrProxy {
public:
    ErrCode GetBundleInfo(const std::string &bundleName, int32_t flags, BundleInfo &info, int32_t userId) {
        return SendRequest(...);  // ✅ 让服务端打点
    }
};
```

#### Event Naming Conventions

**⚠️ 重要：区分业务场景**

在 HiSysEvent 打点时，**必须区分不同的业务场景**。同一操作在不同场景下应使用不同的 `InstallScene` / `BundleEventType` 组合。

**为什么需要区分业务场景？**
- 不同场景的失败率、耗时、影响范围可能不同
- 问题定位时需要知道具体的触发场景
- 性能优化需要针对具体场景进行优化
- 安全审计需要区分不同来源的操作

**场景区分原则**：
1. **调用来源**：用户主动安装、系统启动扫描、OTA 升级、创建用户等
2. **安装场景**：`InstallScene::NORMAL` / `BOOT` / `REBOOT` / `CREATE_USER` / `REMOVE_USER`
3. **操作上下文**：首次安装、更新、卸载、回滚、异常恢复
4. **设备状态**：正常启动、OTA、恢复模式

**Bundle Framework 场景常量**（`event_report.h`）：
```cpp
enum class InstallScene : uint8_t {
    NORMAL = 0,        // 用户/API 触发的普通安装
    BOOT,              // 首次开机扫描
    REBOOT,            // 非首次开机扫描
    CREATE_USER,       // 创建新用户触发
    REMOVE_USER        // 删除用户触发
};

enum class BundleEventType : uint8_t {
    INSTALL,           // 首次安装
    UNINSTALL,         // 卸载
    UPDATE,            // 更新
    RECOVER,           // 恢复（异常恢复后重装）
    QUICK_FIX          // 补丁修复
};
```

**场景命名规范**：

建议组合使用 `BundleEventType` + `InstallScene` 来唯一标识场景：

| BundleEventType | InstallScene | 场景描述 |
|----------------|--------------|---------|
| INSTALL | NORMAL | 用户/API 主动安装 |
| INSTALL | BOOT | 首次开机扫描预装 |
| INSTALL | REBOOT | 非首次开机扫描 |
| INSTALL | CREATE_USER | 创建新用户时预装 |
| UPDATE | NORMAL | 用户/API 主动更新 |
| UPDATE | REBOOT | OTA 升级 |
| UNINSTALL | NORMAL | 用户/API 主动卸载 |
| UNINSTALL | REMOVE_USER | 删除用户时清理 |

**事件前缀说明**：

| 前缀 | 含义 | 对应 BMSEventType |
|------|------|------------------|
| `BOOT_SCAN_*` | 开机扫描相关 | `BOOT_SCAN_START`、`BOOT_SCAN_END` |
| `BUNDLE_INSTALL*` | 安装相关 | `BUNDLE_INSTALL`（行为）、`BUNDLE_INSTALL_EXCEPTION`（故障） |
| `BUNDLE_UNINSTALL*` | 卸载相关 | `BUNDLE_UNINSTALL`、`BUNDLE_UNINSTALL_EXCEPTION` |
| `BUNDLE_UPDATE*` | 更新相关 | `BUNDLE_UPDATE`、`BUNDLE_UPDATE_EXCEPTION` |
| `PRE_BUNDLE_RECOVER*` | 预装恢复 | `PRE_BUNDLE_RECOVER`、`PRE_BUNDLE_RECOVER_EXCEPTION` |
| `DB_ERROR` | 数据库错误 | `DB_ERROR` |
| `HIGH_RISK_EVENT` | 高风险事件 | `HIGH_RISK_EVENT` |

#### Error Reporting Pattern

**Fill EventInfo completely before calling Send\***:
```cpp
EventInfo eventInfo;
eventInfo.bundleName = bundleName_;
eventInfo.userId = userId_;
eventInfo.versionCode = versionCode_;
eventInfo.errCode = result;
eventInfo.callingUid = IPCSkeleton::GetCallingUid();
eventInfo.preBundleScene = InstallScene::NORMAL;
eventInfo.failureReason = "specific reason text";
EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
```

**Real example pattern from `base_bundle_installer.cpp` (MarkInstallFinish rollback path)**:
```cpp
if (result != ERR_OK) {
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName_;
    eventInfo.errCode = result;
    eventInfo.userId = userId_;
    eventInfo.versionCode = versionCode_;
    EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
    RollBack();
    return result;
}
```

#### Data Privacy

**Use `%{private}` for sensitive data in format strings**, bundle_framework uses `APP_LOG*` macros from `app_log_wrapper.h`:

```cpp
// HAP/HSP file paths, code paths, fingerprints are private
APP_LOGI("install bundlePath=%{private}s", bundlePath.c_str());  // 路径脱敏
APP_LOGI("bundleName=%{public}s, userId=%{public}d", bundleName.c_str(), userId);  // 业务字段公开
APP_LOGI("fingerprint=%{private}s", fingerprint.c_str());  // 签名指纹必须脱敏
```

**Sensitive fields in EventInfo**:
- `fingerprint`, `appId`, `appIdentifier` — 应使用 `callingAppId`/`bundleName` 等不带签名的字段
- `provisionInfo`, `appProvisionType` — 谨慎记录，旧值/新值成对记录用于变更追踪
- 原始文件路径 — 使用 `%{private}` 标识

#### Conditional Compilation

**Check `HAS_HISYSEVENT_PART` if adding direct HiSysEvent calls**:
```cpp
#ifdef HAS_HISYSEVENT_PART
    HiSysEventWrite(...);
#endif
```

Note: `EventReport` class internally handles the conditional compilation; callers do not need to wrap `EventReport::Send*` calls themselves.

### 2. HiTrace Review

#### Available Trace Macros

bundle_framework uses standard HiTrace macros directly (no adapter layer):
```cpp
#include "hitrace_meter.h"

HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
// or with custom name
HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, "ProcessBundleInstall", nullptr);
```

#### Trace Scoping

**Real example from `base_bundle_installer.cpp:761`**:
```cpp
ErrCode BaseBundleInstaller::UninstallBundle(
    const std::string &bundleName, const std::string &modulePackage, const InstallParam &installParam)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    CheckSystemFreeSizeAndClean();
    // ... uninstall logic ...
}
```

**Best Practice - Use function-scope trace**:
```cpp
// Good: Function-level trace via __PRETTY_FUNCTION__
HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
// entire function is traced; auto-finalized at scope exit
```

For sub-function tracing, use scoped block:
```cpp
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, "ExtractHap", nullptr);
    // ... extract logic ...
}  // trace auto-finalized here
```

#### Trace Naming

**Current naming patterns in bundle_framework**:
- Use `__PRETTY_FUNCTION__` for full function signature (most common)
- Use operation-level name like `"ProcessBundleInstall"`, `"BootScan"` for sub-section tracing
- Use `HITRACE_TAG_APP` tag consistently

**Recommendations**:
- Use descriptive trace names that identify the operation
- Avoid overly generic names like "operation" or "process"
- Keep names concise but meaningful (typically 15-40 characters for `__PRETTY_FUNCTION__`)

#### Performance Impact
- Minimize overhead in trace code
- Avoid complex operations within trace sections
- Use `HITRACE_METER_NAME_EX` (RAII-style) instead of manual Start/Finish pairs

### 3-5. 日志通用规则（HiLog）

> 以下通用规则来自 OpenHarmony 日志规范，已提取至独立文档便于复用，详见 [hilog_general_rules.md](./hilog_general_rules.md)。

| 索引 | 章节 | 描述 |
|------|------|------|
| `[1]` | 日志基础规范 | 日志级别定义、日志内容规则、打印时机规则 |
| `[2]` | HiLog API 使用规范 | Domain ID 管理、日志流量管控、隐私参数标识 `{public}`/`{private}` |
| `[3]` | 常见模式日志打印检查 | 流程类、数据库类、文件类、线程、并发控制、状态机等日志检查项 |

审查时请参照 [hilog_general_rules.md](./hilog_general_rules.md) 中对应 `[1]` `[2]` `[3]` 索引的章节内容。

bundle_framework 使用的日志宏和 Domain：
- 日志宏：`APP_LOGD/I/W/E`、`LOG_D/I/W/E(BMS_TAG_*, ...)`、`APP_LOGI_NOFUNC`/`APP_LOGE_NOFUNC`（不带函数名）
- Domain：`0xD001120`（BMS domain，参考 `app_log_wrapper.h`）
- Tag 常量：`BMS_TAG_INSTALLER`、`BMS_TAG_QUERY`、`BMS_TAG_PERMISSION`、`BMS_TAG_COMMON`、`BMS_TAG_NATIVE` 等

## 业务场景区分最佳实践

### 常见业务场景示例

#### 1. 应用安装场景

**已有的场景区分** (`InstallScene` enum + `BundleEventType::INSTALL`):
```cpp
// ✅ 已有场景区分
InstallScene::NORMAL       // 用户/API 主动安装
InstallScene::BOOT         // 首次开机预装
InstallScene::REBOOT       // 非首次开机扫描重装
InstallScene::CREATE_USER  // 创建新用户预装
InstallScene::REMOVE_USER  // 删除用户清理（虽然主要是卸载）
```

**实现示例** (`base_bundle_installer.cpp` + `bundle_mgr_service.cpp` boot scan 路径):

```cpp
// ❌ 不好的实践 - 无法区分场景
ErrCode BaseBundleInstaller::ProcessBundleInstall(...)
{
    ErrCode result = InnerProcessBundleInstall(...);
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName_;
    // 所有场景都用同一个事件
    EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);
    return result;
}

// ✅ 好的实践 - 区分不同场景
ErrCode BaseBundleInstaller::ProcessBundleInstall(...)
{
    ErrCode result = InnerProcessBundleInstall(...);
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName_;
    eventInfo.errCode = result;
    eventInfo.preBundleScene = installScene_;  // 区分 BOOT/REBOOT/CREATE_USER/NORMAL
    eventInfo.callingUid = IPCSkeleton::GetCallingUid();
    if (result != ERR_OK) {
        EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
    } else {
        EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);
    }
    return result;
}
```

#### 2. 应用更新场景

```cpp
// 建议区分的更新场景：
// - 用户/API 主动更新 (InstallScene::NORMAL)
// - OTA 升级 (InstallScene::REBOOT + otaInstall_=true)
// - 补丁更新 (BundleEventType::QUICK_FIX)
// - 恢复重装 (BundleEventType::RECOVER)

ErrCode BaseBundleInstaller::UpdateBundle(...)
{
    ErrCode result = InnerUpdateBundle(...);
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName_;
    eventInfo.versionCode = versionCode_;
    eventInfo.errCode = result;
    eventInfo.isPatch = isPatch_;          // 是否补丁更新
    eventInfo.isDowngrade = isDowngrade_;  // 是否降级
    eventInfo.preBundleScene = otaInstall_ ? InstallScene::REBOOT : InstallScene::NORMAL;
    if (result != ERR_OK) {
        EventReport::SendSystemEvent(BMSEventType::BUNDLE_UPDATE_EXCEPTION, eventInfo);
    } else {
        EventReport::SendBundleSystemEvent(BundleEventType::UPDATE, eventInfo);
    }
    return result;
}
```

#### 3. 应用卸载场景

```cpp
// 建议区分的卸载场景：
// - 用户主动卸载 (InstallScene::NORMAL)
// - 系统清理 (InstallScene::REMOVE_USER)
// - 异常恢复卸载 (BundleEventType::RECOVER 前的清理)
// - 强制卸载（不可卸载应用的强制清理）

ErrCode BaseBundleInstaller::ProcessBundleUninstall(...)
{
    ErrCode result = InnerProcessBundleUninstall(...);
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName_;
    eventInfo.userId = userId_;
    eventInfo.errCode = result;
    eventInfo.isKeepData = installParam.isKeepData;
    if (result != ERR_OK) {
        EventReport::SendSystemEvent(BMSEventType::BUNDLE_UNINSTALL_EXCEPTION, eventInfo);
    } else {
        EventReport::SendBundleSystemEvent(BundleEventType::UNINSTALL, eventInfo);
    }
    return result;
}
```

#### 4. 开机扫描场景

```cpp
// bundle_mgr_service.cpp boot scan 流程
void BundleMgrService::BootScan()
{
    EventReport::SendScanSysEvent(BMSEventType::BOOT_SCAN_START);
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, "BootScan", nullptr);
    // ... 扫描所有已安装应用 ...
    EventReport::SendScanSysEvent(BMSEventType::BOOT_SCAN_END);
}
```

### 场景信息传递建议

#### 方法 1: 通过 InstallParam 字段传递

`InstallParam` 已经携带 `isPreInstallApp`、`isOTA`、`isCreateUser`、`isFirstBootInstall` 等标志位，使用这些字段推断场景：

```cpp
InstallScene BaseBundleInstaller::InferScene(const InstallParam &installParam)
{
    if (installParam.isFirstBootInstall) {
        return InstallScene::BOOT;
    }
    if (installParam.isOTA) {
        return InstallScene::REBOOT;
    }
    if (installParam.isCreateUser) {
        return InstallScene::CREATE_USER;
    }
    return InstallScene::NORMAL;
}
```

#### 方法 2: 通过 BMSEventType 直接区分故障/行为

`BMSEventType` 区分 FAULT（异常）和 BEHAVIOR（正常）事件，便于统计：
- 故障：`BUNDLE_INSTALL_EXCEPTION`、`BUNDLE_UNINSTALL_EXCEPTION`、`BUNDLE_UPDATE_EXCEPTION`
- 行为：`BUNDLE_INSTALL`、`BUNDLE_UNINSTALL`、`BUNDLE_UPDATE`

### 场景统计和分析

区分业务场景后，可以进行更精细的统计分析：

```
// 示例：分析不同场景的安装成功率
// 场景           | 总次数 | 成功 | 失败 | 成功率 | 平均耗时
// NORMAL install | 10000  | 9900 | 100  | 99.0%  | 800ms
// BOOT install   | 500    | 498  | 2    | 99.6%  | 200ms
// REBOOT install | 800    | 760  | 40   | 95.0%  | 1500ms (OTA 升级耗时长)
// CREATE_USER    | 200    | 195  | 5    | 97.5%  | 500ms

// 这种统计可以帮助发现：
// 1. OTA 升级成功率较低 -> 需要排查 OTA 流程
// 2. NORMAL install 耗时较长 -> 需要优化安装性能
// 3. BOOT install 最稳定 -> 作为基准参考
```

---

## Real Code Examples from bundle_framework Codebase

### Bundle Install with Full DFX Reporting

**Pattern from `base_bundle_installer.cpp`** - A complete real example:
```cpp
ErrCode BaseBundleInstaller::ProcessBundleInstall(
    const std::vector<std::string> &inBundlePaths,
    const InstallParam &installParam, const Constants::AppType appType,
    int32_t &uid, bool isRecover)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);

    // 1. 校验安装参数
    if (!InitDataMgr()) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    // 2. 解析跨应用共享包（HSP）
    SharedBundleInstaller sharedBundleInstaller(installParam, appType);
    ErrCode result = sharedBundleInstaller.ParseFiles();
    CHECK_RESULT(result, "parse cross-app shared bundles failed %{public}d");

    // 3. 实际安装
    result = InnerProcessBundleInstall(inBundlePaths, installParam, appType, uid, isRecover);

    // 4. DFX 事件上报
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName_;
    eventInfo.userId = userId_;
    eventInfo.versionCode = versionCode_;
    eventInfo.errCode = result;
    eventInfo.callingUid = IPCSkeleton::GetCallingUid();
    eventInfo.preBundleScene = InferScene(installParam);
    if (result != ERR_OK) {
        // 失败：故障事件
        EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
    } else {
        // 成功：行为事件
        EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);
    }
    return result;
}
```

**Key DFX Points**:
- ✅ 使用 `HITRACE_METER_NAME_EX` 函数级 trace
- ✅ 成功路径上报行为事件（`BUNDLE_INSTALL`）
- ✅ 失败路径上报故障事件（`BUNDLE_INSTALL_EXCEPTION`）
- ✅ EventInfo 填充完整（bundleName/userId/versionCode/errCode/callingUid/scene）
- ✅ 通过 `preBundleScene` 区分场景
- ⚠️ **可改进**：进一步通过 `failureReason` 描述具体失败原因

### Boot Scan Trace

**Pattern from `bundle_mgr_service.cpp` BootScan**:
```cpp
void BundleMgrService::ScanSystemBundle()
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, "ScanSystemBundle", nullptr);
    EventReport::SendScanSysEvent(BMSEventType::BOOT_SCAN_START);
    // ... 扫描逻辑 ...
    EventReport::SendScanSysEvent(BMSEventType::BOOT_SCAN_END);
}
```

**Key Points**:
- ✅ 使用 `HITRACE_METER_NAME_EX` 包裹扫描过程
- ✅ 上报扫描开始/结束事件
- ✅ Tag 使用 `HITRACE_TAG_APP`

### DB Error Reporting

**Pattern from `bundle_data_mgr.cpp`** - DB operation errors:
```cpp
bool BundleDataMgr::SaveStorageBundleInfo(const InnerBundleInfo &info)
{
    bool ret = dataStorage_->SaveStorageBundleInfo(info);
    if (!ret) {
        EventReport::SendDbErrorEvent(
            "bundle_info_db",
            static_cast<int32_t>(DB_OPERATION_TYPE::INSERT),
            static_cast<int32_t>(ret));
    }
    return ret;
}
```

## HiSysEvent Point Placement Guidelines

### Critical Event Points

#### 1. Bundle Lifecycle Events
**Confidence Level: HIGH** - Core bundle operations that must be tracked for system reliability and debugging.

**Required Events:**
- Bundle install (success/failure) - **HIGH** (`BUNDLE_INSTALL` / `BUNDLE_INSTALL_EXCEPTION`)
- Bundle uninstall (success/failure) - **HIGH** (`BUNDLE_UNINSTALL` / `BUNDLE_UNINSTALL_EXCEPTION`)
- Bundle update (success/failure) - **HIGH** (`BUNDLE_UPDATE` / `BUNDLE_UPDATE_EXCEPTION`)
- Boot scan start/end - **HIGH** (`BOOT_SCAN_START` / `BOOT_SCAN_END`)
- Pre-install recover - **HIGH** (`PRE_BUNDLE_RECOVER` / `PRE_BUNDLE_RECOVER_EXCEPTION`)

**Real Implementation Pattern** (`base_bundle_installer.cpp`):
```cpp
result = InnerProcessBundleInstall(...);
EventInfo eventInfo;
eventInfo.bundleName = bundleName_;
eventInfo.errCode = result;
if (result != ERR_OK) {
    EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
} else {
    EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);
}
```

#### 2. Permission and Security Events
**Confidence Level: HIGH** - Permission and security checks must be monitored.

**Required Events:**
- Permission denied for install/uninstall - **HIGH**
- Code signature verification failure - **HIGH**
- Enterprise bundle policy violation - **HIGH**
- High-risk events (OTA fallback, scan timeout) - **HIGH** (`HIGH_RISK_EVENT`)

**Placement:**
```cpp
// Permission Check Failure
if (!BundlePermissionMgr::CheckInstallPermission(...)) {
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName_;
    eventInfo.errCode = ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED;
    EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
    return ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED;
}

// High Risk Operation
EventReport::SendHighRiskEvent(eventInfo);
EventReport::SendTriggerFallbackEvent(
    HighRiskOperationType::OTA_SCAN_TIMEOUT, bundleName_, userId, paths);
```

#### 3. Data Operation Events
**Confidence Level: MEDIUM** - Data operations are important for data integrity and debugging.

**Required Events:**
- Database operations (read/write failures) - **HIGH** (`DB_ERROR`)
- File operations (HAP copy/extract failures) - **MEDIUM**
- Data corruption detection - **HIGH**
- Storage quota exceeded - **MEDIUM** (`BMS_DISK_SPACE`)

**Placement:**
```cpp
// DB Operation Failure
ErrCode BundleDataMgr::AddInnerBundleInfo(...)
{
    if (!dataStorage_->SaveStorageBundleInfo(info)) {
        EventReport::SendDbErrorEvent("bundle_info_db",
            static_cast<int32_t>(DB_OPERATION_TYPE::INSERT),
            static_cast<int32_t>(ERR_OK));
        return ERR_APPEXECFWK_ADD_BUNDLE_ERROR;
    }
    return ERR_OK;
}

// Disk Space Check
if (freeSize < MIN_INSTALL_SIZE) {
    EventReport::SendDiskSpaceEvent(bundlePath, freeSize,
        static_cast<int32_t>(ControlActionType::INSTALL));
    return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
}
```

#### 4. External Module Interface Call Events
**Confidence Level: MEDIUM** - External interface failures help identify dependency issues.

**Required Events:**
- Installd daemon IPC call failures - **HIGH**
- Ability manager interface call failures - **MEDIUM**
- App control manager interface call failures - **MEDIUM**
- Storage service interface call failures - **MEDIUM**

**Placement:**
```cpp
// Installd Client Call Failure
ErrCode result = InstalldClient::GetInstance()->CreateBundleDir(...);
if (result != ERR_OK) {
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName_;
    eventInfo.errCode = result;
    eventInfo.failureReason = "InstalldClient::CreateBundleDir failed";
    EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
    return result;
}

// Ability Manager Call (kill process on uninstall)
if (!AbilityManagerHelper::UninstallApplicationProcesses(...)) {
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName_;
    eventInfo.errCode = ERR_APPEXECFWK_UNINSTALL_KILLING_APP_ERROR;
    EventReport::SendSystemEvent(BMSEventType::BUNDLE_UNINSTALL_EXCEPTION, eventInfo);
    return ERR_APPEXECFWK_UNINSTALL_KILLING_APP_ERROR;
}
```

**External Interface Call Best Practices:**
- Always check proxy/interface pointer before use
- Report failures with specific interface and method names
- Include error codes from external modules in event messages
- Distinguish between proxy acquisition failures and method call failures
- Use appropriate `BMSEventType` based on operation type

### Event Placement Best Practices

#### 1. Entry and Exit Points
- Place events at function entry for tracking operation start
- Place events at all exit points (success and failure paths)
- Use RAII guards (`HITRACE_METER_NAME_EX`) for trace operations

#### 2. Error Path Coverage
- Every error return should have corresponding event reporting
- Include meaningful error context in event messages
- Use appropriate error codes from `appexecfwk_errors.h`

#### 3. Performance Critical Paths
- Minimize event reporting in hot paths
- Use `CountTrace` for metrics without detailed tracing
- Avoid complex string operations in event reporting

#### 4. Cross-Boundary Operations
- Report events at IPC boundaries (service entry/exit)
- Track async operation start and completion
- Monitor timeout scenarios

### Event Density Guidelines

#### High Priority Events (Always Report)
- Bundle lifecycle changes (install/uninstall/update) - **HIGH**
- Security violations (signature, permission) - **HIGH**
- Data corruption (DB errors) - **HIGH**
- Critical failures (boot scan, OTA) - **HIGH**

#### Medium Priority Events (Report in Normal Flow)
- Cache operations (`BUNDLE_CLEAN_CACHE`) - **MEDIUM**
- App control rule changes (`APP_CONTROL_RULE`) - **MEDIUM**
- Default app changes (`DEFAULT_APP`) - **MEDIUM**

#### Low Priority Events (Report on Failure Only)
- Query operations (`QUERY_BUNDLE_INFO`) - **LOW**
- Cache hits/misses - **LOW**

## HiTrace Point Placement Guidelines

### Critical Trace Points

#### 1. Long-Running Operations
**Confidence Level: HIGH** - Operations that can take significant time.

**Trace Scenarios:**
- Bundle install/uninstall - **HIGH**
- Boot scan - **HIGH**
- OTA upgrade - **HIGH**
- DB migration - **MEDIUM**

**Placement:**
```cpp
ErrCode BaseBundleInstaller::ProcessBundleInstall(...)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    // install logic auto-traced
}
```

#### 2. IPC Call Chains
**Confidence Level: MEDIUM**

**Trace Scenarios:**
- IDL Host method calls - **MEDIUM**
- Installd IPC calls - **HIGH**
- Cross-process bundle queries - **MEDIUM**

#### 3. Critical Path Operations
**Confidence Level: HIGH**

**Trace Scenarios:**
- Boot scan sequence - **HIGH**
- Install signature verification - **HIGH**
- DB write operations - **MEDIUM**

### Trace Placement Best Practices

#### 1. Granularity
- Trace at function level via `__PRETTY_FUNCTION__`
- Use named trace for sub-sections: `HITRACE_METER_NAME_EX(..., "ExtractHap", ...)`
- Avoid nested traces for simple operations

#### 2. Duration Considerations
- Only trace operations that take >1ms in typical cases
- Use `CountTrace` for frequent operations
- Consider compile-time flags for debug traces

#### 3. Resource Tracking
- Trace resource acquisition (locks, file handles)
- Monitor lock contention points
- Track memory allocation in critical paths

#### 4. Time-Sensitive Operations

**Critical Operations Requiring HiTrace:**
- **HAP File Operations**: HAP copy/extract (>50ms expected) - **MEDIUM**
- **DB Operations**: SaveStorageBundleInfo, query (>10ms expected) - **HIGH**
- **Installd IPC**: CreateBundleDir, ExtractModuleFiles (>50ms expected) - **HIGH**
- **Signature Verification**: VerifyCodeSignature (>100ms expected) - **HIGH**
- **Boot Scan**: Full system scan (>1s expected) - **HIGH**
- **AOT Compilation**: AOTHandler::ExecuteAOT (>1s expected) - **HIGH**
- **Lock Operations**: bundleInfoMutex_ holds with IO (>10ms expected) - **MEDIUM**

**Time-Sensitive Trace Examples:**
```cpp
// DB Write Operation
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, "SaveStorageBundleInfo", nullptr);
    if (!dataStorage_->SaveStorageBundleInfo(info)) {
        return ERR_APPEXECFWK_ADD_BUNDLE_ERROR;
    }
}

// Installd IPC Operation
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, "ExtractModuleFiles", nullptr);
    ErrCode result = InstalldClient::GetInstance()->ExtractModuleFiles(...);
    if (result != ERR_OK) {
        return result;
    }
}

// Signature Verification
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, "VerifyCodeSignature", nullptr);
    ErrCode result = InstalldClient::GetInstance()->VerifyCodeSignature(...);
    // ...
}
```

**Performance Thresholds:**
- **Fast Operations** (<1ms): No trace needed typically
- **Normal Operations** (1-10ms): Consider trace for critical paths
- **Slow Operations** (10-50ms): Should trace for performance monitoring
- **Very Slow Operations** (>50ms): Must trace for performance analysis

### Confidence Level Definitions

**HIGH** - **Strongly Recommended**
- **Definition**: Critical operations that must have DFX tracing for system reliability, security, or performance monitoring
- **Characteristics**:
  - Core bundle lifecycle operations (install, uninstall, update)
  - Security-critical operations (signature verification, permission check)
  - High-latency operations (>100ms) that impact user experience
  - Boot scan and OTA upgrade operations
  - Data integrity operations (DB, file system)
- **Action**: Always add DFX traces; missing traces should be considered a code review issue

**MEDIUM** - **Recommended**
- **Definition**: Important operations that benefit from DFX tracing for debugging and monitoring
- **Characteristics**:
  - External interface calls that may fail (InstalldClient, AbilityManagerHelper)
  - Moderate-latency operations (10-100ms)
  - Operations with occasional failures
  - File I/O operations and configuration management
- **Action**: Add DFX traces in most cases; consider based on specific context

**LOW** - **Optional**
- **Definition**: Operations where DFX tracing provides limited value or may impact performance
- **Characteristics**:
  - Very fast operations (<1ms) with minimal performance impact
  - High-frequency query operations
  - Cache operations and internal optimizations
- **Action**: Add DFX traces only if specifically needed

## Common Issues to Check

### 1. Client-Side HiSysEvent Reporting (Architecture Violation)

**🔴 严重问题：客户端代码进行 HiSysEvent 打点**

```cpp
// ❌ 错误：客户端代码直接打点
// 文件: interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_proxy.cpp
ErrCode BundleMgrProxy::GetBundleInfo(...)
{
    ErrCode ret = SendRequest(...);
    if (ret != ERR_OK) {
        EventReport::SendSystemEvent(BMSEventType::QUERY_BUNDLE_INFO, eventInfo);  // ❌ 违反架构规则
    }
    return ret;
}

// ✅ 正确：客户端只调用服务端
ErrCode BundleMgrProxy::GetBundleInfo(...)
{
    return SendRequest(...);  // ✅ 让服务端负责打点
}

// ✅ 正确：服务端进行打点
// 文件: services/bundlemgr/src/bundle_mgr_host_impl.cpp
ErrCode BundleMgrHostImpl::GetBundleInfo(...)
{
    ErrCode ret = dataMgr_->GetBundleInfo(...);
    if (ret != ERR_OK) {
        EventReport::SendSystemEvent(BMSEventType::QUERY_BUNDLE_INFO, eventInfo);  // ✅ 服务端打点
    }
    return ret;
}
```

**检查命令**:
```bash
# 检查客户端是否违规打点
grep -rn "EventReport::\|HiSysEventWrite" \
    interfaces/inner_api/ interfaces/kits/ --include="*.cpp" --include="*.h"
```

### 2. Missing Error Reporting
```cpp
// BAD: No error reporting
if (result != ERR_OK) {
    return result;
}

// GOOD: Proper error reporting
if (result != ERR_OK) {
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName_;
    eventInfo.errCode = result;
    EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
    return result;
}
```

### 3. Sensitive Data Logging
```cpp
// BAD: Logging sensitive data with %{public}
APP_LOGI("install hap path=%{public}s", hapPath.c_str());  // ❌ 文件路径泄露
APP_LOGI("fingerprint=%{public}s", fingerprint.c_str());  // ❌ 签名指纹泄露

// GOOD: Using %{private}
APP_LOGI("install hap path=%{private}s", hapPath.c_str());  // ✅
APP_LOGI("fingerprint=%{private}s", fingerprint.c_str());  // ✅
```

### 4. Missing Trace Scoping
```cpp
// BAD: Function with long operation but no trace
ErrCode BaseBundleInstaller::ProcessBundleInstall(...)
{
    // 长时间操作，但没有 HiTrace span
    InnerProcessBundleInstall(...);
    return ERR_OK;
}

// GOOD: Function-level trace
ErrCode BaseBundleInstaller::ProcessBundleInstall(...)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    InnerProcessBundleInstall(...);
    return ERR_OK;
}
```

### 5. Incorrect Event Placement
```cpp
// BAD: Event placed before validation
ErrCode BaseBundleInstaller::ProcessBundleInstall(...)
{
    EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);  // Too early!

    if (bundlePath.empty()) {
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }
    // ...
}

// GOOD: Event placed after operation result is known
ErrCode BaseBundleInstaller::ProcessBundleInstall(...)
{
    if (bundlePath.empty()) {
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    ErrCode result = InnerProcessBundleInstall(...);
    if (result != ERR_OK) {
        EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
    } else {
        EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);
    }
    return result;
}
```

## Code Quality Checklist

### 基础检查项
- [ ] **架构规则：客户端代码不包含 HiSysEvent 打点**
  - [ ] `interfaces/inner_api/appexecfwk_core/` 目录下无 `EventReport::` 调用
  - [ ] `interfaces/kits/appkit/` 目录下无 `EventReport::` 调用
  - [ ] `interfaces/kits/js/`、`ndk/`、`cj/` 目录下无 `EventReport::` 调用
  - [ ] 客户端代码不包含 `HiSysEventWrite` 直接调用
  - [ ] 所有业务事件都在服务端打点
- [ ] All error paths include appropriate HiSysEvent reporting
- [ ] Success paths have behavior event reporting
- [ ] Sensitive data uses `%{private}` placeholder
- [ ] Trace operations use `HITRACE_METER_NAME_EX` (RAII)
- [ ] Events are placed at appropriate points (after validation, on success/failure)
- [ ] Event names follow conventions (use `BMSEventType::*` / `BundleEventType::*` constants)
- [ ] Error messages are descriptive and include context
- [ ] No performance impact in normal operation paths
- [ ] Trace sections cover critical operations
- [ ] Memory is properly managed in DFX operations
- [ ] Conditional compilation for `HAS_HISYSEVENT_PART` is correct (when using direct HiSysEvent)

### ⚠️ 业务场景区分检查项
- [ ] **事件能区分不同的业务场景**
  - [ ] 通过 `InstallScene` 区分 BOOT/REBOOT/CREATE_USER/NORMAL
  - [ ] 通过 `BundleEventType` 区分 INSTALL/UNINSTALL/UPDATE/RECOVER/QUICK_FIX
  - [ ] 通过 `BMSEventType` 区分故障事件与行为事件

- [ ] **同一操作的不同触发来源有区分**
  - [ ] 用户主动操作 vs 系统自动操作
  - [ ] 普通更新 vs OTA 升级 vs 补丁修复
  - [ ] 正常安装 vs 异常恢复重装

- [ ] **场景信息完整传递**
  - [ ] EventInfo 中 `preBundleScene` 字段填充正确
  - [ ] EventInfo 中 `isPatch`、`isDowngrade`、`isKeepData` 等标志位填充正确
  - [ ] 失败场景包含 `failureReason` 上下文信息

### 审查示例

**场景 1: 安装事件缺少场景区分**
```cpp
// ❌ 问题代码
ErrCode ProcessBundleInstall(...)
{
    // 无法区分是用户主动安装还是 OTA 升级
    EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);
    return ERR_OK;
}

// ✅ 改进代码
ErrCode ProcessBundleInstall(...)
{
    eventInfo.preBundleScene = InferScene(installParam);  // 区分 BOOT/REBOOT/NORMAL
    EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);
    return ERR_OK;
}
```

**场景 2: 数据库错误未上报**
```cpp
// ❌ 问题代码
bool SaveStorageBundleInfo(...)
{
    if (!dataStorage_->SaveStorageBundleInfo(info)) {
        return false;  // 数据库失败但不上报
    }
    return true;
}

// ✅ 改进代码
bool SaveStorageBundleInfo(...)
{
    if (!dataStorage_->SaveStorageBundleInfo(info)) {
        EventReport::SendDbErrorEvent("bundle_info_db",
            static_cast<int32_t>(DB_OPERATION_TYPE::INSERT), -1);
        return false;
    }
    return true;
}
```

## Automated DFX Checks

### Check Script for Missing Error Reporting

Save as `scripts/check_dfx_events.sh`:
```bash
#!/bin/bash
# Check for missing HiSysEvent error reporting in bundle_framework error paths

echo "Checking for missing HiSysEvent error reporting..."
echo ""

# Find error returns without DFX reporting
grep -rn "return.*ERR_APPEXECFWK_\|return.*ERR_BUNDLE_MANAGER_" --include="*.cpp" services/bundlemgr/src/ | \
    grep -v "EventReport::" | \
    grep -v "APP_LOG" | \
    grep -v "LOG_E\|LOG_W" | \
    grep -v "//" | \
    head -20

echo ""
echo "Checking for unpaired HITRACE meter usage..."
echo ""

# Check that HITRACE_METER_NAME_EX is at function scope (RAII), not paired manually
grep -rn "StartTrace\|FinishTrace" --include="*.cpp" services/bundlemgr/src/ | head -10
# bundle_framework 应该使用 HITRACE_METER_NAME_EX 而非 StartTrace/FinishTrace 对
```

### Check Sensitive Data Logging

```bash
#!/bin/bash
# Check for potential sensitive data logging in bundle_framework

echo "Checking for sensitive data in logs..."
echo ""

# Check for fingerprint/code path logging with %{public}
grep -rn "fingerprint\|hapPath\|codePath\|appIdentifier" --include="*.cpp" services/bundlemgr/src/ | \
    grep "APP_LOG\|LOG_" | \
    grep "%{public}" | \
    head -10

echo ""
echo "Checking for HiSysEvent direct calls in client directories..."
echo ""

grep -rn "HiSysEventWrite\|EventReport::" \
    interfaces/inner_api/ interfaces/kits/ --include="*.cpp" --include="*.h" 2>/dev/null | head -10
```

## Testing Recommendations

1. **Unit Tests**: Test EventReport with various EventInfo payloads
2. **Integration Tests**: Verify event reporting in real install/uninstall operations
3. **Performance Tests**: Ensure minimal overhead from DFX operations
4. **Privacy Tests**: Verify no sensitive data is logged with `%{public}`
5. **Event Coverage Tests**: Verify all critical events are reported

### Test Event Reporting

```bash
# Trigger bundle install and check HiSysEvent
# 1. Install an application
hdc shell bm install -p /path/to/hap

# 2. Check HiSysEvent output
hdc shell hidumper -s HiSysEventProcessor -a -e

# 3. Filter for bundle events
hdc shell hidumper -s HiSysEventProcessor -a -e | grep -E "BUNDLEMANAGER|BUNDLE_INSTALL"
```

### Test HiTrace

```bash
# 1. Enable HiTrace with APP tag
hdc shell hitrace start --record --tags app

# 2. Trigger operations (install/uninstall bundle)

# 3. Stop and dump trace
hdc shell hitrace stop -o /data/local/tmp/trace.ftrace
hdc file recv /data/local/tmp/trace.ftrace ./
```

## Quick Reference

### 架构规则：客户端 vs 服务端

**HiSysEvent 打点位置规则**：

| 代码位置 | 允许打点 | 说明 |
|----------|----------|------|
| `services/bundlemgr/src/` | ✅ 是 | 服务端实现 |
| `services/bundlemgr/include/` | ✅ 是 | 服务端接口 |
| `services/bundlemgr/src/event_report.cpp` | ✅ 是 | DFX 实现本身 |
| `interfaces/inner_api/appexecfwk_core/` | ❌ 否 | Inner API 客户端 |
| `interfaces/kits/appkit/` | ❌ 否 | 应用侧 Kit |
| `interfaces/kits/js/`、`ndk/`、`cj/` | ❌ 否 | JS/NDK/CJ 接口 |

**记住**: 所有业务操作的事件必须在服务端打点，客户端只负责调用服务端。

### 业务场景快速参考

**InstallScene 枚举**：

| Scene | 使用场景 |
|-------|---------|
| `NORMAL` | 用户/API 主动安装、卸载、更新 |
| `BOOT` | 首次开机扫描预装 |
| `REBOOT` | 非首次开机扫描（OTA 后） |
| `CREATE_USER` | 创建新用户时预装 |
| `REMOVE_USER` | 删除用户时清理 |

**BundleEventType 枚举**：

| Type | 使用场景 |
|------|---------|
| `INSTALL` | 首次安装 |
| `UNINSTALL` | 卸载 |
| `UPDATE` | 更新 |
| `RECOVER` | 异常恢复后重装 |
| `QUICK_FIX` | 补丁修复 |

**BMSEventType 故障/行为对应**：

| 故障事件 | 行为事件 | 场景 |
|---------|---------|------|
| `BUNDLE_INSTALL_EXCEPTION` | `BUNDLE_INSTALL` | 安装 |
| `BUNDLE_UNINSTALL_EXCEPTION` | `BUNDLE_UNINSTALL` | 卸载 |
| `BUNDLE_UPDATE_EXCEPTION` | `BUNDLE_UPDATE` | 更新 |
| `PRE_BUNDLE_RECOVER_EXCEPTION` | `PRE_BUNDLE_RECOVER` | 预装恢复 |
| `BUNDLE_STATE_CHANGE_EXCEPTION` | `BUNDLE_STATE_CHANGE` | 状态变更（enable/disable） |
| `BUNDLE_CLEAN_CACHE_EXCEPTION` | `BUNDLE_CLEAN_CACHE` | 清理缓存 |
| - | `BOOT_SCAN_START` / `BOOT_SCAN_END` | 开机扫描 |

### EventReport API Summary

| Function | Usage | Header |
|----------|-------|--------|
| `SendBundleSystemEvent(BundleEventType, EventInfo)` | Bundle lifecycle behavior events | `event_report.h` |
| `SendScanSysEvent(BMSEventType)` | Boot scan events | `event_report.h` |
| `SendSystemEvent(BMSEventType, EventInfo)` | Generic fault/behavior events | `event_report.h` |
| `SendUserSysEvent(UserEventType, userId)` | User create/remove events | `event_report.h` |
| `SendCleanCacheSysEvent(...)` | Cache clean events | `event_report.h` |
| `SendDiskSpaceEvent(fileName, freeSize, opType)` | Disk space insufficient events | `event_report.h` |
| `SendDbErrorEvent(dbName, opType, errCode)` | DB operation failure events | `event_report.h` |
| `SendHighRiskEvent(EventInfo)` | High risk events | `event_report.h` |
| `SendTriggerFallbackEvent(op, bundleName, userId, paths)` | Trigger fallback events | `event_report.h` |

### HiTrace Macros Summary

| Macro | Purpose |
|-------|---------|
| `HITRACE_METER_NAME_EX(level, tag, name, customCategory)` | Scoped trace span (RAII) |
| `HITRACE_METER(level, name)` | Simpler scoped trace |
| `CountTrace(tag, name, count)` | Record metric count |

**Note**: bundle_framework should use `HITRACE_METER_NAME_EX` consistently, not manual `StartTrace`/`FinishTrace` pairs.

### Constants for Operation Names

**InstallScene** (`event_report.h`): NORMAL, BOOT, REBOOT, CREATE_USER, REMOVE_USER
**BundleEventType** (`event_report.h`): INSTALL, UNINSTALL, UPDATE, RECOVER, QUICK_FIX
**BMSEventType** (`event_report.h`): see enum above for full list

## References

**Source Files**:
- `services/bundlemgr/include/event_report.h` - EventReport class definition
- `services/bundlemgr/include/inner_event_report.h` - InnerEventReport helpers
- `services/bundlemgr/src/event_report.cpp` - EventReport implementation
- `services/bundlemgr/src/base_bundle_installer.cpp` - Real install DFX examples
- `services/bundlemgr/src/bundle_mgr_service.cpp` - Real boot scan DFX examples
- `services/bundlemgr/src/bundle_data_mgr.cpp` - Real DB error DFX examples
- `hisysevent.yaml` - Event domain/names/params definition

**External Documentation**:
- [OpenHarmony HiSysEvent Documentation](https://docs.openharmony.cn/)
- [OpenHarmony HiTrace Documentation](https://docs.openharmony.cn/)

## Review Workflow

When reviewing DFX-related changes:

1. **Identify DFX Components**: Which EventReport API is being called? Is the location correct (server vs client)?
2. **Check Error Reporting**: Are all error cases properly reported?
3. **Verify Success Events**: Are success paths properly reported (behavior events)?
4. **Check Event Placement**: Are events at appropriate points (after validation, after operation)?
5. **Verify Data Privacy**: Is sensitive data (paths, fingerprints) using `%{private}`?
6. **Review Performance Impact**: Will this affect normal operations?
7. **Check Trace Coverage**: Are critical operations traced?
8. **Validate Naming**: Do event types follow conventions (`BMSEventType::*` / `BundleEventType::*`)?
9. **Test Coverage**: Are there tests for the DFX changes?
10. **Conditional Compilation**: Does code work with/without `HAS_HISYSEVENT_PART`?

## Success Criteria

A DFX change is considered good when:
- ✅ All error paths have appropriate HiSysEvent reporting
- ✅ Success paths have behavior event reporting
- ✅ No sensitive data is exposed in logs (`%{private}` for paths/fingerprints)
- ✅ Trace operations use `HITRACE_METER_NAME_EX` (RAII)
- ✅ Events are placed at appropriate points
- ✅ Code compiles in all configurations
- ✅ Performance impact is minimal
- ✅ Naming conventions are followed (uses `BMSEventType::*` / `BundleEventType::*`)
- ✅ Tests cover the DFX functionality
- ✅ Client directories do NOT contain `EventReport::` calls

## Common Issues and Solutions

### Issue 1: HiSysEvent Not Appearing in Logs

**Symptoms**: Events are not showing up in `hidumper` output.

**Possible Causes**:
1. `HAS_HISYSEVENT_PART` is not defined
2. HiSysEvent service is not running
3. Event filter is too restrictive

**Debug Steps**:
```bash
# Check if HiSysEvent service is running
hdc shell ps -A | grep hisysevent

# Check all events (not filtered)
hdc shell hidumper -s HiSysEventProcessor -a -e

# Check compilation flag
grep -r "HAS_HISYSEVENT_PART" services/bundlemgr/
```

**Solution**:
- Ensure conditional compilation is correct
- Check event domain (`BUNDLEMANAGER_UE`) and name match expected format
- Verify event parameters are valid

### Issue 2: HiTrace Data Incomplete

**Symptoms**: Trace spans are missing or incomplete.

**Possible Causes**:
1. Trace tag `HITRACE_TAG_APP` not enabled
2. Trace buffer overflow

**Debug Steps**:
```bash
# Enable HiTrace with app tag
hdc shell hitrace start --record --tags app

# Check trace buffer
hdc shell hitrace list --buffer-size
```

**Solution**:
- Use `HITRACE_METER_NAME_EX` (RAII) for automatic scope management
- Ensure trace tag is enabled when capturing

### Issue 3: Sensitive Data Leaked in Logs

**Symptoms**: HAP paths, fingerprints, or app identifiers appear in logs.

**Solution**:
```cpp
// BAD
APP_LOGI("hap path=%{public}s", hapPath.c_str());

// GOOD
APP_LOGI("hap path=%{private}s", hapPath.c_str());
```

### Issue 4: Performance Impact from DFX

**Symptoms**: Operations are slower with DFX enabled.

**Solutions**:
- Move HiSysEvent calls off critical path
- Use `CountTrace` for frequent operations
- Consider batch event reporting
- Reuse `EventInfo` via `Reset()` instead of constructing new instance

## Tips and Best Practices

### 1. Event Placement Strategy

**When to add HiSysEvent**:
- ✅ At IDL host entry points (IPC boundaries)
- ✅ Before/after external module calls (InstalldClient, AbilityManagerHelper)
- ✅ On validation failures (signature, permission)
- ✅ On resource acquisition failures
- ✅ On state changes (install/uninstall/update success/failure)

**When to skip HiSysEvent**:
- ❌ In tight loops
- ❌ For trivial getters
- ❌ In performance-critical paths (>1000 calls/sec, e.g., GetBundleInfo query)

### 2. Trace Granularity

**Good trace granularity**:
```cpp
// Too fine (not recommended)
HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, "GetBundleMutex", nullptr);
auto &mtx = dataMgr_->GetBundleMutex(bundleName);
std::lock_guard lock {mtx};  // trace ends here, too short

// Better (recommended)
HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
auto &mtx = dataMgr_->GetBundleMutex(bundleName);
std::lock_guard lock {mtx};
ProcessBundle();  // entire function traced
```

### 3. Error Message Best Practices

**Good error messages** include:
- What operation failed
- Why it failed (error context)
- Relevant IDs (bundleName, userId)
- Suggested action (if applicable)

```cpp
// Good
EventInfo eventInfo;
eventInfo.bundleName = bundleName_;
eventInfo.errCode = result;
eventInfo.failureReason = "InstalldClient::ExtractModuleFiles failed: insufficient disk space";
EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);

// Less helpful
eventInfo.failureReason = "Failed";
```

### 4. Testing DFX Functionality

**Unit test example**:
```cpp
TEST(EventReportTest, TestInstallExceptionReporting)
{
    // Mock HiSysEvent adapter
    // Expect event to be reported
    EventInfo eventInfo;
    eventInfo.bundleName = "com.example.test";
    eventInfo.errCode = ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
    // Verify via mock that HiSysEventWrite was called with expected params
}
```

## Quick Decision Tree

```
Need to add DFX to code?
│
├─ Is this in interfaces/inner_api/ or interfaces/kits/?
│  └─ YES → STOP. Client code must NOT call EventReport::.
│           Return error to caller; server will report.
│
├─ Is this an error path in services/bundlemgr/?
│  └─ YES → Add HiSysEvent fault event
│           Use EventReport::SendSystemEvent(BMSEventType::*_EXCEPTION, eventInfo)
│
├─ Is this a success path for bundle lifecycle operation?
│  └─ YES → Add HiSysEvent behavior event
│           Use EventReport::SendBundleSystemEvent(BundleEventType::*, eventInfo)
│
├─ Is this a long-running operation (>10ms)?
│  └─ YES → Add HiTrace span
│           Use HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, name, nullptr)
│
├─ Does this handle sensitive data (paths, fingerprints)?
│  └─ YES → Use %{private} placeholder in APP_LOG*
│
└─ Is this in a hot path (>1000/sec, e.g., query API)?
   └─ YES → Skip HiTrace for query; only report on failure
            Minimize HiSysEvent overhead
```

## Summary of Changes in This Version

**Adapted from os_account version to bundle_framework version**:
- ✅ Replaced `account_hisysevent_adapter` references with `EventReport` class
- ✅ Updated file paths from `services/accountmgr/` to `services/bundlemgr/`
- ✅ Replaced `REPORT_*_FAIL` macros with `EventReport::Send*` methods
- ✅ Replaced `OsAccount`/`Domain Account`/`App Account` scenarios with `BundleEventType`/`InstallScene`/`BMSEventType`
- ✅ Updated directory rules (`frameworks/` → `interfaces/inner_api/` + `interfaces/kits/`)
- ✅ Real code examples from `base_bundle_installer.cpp` and `bundle_mgr_service.cpp`
- ✅ Updated automated check scripts for bundle_framework paths
- ✅ Updated test commands for bundle operations (`bm install` instead of account operations)
- ✅ Updated troubleshooting guide for bundle_framework DFX issues

**🆕 Business Scenario Differentiation**:
- ✅ Complete scenario naming conventions via `InstallScene` + `BundleEventType` + `BMSEventType`
- ✅ Scenario examples for install/update/uninstall/boot scan
- ✅ Detailed code examples showing how to differentiate scenarios
- ✅ Extended quality checklist including scenario differentiation
- ✅ Quick reference tables for event types

---

## 🎯 业务场景区分的重要性

### 为什么必须区分业务场景？

**1. 精准的问题定位**
```
问题：应用安装失败率突然上升
没有场景区分：
  - "BUNDLE_INSTALL 失败 100 次" -> 无法定位问题

有场景区分：
  - "NORMAL install 失败 95 次" -> 用户/API 主动安装问题
  - "BOOT install 失败 5 次" -> 开机扫描问题
```

**2. 性能优化针对性**
```
性能优化：应用安装耗时过长
没有场景区分：
  - "install 平均耗时 500ms" -> 不知道优化哪里

有场景区分：
  - "NORMAL install 平均耗时 800ms" -> 需要优化主动安装性能
  - "BOOT install 平均耗时 200ms" -> 正常
  - "REBOOT install 平均耗时 1500ms" -> OTA 升级耗时长，可以接受
```

**3. 用户体验监控**
```
用户投诉：安装应用太慢
没有场景区分：
  - 无法区分是用户主动安装还是 OTA 升级

有场景区分：
  - "用户主动安装平均耗时 800ms" -> 可以接受
  - "OTA 升级平均耗时 1500ms" -> 后台进行，可以接受
  - "创建新用户预装平均耗时 2000ms" -> 需要优化
```

**4. 安全审计要求**
```
安全审计：谁安装了应用？
没有场景区分：
  - "BUNDLE_INSTALL 被调用 1000 次" -> 无法审计

有场景区分：
  - "NORMAL install 被调用 800 次" -> 用户/API 操作
  - "BOOT install 被调用 150 次" -> 开机扫描
  - "CREATE_USER install 被调用 50 次" -> 创建新用户
```

### 场景区分的最佳实践总结

**DO ✅**:
1. 通过 `InstallScene` 区分 BOOT/REBOOT/CREATE_USER/NORMAL/REMOVE_USER
2. 通过 `BundleEventType` 区分 INSTALL/UNINSTALL/UPDATE/RECOVER/QUICK_FIX
3. 通过 `BMSEventType` 区分故障事件（`*_EXCEPTION`）与行为事件
4. EventInfo 中填充 `preBundleScene`、`isPatch`、`isDowngrade`、`isKeepData` 等上下文字段
5. 失败事件填充 `failureReason` 描述具体原因
6. 定期分析不同场景的性能和失败率

**DON'T ❌**:
1. 不要让不同场景使用相同的事件类型而无场景字段
2. 不要在事后推断场景（应该在调用时通过 InstallParam 明确）
3. 不要使用过于宽泛的事件类型
4. 不要忽略 EventInfo 中的上下文字段
5. 不要混淆 BundleEventType 和 BMSEventType（前者是操作类型，后者是事件类型）

### 快速自查

在添加新的 HiSysEvent 打点时，问自己：

1. **Q**: 这个操作可能在哪些场景下被调用？
   **A**: 列出所有可能的场景（NORMAL/BOOT/REBOOT/CREATE_USER/REMOVE_USER）

2. **Q**: 这些场景是否需要在事件中区分？
   **A**: 如果场景的性能特征、失败率、安全性要求不同，则需要区分

3. **Q**: 我使用的 EventInfo 字段是否包含场景信息？
   **A**: 检查 `preBundleScene`、`isPatch`、`isDowngrade`、`isKeepData` 是否填充

4. **Q**: 场景信息是否正确传递到 HiSysEvent？
   **A**: 确保 EventInfo 中字段没有被丢弃或混淆

5. **Q**: 是否使用了正确的 BMSEventType？
   **A**: 故障用 `*_EXCEPTION`，正常行为用 `BUNDLE_*`

---

**文档版本**: v2.1
**最后更新**: 2026-06-22
**更新内容**:
- v2.1 (2026-06-22): 改造为 bundle_framework 专用版本，从 os_account 适配而来
- v2.0 (2026-03-23): 添加业务场景区分指南和最佳实践（os_account 版本）
