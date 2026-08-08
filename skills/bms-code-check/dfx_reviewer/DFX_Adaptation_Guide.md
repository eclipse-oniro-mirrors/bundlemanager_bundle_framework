# DFX Skill 适配指南

**目标**: 将 DFX Review Skill 从一个特定代码仓版本转换为另一个特定代码仓版本（本指南最初用于把 os_account 版本转换为通用版本，现用作把通用版本适配到任意代码仓的指引；当前 SKILL.md 已适配为 bundle_framework 专用）

---

## 📋 适配步骤概览

| 步骤 | 任务 | 预计时间 | 难度 |
|------|------|----------|------|
| 1 | 确定代码仓结构 | 10 分钟 | ⭐ 简单 |
| 2 | 定义操作类型常量 | 15 分钟 | ⭐⭐ 中等 |
| 3 | 更新文件路径引用 | 10 分钟 | ⭐ 简单 |
| 4 | 替换示例代码 | 30 分钟 | ⭐⭐⭐ 复杂 |
| 5 | 添加特定规则 | 20 分钟 | ⭐⭐ 中等 |
| 6 | 验证和测试 | 15 分钟 | ⭐⭐ 中等 |

**总计**: 约 1.5-2 小时

---

## Step 1: 确定代码仓结构

### 1.1 识别服务端目录

服务端目录是**允许**进行 HiSysEvent 打点的地方。

**示例配置**:

```yaml
# 你的代码仓的服务端目录
server_dirs:
  - "services/{module_name}/src"           # 主要服务实现
  - "services/{module_name}/include"        # 服务头文件
  - "foundation/{module_name}/"             # 基础服务
  - "sa_profile/{module_name}/"              # System Ability

# 示例（网络模块）:
# - "services/network/src"
# - "services/netmanager/src"
# - "foundation/communication/"
```

**如何识别**:
- 包含 `*service.cpp`, `*manager.cpp` 的目录
- 包含 `*sa_profile/` 的目录
- 实现 System Ability 的目录

### 1.2 识别客户端目录

客户端目录是**禁止**进行 HiSysEvent 打点的地方。

```yaml
# 你的代码仓的客户端目录
client_dirs:
  - "frameworks/{module_name}/"             # 框架层
  - "interfaces/kits/{module_name}/"        # 公共 SDK
  - "interfaces/innerkits/{module_name}/"   # 内部 SDK
  - "sdk/{module_name}/"                    # SDK 目录
  - "napi/{module_name}/"                   # NAPI 接口

# 示例（网络模块）:
# - "frameworks/netmanager/"
# - "interfaces/kits/net/"
# - "sdk/network/"
```

**如何识别**:
- 包含 `*client.cpp`, `*proxy.cpp` 的目录
- 包含 `kits/`, `sdk/` 的目录
- NAPI/JS 接口目录

### 1.3 识别 DFX 目录

```yaml
# DFX 适配器目录
dfx_dirs:
  - "dfx/hisysevent_adapter/"
  - "dfx/hitrace_adapter/"
```

---

## Step 2: 定义操作类型常量

### 2.1 确定你的核心操作

**模板**:

```cpp
namespace Constants {
    // 核心操作（根据你的模块替换）
    const char {MODULE}_OPT_CREATE[] = "create";           // 创建
    const char {MODULE}_OPT_DELETE[] = "delete";           // 删除
    const char {MODULE}_OPT_UPDATE[] = "update";           // 更新
    const char {MODULE}_OPT_QUERY[] = "query";             // 查询

    // 特定操作（添加你的特定操作）
    const char {MODULE}_OPT_CONNECT[] = "connect";         // 连接
    const char {MODULE}_OPT_DISCONNECT[] = "disconnect";   // 断开
    const char {MODULE}_OPT_SEND[] = "send";               // 发送
    const char {MODULE}_OPT_RECEIVE[] = "receive";         // 接收
}
```

**示例映射**:

| 你的模块 | 操作名称 | 示例常量/枚举 |
|----------|----------|----------|
| **Bundle Framework** | Install bundle | `BundleEventType::INSTALL`、`InstallScene::BOOT` |
| **Network Stack** | Connect to network | `NETWORK_OPT_CONNECT[] = "connect"` |
| **Storage Manager** | Write file | `STORAGE_OPT_WRITE[] = "write"` |
| **Database Manager** | Execute query | `DATABASE_OPT_QUERY[] = "query"` |

### 2.2 确定业务场景

```cpp
// 场景前缀（通用）
const char SCENARIO_BOOT[] = "boot_";           // 系统启动
const char SCENARIO_SETTINGS[] = "settings_";   // 设置界面
const char SCENARIO_API[] = "api_";             // API 调用
const char SCENARIO_MDM[] = "mdm_";             // 设备管理
const char SCENARIO_RECOVERY[] = "recovery_";   // 恢复模式

// 场景后缀（通用）
const char SUFFIX_LOCAL[] = "_local";           // 本地操作
const char SUFFIX_NETWORK[] = "_network";       // 网络操作
const char SUFFIX_OFFLINE[] = "_offline";       // 离线操作
const char SUFFIX_AUTO[] = "_auto";             // 自动操作
const char SUFFIX_MANUAL[] = "_manual";         // 手动操作
```

**组合使用**: `{SCENARIO_PREFIX}{OPERATION_NAME}{SUFFIX}`

**示例**:
- `boot_create` - 启动时创建
- `settings_create_manual` - 设置中手动创建
- `api_connect_network` - API 网络连接

---

## Step 3: 更新文件路径引用

### 3.1 在文档中替换路径

**查找并替换**:

```bash
# 在你的 DFX skill 文档中
# 替换这些占位符：

# 当前 bundle_framework 特定（已在 SKILL.md 中完成）
# "services/bundlemgr/" → "services/your_module/"
# "interfaces/inner_api/appexecfwk_core/" → "interfaces/inner_api/your_module/"
# "interfaces/kits/appkit/" → "interfaces/kits/your_module/"

# 通用化
{MODULE_NAME} → 你的模块名
{OPERATION_NAME} → 你的操作名
```

**替换脚本**:

```bash
#!/bin/bash
# adapt_paths.sh

MODULE_NAME="your_module"  # 替换为你的模块名

sed -i "s/services\/bundlemgr\//services\/${MODULE_NAME}\//g" dfx_reviewer.md
sed -i "s/interfaces\/inner_api\/appexecfwk_core\//interfaces\/inner_api\/${MODULE_NAME}\//g" dfx_reviewer.md
sed -i "s/EventReport::/YourEventReport::/g" dfx_reviewer.md
```

---

## Step 4: 替换示例代码

### 4.1 更新宏定义

**当前版本** (Bundle Framework):

```cpp
// EventReport 静态 API（services/bundlemgr/include/event_report.h）
EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);
```

**你的版本** (模板):

```cpp
YourEventReport::SendSystemEvent(YourEventType::OPERATION_EXCEPTION, eventInfo);
YourEventReport::SendBehaviorEvent(YourOperationType::CREATE, eventInfo);
```

**示例** (Network Manager):

```cpp
#define REPORT_NETWORK_FAIL(id, operationStr, errCode, errMsg) \
    ReportNetworkOperationFail(id, operationStr, errCode, errMsg)
```

### 4.2 更新函数示例

**当前版本** (Bundle Framework):

```cpp
ErrCode BaseBundleInstaller::ProcessBundleInstall(...)
{
    ErrCode result = InnerProcessBundleInstall(...);
    EventInfo eventInfo;
    eventInfo.bundleName = bundleName_;
    eventInfo.errCode = result;
    if (result != ERR_OK) {
        EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
        return result;
    }
    EventReport::SendBundleSystemEvent(BundleEventType::INSTALL, eventInfo);
    return ERR_OK;
}
```

**你的版本** (Network Manager 示例):

```cpp
ErrCode NetworkManagerService::Connect(const std::string &networkId)
{
    ErrCode ret = innerManager_->Connect(networkId);
    if (ret != ERR_OK) {
        REPORT_NETWORK_FAIL(id, NETWORK_OPT_CONNECT, ret, "Connection failed");
        return ret;
    }
    ReportNetworkLifeCycle(id, NETWORK_OPT_CONNECT);
    return ERR_OK;
}
```

### 4.3 更新真实代码路径

在文档的"真实代码示例"部分，替换为你的代码：

**查找模式**:
```bash
# 当前（Bundle Framework）
services/bundlemgr/src/base_bundle_installer.cpp
services/bundlemgr/src/bundle_mgr_service.cpp

# 你的（Network Manager）
services/networkmgr/src/network_manager_service.cpp
```

---

## Step 5: 添加特定规则

### 5.1 模块特定的 DFX 点

**模板**:

```markdown
### Critical DFX Points for {MODULE_NAME}

#### 1. {Operation_1} Events
**Confidence Level**: HIGH

**Required Events**:
- {Operation_1} (success/failure) - HIGH
- {Operation_2} (success/failure) - MEDIUM

**Placement**:
```cpp
ErrCode {Module}Manager::{Operation}(...)
{
    StartTraceAdapter("{Module}_{Operation}");
    auto traceGuard = MakeScopeGuard([]() { FinishTraceAdapter(); });

    ErrCode ret = {Operation}Internal(...);
    if (ret != ERR_OK) {
        REPORT_{MODULE}_FAIL(id, {MODULE}_OPT_{OPERATION}, ret, "Failed");
        return ret;
    }

    Report{Module}LifeCycle(id, {MODULE}_OPT_{OPERATION});
    return ERR_OK;
}
```
```

### 5.2 特殊注意事项

**模板**:

```markdown
### Special Considerations for {MODULE_NAME}

**Unique Challenges**:
1. {Challenge_1}: Description and handling
2. {Challenge_2}: Description and handling

**Recommended Approach**:
- {Approach_1}
- {Approach_2}
```

**示例** (Network Manager):

```markdown
### Special Considerations for Network Manager

**Unique Challenges**:
1. **Asynchronous Operations**: Network operations are async
   - Use separate events for request and completion
   - Track timeout scenarios separately

2. **Multiple Network Types**: WiFi, Cellular, Ethernet
   - Add network type as event parameter
   - Distinguish in event names (connect_wifi, connect_cellular)

3. **State Transitions**: Connecting → Connected → Disconnecting
   - Report each state transition
   - Track time in each state
```

---

## Step 6: 验证和测试

### 6.1 自动化检查

**运行检查脚本**:

```bash
# 1. 客户端打点检查
./.refdocs/scripts/check_client_hisysevent.sh

# 2. DFX 覆盖率检查
./.refdocs/scripts/check_dfx_coverage.sh

# 3. 敏感数据检查
./.refdocs/scripts/check_sensitive_data.sh
```

### 6.2 手动验证

**检查清单**:

- [ ] 所有示例代码可以在你的代码库中找到对应文件
- [ ] 所有操作常量在你的 `constants.h` 中已定义
- [ ] 所有文件路径指向实际存在的位置
- [ ] 检查脚本能正确识别违规
- [ ] 团队成员能够理解文档中的所有规则

### 6.3 团队评审

**评审流程**:

1. **技术评审**: 与架构师评审架构规则
2. **准确性评审**: 与模块 owner 验证示例代码
3. **可用性评审**: 与团队成员评审理解难度
4. **迭代**: 根据反馈更新文档

---

## 快速适配模板

### 配置文件模板

创建 `dfx_skill_config.yaml`:

```yaml
# DFX Skill 配置文件

codebase:
  name: "Your Module Name"
  abbreviation: "YOUR_MODULE"  # 用于宏命名，如 REPORT_YOUR_MODULE_FAIL

  directories:
    server:
      - "services/your_module/src"
      - "foundation/your_module/"
    client:
      - "frameworks/your_module/"
      - "interfaces/kits/your_module/"
      - "sdk/your_module/"
    dfx:
      - "dfx/hisysevent_adapter/"
      - "dfx/hitrace_adapter/"

  operations:
    # 核心操作
    - name: "create"
      constant: "YOUR_MODULE_OPT_CREATE"
      scenarios: ["boot", "settings", "api", "mdm"]

    - name: "delete"
      constant: "YOUR_MODULE_OPT_DELETE"
      scenarios: ["settings", "api", "mdm"]

    - name: "update"
      constant: "YOUR_MODULE_OPT_UPDATE"
      scenarios: ["settings", "api"]

    # 添加你的操作...

  sensitive_data:
    # 需要匿名化的数据
    - "user_name"
    - "user_id"
    - "auth_token"
    - "credential"

  performance_thresholds:
    # 性敏感操作阈值（毫秒）
    database: 10
    file_io: 50
    network: 100
    ipc: 5
```

### 使用配置文件生成文档

```bash
#!/bin/bash
# generate_dfx_skill.sh

# 读取配置
MODULE_NAME=$(yq '.codebase.name' dfx_skill_config.yaml)
ABBREV=$(yq '.codebase.abbreviation' dfx_skill_config.yaml)

# 复制通用模板
cp dfx_reviewer_universal.md dfx_reviewer.md

# 替换占位符
sed -i "s/{MODULE_NAME}/$MODULE_NAME/g" dfx_reviewer.md
sed -i "s/{MODULE}/$ABBREV/g" dfx_reviewer.md

echo "DFX skill generated for $MODULE_NAME"
```

---

## 常见适配场景

### 场景 1: 网络模块

**配置**:
```yaml
codebase:
  name: "Network Manager"
  abbreviation: "NETWORK"

operations:
  - name: "connect"
  - name: "disconnect"
  - name: "send"
  - name: "receive"

performance_thresholds:
  network: 100    # 网络操作 >100ms 需要追踪
  ipc: 5          # IPC 调用阈值
```

### 场景 2: 存储模块

**配置**:
```yaml
codebase:
  name: "Storage Manager"
  abbreviation: "STORAGE"

operations:
  - name: "read"
  - name: "write"
  - name: "delete"
  - name: "format"

performance_thresholds:
  file_io: 50     # 文件操作 >50ms 需要追踪
  database: 10    # 数据库操作 >10ms 需要追踪
```

### 场景 3: 数据库模块

**配置**:
```yaml
codebase:
  name: "Database Manager"
  abbreviation: "DATABASE"

operations:
  - name: "query"
  - name: "insert"
  - name: "update"
  - name: "delete"

performance_thresholds:
  database: 10    # 所有 DB 操作 >10ms 需要追踪
  transaction: 50 # 事务操作 >50ms 需要追踪
```

---

## 验证清单

适配完成后，检查以下项目：

### 文档完整性
- [ ] 所有 `{PLACEHOLDER}` 已替换
- [ ] 所有文件路径指向实际位置
- [ ] 所有代码示例可以找到对应实现
- [ ] 操作常量列表完整

### 规则适用性
- [ ] 架构规则适用于你的代码仓
- [ ] 客户端/服务端区分准确
- [ ] 操作类型覆盖你的主要功能
- [ ] 性能阈值符合你的需求

### 工具可用性
- [ ] 检查脚本可以运行
- [ ] 路径模式正确匹配
- [ ] 违规检测有效
- [ ] 输出格式清晰

### 团队接受度
- [ ] 文档易于理解
- [ ] 规则清晰明确
- [ ] 示例代码有帮助
- [ ] 团队愿意使用

---

## 示例对比

### 适配前 (OS Account 特定版本)

```markdown
## HiSysEvent Adapter Review

### Available Report Macros

**OS Account Events** (`account_hisysevent_adapter.h:116-125`):
```cpp
#define REPORT_OS_ACCOUNT_FAIL(id, operationStr, errCode, errMsg)
void ReportOsAccountLifeCycle(int32_t id, const std::string& operationStr);
```

**Real Example** (`os_account_manager_service.cpp:487-492`):
```cpp
ReportOsAccountLifeCycle(convertOsAccountInfo.GetLocalId(),
                         Constants::OPERATION_CREATE_WITH_FULL_INFO);
```
```

### 适配后 (Bundle Framework 特定版本)

```markdown
## HiSysEvent Review

### Available Report Functions

**EventReport API** (`services/bundlemgr/include/event_report.h`):
```cpp
static void EventReport::SendSystemEvent(BMSEventType eventType, const EventInfo& eventInfo);
static void EventReport::SendBundleSystemEvent(BundleEventType bundleEventType, const EventInfo& eventInfo);
```

**Real Example** (`base_bundle_installer.cpp`):
```cpp
EventInfo eventInfo;
eventInfo.bundleName = bundleName_;
eventInfo.errCode = result;
eventInfo.preBundleScene = InstallScene::NORMAL;
EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);
```
```

---

## 持续维护

### 定期更新

**每月**:
- [ ] 检查是否有新的操作类型
- [ ] 更新代码示例
- [ ] 收集团队反馈
- [ ] 优化文档结构

**每季度**:
- [ ] 重新评估性能阈值
- [ ] 更新违规统计
- [ ] 改进检查脚本
- [ ] 进行团队培训

---

## 工具支持

### 配置文件生成器

```python
#!/usr/bin/env python3
"""
DFX Skill 配置生成器
自动生成适配后的 DFX skill 文档
"""

import yaml
import re

def generate_dfx_skill(config_file, output_file):
    """从配置文件生成 DFX skill 文档"""

    with open(config_file) as f:
        config = yaml.safe_load(f)

    # 读取模板
    with open('dfx_reviewer_universal.md') as f:
        template = f.read()

    # 替换占位符
    template = template.replace('{MODULE_NAME}', config['codebase']['name'])
    template = template.replace('{MODULE}', config['codebase']['abbreviation'])

    # 生成操作常量部分
    operations_section = generate_operations_section(config['codebase']['operations'])
    template = re.sub(r'## Operations Template', operations_section, template)

    # 输出
    with open(output_file, 'w') as f:
        f.write(template)

    print(f"DFX skill generated: {output_file}")

def generate_operations_section(operations):
    """生成操作常量部分"""
    section = "### Operation Constants\n\n```cpp\nnamespace Constants {\n"

    for op in operations:
        section += f'    const char {op["constant"]}[] = "{op["name"]}";\n'

    section += "}\n```\n"
    return section

if __name__ == '__main__':
    import sys
    generate_dfx_skill(sys.argv[1], sys.argv[2])
```

**使用**:
```bash
python3 generate_dfx_skill.py dfx_skill_config.yaml dfx_reviewer.md
```

---

## 总结

适配流程：
1. ✅ **配置**: 定义你的代码仓结构
2. ✅ **定制**: 替换占位符和示例
3. ✅ **验证**: 运行检查和测试
4. ✅ **维护**: 定期更新和改进

预期时间：1.5-2 小时
维护成本：每月 30 分钟

**收益**：
- ✅ 团队统一的 DFX 标准
- ✅ 自动化的质量检查
- ✅ 快速的代码审查
- ✅ 持续的质量改进

---

**文档版本**: v1.1
**最后更新**: 2026-06-22
**适用于**: 任何使用 HiSysEvent/HiTrace 的代码仓（当前 SKILL.md 已适配为 bundle_framework 专用）
