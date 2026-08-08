# 代码规范检视技能

## 📋 简介

本技能定义了一位**OpenHarmony 代码规范检视专家**角色，用于对代码变更（PR/MR）进行全面的规范检视。它基于 OpenHarmony 项目的四大规范要求：

1. **兼容性上库规范** - 保证 API 向后兼容
2. **日志打印规范** - 统一日志格式和打印策略
3. **安全编码规范** - 防范内存安全和安全漏洞
4. **常见陷阱规范** - 避免 bundle_framework 子系统的特有设计陷阱

## 🎯 核心功能

### 自动检视四大类规范问题

#### 兼容性检视（Compatibility）
- ✅ API 变更检测
- ✅ 回调和生命周期变更检测
- ✅ 参数规格变更检测
- ✅ 权限校验变更检测
- ✅ 错误码变更检测
- ✅ 性能劣化检测

#### 日志规范检视（Logging）
- ✅ 日志打印策略检查（高频/低频）
- ✅ 日志格式规范检查
  - 事件记录：`who do what` 主谓宾格式
  - 状态变化：`state_name:s1->s2, reason:msg` 格式
  - 参数值：`name1=value1, name2=value2` 格式
  - 成功日志：`xxx successful` 格式
  - 失败日志：`xxx failed, please xxx` 格式

#### 安全编码检视（Security）
- ✅ 指针和智能指针安全检查
- ✅ 类型安全检查（JSON、整型位宽）
- ✅ 数组和序列化安全检查
- ✅ 路径规范化检查
- ✅ 内存管理检查（分配、释放、泄漏）
- ✅ 敏感信息保护检查
- ✅ 整数运算安全检查
- ✅ 危险函数使用检查
- ✅ 权限校验绕过检查

#### 常见陷阱检视（Common Pitfalls）
- ✅ SA 初始化阻塞检查（Pitfall 1）
- ✅ 数据一致性检查（Pitfall 2）
- ✅ 敏感数据处理检查（Pitfall 3）
- ✅ 错误码处理检查（Pitfall 4）
- ✅ SA 启动流程变更检查（Pitfall 5）
- ✅ 锁性能检查（Pitfall 6）
- ✅ IDL 文件接口顺序检查（Pitfall 7）

#### 智能模块识别与检查
- ✅ **自动识别变更文件所属模块**
  - 安装/卸载核心模块（路径包含 `base_bundle_installer`、`bundle_installer`）
  - 数据管理模块（路径包含 `bundle_data_mgr`、`bundle_data_storage`）
  - BMS 主服务模块（路径包含 `bundle_mgr_service`、`bundle_mgr_host_impl`）
  - installd 客户端模块（路径包含 `services/bundlemgr/src/installd/`）
  - 跨应用 HSP 模块（路径包含 `services/bundlemgr/src/shared/`）
  - 克隆应用模块（路径包含 `services/bundlemgr/src/clone/`）
  - IDL/Inner API 模块（路径包含 `interfaces/inner_api/appexecfwk_core/`）
  - 客户端 Kit 模块（路径包含 `interfaces/kits/`）
- ✅ **应用模块特定的 Pitfalls 检查**
  - 每个模块除了通用检查外，还会应用其特有的陷阱规则
  - 基于 bundle_framework 架构与历史问题总结
- ✅ **跨模块变更支持**
  - 自动检测涉及多个模块的变更
  - 分别应用各模块的检查策略
  - 检查跨模块接口兼容性

## 📊 输出报告

检视报告包含以下内容：

### 总体概览
- 变更文件统计
- 问题总数统计
- 问题分布（按类别和严重程度）

### 问题详情

每个问题包含：
- **问题编号**：C-xxx（兼容性）、L-xxx（日志）、S-xxx（安全）、P-xxx（通用陷阱）、B-xxx（bundle_framework 特有陷阱）
- **严重等级**：致命、严重、警告、建议
- **代码位置**：精确到文件名和行号
- **问题描述**：详细的违规说明
- **风险分析**：可能造成的影响
- **修复建议**：具体的修复代码示例

## 🚀 使用方法

### 作为 Code Review 辅助工具

```bash
# 在 PR/MR 流程中使用
# 技能会自动分析变更文件并生成检视报告
```

### 适用场景

1. **PR/MR 自动检视**：代码提交前的自动规范检查
2. **人工 Review 辅助**：为 Reviewer 提供规范检查清单
3. **代码质量门禁**：作为 CI/CD 流程的质量关卡
4. **新人培训**：帮助新人理解编码规范

## 🧠 智能模块识别与检查

### 模块自动识别机制

技能会根据变更文件的路径自动识别所属模块，并应用对应的检查规则：

| 模块名称 | 路径特征 | 特有 Pitfalls 数量 | 问题编号前缀 |
|---------|---------|------------------|-------------|
| **安装/卸载核心** | `*/base_bundle_installer*`<br>`*/bundle_installer.cpp` | B1/B2/B3/B7 重点 | B-xxx |
| **数据管理** | `*/bundle_data_mgr*`<br>`*/bundle_data_storage*` | B2/B3 重点 | B-xxx |
| **BMS 主服务** | `*/bundle_mgr_service*`<br>`*/bundle_mgr_host_impl*` | B4/B6 重点 | B-xxx |
| **installd 客户端** | `*/services/bundlemgr/src/installd/*` | B2 重点（文件系统部分） | B-xxx |
| **跨应用 HSP** | `*/services/bundlemgr/src/shared/*` | B1/B2/B7 重点 | B-xxx |
| **克隆应用** | `*/services/bundlemgr/src/clone/*` | B5 重点 | B-xxx |
| **CLI Sandbox** | `*/services/bundlemgr/src/cli_sandbox/*` | B5/B6 重点 | B-xxx |
| **多用户** | `*/bundle_multiuser_installer*` | B1/B5 重点 | B-xxx |
| **OTA/启动** | `*/pre_install_exception_mgr*`<br>`*/bundle_exception_handler*` | B4 重点 | B-xxx |
| **Inner API/IDL** | `*/interfaces/inner_api/appexecfwk_core/*` | B6 重点 | B-xxx |
| **客户端 Kit** | `*/interfaces/kits/*` | Pitfall 1-7（禁止打点） | P-xxx |
| **通用** | 所有路径 | 7 条（P1-P7）+ 7 条（B1-B7） | P-xxx/B-xxx |

### 检查策略

#### 第一层：全局检查（所有模块）
所有代码变更都会先进行**通用陷阱检查**（Pitfall 1-7）：
- ✅ Pitfall 1: SA 初始化阻塞
- ✅ Pitfall 2: 数据一致性
- ✅ Pitfall 3: 敏感数据保护
- ✅ Pitfall 4: 错误码处理
- ✅ Pitfall 5: SA 启动流程保护
- ✅ Pitfall 6: 锁性能优化
- ✅ Pitfall 7: IDL 接口顺序

以及 **bundle_framework 特有陷阱检查**（Pitfall B1-B7）：
- ✅ B1: Per-bundle Mutex 串行化
- ✅ B2: bundleInfos_/DB/文件系统三方一致性
- ✅ B3: InstallState 状态机合法转换
- ✅ B4: OTA 升级幂等性
- ✅ B5: 克隆应用多 appIndex 隔离
- ✅ B6: IDL 接口与 Parcel 序列化兼容性
- ✅ B7: ScopeGuard 使用模式

#### 第二层：模块特定检查
在通用检查的基础上，根据所属模块应用额外的重点检查：

**安装/卸载核心模块**（路径包含 `base_bundle_installer`、`bundle_installer`）：
- ✅ B1: per-bundle mutex 是否正确获取
- ✅ B2: 每个失败路径是否有 ScopeGuard 回滚
- ✅ B3: InstallState 转换是否覆盖所有错误路径
- ✅ B7: 所有 ScopeGuard 是否在成功路径 Dismiss()

**数据管理模块**（路径包含 `bundle_data_mgr`、`bundle_data_storage`）：
- ✅ B2: `UpdateInnerBundleInfo` 的 needSaveStorage 参数使用是否正确
- ✅ B3: `UpdateBundleInstallState` 是否检查返回值
- ✅ B3: `transferStates_` 中转换合法性是否被破坏
- ✅ Pitfall 6: 持有 `bundleInfoMutex_` 时是否有 IO 操作

**BMS 主服务模块**（路径包含 `bundle_mgr_service`、`bundle_mgr_host_impl`）：
- ✅ B4: `ready_` 标志位是否正确保护
- ✅ B4: `otaInstall_` 与 `loadExistData_` 标志位是否正确使用
- ✅ B4: `BundleExceptionHandler` 是否覆盖所有异常状态
- ✅ B6: IDL Host 新增方法是否追加在末尾

**跨应用 HSP 模块**（路径包含 `shared/`）：
- ✅ B1: HSP 操作的 per-bundle mutex 是否正确
- ✅ B2: HSP 更新时 router 信息、preInstallInfo、AOT 文件是否纳入回滚
- ✅ B7: 多 HSP 串行安装的 ScopeGuard 链

**克隆应用模块**（路径包含 `clone/`、`cli_sandbox/`）：
- ✅ B5: Clone 应用的 appIndex 隔离
- ✅ B5: 卸载主 bundle 时级联卸载所有 clone

**OTA/启动模块**（路径包含 `pre_install_exception_mgr`、`bundle_exception_handler`）：
- ✅ B4: 异常状态恢复完整性
- ✅ B4: `GuardAgainstInstallInfosLossedStrategy` 触发条件正确

**IDL/Inner API 模块**（路径包含 `interfaces/inner_api/`）：
- ✅ B6: IDL 文件新增方法是否追加在末尾
- ✅ B6: Parcel 序列化新增字段是否在末尾
- ✅ Pitfall 7: 是否在 IDL 文件中间插入接口

**客户端 Kit 模块**（路径包含 `interfaces/kits/`）：
- ✅ 不允许调用 `EventReport::`（参考 DFX skill）
- ✅ 不允许调用 `HiSysEventWrite`
- ✅ 客户端只负责透传 IPC 调用

### 跨模块变更处理

如果代码变更涉及多个模块（例如同时修改了 `base_bundle_installer.cpp` 和 `bundle_data_mgr.cpp`）：
1. ✅ 对每个模块分别应用对应的检查策略
2. ✅ 检查模块间的接口兼容性（IDL/Parcel 序列化）
3. ✅ 检查跨模块的 per-bundle mutex 一致性
4. ✅ 检查跨模块的数据一致性（内存/DB/文件系统）
5. ✅ 生成综合的检视报告，标注各模块的问题

### 使用示例

```bash
# 示例 1：只修改了安装核心模块
git diff HEAD~1 services/bundlemgr/src/base_bundle_installer.cpp
# → 应用检查：通用 Pitfall 1-7 + bundle B1-B7 + 安装核心重点 B1/B2/B3/B7

# 示例 2：只修改了数据管理模块
git diff HEAD~1 services/bundlemgr/src/bundle_data_mgr.cpp
# → 应用检查：通用 Pitfall 1-7 + bundle B1-B7 + 数据管理重点 B2/B3

# 示例 3：同时修改多个模块
git diff HEAD~1 services/bundlemgr/src/base_bundle_installer.cpp \
              services/bundlemgr/src/bundle_data_mgr.cpp
# → 应用检查：通用 Pitfall 1-7 + bundle B1-B7 + 安装/数据 双模块重点检查
```

## 🎨 问题分级标准

| 等级 | 说明 | 是否阻止上库 |
|------|------|-------------|
| **致命** | API 破坏性变更、内存泄漏、安全漏洞、SA 初始化阻塞、IDL 接口顺序错误 | ✅ 阻止 |
| **严重** | 日志格式错误、未校验外部输入、数据一致性问题 | ⚠️ 强烈建议修复 |
| **警告** | 可优化但不影响功能的问题 | 💡 建议修复 |
| **建议** | 代码风格、性能优化建议 | ℹ️ 可选 |

## 📝 检查清单概览

### 兼容性上库自检（10 项）
- API 功能变更
- 回调/生命周期变更
- 参数规格变更
- 权限校验变更
- 实例数量限制变更
- 返回数据变更
- 新增错误抛出
- 错误码修改
- 性能劣化

### 日志规范自检（7 项）
- 高频代码禁止打印日志
- 异常点必须打印日志
- 事件记录格式（who do what）
- 状态变化格式（state_name:s1->s2）
- 参数值格式（name=value）
- 成功日志格式（xxx successful）
- 失败日志格式（xxx failed, please xxx）

### 安全编码自检（23 项）
- 指针/智能指针安全（3 项）
- 类型安全（3 项）
- 数组/序列化安全（2 项）
- 路径安全（1 项）
- 内存管理（5 项）
- 敏感信息保护（2 项）
- 整数运算安全（3 项）
- 函数使用规范（3 项）
- 权限校验（1 项）

### 常见陷阱自检（7 项）
- **Pitfall 1：SA 初始化阻塞**
  - 避免在 SA 启动时执行耗时操作
  - 禁止在 `OnStart()`/`Init()` 中进行阻塞 I/O、网络请求、复杂计算

- **Pitfall 2：数据一致性**
  - 确保数据库和文件操作的一致性
  - 使用事务保证原子性
  - 实现回滚机制处理部分失败

- **Pitfall 3：敏感数据保护**
  - 使用加密存储（Asset 服务）
  - 使用后清除敏感数据（memset_s）
  - 禁止在日志中打印敏感信息

- **Pitfall 4：错误码处理**
  - 正确处理所有返回值
  - 注意 HILOG 会修改 errno
  - 完整的错误处理逻辑

- **Pitfall 5：SA 启动流程保护**
  - 避免改变 SA 启动依赖关系
  - 避免修改首个用户创建激活流程
  - 确保不影响设备启动时间和成功率

- **Pitfall 6：锁性能优化**
  - 锁内禁止执行文件 I/O、IPC 调用
  - 锁内禁止复杂计算和睡眠等待
  - 避免锁嵌套和长时间持有

- **Pitfall 7：IDL 接口顺序**
  - **禁止**在 IDL 文件中间插入新接口
  - 新接口只能在文件末尾添加
  - 避免删除或重排现有接口

### bundle_framework 特有陷阱（B1-B7）

- **Pitfall B1：Per-bundle Mutex 串行化**
  - 修改 `bundleInfos_` 必须通过 `dataMgr->GetBundleMutex(bundleName)` 串行化
  - 不能在持锁时调用同步 IPC（避免死锁）
  - 代码位置：`base_bundle_installer.cpp:2244-2245`、`bundle_data_mgr.cpp`

- **Pitfall B2：三方一致性破坏**
  - bundleInfos_（内存）↔ DB ↔ 文件系统必须保持一致
  - 修改顺序：内存 → DB → 文件系统；失败时按相反顺序回滚
  - 必须配置 ScopeGuard 配对回滚
  - 代码位置：`bundle_data_mgr.cpp:8869`（`UpdateInnerBundleInfo`）

- **Pitfall B3：InstallState 状态机非法转换**
  - 仅 `transferStates_` 中允许的转换合法（见 `bundle_data_mgr.cpp:5562-5589`）
  - 非法转换被静默拒绝，仅 log warning
  - 关键转换：`INSTALL_SUCCESS → UNINSTALL_START → UNINSTALL_SUCCESS`

- **Pitfall B4：OTA 升级幂等性**
  - `otaInstall_=true` 时仍需版本兼容性校验
  - `loadExistData_=true` 时必须信任 DB InstallMark
  - `BundleExceptionHandler` 必须覆盖所有异常状态
  - 代码位置：`bundle_mgr_service.cpp`、`pre_install_exception_mgr.cpp`

- **Pitfall B5：克隆应用多 appIndex 隔离**
  - appIndex 不能跨 bundle 复用
  - 卸载主 bundle 必须级联卸载所有 clone（`UninstallAllCloneApps`）
  - 多 appIndex 并发操作必须独立加锁
  - 代码位置：`services/bundlemgr/src/clone/bundle_clone_installer.cpp`

- **Pitfall B6：IDL 接口与 Parcel 兼容性**
  - 新增 IDL 方法只能追加在末尾（影响 IPC code 顺序）
  - Parcel 序列化新增字段必须追加在末尾
  - 新增字段必须有默认值
  - 代码位置：`interfaces/inner_api/appexecfwk_core/src/bundlemgr/`

- **Pitfall B7：ScopeGuard 使用模式**
  - 成功路径必须显式 `Dismiss()`
  - 回滚操作必须幂等
  - 代码位置：`base_bundle_installer.cpp`（大量使用）、`inner_shared_bundle_installer.cpp:80`

## 🔍 典型问题示例

### 兼容性问题示例

```cpp
// ❌ 错误：改变参数取值范围
// 旧版本：timeout 范围 0-INT_MAX
// 新版本：timeout 范围 0-30000
void SetTimeout(int32_t timeout) {
    if (timeout < 0 || timeout > 30000) {  // 破坏性变更
        return ERR_INVALID_PARAM;
    }
}
```

### 日志规范示例

```cpp
// ❌ 错误：高频代码打印日志
for (int i = 0; i < 100000; i++) {
    HILOG_INFO("Processing item %{public}d", i);  // 违规
}

// ❌ 错误：格式不规范
APP_LOGI("bundle installed");  // 错误格式
// ✅ 正确格式
APP_LOGI("ProcessBundleInstall successful");

// ✅ 正确：参数值格式
APP_LOGI("ProcessBundleInstall, bundleName=%{public}s, userId=%{public}d", bundleName.c_str(), userId);

// ✅ 正确：状态变化格式
APP_LOGI("install_state:INSTALL_SUCCESS->UNINSTALL_START, reason:user uninstall");
```

### 安全编码示例

```cpp
// ❌ 错误：未校验外部数据
void ProcessData(char* data, int len) {
    char buffer[100];
    memcpy(buffer, data, len);  // 危险：len 未校验
}

// ✅ 正确：校验后拷贝
void ProcessData(char* data, int len) {
    if (data == nullptr || len <= 0 || len > MAX_DATA_SIZE) {
        return ERR_INVALID_PARAM;
    }
    char buffer[100];
    memcpy_s(buffer, sizeof(buffer), data, std::min(len, (int)sizeof(buffer)));
}

// ❌ 错误：使用危险函数
char buf[100];
strcpy(buf, input);  // 危险函数

// ✅ 正确：使用安全函数
strcpy_s(buf, sizeof(buf), input);

// ❌ 错误：有符号整数位运算
int32_t flags = -1;
if (flags & 0x01) { ... }  // 未定义行为

// ✅ 正确：使用无符号类型
uint32_t flags = 0xFFFFFFFF;
if (flags & 0x01) { ... }

// ❌ 错误：外部数据控制循环
void Process(int count) {  // count 来自外部输入
    for (int i = 0; i < count; i++) {  // 危险
        // ...
    }
}

// ✅ 正确：校验循环次数
void Process(int count) {
    if (count < 0 || count > MAX_LOOP_COUNT) {
        return ERR_INVALID_PARAM;
    }
    for (int i = 0; i < count; i++) {
        // ...
    }
}
```

### 常见陷阱示例（Pitfalls）

#### Pitfall 1: SA 初始化阻塞

```cpp
// ❌ 错误：在 SA 启动时执行阻塞操作
void BundleMgrService::OnStart()
{
    // 错误：同步扫描所有已安装应用（可能很慢）
    ScanAllInstalledBundles();

    // 错误：同步读取所有 preInstall 配置
    auto configs = ReadAllPreInstallConfigs();

    // 错误：复杂计算（耗时）
    std::vector<InnerBundleInfo> allInfos = LoadAllBundleInfos();
}

// ✅ 正确：快速启动，异步加载
void BundleMgrService::OnStart()
{
    // 快速初始化：注册 IPC、初始化关键成员
    InitBundleMgrHost();
    InitBundleInstaller();

    // 异步启动 boot scan
    std::thread([this]() {
        BmsStartEvent();  // 包括 FetchAllBundleInfo、ScanSystemBundle 等
    }).detach();
}
```

#### Pitfall 2: 数据一致性问题

```cpp
// ❌ 错误：内存、DB、文件系统操作不保证一致性
ErrCode BaseBundleInstaller::ProcessBundleInstall(...)
{
    // 先写文件系统
    InstalldClient::GetInstance()->CreateBundleDir(...);

    // 如果 DB 写入失败，文件已经创建，三方不一致！
    if (!dataMgr_->AddInnerBundleInfo(bundleName_, info)) {
        return ERR_APPEXECFWK_ADD_BUNDLE_ERROR;  // 文件已创建，但 DB 未更新
    }

    return ERR_OK;
}

// ✅ 正确：使用 ScopeGuard 保证三方一致性
ErrCode BaseBundleInstaller::ProcessBundleInstall(...)
{
    // 文件系统操作配 ScopeGuard
    ScopeGuard codePathGuard([&] { RollbackCodePath(); });

    ErrCode result = InstalldClient::GetInstance()->CreateBundleDir(...);
    CHECK_RESULT(result, "create dir failed");

    // 内存 + DB 同步更新（UpdateInnerBundleInfo(info, true) 内部落盘）
    if (!dataMgr_->AddInnerBundleInfo(bundleName_, info)) {
        return ERR_APPEXECFWK_ADD_BUNDLE_ERROR;  // ScopeGuard 自动回滚文件系统
    }

    codePathGuard.Dismiss();  // 成功路径必须 Dismiss
    return ERR_OK;
}
```

#### Pitfall 3: 敏感数据泄露

```cpp
// ❌ 错误：敏感数据明文打印（hap 路径、签名指纹）
void ProcessHap(const std::string& hapPath, const std::string& fingerprint)
{
    // 错误：用 %{public} 打印敏感路径
    APP_LOGI("hap path=%{public}s", hapPath.c_str());

    // 错误：明文打印签名指纹
    APP_LOGI("fingerprint=%{public}s", fingerprint.c_str());
}

// ✅ 正确：使用 %{private} 标识敏感数据
void ProcessHap(const std::string& hapPath, const std::string& fingerprint)
{
    APP_LOGI("hap path=%{private}s", hapPath.c_str());  // ✅ 路径脱敏
    APP_LOGI("fingerprint=%{private}s", fingerprint.c_str());  // ✅ 指纹脱敏
    APP_LOGI("bundleName=%{public}s", bundleName.c_str());  // 业务字段可以公开
}
```

#### Pitfall 4: 错误处理不当

```cpp
// ❌ 错误：不检查返回值
ErrCode ProcessBundleUninstall(...)
{
    // 不检查返回值，如果状态转换失败会怎样？
    dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);

    // 错误：APP_LOG 会修改 errno
    SomeFunction();
    APP_LOGI("Operation result");
    int err = errno;  // errno 可能被 APP_LOG 修改！
}

// ✅ 正确：正确处理错误码
ErrCode ProcessBundleUninstall(...)
{
    // 保存 errno（如果需要）
    int savedErrno = errno;

    // UpdateBundleInstallState 检查返回值（B3）
    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START)) {
        APP_LOGE("UpdateBundleInstallState failed, bundle=%{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_UPDATE_BUNDLE_INSTALL_STATUS_ERROR;
    }

    APP_LOGI("ProcessBundleUninstall successful, bundle=%{public}s", bundleName.c_str());
    errno = savedErrno;
    return ERR_OK;
}
```

#### Pitfall 6: 锁内长时间操作

```cpp
// ❌ 错误：持有 bundleInfoMutex_ 时执行 IO（参考 RemoveHspModuleByVersionCode）
bool BundleDataMgr::RemoveHspModuleByVersionCode(...)
{
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);  // 写锁
    std::lock_guard<std::mutex> stateLock(stateMutex_);

    // 错误：持锁期间执行磁盘 IO（可能毫秒级，阻塞所有查询）
    if (dataStorage_->SaveStorageBundleInfo(info)) {
        bundleInfos_.at(bundleName) = info;
    }
}

// ✅ 正确：锁内只做内存操作，IO 移到锁外
bool BundleDataMgr::RemoveHspModuleByVersionCode(...)
{
    InnerBundleInfo infoCopy;
    {
        std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
        std::lock_guard<std::mutex> stateLock(stateMutex_);
        // 锁内：只做内存修改
        bundleInfos_.at(bundleName) = info;
        infoCopy = info;
    }  // 锁在这里释放

    // 锁外：执行磁盘 IO
    return dataStorage_->SaveStorageBundleInfo(infoCopy);
}
```

#### Pitfall 7: IDL 文件中间插入接口

```idl
// ❌ 错误：在中间插入新接口（破坏二进制兼容性！）
interface OHOS.AppExecFwk.IBundleMgr {
    void GetBundleInfo(...);        // code = 1
    void SetDefaultApp(...);        // ❌ 新插入
    void Install(...);              // code: 2 → 3
    void Uninstall(...);            // code: 3 → 4
}

// ✅ 正确：在末尾添加新接口
interface OHOS.AppExecFwk.IBundleMgr {
    void GetBundleInfo(...);        // code = 1
    void Install(...);              // code = 2
    void Uninstall(...);            // code = 3
    void SetDefaultApp(...);        // ✅ 在末尾
}
```

**重要提示**：在 IDL 文件中间插入或删除接口会改变所有后续接口的 IPC 代码，导致使用硬编码 IPC 代码的现有客户端调用错误的接口！

## ⚙️ 配置建议

### 作为 PR/MR 必须通过的检查项

建议将此技能配置为：
- **致命问题** → 阻止合并
- **严重问题** → 需要开发者确认后才能合并
- **警告问题** → 建议修复，但不阻止合并

## 🔧 技术特点

1. **只读分析**：不修改原始代码，只生成报告
2. **全面覆盖**：检查所有变更文件
3. **精确定位**：问题定位到具体行号
4. **实用建议**：提供可直接使用的修复代码
5. **分级管理**：按严重程度分类问题

## 📁 文件结构

```
code_review_checklist/
├── README.md          # 本说明文档
└── SKILL.md          # 技能定义文件
```

## 🔗 相关规范

本技能基于以下 OpenHarmony 编码规范和项目文档：
- OpenHarmony API 兼容性规范
- OpenHarmony 日志打印规范
- OpenHarmony 安全编码规范
- bundle_framework 架构与历史问题总结（B1-B7）

## 🤝 维护和更新

当项目规范更新时，需要同步更新 SKILL.md 中的检查清单，确保检视规则与最新规范保持一致。

## 📌 注意事项

1. **误报可能**：某些情况下可能存在误报，需要人工复核
2. **规则覆盖**：无法覆盖所有问题，仍需人工 review
3. **上下文理解**：技能可能无法完全理解业务逻辑，某些设计决策需要人工判断
4. **持续优化**：根据实际使用反馈不断优化检视规则

---

**最后更新**：2026-06-22
**适用版本**：OpenHarmony bundle_framework 子系统
