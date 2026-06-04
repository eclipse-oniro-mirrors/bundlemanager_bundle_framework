# 任务规格

> 最小可执行单元。AI Agent 据此独立完成编码实现。本文档包含 FEAT-PRINT-001 所有子任务。

## 任务总览

| Task ID | 标题 | Phase | 优先级 | 依赖 | 预估工时 | 状态 |
|---------|------|-------|--------|------|----------|------|
| TASK-1.1 | 在 InstalldService 中添加创建打印服务目录接口 | Phase 1 | P0 | 无 | 4h | Pending |
| TASK-1.2 | 在 InstalldService 中添加删除打印服务目录接口 | Phase 1 | P0 | 无 | 2h | Pending |
| TASK-1.3 | 在 InstalldService 中添加验证/修复目录权限接口 | Phase 1 | P0 | TASK-1.1 | 2h | Pending |
| TASK-1.4 | InstalldClient 添加对应接口调用 | Phase 1 | P0 | TASK-1.1, TASK-1.2, TASK-1.3 | 2h | Pending |
| TASK-2.1 | 在 BaseBundleInstaller 中添加驱动应用检测逻辑 | Phase 2 | P0 | TASK-1.4 | 2h | Pending |
| TASK-2.2 | 集成打印服务目录创建到安装流程 | Phase 2 | P0 | TASK-2.1 | 4h | Pending |
| TASK-2.3 | 添加分身应用目录名处理逻辑 | Phase 2 | P0 | TASK-2.2 | 2h | Pending |
| TASK-2.4 | 实现目录权限验证和修复逻辑 | Phase 2 | P1 | TASK-2.2 | 3h | Pending |
| TASK-3.1 | 在卸载流程中集成目录删除逻辑 | Phase 3 | P0 | TASK-1.4 | 2h | Pending |
| TASK-4.1 | 在 BMSEventHandler::ProcessRebootBundle 中添加存量应用扫描 | Phase 4 | P1 | TASK-2.2 | 3h | Pending |
| TASK-4.2 | 实现存量驱动应用目录补建逻辑 | Phase 4 | P1 | TASK-4.1 | 3h | Pending |
| TASK-5.1 | 添加新错误码定义 | Phase 5 | P0 | 无 | 1h | Pending |
| TASK-5.2 | 添加日志记录 | Phase 5 | P0 | TASK-2.2, TASK-3.1, TASK-4.2 | 2h | Pending |
| TASK-6.1 | 单元测试 | Phase 6 | P0 | TASK-5.2 | 4h | Pending |
| TASK-6.2 | 集成测试 | Phase 6 | P0 | TASK-6.1 | 4h | Pending |
| TASK-6.3 | OTA 升级测试 | Phase 6 | P1 | TASK-6.2 | 2h | Pending |

### 任务依赖图

```
TASK-1.1 ────┬──> TASK-1.3 ──┐
             │                │
TASK-1.2 ───┴──> TASK-1.4 ──┴──> TASK-2.1 ──> TASK-2.2 ──┬──> TASK-2.3
                                                   │
                                                   ├──> TASK-2.4
                                                   │
                                                   ├──> TASK-3.1
                                                   │
                                                   └──> TASK-4.1 ──> TASK-4.2

TASK-5.1 (独立)
TASK-5.2 依赖 TASK-2.2, TASK-3.1, TASK-4.2
TASK-6.1 依赖 TASK-5.2
TASK-6.2 依赖 TASK-6.1
TASK-6.3 依赖 TASK-6.2
```

---

## TASK-1.1：在 InstalldService 中添加创建打印服务目录接口

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-1.1 |
| 标题 | 在 InstalldService 中添加创建打印服务目录接口 |
| 关联 Feature | FEAT-PRINT-001（驱动应用打印服务目录管理） |
| 目标仓库 | bundlemanager_bundle_framework |
| 目标模块 | services/bundlemgr/src/ipc/ → services/bundlemgr/src/installd/ |
| 分支 | test_sdd_code |
| 优先级 | P0 |
| 复杂度 | 中 |
| 执行方式 | 可独立执行（无前置 Task 依赖） |
| 关联 Phase | Phase 1: Installd 接口扩展 |
| 预估工时 | 4h |
| 状态 | Pending |

### 做什么

1. 在 InstalldService 中新增 `CreatePrintServiceDir` 接口，用于创建驱动应用的打印服务专属目录
2. 实现目录创建、属主/属组设置、权限设置的核心逻辑
3. 处理目录已存在时的权限验证与修复
4. 处理父目录不存在、目录创建/权限设置失败等异常场景
5. 在 `appexecfwk_errors.h` 中定义相关错误码

### 不做什么

- 不实现 `RemovePrintServiceDir`（删除接口，属于 TASK-1.2）
- 不实现安装流程集成（属于 TASK-2.1、TASK-2.2）
- 不实现分身应用安装流程集成（属于 TASK-2.3）
- 不实现卸载流程集成（属于 TASK-3.1）
- 不实现 OTA 场景支持（属于 TASK-4.1、TASK-4.2）
- 不实现 `InstalldClient` 的调用封装（属于 TASK-1.4）
- 不自动创建父目录（父目录由打印服务负责，见 ADR-2）
- 不阻塞安装流程（见 ADR-3）

### AC 映射

| AC | 来源 | 本 Task 覆盖范围 | 验证方式 |
|----|------|------------------|----------|
| AC-1 | spec.md US-1 | WHEN 安装驱动应用 THEN 创建 `/data/service/el1/{userId}/print_service/data/{bundleName}` 目录 | 单元测试 |
| AC-2 | spec.md US-1 | WHEN 创建目录 THEN 属主为应用 uid，属组为 3823 | 单元测试 |
| AC-3 | spec.md US-1 | WHEN 创建目录 THEN 权限为 02750（sticky bit + rwxr-x---） | 单元测试 |
| AC-4 | spec.md US-1 | WHEN 父目录不存在 THEN 返回 ERR_APPEXECFWK_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS | 单元测试 |
| AC-5 | spec.md US-1 | WHEN 目录已存在 THEN 验证并修复权限 | 单元测试 |

### 规则映射

| Rule ID | Must / Must Not | 本 Task 摘要 |
|---------|-----------------|-------------|
| FR-1 | Must | 创建打印服务目录（目录路径构建 + mkdir） |
| FR-2 | Must | 设置目录属主属组（chown appUid:3823） |
| FR-3 | Must | 设置目录权限（chmod 02750） |
| FR-4 | Must | 检查父目录存在性（access 检查 baseDir） |
| FR-5 | Must | 验证修复已有目录权限 |
| BR-2 | Must | 目录属组固定为 3823 |
| BR-3 | Must | 目录权限固定为 02750 |
| BR-4 | Must | 不自动创建父目录 |
| ER-1 | Must | 父目录不存在时返回错误码 |
| ER-2 | Must | mkdir 失败时返回错误码 |
| ER-3 | Must | chown 失败时返回错误码 |
| ER-4 | Must | chmod 失败时清理目录并返回错误码 |
| OH-ARCH-IPC-SAF | Must | 使用现有 IPC 框架，新增接口码 79 |
| OH-ARCH-ERROR-LOG | Must | 新增错误码，使用 BUNDLE_MGR_ERR_OFFSET + 0x0500 范围 |

### 前置依赖

| 类型 | 编号 | 原因 |
|------|------|------|
| Design | design.md | ADR-1 ~ ADR-4 决定本 Task 的实现方式 |
| Spec | spec.md | FR-1 ~ FR-5, ER-1 ~ ER-4 定义功能边界 |

### 完成判据

- `CreatePrintServiceDir` 接口在 InstalldService 中实现并通过编译
- 目录创建逻辑正确处理正常流程和异常流程
- 错误码已定义且语义明确

### 停止条件

- 发现 InstalldService 现有接口码空间不足，需与 Installd 模块 Owner 协调
- 发现 `/data/service/el1/` 路径权限模型与预期不符，需确认 SELinux 策略

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `interfaces/inner_api/appexecfwk_base/include/appexecfwk_errors.h` | 新增 5 个打印服务相关错误码 |
| 修改 | `services/bundlemgr/include/ipc/installd_interface.h` | 新增 CreatePrintServiceDir 接口声明 |
| 修改 | `services/bundlemgr/include/ipc/installd_host.h` | 新增 CreatePrintServiceDir 宿主端声明 |
| 修改 | `services/bundlemgr/include/ipc/installd_proxy.h` | 新增 CreatePrintServiceDir 代理端声明 |
| 修改 | `services/bundlemgr/src/ipc/installd_host_impl.cpp` | 新增 CreatePrintServiceDir 宿主端实现 |
| 修改 | `services/bundlemgr/src/ipc/installd_proxy.cpp` | 新增 CreatePrintServiceDir 代理端实现 |
| 修改 | `services/bundlemgr/src/installd/installd_operator.h` | 新增 CreatePrintServiceDir 声明 |
| 修改 | `services/bundlemgr/src/installd/installd_operator.cpp` | 新增 CreatePrintServiceDir 核心逻辑 |
| 修改 | `services/bundlemgr/src/installd/installd_service.cpp` | 注册新接口 |

### 代码变更规格

#### 修改文件: `interfaces/inner_api/appexecfwk_base/include/appexecfwk_errors.h`

**变更原因：** 定义打印服务目录操作相关错误码

**目标代码：**
```cpp
// Print service directory errors
constexpr ErrCode APPEXECFWK_PRINT_SERVICE_DIR_BASE = ERR_APPEXECFWK_BUNDLEMGR_ERR_OFFSET + 0x0500;

enum {
    ERR_APPEXECFWK_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS = APPEXECFWK_PRINT_SERVICE_DIR_BASE + 1,
    ERR_APPEXECFWK_PRINT_SERVICE_DIR_CREATE_FAILED = APPEXECFWK_PRINT_SERVICE_DIR_BASE + 2,
    ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHOWN_FAILED = APPEXECFWK_PRINT_SERVICE_DIR_BASE + 3,
    ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHMOD_FAILED = APPEXECFWK_PRINT_SERVICE_DIR_BASE + 4,
    ERR_APPEXECFWK_PRINT_SERVICE_DIR_REMOVE_FAILED = APPEXECFWK_PRINT_SERVICE_DIR_BASE + 5,
};
```

#### 修改文件: `services/bundlemgr/src/installd/installd_operator.cpp`

**变更原因：** 实现 CreatePrintServiceDir 核心业务逻辑

**目标代码（伪代码）：**
```cpp
ErrCode InstalldOperator::CreatePrintServiceDir(
    const std::string& bundleName, int32_t userId, int32_t appIndex, uid_t appUid)
{
    // 1. 参数校验
    if (bundleName.empty() || userId < 0 || appUid < 0) {
        APP_LOGE("Invalid parameters");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    // 2. 构建目录路径
    std::string baseDir = "/data/service/el1/" + std::to_string(userId) + "/print_service/data";
    std::string bundleDir = baseDir + "/" + GetBundleDirName(bundleName, appIndex);

    // 3. 检查父目录是否存在（ADR-2: 不自动创建父目录）
    if (access(baseDir.c_str(), F_OK) != 0) {
        APP_LOGE("Print service base directory not exists: %{public}s", baseDir.c_str());
        return ERR_APPEXECFWK_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS;
    }

    // 4. 目录已存在时验证并修复权限（ADR-4）
    if (access(bundleDir.c_str(), F_OK) == 0) {
        VerifyAndFixPermission(bundleDir, appUid, 3823, 02750);
        return ERR_OK;
    }

    // 5. 创建目录
    if (mkdir(bundleDir.c_str(), 02750) != 0) {
        APP_LOGE("Failed to create print service dir: %{public}s, errno: %{public}d",
            bundleDir.c_str(), errno);
        return ERR_APPEXECFWK_PRINT_SERVICE_DIR_CREATE_FAILED;
    }

    // 6. 设置属主属组
    if (chown(bundleDir.c_str(), appUid, 3823) != 0) {
        APP_LOGE("Failed to chown print service dir: %{public}s, errno: %{public}d",
            bundleDir.c_str(), errno);
        return ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHOWN_FAILED;
    }

    // 7. 确保权限正确（含 sticky bit）
    if (chmod(bundleDir.c_str(), 02750) != 0) {
        APP_LOGE("Failed to chmod print service dir: %{public}s, errno: %{public}d",
            bundleDir.c_str(), errno);
        ForceRemoveDirectory(bundleDir);
        return ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHMOD_FAILED;
    }

    APP_LOGI("Create print service dir success: %{public}s", bundleDir.c_str());
    return ERR_OK;
}

std::string InstalldOperator::GetBundleDirName(
    const std::string& bundleName, int32_t appIndex)
{
    if (appIndex == 0) {
        return bundleName;
    }
    return BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
}

void InstalldOperator::VerifyAndFixPermission(
    const std::string& dirPath, uid_t uid, gid_t gid, mode_t mode)
{
    chown(dirPath.c_str(), uid, gid);
    chmod(dirPath.c_str(), mode);
}
```

#### 修改文件: `services/bundlemgr/src/ipc/installd_host_impl.cpp`

**变更原因：** 新增 CreatePrintServiceDir IPC 宿主端实现

**变更位置：** InstalldHostImpl::OnRemoteRequest 新增 case 分支（接口码 79）

**目标代码（伪代码）：**
```cpp
case InstalldInterfaceCode::CREATE_PRINT_SERVICE_DIR:
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName;
    int32_t userId = 0;
    int32_t appIndex = 0;
    uid_t appUid = 0;
    READ_STRING(data, bundleName, "CreatePrintServiceDir");
    READ_INT32(data, userId, "CreatePrintServiceDir");
    READ_INT32(data, appIndex, "CreatePrintServiceDir");
    READ_UINT32(data, appUid, "CreatePrintServiceDir");

    ErrCode result = InstalldOperator::CreatePrintServiceDir(
        bundleName, userId, appIndex, appUid);
    reply.WriteInt32(result);
    break;
}
```

#### 修改文件: `services/bundlemgr/src/ipc/installd_proxy.cpp`

**变更原因：** 新增 CreatePrintServiceDir IPC 代理端实现

**目标代码（伪代码）：**
```cpp
ErrCode InstalldProxy::CreatePrintServiceDir(
    const std::string& bundleName, int32_t userId, int32_t appIndex, uid_t appUid)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    data.WriteString(bundleName);
    data.WriteInt32(userId);
    data.WriteInt32(appIndex);
    data.WriteUint32(appUid);

    int32_t ret = Remote()->SendRequest(
        static_cast<uint32_t>(InstalldInterfaceCode::CREATE_PRINT_SERVICE_DIR),
        data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGE("SendRequest failed, error: %{public}d", ret);
        return ret;
    }
    return reply.ReadInt32();
}
```

### 测试用例

| 用例 ID | 描述 | 覆盖 AC | 期望结果 |
|---------|------|---------|----------|
| TC-1.1-1 | 正常创建目录 | AC-1, AC-2, AC-3 | 目录创建成功，属主/属组/权限正确 |
| TC-1.1-2 | 父目录不存在 | AC-4 | 返回 ERR_APPEXECFWK_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS |
| TC-1.1-3 | 目录已存在且权限正确 | AC-5 | 返回 ERR_OK，不重复创建 |
| TC-1.1-4 | 分身应用目录名（appIndex > 0） | AC-1 | 目录名格式为 `+clone-{appIndex}+{bundleName}` |
| TC-1.1-5 | mkdir 失败 | ER-2 | 返回 ERR_APPEXECFWK_PRINT_SERVICE_DIR_CREATE_FAILED |
| TC-1.1-6 | chown 失败 | ER-3 | 返回 ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHOWN_FAILED |
| TC-1.1-7 | chmod 失败 | ER-4 | 返回 ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHMOD_FAILED |
| TC-1.1-8 | 参数校验失败（空 bundleName） | EX-2 | 返回 ERR_APPEXECFWK_INSTALLD_PARAM_ERROR |

### 验证检查清单

- [ ] 所有 AC（AC-1 ~ AC-5）有对应的测试覆盖
- [ ] 测试通过
- [ ] 构建通过
- [ ] 静态检查通过
- [ ] 未修改文件范围外的内容

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R installd` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-1.2：在 InstalldService 中添加删除打印服务目录接口

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-1.2 |
| 标题 | 在 InstalldService 中添加删除打印服务目录接口 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | services/bundlemgr/src/ipc/ → services/bundlemgr/src/installd/ |
| 优先级 | P0 |
| 依赖 | 无 |
| 复杂度 | 低 |
| 执行方式 | 可独立执行 |
| 预估工时 | 2h |
| 状态 | Pending |

### 做什么

1. 在 InstalldService 中新增 `RemovePrintServiceDir` 接口
2. 实现目录删除核心逻辑（ForceRemoveDirectory）
3. 处理目录不存在、删除失败等异常场景

### 不做什么

- 不实现安装/卸载流程集成（属于 TASK-2.2、TASK-3.1）
- 删除失败不阻塞卸载流程（记录警告，见 ADR-3、BR-5）

### AC 映射

| AC | 来源 | 本 Task 覆盖范围 | 验证方式 |
|----|------|------------------|----------|
| AC-6 | spec.md US-2 | WHEN 卸载驱动应用 THEN 删除对应的打印服务目录 | 单元测试 |
| AC-9 | spec.md US-2 | WHEN 目录删除失败 THEN 记录警告日志，不阻塞卸载流程 | 单元测试 |

### 规则映射

| Rule ID | Must / Must Not | 本 Task 摘要 |
|---------|-----------------|-------------|
| FR-6 | Must | 删除打印服务目录（ForceRemoveDirectory） |
| ER-5 | Must | 删除失败返回错误码，记录警告 |
| BR-5 | Must | 目录操作失败不阻塞卸载（本层返回错误码，调用方负责不阻塞） |

### 前置依赖

| 类型 | 编号 | 原因 |
|------|------|------|
| Design | design.md | 卸载调用链路设计 |
| Spec | spec.md | FR-6, ER-5 定义删除功能边界 |

### 完成判据

- `RemovePrintServiceDir` 接口实现并通过编译
- 删除逻辑正确处理正常和异常场景
- 删除失败时记录警告日志并返回错误码

### 停止条件

- 发现 ForceRemoveDirectory 不适用于非空目录嵌套场景，需确认 Installd 现有工具能力

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/bundlemgr/include/ipc/installd_interface.h` | 新增 RemovePrintServiceDir 接口声明 |
| 修改 | `services/bundlemgr/include/ipc/installd_host.h` | 新增宿主端声明 |
| 修改 | `services/bundlemgr/include/ipc/installd_proxy.h` | 新增代理端声明 |
| 修改 | `services/bundlemgr/src/ipc/installd_host_impl.cpp` | 新增宿主端实现（接口码 80） |
| 修改 | `services/bundlemgr/src/ipc/installd_proxy.cpp` | 新增代理端实现 |
| 修改 | `services/bundlemgr/src/installd/installd_operator.h` | 新增 RemovePrintServiceDir 声明 |
| 修改 | `services/bundlemgr/src/installd/installd_operator.cpp` | 新增 RemovePrintServiceDir 核心逻辑 |

### 代码变更规格

#### 修改文件: `services/bundlemgr/src/installd/installd_operator.cpp`

**变更原因：** 实现 RemovePrintServiceDir 核心业务逻辑

**目标代码（伪代码）：**
```cpp
ErrCode InstalldOperator::RemovePrintServiceDir(
    const std::string& bundleName, int32_t userId, int32_t appIndex)
{
    // 1. 参数校验
    if (bundleName.empty() || userId < 0) {
        APP_LOGE("Invalid parameters");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    // 2. 构建目录路径
    std::string baseDir = "/data/service/el1/" + std::to_string(userId) + "/print_service/data";
    std::string bundleDir = baseDir + "/" + GetBundleDirName(bundleName, appIndex);

    // 3. 目录不存在时直接返回成功
    if (access(bundleDir.c_str(), F_OK) != 0) {
        APP_LOGW("Print service dir not exists: %{public}s", bundleDir.c_str());
        return ERR_OK;
    }

    // 4. 删除目录
    if (!ForceRemoveDirectory(bundleDir)) {
        APP_LOGW("Failed to remove print service dir: %{public}s", bundleDir.c_str());
        return ERR_APPEXECFWK_PRINT_SERVICE_DIR_REMOVE_FAILED;
    }

    APP_LOGI("Remove print service dir success: %{public}s", bundleDir.c_str());
    return ERR_OK;
}
```

### 测试用例

| 用例 ID | 描述 | 覆盖 AC | 期望结果 |
|---------|------|---------|----------|
| TC-1.2-1 | 正常删除目录 | AC-6 | 目录删除成功，返回 ERR_OK |
| TC-1.2-2 | 目录不存在 | AC-6 | 返回 ERR_OK（不视为错误） |
| TC-1.2-3 | 删除失败 | AC-9 | 记录警告日志，返回错误码 |
| TC-1.2-4 | 分身应用目录删除 | AC-6 | 正确构建分身目录名并删除 |
| TC-1.2-5 | 参数校验失败 | EX-2 | 返回 ERR_APPEXECFWK_INSTALLD_PARAM_ERROR |

### 验证检查清单

- [ ] AC-6、AC-9 有对应测试覆盖
- [ ] 测试通过
- [ ] 构建通过

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R installd` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-1.3：在 InstalldService 中添加验证/修复目录权限接口

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-1.3 |
| 标题 | 在 InstalldService 中添加验证/修复目录权限接口 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | services/bundlemgr/src/installd/ |
| 优先级 | P0 |
| 依赖 | TASK-1.1（复用 GetBundleDirName 和 VerifyAndFixPermission） |
| 复杂度 | 低 |
| 执行方式 | 依赖 TASK-1.1 完成 |
| 预估工时 | 2h |
| 状态 | Pending |

### 做什么

1. 在 InstalldService 中新增 `VerifyPrintServiceDirPermission` 接口
2. 验证目录的属主、属组、权限是否符合规范
3. 不符合时自动修复为正确的属主（appUid）、属组（3823）、权限（02750）
4. 处理目录不存在、权限修复失败等异常场景

### 不做什么

- 不创建新目录（仅验证和修复已有目录）
- 不删除目录

### AC 映射

| AC | 来源 | 本 Task 覆盖范围 | 验证方式 |
|----|------|------------------|----------|
| AC-5 | spec.md US-1 | WHEN 目录已存在 THEN 验证并修复权限 | 单元测试 |
| AC-2 | spec.md US-1 | 修复后属主为应用 uid，属组为 3823 | 单元测试 |
| AC-3 | spec.md US-1 | 修复后权限为 02750 | 单元测试 |

### 规则映射

| Rule ID | Must / Must Not | 本 Task 摘要 |
|---------|-----------------|-------------|
| FR-5 | Must | 验证修复已有目录权限（stat + chown + chmod） |
| BR-2 | Must | 属组固定为 3823 |
| BR-3 | Must | 权限固定为 02750 |
| RC-3 | Must | OTA 后权限不一致时重新设置 |

### 前置依赖

| 类型 | 编号 | 原因 |
|------|------|------|
| Task | TASK-1.1 | 复用 GetBundleDirName、VerifyAndFixPermission 方法 |

### 停止条件

- 发现 stat 获取的权限信息不完整，需确认 stat 系统调用在 Installd 进程的可用性

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/bundlemgr/src/installd/installd_operator.h` | 新增 VerifyPrintServiceDirPermission 声明 |
| 修改 | `services/bundlemgr/src/installd/installd_operator.cpp` | 新增验证/修复逻辑 |
| 修改 | `services/bundlemgr/src/ipc/installd_host_impl.cpp` | 新增 IPC 宿主端 |
| 修改 | `services/bundlemgr/src/ipc/installd_proxy.cpp` | 新增 IPC 代理端 |

### 测试用例

| 用例 ID | 描述 | 期望结果 |
|---------|------|----------|
| TC-1.3-1 | 权限正确时不修改 | 返回 ERR_OK，权限不变 |
| TC-1.3-2 | 属主错误时修复 | 修复为正确 appUid |
| TC-1.3-3 | 权限位错误时修复 | 修复为 02750 |
| TC-1.3-4 | 目录不存在 | 返回错误码 |

### 验证检查清单

- [ ] AC-2、AC-3、AC-5 有对应测试覆盖
- [ ] 测试通过
- [ ] 构建通过

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R installd` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-1.4：InstalldClient 添加对应接口调用

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-1.4 |
| 标题 | InstalldClient 添加对应接口调用 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | services/bundlemgr/src/installd/ → services/bundlemgr/include/ipc/ |
| 优先级 | P0 |
| 依赖 | TASK-1.1, TASK-1.2, TASK-1.3 |
| 复杂度 | 低 |
| 执行方式 | 依赖 Phase 1 前三个 Task 完成 |
| 预估工时 | 2h |
| 状态 | Pending |

### 做什么

1. 在 InstalldClient 中封装 `CreatePrintServiceDir` 调用
2. 在 InstalldClient 中封装 `RemovePrintServiceDir` 调用
3. 在 InstalldClient 中封装 `VerifyPrintServiceDirPermission` 调用
4. 添加参数校验和 IPC 错误处理

### 不做什么

- 不实现业务逻辑（仅封装 IPC 调用）

### AC 映射

| AC | 来源 | 本 Task 覆盖范围 | 验证方式 |
|----|------|------------------|----------|
| AC-1 | spec.md | 通过 Client 调用 CreatePrintServiceDir 成功 | 单元测试 |
| AC-6 | spec.md | 通过 Client 调用 RemovePrintServiceDir 成功 | 单元测试 |

### 停止条件

- 发现 InstalldClient 连接状态管理机制与预期不符，需确认 IPC 重连策略

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/bundlemgr/include/ipc/installd_client.h` | 新增 3 个接口声明 |
| 修改 | `services/bundlemgr/src/ipc/installd_client.cpp` | 新增 3 个接口实现（调用 proxy） |

### 测试用例

| 用例 ID | 描述 | 期望结果 |
|---------|------|----------|
| TC-1.4-1 | CreatePrintServiceDir 调用成功 | 通过 proxy 转发成功 |
| TC-1.4-2 | RemovePrintServiceDir 调用成功 | 通过 proxy 转发成功 |
| TC-1.4-3 | VerifyPrintServiceDirPermission 调用成功 | 通过 proxy 转发成功 |
| TC-1.4-4 | IPC 连接失败 | 返回连接错误 |

### 验证检查清单

- [ ] 3 个 Client 接口均实现
- [ ] 测试通过
- [ ] 构建通过

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R installd` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-2.1：在 BaseBundleInstaller 中添加驱动应用检测逻辑

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-2.1 |
| 标题 | 在 BaseBundleInstaller 中添加驱动应用检测逻辑 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | services/bundlemgr/src/ |
| 优先级 | P0 |
| 依赖 | TASK-1.4 |
| 复杂度 | 低 |
| 预估工时 | 2h |
| 状态 | Pending |

### 做什么

1. 在 BaseBundleInstaller 中添加 `IsDriverApplication` 检测方法
2. 判断当前安装的 HAP 是否包含 DRIVER 类型的 ExtensionAbility
3. 提取 bundleName、appIndex、appUid 等参数供后续调用使用

### 不做什么

- 不调用 CreatePrintServiceDir（属于 TASK-2.2）

### AC 映射

| AC | 来源 | 本 Task 覆盖范围 | 验证方式 |
|----|------|------------------|----------|
| AC-1 | spec.md | 检测到驱动应用后触发后续流程 | 单元测试 |
| BR-1 | spec.md | 仅驱动应用触发（ExtensionAbilityType == DRIVER） | 单元测试 |

### 停止条件

- 发现 ExtensionAbilityType 枚举中无 DRIVER 类型，需确认驱动应用标识方式

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/bundlemgr/include/base_bundle_installer.h` | 新增 IsDriverApplication 声明 |
| 修改 | `services/bundlemgr/src/base_bundle_installer.cpp` | 新增驱动应用检测逻辑 |

### 测试用例

| 用例 ID | 描述 | 期望结果 |
|---------|------|----------|
| TC-2.1-1 | 安装驱动应用 | 返回 true |
| TC-2.1-2 | 安装非驱动应用 | 返回 false |
| TC-2.1-3 | 多模块混合（含驱动+非驱动） | 返回 true |

### 验证检查清单

- [ ] 驱动应用检测逻辑实现
- [ ] 测试通过
- [ ] 构建通过

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R bundle_installer` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-2.2：集成打印服务目录创建到安装流程

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-2.2 |
| 标题 | 集成打印服务目录创建到安装流程 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | services/bundlemgr/src/ |
| 优先级 | P0 |
| 依赖 | TASK-2.1 |
| 复杂度 | 中 |
| 预估工时 | 4h |
| 状态 | Pending |

### 做什么

1. 在 BaseBundleInstaller::ProcessBundleInstall 中，驱动应用安装成功后调用 CreatePrintServiceDir
2. 传递 bundleName、userId、appIndex、appUid 参数
3. 处理调用失败：记录警告日志，不阻塞安装流程（ADR-3、BR-5）

### 不做什么

- 不修改 InstalldService 接口（属于 TASK-1.1）
- 不处理分身应用逻辑（属于 TASK-2.3）

### AC 映射

| AC | 来源 | 本 Task 覆盖范围 | 验证方式 |
|----|------|------------------|----------|
| AC-1 | spec.md | 驱动应用安装时触发目录创建 | 集成测试 |
| AC-9 | spec.md | 创建失败不阻塞安装 | 单元测试 |

### 规则映射

| Rule ID | Must / Must Not | 本 Task 摘要 |
|---------|-----------------|-------------|
| BR-5 | Must | 目录操作失败不阻塞安装（记录警告继续） |
| EX-1 | Must | 创建失败记录警告，继续安装 |
| OH-ARCH-LAYERING | Must | 通过 InstalldClient 调用，不直接操作文件系统 |

### 停止条件

- 发现安装流程集成点与 ProcessBundleInstall 生命周期不匹配，需确认调用时机

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/bundlemgr/include/base_bundle_installer.h` | 新增 CreatePrintServiceDir 方法声明 |
| 修改 | `services/bundlemgr/src/base_bundle_installer.cpp` | 集成目录创建到安装流程 |

### 测试用例

| 用例 ID | 描述 | 期望结果 |
|---------|------|----------|
| TC-2.2-1 | 驱动应用安装成功 | 调用 CreatePrintServiceDir，安装正常完成 |
| TC-2.2-2 | CreatePrintServiceDir 失败 | 记录警告，安装正常完成（不阻塞） |
| TC-2.2-3 | 非驱动应用安装 | 不调用 CreatePrintServiceDir |

### 验证检查清单

- [ ] 安装流程集成完成
- [ ] 失败不阻塞安装流程
- [ ] 测试通过
- [ ] 构建通过

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R bundle_installer` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-2.3：添加分身应用目录名处理逻辑

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-2.3 |
| 标题 | 添加分身应用目录名处理逻辑 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | services/bundlemgr/src/ |
| 优先级 | P0 |
| 依赖 | TASK-2.2 |
| 复杂度 | 低 |
| 预估工时 | 2h |
| 状态 | Pending |

### 做什么

1. 在安装流程中正确传递 appIndex 参数给 CreatePrintServiceDir
2. 确保 appIndex > 0 时目录名格式为 `+clone-{appIndex}+{bundleName}`
3. 复用 BundleCloneCommonHelper::GetCloneDataDir 生成目录名

### AC 映射

| AC | 来源 | 本 Task 覆盖范围 | 验证方式 |
|----|------|------------------|----------|
| AC-7 | spec.md US-3 | 分身驱动应用创建 `+clone-{appIndex}+{bundleName}` 格式目录 | 单元测试 |

### 停止条件

- 发现 GetCloneDataDir 接口不存在或签名不匹配，需确认分身目录名生成接口

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/bundlemgr/src/base_bundle_installer.cpp` | 传递 appIndex 参数 |
| 依赖 | `services/bundlemgr/include/inner_bundle_clone_common.h` | 复用 GetCloneDataDir |

### 测试用例

| 用例 ID | 描述 | 期望结果 |
|---------|------|----------|
| TC-2.3-1 | 普通应用（appIndex=0） | 目录名为 bundleName |
| TC-2.3-2 | 分身应用（appIndex=1） | 目录名为 `+clone-1+{bundleName}` |
| TC-2.3-3 | 多分身（appIndex=2） | 目录名为 `+clone-2+{bundleName}` |

### 验证检查清单

- [ ] AC-7 有对应测试覆盖
- [ ] 测试通过
- [ ] 构建通过

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R bundle_installer` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-2.4：实现目录权限验证和修复逻辑

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-2.4 |
| 标题 | 实现目录权限验证和修复逻辑 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | services/bundlemgr/src/ |
| 优先级 | P1 |
| 依赖 | TASK-2.2 |
| 复杂度 | 低 |
| 预估工时 | 3h |
| 状态 | Pending |

### 做什么

1. 在安装流程中，目录创建成功后调用 VerifyPrintServiceDirPermission 验证权限
2. 确保安装完成后权限符合规范（属主/属组/权限位）
3. 记录验证结果

### 不做什么

- 不修改 InstalldService 层的验证逻辑（属于 TASK-1.3）

### 停止条件

- 发现安装后权限验证影响安装性能，需评估是否异步执行

### AC 映射

| AC | 来源 | 本 Task 覆盖范围 | 验证方式 |
|----|------|------------------|----------|
| AC-2 | spec.md | 安装后验证属主属组 | 单元测试 |
| AC-3 | spec.md | 安装后验证权限位 | 单元测试 |
| AC-5 | spec.md | 权限不符时自动修复 | 单元测试 |

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/bundlemgr/src/base_bundle_installer.cpp` | 安装后添加验证调用 |

### 测试用例

| 用例 ID | 描述 | 期望结果 |
|---------|------|----------|
| TC-2.4-1 | 权限正确 | 验证通过 |
| TC-2.4-2 | 权限错误 | 自动修复 |

### 验证检查清单

- [ ] AC-2、AC-3、AC-5 有对应测试覆盖
- [ ] 测试通过
- [ ] 构建通过

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R bundle_installer` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-3.1：在卸载流程中集成目录删除逻辑

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-3.1 |
| 标题 | 在卸载流程中集成目录删除逻辑 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | services/bundlemgr/src/ |
| 优先级 | P0 |
| 依赖 | TASK-1.4 |
| 复杂度 | 低 |
| 预估工时 | 2h |
| 状态 | Pending |

### 做什么

1. 在 BaseBundleInstaller::ProcessBundleUninstall 中，驱动应用卸载时调用 RemovePrintServiceDir
2. 传递 bundleName、userId、appIndex 参数
3. 删除失败时记录警告日志，不阻塞卸载流程（BR-5）

### 停止条件

- 发现卸载流程中无法获取 bundleName/appIndex 参数，需确认参数传递链路

### AC 映射

| AC | 来源 | 本 Task 覆盖范围 | 验证方式 |
|----|------|------------------|----------|
| AC-6 | spec.md US-2 | 卸载驱动应用时删除对应目录 | 单元测试/集成测试 |
| AC-9 | spec.md US-2 | 删除失败不阻塞卸载 | 单元测试 |

### 规则映射

| Rule ID | Must / Must Not | 本 Task 摘要 |
|---------|-----------------|-------------|
| FR-6 | Must | 调用 RemovePrintServiceDir 删除目录 |
| BR-5 | Must | 删除失败不阻塞卸载 |
| ER-5 | Must | 删除失败记录警告 |
| OH-ARCH-LAYERING | Must | 通过 InstalldClient 调用 |

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/bundlemgr/include/base_bundle_installer.h` | 新增 DeletePrintServiceDir 方法声明 |
| 修改 | `services/bundlemgr/src/base_bundle_installer.cpp` | 集成目录删除到卸载流程 |

### 测试用例

| 用例 ID | 描述 | 期望结果 |
|---------|------|----------|
| TC-3.1-1 | 驱动应用卸载成功 | 调用 RemovePrintServiceDir，卸载正常完成 |
| TC-3.1-2 | RemovePrintServiceDir 失败 | 记录警告，卸载正常完成 |
| TC-3.1-3 | 非驱动应用卸载 | 不调用 RemovePrintServiceDir |
| TC-3.1-4 | 分身应用卸载 | 正确构建分身目录名并删除 |

### 验证检查清单

- [ ] AC-6、AC-9 有对应测试覆盖
- [ ] 删除失败不阻塞卸载
- [ ] 测试通过
- [ ] 构建通过

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R bundle_installer` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-4.1：在 BMSEventHandler::ProcessRebootBundle 中添加存量应用扫描

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-4.1 |
| 标题 | 在 BMSEventHandler::ProcessRebootBundle 中添加存量应用扫描 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | services/bundlemgr/src/ |
| 优先级 | P1 |
| 依赖 | TASK-2.2 |
| 复杂度 | 中 |
| 预估工时 | 3h |
| 状态 | Pending |

### 做什么

1. 在 BMSEventHandler::ProcessRebootBundle 中添加存量驱动应用扫描逻辑
2. 遍历所有已安装应用，识别驱动类型应用
3. 收集需要检查/修复的驱动应用列表

### 不做什么

- 不实际修复权限（属于 TASK-4.2）

### 停止条件

- 发现 ProcessRebootBundle 不适合添加扫描逻辑，需确认替代入口点

### AC 映射

| AC | 来源 | 本 Task 覆盖范围 | 验证方式 |
|----|------|------------------|----------|
| AC-8 | spec.md US-4 | 设备 OTA 升级后扫描驱动应用 | 集成测试 |

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/bundlemgr/include/bundle_mgr_service_event_handler.h` | 新增 ProcessCheckPrintServiceDir 声明 |
| 修改 | `services/bundlemgr/src/bundle_mgr_service_event_handler.cpp` | 添加扫描逻辑 |

### 测试用例

| 用例 ID | 描述 | 期望结果 |
|---------|------|----------|
| TC-4.1-1 | 设备重启且有驱动应用 | 扫描到驱动应用列表 |
| TC-4.1-2 | 设备重启但无驱动应用 | 列表为空，不触发后续处理 |
| TC-4.1-3 | 多用户场景 | 扫描所有用户的驱动应用 |

### 验证检查清单

- [ ] AC-8 有对应测试覆盖
- [ ] 测试通过
- [ ] 构建通过

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R reboot_handler` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-4.2：实现存量驱动应用目录补建逻辑

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-4.2 |
| 标题 | 实现存量驱动应用目录补建逻辑 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | services/bundlemgr/src/ |
| 优先级 | P1 |
| 依赖 | TASK-4.1 |
| 复杂度 | 中 |
| 预估工时 | 3h |
| 状态 | Pending |

### 做什么

1. 实现 InnerProcessCheckPrintServiceDir 方法
2. 对扫描到的每个驱动应用调用 CreatePrintServiceDir（复用创建接口，目录已存在时会验证修复权限）
3. 记录修复结果日志

### 停止条件

- 发现存量应用信息不完整（缺少 appUid），需确认数据获取方式

### AC 映射

| AC | 来源 | 本 Task 覆盖范围 | 验证方式 |
|----|------|------------------|----------|
| AC-8 | spec.md US-4 | OTA 后修复存量驱动应用目录权限 | 集成测试 |

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/bundlemgr/src/bundle_mgr_service_event_handler.cpp` | 实现目录补建逻辑 |

### 测试用例

| 用例 ID | 描述 | 期望结果 |
|---------|------|----------|
| TC-4.2-1 | 存量驱动应用目录不存在 | 创建目录 |
| TC-4.2-2 | 存量驱动应用目录存在但权限错误 | 修复权限 |
| TC-4.2-3 | 补建失败 | 记录警告，不影响其他应用 |

### 验证检查清单

- [ ] AC-8 有对应测试覆盖
- [ ] 测试通过
- [ ] 构建通过

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R reboot_handler` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-5.1：添加新错误码定义

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-5.1 |
| 标题 | 添加新错误码定义 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | interfaces/inner_api/appexecfwk_base/include/ |
| 优先级 | P0 |
| 依赖 | 无（可独立执行） |
| 复杂度 | 低 |
| 预估工时 | 1h |
| 状态 | Pending |

### 做什么

1. 在 `appexecfwk_errors.h` 中定义打印服务目录操作相关错误码
2. 错误码范围：`ERR_APPEXECFWK_BUNDLEMGR_ERR_OFFSET + 0x0500` 起

### 停止条件

- 发现错误码范围 0x0500 与已有定义冲突，需重新分配范围

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `interfaces/inner_api/appexecfwk_base/include/appexecfwk_errors.h` | 新增 5 个错误码 |

> **注：** 错误码定义与 TASK-1.1 的代码变更规格中已包含，本 Task 可与 TASK-1.1 合并执行，或独立提前完成。

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | 编译检查 | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-5.2：添加日志记录

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-5.2 |
| 标题 | 添加日志记录 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | 涉及的所有模块 |
| 优先级 | P0 |
| 依赖 | TASK-2.2, TASK-3.1, TASK-4.2 |
| 复杂度 | 低 |
| 预估工时 | 2h |
| 状态 | Pending |

### 做什么

1. 在安装流程中添加打印服务目录创建的日志记录（成功/失败/警告）
2. 在卸载流程中添加目录删除的日志记录
3. 在 OTA 场景中添加目录补建的日志记录
4. 确保日志遵循 `%{public}` / `%{private}` 规范

### 不做什么

- 不修改业务逻辑（仅补充日志）

### 停止条件

- 发现日志量过大影响系统性能，需调整日志级别策略

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/bundlemgr/src/base_bundle_installer.cpp` | 安装/卸载流程日志 |
| 修改 | `services/bundlemgr/src/bundle_mgr_service_event_handler.cpp` | OTA 场景日志 |
| 修改 | `services/bundlemgr/src/installd/installd_operator.cpp` | 底层操作日志（已在 TASK-1.1 中覆盖） |

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `hilog -T BMS` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target` | PASS/FAIL |

---

## TASK-6.1：单元测试

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-6.1 |
| 标题 | 单元测试 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | test/unittest/ |
| 优先级 | P0 |
| 依赖 | TASK-5.2 |
| 复杂度 | 中 |
| 预估工时 | 4h |
| 状态 | Pending |

### 做什么

1. 编写 InstalldOperator 的单元测试（CreatePrintServiceDir、RemovePrintServiceDir、VerifyPrintServiceDirPermission）
2. 编写 BaseBundleInstaller 的单元测试（IsDriverApplication、安装/卸载流程集成）
3. 覆盖所有 AC 和异常场景
4. 目标覆盖率 ≥ 80%

### 停止条件

- 测试环境无法模拟目录权限操作，需搭建 mock 环境

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 新增 | `test/unittest/bms_print_service_operator_test.cpp` | 单元测试文件 |
| 修改 | `test/unittest/BUILD.gn` | 新增测试 target |

### 测试覆盖矩阵

| AC | 测试用例 |
|----|----------|
| AC-1 | TC-1.1-1（创建成功） |
| AC-2 | TC-1.1-1（属主检查） |
| AC-3 | TC-1.1-1（权限检查） |
| AC-4 | TC-1.1-2（父目录不存在） |
| AC-5 | TC-1.1-3（目录已存在修复） |
| AC-6 | TC-1.2-1（删除成功）、TC-3.1-1（卸载集成） |
| AC-7 | TC-1.1-4（分身目录名） |
| AC-8 | TC-4.2-1/2（OTA 修复） |
| AC-9 | TC-1.2-3（删除失败不阻塞） |

### 验证检查清单

- [ ] 覆盖率 ≥ 80%
- [ ] 所有 AC 有对应测试
- [ ] 测试全部通过

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R print_service` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target test/unittest:bms_print_service_operator_test` | PASS/FAIL |

---

## TASK-6.2：集成测试

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-6.2 |
| 标题 | 集成测试 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | test/moduletest/ |
| 优先级 | P0 |
| 依赖 | TASK-6.1 |
| 复杂度 | 中 |
| 预估工时 | 4h |
| 状态 | Pending |

### 做什么

1. 编写端到端集成测试：安装驱动应用 → 验证目录创建 → 卸载 → 验证目录删除
2. 编写分身应用集成测试
3. 验证 IPC 调用链路完整性

### 停止条件

- 集成测试依赖 InstalldService 运行，测试环境不具备条件

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 新增 | `test/moduletest/bms_print_service_integration_test.cpp` | 集成测试文件 |

### 测试场景

| 场景 | 验证点 |
|------|--------|
| 驱动应用安装 | 目录创建、权限正确 |
| 驱动应用卸载 | 目录删除 |
| 分身应用安装 | 目录名格式正确 |
| 非驱动应用安装 | 不创建目录 |

### 验证检查清单

- [ ] 集成测试全部通过
- [ ] 覆盖安装/卸载/分身场景

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R print_service_integration` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target test/unittest:bms_print_service_operator_test` | PASS/FAIL |

---

## TASK-6.3：OTA 升级测试

### 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-6.3 |
| 标题 | OTA 升级测试 |
| 关联 Feature | FEAT-PRINT-001 |
| 目标模块 | test/systemtest/ |
| 优先级 | P1 |
| 依赖 | TASK-6.2 |
| 复杂度 | 中 |
| 预估工时 | 2h |
| 状态 | Pending |

### 做什么

1. 模拟 OTA 升级场景：先安装驱动应用（旧版本无打印服务目录），触发重启后验证目录补建
2. 模拟 OTA 后权限修复场景
3. 验证多用户、分身应用场景

### 停止条件

- OTA 升级测试需要完整的系统环境，需确认测试设备可用性

### 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 新增 | `test/systemtest/bms_print_service_ota_test.cpp` | OTA 测试文件 |

### 测试场景

| 场景 | 验证点 |
|------|--------|
| OTA 后目录补建 | 存量驱动应用目录被创建 |
| OTA 后权限修复 | 权限不符合规范时自动修复 |
| OTA 多用户 | 所有用户的驱动应用被处理 |

### 验证检查清单

- [ ] OTA 场景测试通过
- [ ] 覆盖目录补建和权限修复场景

**完成证据：**

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 测试 | `ctest -R print_service_ota` | PASS/FAIL |
| 构建 | `./build.sh --product-name rk3568 --build-target test/unittest:bms_print_service_operator_test` | PASS/FAIL |

## BUILD.gn 变更

```
文件路径: test/unittest/BUILD.gn
变更说明: 新增 bms_print_service_operator_test.cpp 测试 target
```

## context-references

```yaml
context-queries:
  - repo: "openharmony/bundlemanager_bundle_framework"
    query: "InstalldService IPC interface pattern and interface code allocation"
  - repo: "openharmony/bundlemanager_bundle_framework"
    query: "BundleInstaller install/uninstall flow and driver application detection"
  - repo: "openharmony/bundlemanager_bundle_framework"
    query: "BundleCloneCommonHelper GetCloneDataDir interface for clone app directory naming"
```
