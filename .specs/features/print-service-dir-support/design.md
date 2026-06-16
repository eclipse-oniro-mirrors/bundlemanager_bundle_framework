# 架构设计

> 确认目标仓和模块的架构约束、关键设计决策、Spec 拆分方向。简单变更（单仓小修、无新 API）可跳过本文档。

## 设计元数据

| 字段 | 内容 |
|------|------|
| Design ID | DESIGN-PRINT-001 |
| 关联需求 | [proposal.md](proposal.md) |
| 关联 Epic | 无（独立特性） |
| 目标 Feature | print-service-dir-support |
| 复杂度 | 标准 |
| 目标版本 | OpenHarmony-5.0-Release |
| Owner | [待确认] |
| 状态 | Approved |

## 需求基线

需求基线详见 [proposal.md](proposal.md)。

| 项 | 补充说明 |
|----|----------|
| 功能范围 | 仅涉及 bundlemanager_bundle_framework 仓 |
| API 变更 | InnerApi 层，新增 InstalldService 接口 |
| 兼容性 | 向后兼容，仅新增接口 |

## 上下文和现状

### 涉及仓和模块

| 仓库 | 补充架构说明 |
|------|-------------|
| bundlemanager_bundle_framework | 负责应用包管理，InstalldService(SA 511) 处理特权文件操作 |

### 适用架构规则

| Rule ID | 适用原因 | 设计结论 | 验证方式 |
|---------|----------|----------|----------|
| OH-ARCH-LAYERING | BundleInstaller → InstalldService 跨层调用 | 通过 IPC 正确调用，符合分层架构 | 代码评审 |
| OH-ARCH-IPC-SAF | 跨进程调用 InstalldService | 使用现有的 IPC 框架，新增接口码 79/80 | 集成测试 |
| OH-ARCH-ERROR-LOG | 新增 5 个错误码 | 使用 BUNDLE_MGR_ERR_OFFSET + 0x0701 范围 | 单元测试 |

## 不涉及项承接

| 维度 | 设计结论 |
|------|----------|
| Public API 变更 | 不涉及，仅内部 InnerApi |
| 跨子系统协作 | 不涉及，仅 bundlemanager 内部 |
| 构建系统影响 | 仅新增测试 target，不影响现有构建 |

## 关键设计决策

| 决策 ID | 问题 | 推荐方案 | 探索过的替代方案 | 取舍理由 | 影响 |
|---------|------|----------|-----------------|----------|------|
| ADR-1 | 在哪一层实现目录创建？ | InstalldService (SA 511) | 备选1: BundleManagerService 直接创建<br>备选2: 打印服务负责创建 | InstalldService 已有特权操作能力，设置属主属组需要 root 权限 | 新增 IPC 接口 |
| ADR-2 | 父目录不存在时如何处理？ | 返回错误码，不自动创建 | 备选1: 自动创建父目录<br>备选2: 静默忽略 | print 服务目录应由打印服务负责，BMS 不应越权 | 调用方需处理错误 |
| ADR-3 | 目录创建失败是否阻塞安装？ | 记录警告，不阻塞安装 | 备选1: 阻塞安装流程<br>备选2: 抛出异常 | 降低安装失败率，提升用户体验，目录可后续修复 | 影响错误处理策略 |
| ADR-4 | 目录已存在时如何处理？ | 验证并修复权限 | 备选1: 直接返回成功<br>备选2: 删除重建 | 确保 OTA 升级后权限一致性，不影响已有数据 | 增加权限检查逻辑 |

## 设计骨架

### 骨架范围

| 骨架项 | 目标 | 不包含 | 验证方式 |
|--------|------|--------|----------|
| API/接口骨架 | InstalldService::CreatePrintServiceDir/RemovePrintServiceDir | 完整业务逻辑 | 编译通过 |
| 模块骨架 | installd_operator.cpp 中新增函数 | 复杂策略 | 单元测试通过 |
| 测试骨架 | 10 个测试用例覆盖主要场景 | 边界条件 | 测试通过 |

### 骨架 Spec 拆分

| Task ID | 目标 | 受影响文件 | AC |
|---------|------|------------|-----|
| TASK-SKELETON-1 | 建立 IPC 接口骨架 | installd_interface.h, installd_host.h, installd_proxy.h | WHEN 编译 THEN 接口签名正确 |
| TASK-SKELETON-2 | 建立实现函数骨架 | installd_operator.cpp | WHEN 调用 THEN 返回 ERR_OK |

## 后续 Task 拆分

| Task ID | 目标 | 受影响文件 | 依赖 |
|---------|------|------------|------|
| TASK-1.1 | 实现 CreatePrintServiceDir 核心逻辑 | installd_operator.cpp | design.md + spec.md Approved |
| TASK-1.2 | 集成到安装流程 | base_bundle_installer.cpp | TASK-1.1 完成 |
| TASK-1.3 | 集成到卸载流程 | base_bundle_installer.cpp | TASK-1.1 完成 |
| TASK-1.4 | 支持分身应用 | bundle_clone_installer.cpp | TASK-1.1 完成 |
| TASK-1.5 | OTA 场景支持 | bundle_mgr_service_event_handler.cpp | TASK-1.1 完成 |
| TASK-1.6 | 单元测试 | bms_print_service_operator_test.cpp | TASK-1.1 完成 |

## API 签名、Kit 与权限

> 本节承接 spec.md"API 变更分析"中识别的 API，给出签名、权限和实现细节。

### 新增 API

| API 签名 | 类型 | Kit | d.ts 位置 | 权限要求 | SysCap |
|----------|------|-----|-----------|----------|--------|
| `CreatePrintServiceDir(bundleName: string, userId: int32, appIndex: int32, appUid: uid_t) → ErrCode` | InnerApi | - | - | - | - |
| `RemovePrintServiceDir(bundleName: string, userId: int32, appIndex: int32) → ErrCode` | InnerApi | - | - | - | - |
| `VerifyPrintServiceDirPermission(bundleName: string, userId: int32, appIndex: int32, appUid: uid_t) → ErrCode` | InnerApi | - | - | - | - |

### 变更/废弃 API

无变更或废弃 API。

## 构建系统影响

### BUILD.gn 变更

```
文件路径: test/unittest/BUILD.gn
变更说明: 新增 bms_print_service_operator_test.cpp 测试 target
```

### bundle.json 变更

无新增 component，不影响现有依赖关系。

---

## 可选设计扩展

> 标准复杂度展开以下章节。

### 数据模型设计 — 目录结构

```
/data/service/el1/{userId}/print_service/data/{bundleDirName}
```

| 组件 | 格式 | 示例 |
|------|------|------|
| userId | 数字 | 100 |
| bundleDirName (普通) | {bundleName} | com.example.driver.print |
| bundleDirName (分身) | +clone-{appIndex}+{bundleName} | +clone-1+com.example.driver.print |

### 权限设计

| 属性 | 值 | 说明 |
|------|-----|------|
| 权限位 | 02750 | sticky bit + rwxr-x--- |
| 属主 | {appUid} | 应用 uid |
| 属组 | 3823 | PRINT_SERVICE_UID |

### 数据流/控制流 — 调用链路设计

#### 安装流程

```
BaseBundleInstaller::ProcessBundleInstall
  └── BaseBundleInstaller::CreatePrintServiceDir
        ├── BaseBundleInstaller::IsDriverApplication (检测驱动应用)
        └── InstalldClient::CreatePrintServiceDir
              └── InstalldProxy::CreatePrintServiceDir
                    └── InstalldHostImpl::CreatePrintServiceDir
                          ├── InstalldPermissionMgr::VerifyCallingPermission (权限校验)
                          └── InstalldOperator::CreatePrintServiceDir (核心实现)
```

#### 卸载流程

```
BaseBundleInstaller::ProcessBundleUninstall
  └── BaseBundleInstaller::DeletePrintServiceDir
        └── InstalldClient::RemovePrintServiceDir
              └── InstalldProxy::RemovePrintServiceDir
                    └── InstalldHostImpl::RemovePrintServiceDir
                          └── InstalldOperator::RemovePrintServiceDir
```

#### OTA 检查流程

```
BMSEventHandler::ProcessRebootBundle
  └── BMSEventHandler::ProcessCheckPrintServiceDir
        └── BMSEventHandler::InnerProcessCheckPrintServiceDir
              └── InstalldClient::CreatePrintServiceDir (修复权限)
```

### 异常传播时序图 — 错误处理设计

#### 错误码映射

| 场景 | 错误码 | 处理方式 |
|------|--------|----------|
| 父目录不存在 | ERR_APPEXECFWK_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS | 返回错误，不创建目录 |
| mkdir 失败 | ERR_APPEXECFWK_PRINT_SERVICE_DIR_CREATE_FAILED | 记录日志，返回错误 |
| chmod 失败 | ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHMOD_FAILED | 清理目录，返回错误 |
| chown 失败 | ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHOWN_FAILED | 记录日志，返回错误 |
| 删除失败 | ERR_APPEXECFWK_PRINT_SERVICE_DIR_REMOVE_FAILED | 记录警告，不阻塞卸载 |

#### 错误传播策略

```
InstalldOperator (底层)
  └── 返回具体错误码
        └── InstalldClient (中层)
              └── 记录日志，不阻塞安装流程
```

### 测试性设计

#### 单元测试覆盖

| 测试类别 | 覆盖场景 | 用例数 |
|----------|----------|--------|
| 正常流程 | 创建目录成功、删除目录成功 | 3 |
| 异常流程 | 父目录不存在、参数错误 | 3 |
| 边界条件 | 目录已存在、权限修复 | 3 |
| 分身应用 | 分身目录名格式 | 1 |

#### 集成测试场景

| 场景 | 验证点 |
|------|--------|
| 驱动应用安装 | 目录创建、权限正确 |
| 驱动应用卸载 | 目录删除 |
| 分身应用安装 | 目录名格式正确 |
| OTA 升级 | 存量目录权限修复 |

## 风险和开放问题

| 项 | 类型 | 影响 | 处理方式 | Owner |
|----|------|------|----------|-------|
| 目录创建失败 | 技术 | 中 | 异常处理和日志记录 | [待确认] |
| OTA 升级兼容性 | 技术 | 中 | 充分测试升级场景 | [待确认] |

## 设计审批

- [x] 需求基线已确认，设计覆盖 P0/P1 AC
- [x] 不涉及项已承接，N/A 和展开项都有结论
- [x] 涉及仓和模块职责清楚
- [x] 适用架构规则已识别并形成设计结论
- [x] 分层和子系统边界合规
- [x] API 变更有签名、权限、错误码和兼容性说明
- [x] BUILD.gn/bundle.json 影响明确
- [x] 设计输出和后续 Task 拆分明确
- [x] 关键设计决策有理由和影响说明
- [x] 风险和开放问题有 Owner

**结论:** 通过
