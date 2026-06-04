# 特性规格

> 固化用户可见行为和验收标准。复杂交互、状态机、异常流程可补充 Gherkin 场景。

> **不应包含：** InnerKit 接口定义、内部实现流程、中间件调用链路、框架层类名/方法名、内部性能指标（如函数执行时间、内存分配次数）。这些内容属于 design.md。Spec 只描述用户可见行为、API 契约和验收标准。

## 概述

| 属性 | 值 |
|------|-----|
| 特性名称 | 驱动应用打印服务目录管理 |
| 特性编号 | FEAT-PRINT-001 |
| 所属 Epic | 无 |
| 优先级 | P1 |
| 目标版本 | OpenHarmony-5.0-Release |
| SIG 归属 | SIG_ApplicationFramework |
| 状态 | Approved |
| 复杂度 | 标准 |

## 本次变更范围（Delta）

全新特性（lineage: new）。

| 类型 | 内容 | 说明 |
|------|------|------|
| ADDED | 驱动应用打印服务目录管理功能 | 涉及 bundlemanager_bundle_framework |

## 输入文档

| 文档 | 路径 | 状态 |
|------|------|------|
| Requirement | [proposal.md](proposal.md) | Approved |
| Design | [design.md](design.md) | Approved |

## 用户故事

### US-1: 驱动应用安装时创建打印服务目录

**作为** 系统开发者,
**我想要** 在驱动应用安装时自动创建打印服务专属目录,
**以便** 驱动应用能够存储打印相关的数据和配置文件。

**验收标准：**

- **AC-1:** WHEN 安装驱动应用 THEN 系统应当创建 `/data/service/el1/{userId}/print_service/data/{bundleName}` 目录
- **AC-2:** WHEN 创建目录 THEN 系统应当设置属主为应用 uid，属组为 3823
- **AC-3:** WHEN 创建目录 THEN 系统应当设置权限为 2750 (rwxr-x--- with sticky bit)
- **AC-4:** WHEN 父目录不存在 THEN 系统应当返回错误码 ERR_APPEXECFWK_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS
- **AC-5:** WHEN 目录已存在 THEN 系统应当验证并修复权限

### US-2: 驱动应用卸载时删除打印服务目录

**作为** 系统开发者,
**我想要** 在驱动应用卸载时自动删除打印服务专属目录,
**以便** 清理不再使用的目录资源。

**验收标准：**

- **AC-6:** WHEN 卸载驱动应用 THEN 系统应当删除对应的打印服务目录
- **AC-9:** WHEN 目录删除失败 THEN 系统应当记录警告日志，不阻塞卸载流程

### US-3: 支持分身应用的打印服务目录

**作为** 系统开发者,
**我想要** 为分身应用创建独立命名的打印服务目录,
**以便** 分身应用拥有独立的打印数据空间。

**验收标准：**

- **AC-7:** WHEN 安装分身驱动应用 THEN 系统应当创建名为 `+clone-{appIndex}+{bundleName}` 的目录

### US-4: OTA 升级后修复目录权限

**作为** 系统开发者,
**我想要** 在设备 OTA 升级后检查并修复现有驱动应用的打印服务目录权限,
**以便** 确保权限设置符合最新规范。

**验收标准：**

- **AC-8:** WHEN 设备 OTA 升级 THEN 系统应当遍历所有驱动应用并修复打印服务目录权限

## 验收追溯

| AC | 关联规则 | 关联 Task | 验证方式 | 证据 |
|----|----------|-----------|----------|------|
| AC-1 | FR-1 | TASK-1.1, TASK-1.2 | 单元测试/集成测试 | bms_print_service_operator_test.cpp |
| AC-2 | FR-2 | TASK-1.1 | 单元测试 | BmsPrintServiceOperatorTest_0001 |
| AC-3 | FR-3 | TASK-1.1 | 单元测试 | BmsPrintServiceOperatorTest_0001 |
| AC-4 | FR-4 | TASK-1.1 | 单元测试 | BmsPrintServiceOperatorTest_0002 |
| AC-5 | FR-5 | TASK-1.1 | 单元测试 | BmsPrintServiceOperatorTest_0003, BmsPrintServiceOperatorTest_0010 |
| AC-6 | FR-6 | TASK-1.3 | 单元测试/集成测试 | BmsPrintServiceOperatorTest_0006 |
| AC-7 | FR-7 | TASK-1.4 | 单元测试 | BmsPrintServiceOperatorTest_0004 |
| AC-8 | FR-8 | TASK-1.5 | 集成测试 | ProcessCheckPrintServiceDir |
| AC-9 | ER-1 | TASK-1.1, TASK-1.2, TASK-1.3 | 单元测试 | BmsPrintServiceOperatorTest_0009 |

## 业务规则

| 编号 | 规则描述 | 约束条件 | 关联 AC |
|------|----------|----------|---------|
| BR-1 | 仅驱动应用创建打印服务目录 | ExtensionAbilityType == DRIVER | AC-1, AC-6 |
| BR-2 | 目录属组固定为 3823 | PRINT_SERVICE_UID | AC-2 |
| BR-3 | 目录权限固定为 2750 | 包含 sticky bit | AC-3 |
| BR-4 | 父目录由打印服务负责创建 | 不自动创建父目录 | AC-4 |
| BR-5 | 目录操作失败不阻塞安装/卸载 | 记录警告日志 | AC-9 |

## 功能规则

| 编号 | 规则描述 | 触发条件 | 作用对象 | 关联 AC |
|------|----------|----------|----------|---------|
| FR-1 | 创建打印服务目录 | 驱动应用安装 | bundleName, userId, appUid | AC-1 |
| FR-2 | 设置目录属主属组 | 目录创建成功 | 目录 uid/gid | AC-2 |
| FR-3 | 设置目录权限 | 目录创建成功 | 目录 mode | AC-3 |
| FR-4 | 检查父目录存在性 | 创建目录前 | /data/service/el1/{userId}/print_service/data | AC-4 |
| FR-5 | 验证修复已有目录权限 | 目录已存在 | 已有目录 | AC-5 |
| FR-6 | 删除打印服务目录 | 驱动应用卸载 | bundleName, userId | AC-6 |
| FR-7 | 生成分身应用目录名 | appIndex > 0 | 目录名 | AC-7 |
| FR-8 | OTA 升级后检查修复 | 设备重启 | 所有驱动应用 | AC-8 |

## 异常/豁免规则

| 编号 | 异常码/枚举 | 规则描述 | 触发条件 | 超时阈值 | 处理结果 | 关联 AC |
|------|-------------|----------|----------|----------|----------|---------|
| ER-1 | ERR_APPEXECFWK_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS | 父目录不存在 | access(baseDir) != 0 | N/A | 返回错误，不创建目录 | AC-4 |
| ER-2 | ERR_APPEXECFWK_PRINT_SERVICE_DIR_CREATE_FAILED | 目录创建失败 | mkdir() != 0 | N/A | 返回错误 | AC-9 |
| ER-3 | ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHOWN_FAILED | 设置属主属组失败 | chown() != 0 | N/A | 返回错误 | AC-9 |
| ER-4 | ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHMOD_FAILED | 设置权限失败 | chmod() != 0 | N/A | 清理目录，返回错误 | AC-9 |
| ER-5 | ERR_APPEXECFWK_PRINT_SERVICE_DIR_REMOVE_FAILED | 删除目录失败 | ForceRemoveDirectory() == false | N/A | 记录警告，不阻塞卸载 | AC-6, AC-9 |
| EX-1 | 目录操作失败 | 不阻塞安装流程 | 任何创建失败 | N/A | 记录警告，继续安装 | AC-9 |
| EX-2 | 参数校验失败 | 返回参数错误 | bundleName 为空或 userId/appUid < 0 | N/A | 返回 ERR_APPEXECFWK_INSTALLD_PARAM_ERROR | - |

## 恢复契约

| 编号 | 触发条件 | 恢复策略 | 恢复结果 | 约束 |
|------|----------|----------|----------|------|
| RC-1 | 目录创建失败 | 不阻塞安装流程 | 安装继续，目录缺失 | 记录警告日志 |
| RC-2 | 目录权限设置失败 | 清理已创建目录 | 返回错误，目录不存在 | 仅在 chmod 失败时清理 |
| RC-3 | OTA 升级后权限不一致 | 重新设置权限 | 权限修复为正确值 | 在下次设备重启时检查 |

## 验证映射

| 编号 | 对应规格项 | 验证方式 | 验证重点 |
|------|------------|----------|----------|
| VM-1 | FR-1 / AC-1 | 单元测试 | 目录创建成功 |
| VM-2 | FR-2, FR-3 / AC-2, AC-3 | 单元测试 | 属主属组权限正确 |
| VM-3 | FR-4 / AC-4 | 单元测试 | 父目录不存在返回错误 |
| VM-4 | FR-5 / AC-5 | 单元测试 | 已有目录权限修复 |
| VM-5 | FR-6 / AC-6 | 单元测试 | 目录删除成功 |
| VM-6 | FR-7 / AC-7 | 单元测试 | 分身目录名格式 |
| VM-7 | FR-8 / AC-8 | 集成测试 | OTA 场景权限修复 |
| VM-8 | EX-1 / AC-9 | 单元测试 | 失败不阻塞流程 |

## API 变更分析

### 新增 API

| API 名称 | 开放范围 | 入参概要 | 返回值 | 错误码范围 | 功能描述 | 关联 AC |
|----------|----------|----------|--------|------------|----------|---------|
| CreatePrintServiceDir | InnerApi | bundleName: string, userId: int32, appIndex: int32, appUid: uid_t | ErrCode | ERR_APPEXECFWK_PRINT_SERVICE_* | 创建驱动应用打印服务目录 | AC-1, AC-2, AC-3, AC-4, AC-5 |
| RemovePrintServiceDir | InnerApi | bundleName: string, userId: int32, appIndex: int32 | ErrCode | ERR_APPEXECFWK_PRINT_SERVICE_* | 删除驱动应用打印服务目录 | AC-6 |

### 错误码定义

| 错误码名称 | 值 | 含义 | 关联 AC |
|-----------|-----|------|---------|
| ERR_APPEXECFWK_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS | 8521473 | 父目录不存在 | AC-4 |
| ERR_APPEXECFWK_PRINT_SERVICE_DIR_CREATE_FAILED | 8521474 | 目录创建失败 | - |
| ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHOWN_FAILED | 8521475 | 设置属主属组失败 | - |
| ERR_APPEXECFWK_PRINT_SERVICE_DIR_CHMOD_FAILED | 8521476 | 设置权限失败 | - |
| ERR_APPEXECFWK_PRINT_SERVICE_DIR_REMOVE_FAILED | 8521477 | 删除目录失败 | AC-6 |

## 兼容性声明

- **已有 API 行为变更:** 否，仅新增 InnerApi 接口
- **配置文件格式变更:** 否
- **数据存储格式变更:** 否，新增目录结构由系统管理
- **最低支持版本:** OpenHarmony-5.0-Release
- **API 版本号策略:** N/A（无 Public/System API）

### OTA 兼容性

| 场景 | 处理方式 | 说明 |
|------|----------|------|
| 新装设备 | 正常创建 | 按标准流程创建目录 |
| OTA 升级 | 检查修复 | 设备重启后检查并修复权限 |
| 版本回退 | 兼容 | 目录结构不变 |

## 架构约束

> 本节列出本特性 AC 验证必须满足的约束。架构规则适用性及设计方案见 design.md。

| 关键约束 | 约束说明 | 影响 AC |
|----------|----------|---------|
| 目录操作必须通过 InstalldService | BundleMgrService 无特权直接设置属主属组，需通过 IPC 调用 SA 511 | AC-1, AC-2, AC-3 |
| 父目录由打印服务负责创建 | BMS 不越权创建父目录，父目录不存在时返回错误码 | AC-4 |
| 目录操作失败不阻塞安装/卸载 | 记录警告日志，允许安装/卸载流程继续 | AC-9 |

## 非功能需求

> N/A 判定见 proposal.md 不涉及项确认。本节仅为适用项填写具体指标。

| 类型 | 指标/阈值 | 验证方式 | 证据 |
|------|-----------|----------|------|
| 性能 | 目录创建 < 100ms | 单元测试计时 | bms_print_service_operator_test.cpp |
| 可靠性 | 失败不阻塞安装/卸载 | 异常场景测试 | BmsPrintServiceOperatorTest_0009 |
| 安全 | 权限 02750、属组 3823 严格控制 | 权限验证测试 | BmsPrintServiceOperatorTest_0001 |
| 问题定位 | HiLog 日志记录完整 | 日志检查 | hilog -T BMS |

## 多设备适配声明

无差异。目录管理行为在所有设备类型上一致，不涉及 UI 相关逻辑。

## 全局特性影响

| 特性 | 适用？ | 结论 | 关联场景 |
|------|--------|------|----------|
| 无障碍 | 否 | 无 UI 相关 | N/A |
| 大字体 | 否 | 无 UI 相关 | N/A |
| 深色模式 | 否 | 无 UI 相关 | N/A |
| 多窗口/分屏 | 否 | 无 UI 相关 | N/A |
| 多用户 | 是 | userId 参数支持，为每个用户独立创建/删除目录 | AC-9 |
| 版本升级 | 是 | OTA 升级后存量驱动应用目录补建 | AC-8 |
| 生态兼容 | 否 | 仅 DRIVER 类型 ExtensionAbility | N/A |

## Spec 自审清单

在提交审查前逐项自检：

- [x] 无"待定""TBD""TODO"等占位符
- [x] 所有 AC 使用 WHEN/THEN 格式，可独立测试
- [x] 范围边界明确（做什么/不做什么清晰）
- [x] 无语义模糊表述（"快速""稳定""尽可能"等）
- [x] AC 与业务规则/异常规则/恢复契约交叉一致

## context-references

```yaml
context-queries:
  - repo: "openharmony/bundlemanager_bundle_framework"
    query: "InstalldService IPC interface pattern for file system operations"
  - repo: "openharmony/bundlemanager_bundle_framework"
    query: "BundleInstaller install/uninstall flow integration points"
```

**关键文档：** [design.md](design.md), [proposal.md](proposal.md)
