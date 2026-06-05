---
name: bms-install-flow
description: 用于处理 OpenHarmony BundleManager 中安装、更新、卸载、恢复、HAP/HSP 解析、安装检查、Installd 文件操作和安装状态变更相关任务。 当需求涉及 BundleInstaller、BaseBundleInstaller、BundleInstallChecker、BundleParser、InstalldClient、安装错误码或安装系统测试时使用。
---

# BMS 安装流程

使用此 skill 处理 BundleManager 的安装、更新、卸载和恢复链路。

## 工作流程

1. 先判断需求属于哪段流程：
   - API/IPC 入口：`BundleMgrHostImpl` 或 installer IPC。
   - 安装入口和任务调度：`BundleInstaller`、`BundleInstallerManager`。
   - 核心安装、更新、卸载动作：`BaseBundleInstaller`。
   - 安装前检查：`BundleInstallChecker`。
   - HAP/HSP/profile 解析：`BundleParser`。
   - 特权文件操作：`InstalldClient` 到 `InstalldService`。
   - 数据写入和查询：`BundleDataMgr` 和 RDB。

2. 读取 `references/install-map.md`，确认核心文件和典型调用路径。

3. 读取 `references/search-recipes.md`，用 `rg` 追踪具体方法、错误码、测试。

4. 修改时同时检查：
   - `userId` 和多用户语义。
   - 安装参数 `InstallParam`。
   - 是否需要经过 Installs 进程，而不是直接做文件系统操作。
   - 错误码是否映射到 `appexecfwk_errors.h` 中已有分类。
   - 是否影响安装、更新、卸载、回滚或恢复中的任意一个分支。

## 注意事项

- 不要在 Foundation 进程中新增需要特权的文件操作，优先走 `InstalldClient`。
- 安装流程常有清理、回滚、异常恢复分支，修改主路径时要搜索失败路径。
- 涉及 Bundle 信息变更时，同时检查内存态 `InnerBundleInfo`、持久化和资源数据。
- 涉及系统应用、预置应用、HSP、shared bundle、sandbox、clone、overlay、quick fix 时，先看对应功能目录是否有特殊处理。

## 参考资料

- `references/install-map.md`：安装链路文件地图。
- `references/search-recipes.md`：安装流程搜索命令。
