---
name: bms-navigation
description: 用于在 OpenHarmony BundleManager Bundle Framework 仓库中快速定位代码。 当需要查找源码文件、职责边界、调用链、测试位置、构建目标、IPC 入口、数据管理器、功能模块或 Bundle Manager Service (BMS) 相关修改点时使用。
---

# BMS 代码导航

使用此 skill 在动手修改前快速判断 BundleManager 需求应该落在哪些文件和模块。

## 工作流程

1. 先按入口面分类：
   - Public/native/JS/CJ/ANI API：从 `interfaces/` 开始。
   - 服务侧行为：从 `services/bundlemgr/include/` 和 `services/bundlemgr/src/` 开始。
   - 安装、更新、卸载流程：从 `services/bundlemgr/src/` 下的 installer 相关文件开始。
   - 特权文件操作：检查 Installs 进程和 IPC，重点看 `services/bundlemgr/include/ipc/`、`services/bundlemgr/src/ipc/`、`services/bundlemgr/src/installd/`。
   - 持久化或查询状态：先看 `BundleDataMgr`，再看 RDB 封装。
   - 特定功能行为：进入 `services/bundlemgr/src/` 下对应功能子目录。
   - 测试：优先在 `services/bundlemgr/test/` 或 `test/` 中找对应组件已有测试。

2. 阅读 `references/code-map.md`，确认核心路径和模块职责。

3. 使用 `references/search-recipes.md` 中的 `rg` 命令和符号搜索模式。

4. 优先模仿邻近实现，不要凭空创造新模式。遵循现有头文件/源文件配对和 GN target 组织方式。

## 导航规则

- 始终同时查声明和实现。很多服务类的头文件在 `services/bundlemgr/include/`，实现文件在 `services/bundlemgr/src/`。
- 涉及 IPC 时，同时检查 interface、proxy、host、host implementation 和 enum code 文件。
- 涉及功能开关时，先看 `appexecfwk.gni` 和 `services/bundlemgr/appexecfwk_bundlemgr.gni`，不要假设代码一定参与构建。
- 涉及用户维度时，搜索 `userId`、`Constants::ALL_USERID`、`GetCurrentUserId` 或调用方 UID 检查。
- 涉及数据变更时，同时检查序列化、RDB 存储、内存态 `InnerBundleInfo` 和测试。
- 涉及安装路径时，保持权限边界清晰：Foundation 进程控制流程，Installs 进程执行特权文件系统操作。

## 参考资料

- `references/code-map.md`：核心文件、模块地图、测试地图。
- `references/search-recipes.md`：本仓库常用搜索命令。
