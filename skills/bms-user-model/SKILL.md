---
name: bms-user-model
description: 用于处理 OpenHarmony BundleManager 中 userId、多用户、0 用户、1 用户、100 用户、ALL_USERID、ANY_USERID、UNSPECIFIED_USERID、BundleUserMgr、BundleMultiUserInstaller、AccountHelper、InnerBundleUserInfo、跨用户权限和用户维度安装/查询/卸载相关任务。
---

# BMS 用户模型

使用此 skill 处理 BundleManager 中与 userId、多用户、用户隔离、用户维度安装和查询相关的问题。

## 大纲

1. 用户 ID 语义：0 用户、1 用户、100 用户和负数特殊值。
2. 代码地图：BundleUserMgr、BundleMultiUserInstaller、AccountHelper、InnerBundleUserInfo、BundleDataMgr。
3. 修改流程：入口判断、userId 解析、合法性检查、数据读写、权限和测试。
4. 搜索命令：按 userId、常量、BundleUserMgr、多用户安装和测试资源定位代码。

## 工作流程

1. 先判断需求属于哪类用户问题：
   - 创建/删除用户：看 `BundleUserMgrHostImpl`。
   - 已安装应用为新用户补安装：看 `BundleMultiUserInstaller`。
   - 当前用户、调用者用户、前台用户：看 `AccountHelper`。
   - Bundle 每用户状态：看 `InnerBundleUserInfo`、`BundleUserInfo`、`BundleDataMgr`。
   - 查询、安装、卸载接口带 `userId`：看 host/proxy 和 data manager 的 userId 检查。
   - 跨用户访问：看权限 `INTERACT_ACROSS_LOCAL_ACCOUNTS` 和相关 permission helper。

2. 读取 `references/user-id-semantics.md`，确认 0/1/100 和特殊 userId 的语义。

3. 读取 `references/user-map.md`，定位核心文件和测试位置。

4. 使用 `references/search-recipes.md` 搜索相邻实现。

## 基本规则

- 不要把 `0`、`1`、`100` 写成魔法数字，优先使用 `Constants::DEFAULT_USERID`、`Constants::U1`、`Constants::START_USERID`。
- 不要把 `ALL_USERID`、`ANY_USERID`、`UNSPECIFIED_USERID` 当成真实用户。
- 用户维度操作要检查 userId 是否存在、是否允许跨用户、是否需要当前用户兜底。
- 查询类接口要区分 request userId 和 response userId。
- 安装/卸载/清理数据类接口要同步考虑数据目录、access token、bundle user info、clone/sandbox/appIndex。
- 测试中常用 `USERID = 100` 表示普通创建用户，但生产代码应使用常量。

## 参考资料

- `references/user-id-semantics.md`：用户 ID 语义和特殊值。
- `references/user-map.md`：用户相关代码地图。
- `references/search-recipes.md`：用户相关搜索命令。
