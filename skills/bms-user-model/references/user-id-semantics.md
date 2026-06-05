# 用户 ID 语义

定义位置：

```text
interfaces/inner_api/appexecfwk_base/include/bundle_constants.h
```

## 常量速查

| 常量 | 值 | 含义 |
| --- | --- | --- |
| `Constants::DEFAULT_USERID` | `0` | 默认/基础用户。部分启动、预置、系统路径会优先处理该用户。 |
| `Constants::U1` | `1` | 特殊 1 用户。代码中常与 0 用户一起作为低编号特殊用户处理。 |
| `Constants::START_USERID` | `100` | 普通创建用户的起始 ID。测试中常用 `USERID = 100`。 |
| `Constants::INVALID_USERID` | `-1` | 无效用户。常作为校验失败或查询不到 response user 的返回值。 |
| `Constants::UNSPECIFIED_USERID` | `-2` | 未指定用户。常表示需要根据调用者或当前前台用户推导。 |
| `Constants::ALL_USERID` | `-3` | 所有用户。用于全用户查询、广播、聚合状态或全用户安装参数，不是真实用户。 |
| `Constants::ANY_USERID` | `-4` | 任一用户。用于“任意已安装用户可匹配”的查询语义，不是真实用户。 |

## 0 用户

`Constants::DEFAULT_USERID` 是 0。

常见含义：

- 默认系统用户或基础用户。
- 启动、扫描、预置安装、公共状态处理中经常优先处理。
- 部分代码会把 0 和 1 作为特殊低编号用户处理。

注意：

- 不要把 `0` 写成魔法数字。
- 不要假设所有 API 的默认 userId 都是 0；很多接口会根据 caller/current user 推导。

## 1 用户

`Constants::U1` 是 1。

常见含义：

- 特殊低编号用户。
- 代码里常与 `DEFAULT_USERID` 一起处理，例如 `userId == DEFAULT_USERID || userId == U1`。
- 某些 bundle 是否支持 U1 会通过权限或 bundle 信息判断，例如 `PERMISSION_U1_ENABLED`、`IsU1Enable()`。

注意：

- 1 用户不是普通从 100 开始创建的用户。
- 修改预置安装、启动处理、事件发布、权限初始化时要搜索 `U1` 和 `IsU1Enable()`。

## 100 用户

`Constants::START_USERID` 是 100。

常见含义：

- 普通创建用户的起始 ID。
- 单元测试和系统测试常用 `USERID = 100` 表示普通用户。
- `BundleUserMgrHostImpl::CreateNewUser` 和 `BundleMultiUserInstaller` 相关流程通常围绕普通用户展开。

注意：

- 生产代码优先使用 `Constants::START_USERID`，测试常量可以叫 `USERID`。
- 普通用户判断常见形式是 `userId >= Constants::START_USERID`。
- `AccountHelper::CheckUserIsolation` 会跳过小于 `START_USERID` 的已安装用户，再判断企业/隐私空间隔离。

## 调用者 UID 与 userId

相关常量：

- `Constants::BASE_USER_RANGE = 200000`
- `Constants::BASE_APP_UID = 10000`

`AccountHelper::GetOsAccountLocalIdFromUid` 通过 `callingUid / BASE_USER_RANGE` 推导用户。native/shell 调用常走当前前台用户。

注意：

- UID 不是 userId。
- 对外接口传入的 userId 不能直接信任，通常需要结合调用方 token/uid 和跨用户权限判断。

## request user 与 response user

`BundleDataMgr` 中常见模式：

- request userId：调用方请求的 userId。
- response userId：实际命中的用户，如果无效则返回 `INVALID_USERID`。

修改查询逻辑时同时搜索 `GetResponseUserId`、`requestUserId`、`responseUserId`。
