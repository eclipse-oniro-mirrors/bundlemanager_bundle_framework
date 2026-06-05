# 安全修改检查清单

## 权限检查

```powershell
rg -n "VerifyCallingPermission|IsSystemApiCall|GetCallingUid|GetCallingPid|GetCallingTokenID|AccessTokenKit|PERMISSION_GRANTED" services/bundlemgr
```

检查点：

- 是否需要 system API 调用限制。
- 是否需要具体 permission。
- 是否需要 shell/native token 特判。
- `userId` 是否与调用方身份匹配。
- 失败时是否返回已有权限错误码。

## 签名和安装校验

```powershell
rg -n "Verify|Signature|Provision|Certificate|CodeSignature|HapVerify|BundleVerify" services/bundlemgr interfaces test
rg -n "ERR_APPEXECFWK.*SIGN|ERR_APPEXECFWK.*VERIFY|ERR_APPEXECFWK.*PERMISSION|ERR_BUNDLEMANAGER.*" interfaces services
```

检查点：

- 校验失败后不得继续安装写库或执行文件操作。
- 错误码要区分参数错误、权限错误、签名错误、安装失败。
- 日志中证书、路径、bundle 信息是否需要 `%{private}`。
- 是否需要 HiSysEvent 上报。

## Provision Profile

```powershell
rg -n "Provision|profile|AppProvision" services/bundlemgr interfaces test
```

检查点：

- 解析失败路径。
- profile 数据持久化。
- 更新/卸载时是否需要同步清理。
- 多用户或多 bundle 场景是否正确隔离。

## Installs 进程安全

```powershell
rg -n "FOUNDATION_UID|InstalldPermissionMgr|VerifyCallingPermission" services/bundlemgr/src/installd services/bundlemgr/test
```

检查点：

- 新增 Installs 方法是否校验 Foundation UID。
- 入参路径是否经过合法性检查。
- 文件删除、移动、权限修改是否限制在预期目录。

## 测试建议

- 权限变更至少覆盖允许和拒绝两条路径。
- 签名/provision 变更覆盖合法、非法、缺失、损坏输入。
- IPC 权限边界覆盖非 foundation 调用 Installs 的失败路径。
- 优先扩展已有 permission/verify/code signature 测试目录。
