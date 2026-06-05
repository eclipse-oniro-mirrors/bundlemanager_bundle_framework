---
name: bms-security-verify
description: 用于处理 OpenHarmony BundleManager 的安全、权限、签名校验、provision profile、access token、调用方校验、应用控制、code signature、verify manager 和安装校验安全相关任务。 当需求涉及 BundlePermissionMgr、verify、app_provision_info、bundle_verify_mgr、权限错误码、系统 API 调用检查或安全测试时使用。
---

# BMS 安全与校验

使用此 skill 处理 BundleManager 中权限、安全校验、签名校验和 provision profile 相关修改。

## 工作流程

1. 先判断安全面：
   - 调用方权限或 system API：看 `BundleMgrHostImpl` 和 `BundlePermissionMgr`。
   - HAP 签名、完整性、安装校验：看 `verify/`、`BundleInstallChecker`、`BundleParser`。
   - Provision profile：看 `app_provision_info/`。
   - Code signature：搜索 `code signature` 和相关错误码。
   - Installs 进程权限：看 `InstalldPermissionMgr` 和 foundation UID 校验。
   - 应用管控：看 `app_control/`。

2. 阅读 `references/security-map.md`，确认核心文件。

3. 阅读 `references/security-checklist.md`，检查权限、错误码、日志和测试。

4. 修改时把安全失败路径当作主要路径处理，必须明确返回错误码和日志敏感性。

## 安全原则

- 调用方身份检查要靠 token/UID/PID 等系统来源，不要信任入参。
- 多用户场景要检查 `userId` 是否允许调用方操作。
- 敏感日志使用 `%{private}`，公开信息使用 `%{public}`。
- 安装安全检查失败时，不要继续写入数据或执行文件操作。
- Installs 进程只信任 Foundation 进程调用。

## 参考资料

- `references/security-map.md`：安全与校验文件地图。
- `references/security-checklist.md`：安全修改检查清单。
