# 代码检视报告 — services/bundlemgr CLI沙箱调用方校验（Round 1 / 最新提交）

> 本报告由 codecheck 工作台按 [`skills/bms-code-check/codecheck_report_TEMPLATE.md`](skills/bms-code-check/codecheck_report_TEMPLATE.md) v1.1 生成，用于门禁管控。评分与决策按 [`skills/bms-code-check/conventions.md`](skills/bms-code-check/conventions.md) §9 计算。

---

## 报告元数据

> **门禁脚本只读取本 YAML 块**。字段名与取值域为固定合约。

<!-- codecheck-report-metadata:start -->
```yaml
codecheck_report:
  schema_version: "1.1"
  scope: "services/bundlemgr（CLI沙箱增加调用方校验，7 文件 +49 行）"
  round: 1
  commit_id: "7eaf70705768c10fb69aef240017f534be8a8ec5"
  change_id: "If27129f3cc4bd89f2a33d74209fbddc2f7d7fc9a"
  report_id: "If27129f3cc4bd89f2a33d74209fbddc2f7d7fc9a-R1"
  date: "2026-09-14"
  gate_decision: "conditional"
  risk_level: "medium"
  score: 72
  dimensions_required: ["security_review", "logic_analyzer", "dfx_reviewer", "code_review_checklist", "test_coverage_reviewer", "compatibility"]
  dimensions_executed: ["security_review", "logic_analyzer", "dfx_reviewer", "code_review_checklist", "test_coverage_reviewer", "compatibility"]
  compat_risk: "low"
  historical_issues_rechecked: "yes"
  findings_total: 6
  findings_by_severity: {P0: 0, P1: 1, P2: 2, P3: 3}
  gate_blockers: []
  must_fix: ["CHK-001"]
  followups: ["CHK-002", "CHK-003", "CHK-004", "CHK-005", "CHK-006"]
```
<!-- codecheck-report-metadata:end -->

---

## 1. 门禁结论

| 项目 | 结论 |
|---|---|
| 决策 | **conditional** |
| 风险等级 | 🟠 medium |
| 评分 | **72/100** |
| 阻塞项 | 无 P0 |
| 必须修复（P0/P1） | 1 项 |
| 建议跟进（P2/P3） | 5 项 |

**一句话结论**：本 PR 为 CLI 沙箱创建/销毁两个 IPC 入口补充了调用方 token 类型校验（IssueNo:#9749 安全加固），方向正确、校验点选在 host 侧唯一入口、错误码复用既有值、三个 mock 变体同步更新；但**新增安全校验分支零用例覆盖**（P1），且存在 `UninstallCloneApp` 旁路对称性与 DFX 打点两处 P2 待确认项，修复 P1 并确认 P2 后可上库。

---

## 2. 扣分原因

> gate_decision=conditional，本节省略（评分 72 分已计入 §3 P1 扣分）。

---

## 3. 必须立即处理（P0/P1）

| ID | 优先级 | Scanner | 问题 | file:line | 触发路径 | 影响 |
|---|---|---|---|---|---|---|
| CHK-001 | P1 | test_coverage_reviewer | 新增 CLI 工具校验分支（允许+拒绝两条路径）无任何用例覆盖，本次仅更新 mock 未新增 HWTEST | `services/bundlemgr/src/bundle_installer_host.cpp:1655`、`:1696`（本提交后行号） | 任意调用方经 IPC `CREATE/DESTROY_CLI_SANDBOX_APP` 触达新校验分支 | 校验逻辑被后续重构静默破坏（如误删分支、比较符写反）时无法被测试拦截；安全加固自身无回归保障 |

> 详情见 §7 [CHK-001]。

---

## 4. 建议本轮或下一补档处理（P2/P3）

| ID | 优先级 | 问题 | 建议行动 | 排期 |
|---|---|---|---|---|
| CHK-002 | P2 | 校验覆盖不对称：`UninstallCloneApp` 在 appIndex∈[2000,3000] 时直接调用 `BundleCliSandboxInstaller::DestroyCliSandboxApp(..., true)`，绕过本 PR 新增的 CLI 工具校验（该路径仅受 IsSystemApp + PERMISSION_UNINSTALL_CLONE_BUNDLE 约束，属既有行为非本提交引入） | 与安全团队确认旁路是否有意保留（特权系统应用清理路径）；若威胁模型要求"仅 CLI 工具可销毁沙箱"，需在同路径补充同等校验或在设计中明确豁免理由 | 本轮确认 |
| CHK-003 | P2 | 权限拒绝路径无 HiSysEvent 打点（dfx_reviewer 要求 permission denied 场景 HIGH 优先打点） | 拒绝分支补充 `EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION)`（failureReason="caller is not cli tool"）或 `SendHighRiskEvent`，便于安全审计统计被拒调用 | 下一补档 |
| CHK-004 | P3 | 日志文案不合规 + 重复打印（HIST-11 相关）：`"not cli tool calling caller:%{public}"` 非 who-do-what / `xxx failed` 惯例格式；`IsCliToolCalling` 内 LOG_D 与调用点 LOG_E 打印同一信息；callerToken 以 %{public} 全量打印（与仓内既有实践一致，如 `bundle_permission_mgr.cpp:318`，建议评估脱敏） | 文案改为如 `"CreateCliSandboxApp denied, caller is not cli tool, callerToken:%{private}" PRIu64`；删除 `IsCliToolCalling` 内与调用点重复的 LOG_D | 下一补档 |
| CHK-005 | P3 | 校验点位置不一致：`CreateCliSandboxApp` 中校验位于 bundleName 非空校验之后，`DestroyCliSandboxApp` 位于函数入口 | 统一置于函数入口（fail-fast，减少无谓处理与信息暴露面） | 随 CHK-001 顺带 |
| CHK-006 | P3 | `test/mock/src/accesstoken_kit.cpp` 文件末尾无换行符（本次新增代码后仍保持） | 补 EOF 换行，消除 diff 噪音 | 顺手修复 |

---

## 5. 分维度速览

| 维度 | 结果 | 关键说明 |
|---|---|---|
| security_review | ✅ 通过 | 校验置于 host 侧 IPC 唯一入口（choke point）；使用 `GetCallingFullTokenID`（仓内既有实践，5 处先例）；拒绝返回既有错误码。遗留：UninstallCloneApp 旁路待确认（CHK-002） |
| logic_analyzer | ✅ 通过 | 两个入口校验逻辑一致、失败即中止；无共享资源/锁变更；校验点位置轻微不一致（CHK-005，P3） |
| dfx_reviewer | ⚠️ 1 项 P2 | 日志级别选择正确（拒绝=ERROR）；缺 HiSysEvent 打点（CHK-003）；文案格式与重复打印（CHK-004，P3） |
| code_review_checklist | ✅ 通过 | 兼容性自检 §A：IPC code / Parcel / 错误码 / 持久化均无变更；对外行为收紧为 PR 预期（安全修复）；日志规范 1 项 P3 |
| test_coverage_reviewer | 🔴 1 项 P1 | 三份 mock 同步更新保证编译与既有用例（`UninstallCloneApp_0200` 等走旁路不受影响），但新增校验分支零覆盖（CHK-001） |
| compatibility（§6） | ✅ low | 影响面窄：仅 CLI 沙箱管理两接口的调用方收紧；历史问题核对完成，无复发 |

---

## 6. 兼容性影响评估 🔥

### 6.1 影响面分析（修改 → 受影响的功能）

| # | 修改点（file:line） | 变更类型 | 直接影响的功能 | 波及的历史功能/调用方 | 影响程度 |
|---|---|---|---|---|---|
| 1 | `bundle_installer_host.cpp:1655`（CreateCliSandboxApp） | 新增校验分支 | IPC `CREATE_CLI_SANDBOX_APP`（code 20）调用方 | CLI 工具（bm 工具链路，本仓外）——持有 CLI 工具 token，行为不变；**非 CLI 工具 token 的既有调用方将被拒绝**（预期安全效果） | 中 |
| 2 | `bundle_installer_host.cpp:1696`（DestroyCliSandboxApp） | 新增校验分支 | IPC `DESTROY_CLI_SANDBOX_APP`（code 21）调用方 | 同上；另 `UninstallCloneApp` 级联销毁沙箱走 `BundleCliSandboxInstaller` 内部路径，不受新校验影响（CHK-002） | 中 |
| 3 | `bundle_permission_mgr.cpp:359`（IsCliToolCalling 新增） | 新增静态方法 | 无既有调用方 | 纯新增，无波及 | 低 |
| 4 | 3 份 test/mock 文件 | mock 同步 | 单测编译与既有用例 | `BmsBundleInstallerTest`（RETURN_FALSE 变体，IsCliToolCalling=false）与正常变体（true）行为均与既有用例预期兼容，无破坏 | 低 |

> 四条历史链路核对：安装/卸载/更新主流程（不受影响——普通安装/卸载/更新入口未改动）；启动恢复链路（不受影响）；查询链路（不涉及）；持久化链路（不涉及）。**影响面收敛于 CLI 沙箱管理的两个专属 IPC 入口。**

### 6.2 兼容性检查结论

| 兼容性项 | 是否涉及 | 结论 | 证据（file:line） |
|---|---|---|---|
| IPC code 是否仅追加/未变更 | 否（无 IPC code 变更） | ✅ 无变更 | diff 未触碰 `bundle_framework_core_ipc_interface_code.h` / `bundle_framework_services_ipc_interface_code.h` |
| Parcel 序列化 | 否 | ✅ 无变更 | diff 未触碰 Marshalling/Unmarshalling |
| 错误码（是否新增而非修改既有码；映射同步） | 涉及 | ✅ 复用既有 `ERR_APPEXECFWK_PERMISSION_DENIED(8519925)`，无新增/修改，JS/NAPI 映射无需变更 | `appexecfwk_errors.h:203` |
| 对外行为（返回值/校验变化） | 是 | ⚠️ 两接口新增调用方类型校验 = 行为收紧；**这是本 PR 的预期安全目标**（IssueNo:#9749），影响面已识别（6.1），合法调用方（CLI 工具）不受影响 | `bundle_installer_host.cpp:1655-1660`、`:1696-1701` |
| 持久化数据 | 否 | ✅ 不涉及 | — |
| 新特性 flag 五条主流程覆盖 | 否（无新 flag） | ✅ 不涉及 | — |
| 性能 | 涉及 | ✅ 每次调用新增 1 次 AccessTokenKit 查询；CLI 沙箱创建/销毁为低频操作，无热路径影响 | `bundle_permission_mgr.cpp:359-369` |

### 6.3 历史问题核对（对照 bundle_framework_common_issues.md，当前类别 1/2/4/5/6/7/8/9/11/12）

| 问题类别（HIST 编号） | 本 PR 是否涉及 | 核对结论 |
|---|---|---|
| 1. userId 语义混用 | 否 | —（不涉 userId 解析与透传） |
| 2. 并发与锁问题 | 否 | —（无共享资源、锁、临时资源变更） |
| 4. 错误码返回遗漏/映射不合理 | 是 | ✅ 未复发：复用既有错误码 8519925，未修改既有码、proxy→host 返回值透传无覆盖（`appexecfwk_errors.h:203`） |
| 5. JSON 解析健壮性 | 否 | —（无 JSON 解析变更） |
| 6. IPC/Parcel 参数校验缺失 | 是 | ✅ 未复发：未新增 IPC/未改 Parcel；新增的是 host 侧**校验**而非校验缺口；`UninstallCloneApp` 旁路为既有路径，非本提交引入（见 CHK-002 跟进） |
| 7. 路径处理/路径穿越 | 否 | —（无路径操作） |
| 8. 安装/卸载数据一致性与 ID 复用 | 否 | —（无 bundleInfos_/DB/ID 分配变更） |
| 9. 预置应用 × OTA 场景 | 否 | —（不涉预置/OTA 扫描） |
| 11. 日志/DFX 规范不达标 | 是 | ⚠️ 部分符合：新日志带正确 BMS_TAG 与 PRIu64 格式化；但文案非 who-do-what 惯例格式、与内部 LOG_D 重复打印、callerToken 全量 public（CHK-004）。该类问题在本仓为 30+ 笔持续整改项，建议随本 PR 一并修正避免新增欠账 |
| 12. 静态告警与 fuzz 用例质量 | 是 | ⚠️ 部分：mock 三处同步更新（编译与既有用例无破损，好）；但新增安全校验分支未补任何用例（CHK-001，P1），不符合"新增检查点须有回归用例"要求 |

### 6.4 兼容性结论

- **compat_risk**：**low**
- **一句话结论**：本 PR 是行为收紧型安全修复，影响面收敛于 CLI 沙箱管理两个专属 IPC 接口；合法调用方（CLI 工具 token）行为不变，非 CLI 工具调用方被拒即修复目标；无 IPC code/Parcel/错误码/持久化兼容性破坏。
- **回归建议**：① CLI 沙箱创建/销毁全链路（bm 工具创建 → 使用 → 销毁）；② 克隆应用卸载时级联销毁 CLI 沙箱（`UninstallCloneApp` 路径，UninstallCloneApp_0200 已覆盖，建议真机回归）；③ 主应用卸载级联 `DestroyAllCliSandboxApps`（`base_bundle_installer.cpp:2371`）。

---

## 7. 关键发现详情

### [CHK-001] 新增 CLI 工具校验分支零用例覆盖 (P1, scanner=test_coverage_reviewer)

- **位置**：`services/bundlemgr/src/bundle_installer_host.cpp:1655`（CreateCliSandboxApp）、`:1696`（DestroyCliSandboxApp）
- **触发路径**：后续任何重构（如调整校验顺序、误改比较条件、误删分支）均无测试拦截；`BundleCliSandboxInstaller` 层有测试（`bms_bundle_cli_sandbox_installer_test.cpp`），但均在**被测校验的下层**，无法验证 host 入口的放行/拒绝行为
- **影响**：安全加固自身无回归保障；按 test_coverage_reviewer 标准，核心修改点完全无覆盖且本次未补充用例；`BmsBundleInstallerTest` 目标（RETURN_FALSE mock 变体，IsCliToolCalling=false）本可直接断言拒绝路径，成本极低
- **证据**：`git show 7eaf7070 --stat` 仅含 mock 更新（`test/mock/include/accesstoken_kit.h:53`、`test/mock/src/accesstoken_kit.cpp:215`、`test/mock/src/bundle_permission_mgr.cpp:263/337`、`test/mock/src/mock_permission_mgr.cpp:307`），无任何 `*_test.cpp` 变更；grep 全部单测目录，`CreateCliSandboxApp`/`DestroyCliSandboxApp` host 函数无调用点（仅 `UninstallCloneApp_0200` 注释提及）
- **建议**：在 `BmsBundleInstallerTest` 补充 4 个用例——CreateCliSandboxApp_InvalidCaller（mock=false → EXPECT ERR_APPEXECFWK_PERMISSION_DENIED）、CreateCliSandboxApp_CliToolCaller（结合 VerifyPermission mock 断言放行至后续分支）、DestroyCliSandboxApp_InvalidCaller、DestroyCliSandboxApp_CliToolCaller；顺带按 CHK-005 将校验移至入口后补 `@tc.desc`

### [CHK-002] UninstallCloneApp 路径绕过新校验，销毁能力不对称 (P2, scanner=security_review/checklist)

- **位置**：`services/bundlemgr/src/bundle_installer_host.cpp:1266-1270`（UninstallCloneApp 内，appIndex∈[2000,3000] 分支）
- **触发路径**：持有 PERMISSION_UNINSTALL_CLONE_BUNDLE 的系统应用 → IPC `UninstallCloneApp` → 直接构造 `BundleCliSandboxInstaller` 调用 `DestroyCliSandboxApp(..., isUninstallClone=true)` → 不经过 `BundlePermissionMgr::IsCliToolCalling`
- **影响**：若 #9749 的威胁模型是"CLI 沙箱仅可由 CLI 工具管理"，则本 PR 后仍存在特权系统应用的销毁旁路，加固目标未完全闭环；若该旁路是有意保留（系统应用克隆卸载需级联清理），则应记录豁免理由
- **证据**：`bundle_installer_host.cpp:1245-1270`；对比 `:1696` 的 DestroyCliSandboxApp 公开入口有校验；旁路仅受 `:1254` IsSystemApp + `:1259` PERMISSION_UNINSTALL_CLONE_BUNDLE 约束（均为既有代码）
- **建议**：与安全团队确认威胁模型后二选一：① 旁路有意保留 → 在代码注释与本 PR 说明中明确"系统应用克隆卸载级联清理豁免"；② 需要闭环 → 在该分支补充 `IsCliToolCalling || (IsSystemApp && VerifyCallingPermissionForAll(PERMISSION_UNINSTALL_CLONE_BUNDLE))` 等价校验

### [CHK-003] 权限拒绝路径缺 HiSysEvent 打点 (P2, scanner=dfx_reviewer)

- **位置**：`services/bundlemgr/src/bundle_installer_host.cpp:1658-1660`、`:1699-1701`
- **触发路径**：非 CLI 工具调用方调用创建/销毁接口 → 返回 ERR_APPEXECFWK_PERMISSION_DENIED → 仅本地日志，无事件上报
- **影响**：dfx_reviewer 将 "Permission denied for install/uninstall" 列为 HIGH 优先打点场景；无打点则无法从 DFT 平台统计被拒调用来源，安全审计（谁在尝试越权操作）缺数据
- **证据**：拒绝分支仅 `LOG_E` + return；同文件安装类拒绝路径（如 `:1241` InstallExisted permission denied）同样无打点（既有模式），但本 PR 为安全专项，建议按 HIGH 标准补齐
- **建议**：拒绝分支补充 `EventInfo eventInfo; eventInfo.bundleName = bundleName; eventInfo.errCode = ERR_APPEXECFWK_PERMISSION_DENIED; eventInfo.failureReason = "caller is not cli tool"; EventReport::SendSystemEvent(BMSEventType::BUNDLE_INSTALL_EXCEPTION, eventInfo);`

### [CHK-004] 日志文案不合规与重复打印 (P3, scanner=code_review_checklist, HIST-11 相关)

- **位置**：`bundle_installer_host.cpp:1657`、`:1698`；`bundle_permission_mgr.cpp:359-369`
- **触发路径**：每次被拒调用产生两条含同一 callerToken 的日志（调用点 LOG_E + IsCliToolCalling 内 LOG_D）
- **影响**：文案 `"not cli tool calling caller:..."` 不符合仓内 who-do-what / `xxx failed` 日志惯例（对照 HIST-11 持续整改项）；callerToken 全量 %{public} 打印与仓内既有实践一致（`bundle_permission_mgr.cpp:318`），但 token ID 属准敏感标识
- **证据**：diff 中 `LOG_E(BMS_TAG_INSTALLER, "not cli tool calling caller:%{public}" PRIu64, callerToken)` 与 `LOG_D(BMS_TAG_DEFAULT, ...)` 两处
- **建议**：调用点改为 `LOG_E(BMS_TAG_INSTALLER, "CreateCliSandboxApp failed, caller is not cli tool, callerToken:%{private}" PRIu64, callerToken)`（Destroy 同理）；删除 `IsCliToolCalling` 内重复的 LOG_D；callerToken 是否脱敏建议随日志整改系列统一决策

### [CHK-005] 两入口校验点位置不一致 (P3, scanner=logic_analyzer)

- **位置**：`bundle_installer_host.cpp:1655`（Create：位于 envCreatorBundleName/bundleName 非空校验之后）vs `:1696`（Destroy：函数入口）
- **触发路径**：无功能性影响（校验均先于权限校验与业务执行）
- **影响**：一致性与 fail-fast；Create 的空参数分支在校验前打印的日志会暴露"调用方传了非法参数"而未记录调用方类型
- **证据**：diff 上下文
- **建议**：将 Create 的校验块上移至函数入口，与 Destroy 对齐（可随 CHK-001 补用例一并完成）

### [CHK-006] mock 文件末尾无换行符 (P3, scanner=code_review_checklist F 节)

- **位置**：`services/bundlemgr/test/mock/src/accesstoken_kit.cpp:219`（文件尾）
- **触发路径**：—
- **影响**：POSIX 文本文件规范；后续追加内容会产生额外 diff 噪音（本次 diff 已出现 `\ No newline at end of file` 标记）
- **证据**：git diff 尾部标记
- **建议**：补 EOF 换行

---

## 附：检视输入与证据

- 提交：`7eaf70705768c10fb69aef240017f534be8a8ec5`（IssueNo:#9749，CLI沙箱增加调用方校验，7 文件 +49 行）
- 检视依据：`skills/bms-code-check/` 各 SKILL.md v2.x + `bundle_framework_common_issues.md`（当前 HIST 1/2/4/5/6/7/8/9/11/12）+ `codecheck_report_TEMPLATE.md` v1.1 + `conventions.md`
- 评分：100 − (30×0 + 12×1 + 5×2 + 2×3) = **72**；存在 P1 → **conditional**
