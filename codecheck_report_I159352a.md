# 代码检视报告 — 【双模式】OTA子模式安装修复 & policy更新（Round 1 / 最新提交）

> 本报告由 codecheck 工作台按 [`skills/bms-code-check/codecheck_report_TEMPLATE.md`](skills/bms-code-check/codecheck_report_TEMPLATE.md) v1.1 生成，用于门禁管控。评分与决策按 [`skills/bms-code-check/conventions.md`](skills/bms-code-check/conventions.md) §9 计算。

---

## 报告元数据

<!-- codecheck-report-metadata:start -->
```yaml
codecheck_report:
  schema_version: "1.1"
  scope: "services/bundlemgr 双模式OTA修复（bundle_data_mgr / event_handler / base_bundle_installer + 2 测试文件，6 文件 +334/-11）"
  round: 1
  commit_id: "4ff44f4c2411b16a9150cb1c2754a40ead855985"
  change_id: "I159352a0dcb42c4c3cc069afdd92be095647ba11"
  report_id: "I159352a0dcb42c4c3cc069afdd92be095647ba11-R1"
  date: "2026-09-14"
  gate_decision: "conditional"
  risk_level: "medium"
  score: 87
  dimensions_required: ["security_review", "logic_analyzer", "dfx_reviewer", "code_review_checklist", "test_coverage_reviewer", "compatibility"]
  dimensions_executed: ["security_review", "logic_analyzer", "dfx_reviewer", "code_review_checklist", "test_coverage_reviewer", "compatibility"]
  compat_risk: "medium"
  historical_issues_rechecked: "yes"
  findings_total: 5
  findings_by_severity: {P0: 0, P1: 0, P2: 1, P3: 4}
  gate_blockers: []
  must_fix: []
  followups: ["DM-001", "DM-002", "DM-003", "DM-004", "DM-005"]
```
<!-- codecheck-report-metadata:end -->

---

## 1. 门禁结论

| 项目 | 结论 |
|---|---|
| 决策 | **conditional**（评分 87 < 90） |
| 风险等级 | 🟡 medium（compat_risk=medium） |
| 评分 | **87/100** |
| 阻塞项 | 无 P0/P1 |
| 必须修复（P0/P1） | 0 项 |
| 建议跟进（P2/P3） | 5 项 |

**一句话结论**：本 PR 是 HIST-10（新特性遗漏旧分支）类问题的正向修复——① `ShouldUseDualModeCloneName` 移除预置应用短路，使子模式 OTA 预置 different-package 应用按 clone 名安装（对齐 fan-out SECONDARY 通道行为）；② `ProcessUpdateDualPolicy` 将 policy 刷新提前到 early-return 之前，修复"应用不更新时 policy 永不刷新"（旧代码在 temp info 或 preinstall 记录存在时直接跳过更新）；③ 新增 `CheckDualModeCrossInstall` 让异常重试路径支持跨模式安装。修改面收敛、无 IPC/错误码/持久化 schema 变更、测试 +304 行覆盖充分；主要遗留是 `UpdateBundleInfoPolicy` 在写锁临界区内执行两次同步 RDB 保存（P2）与 4 项 P3 跟进。

---

## 2. 扣分原因

> gate_decision=conditional，本节省略。

---

## 3. 必须立即处理（P0/P1）

**无。**　详情见第 4、7 节。

---

## 4. 建议本轮或下一补档处理（P2/P3）

| ID | 优先级 | 问题 | 建议行动 | 排期 |
|---|---|---|---|---|
| DM-001 | P2 | `UpdateBundleInfoPolicy` 持有 `bundleInfoMutex_` 写锁期间执行**两次同步 RDB 保存**（主侧既有 + 本 PR 新增 temp 侧），OTA 扫描对每个 diff-package 应用都会发生，锁内 DB 写时长翻倍，阻塞并发查询（HIST-2 检查点："锁内禁止文件与 DB IO"） | 参考 `a6a17b8a2`（narrow lock scope）/ `4142de240`（copy-then-replace）缩减临界区：锁内拷贝并修改 → 锁外保存 → 锁内替换；或 temp 保存移出临界区 | 下一补档 |
| DM-002 | P3 | temp 分支"先改内存后落盘、落盘失败不回滚"（HIST-8 疑似复发，沿用同函数主侧既有模式）；且主/temp 两次保存非原子——主成 temp 败时双侧 policy 不一致，直至下次刷新才自愈 | 拷贝→持久化→替换三段式；两侧保存失败语义在头文件注释中明确 | 下一补档 |
| DM-003 | P3 | 单侧缺失（同→diff 过渡中间态）时返回 false 并打 ERROR 日志；该契约已被单测 0300 固化为设计（"single-side fails the both-side sync contract, main-side still refreshed"），但 ERROR 级别描述已知中间态、返回契约未在头文件声明 | 日志降为 WARN（过渡中间态非异常）；`bundle_data_mgr.h:1578` 补契约注释（主侧必刷新、双侧齐才返回 true） | 顺手修复 |
| DM-004 | P3 | `HandlePreInstallBundleNamesException` 中 `xmlMap_` 分支优先于跨模式分支——双模式设备若配置了 xmlMap_（指定用户安装），跨模式安装被跳过 | 确认两场景互斥或 `OTAInstallSystemBundleTargetUser` 已覆盖跨模式（其签名已带 forceClone/distPolicy）；若有遗漏需在 TargetUser 路径补跨模式处理 | 本轮确认 |
| DM-005 | P3 | 预置**首装**（非升级）场景子模式 clone 命名 + 异常重试接线（`HandlePreInstallBundleNamesException` 分支）无直接用例（`CheckDualModeCrossInstall` 纯函数已四象限覆盖） | 真机回归主/子模式切换后预置应用可见性；补 exception-retry 路径集成用例 | 真机回归阶段 |

---

## 5. 分维度速览

| 维度 | 结果 | 关键说明 |
|---|---|---|
| security_review | ✅ 通过 | 无新增攻击面：policy 来源为 OTA 扫描的包配置（既有信任链）；diff-package 系统应用白名单校验（`SetDualModeAppInfo`）未被绕过；无 IPC/权限/路径变更 |
| logic_analyzer | ✅ 通过（1 项 P2） | 修复方向与状态机/数据模型一致（bundleInfos_ 与 tempBundleInfos_ 双侧同步）；锁内双次 RDB 写（DM-001）；"先改内存后落盘"沿用既有模式（DM-002） |
| dfx_reviewer | ✅ 通过 | 日志带 tag 与 public/private 标注；`OTAInstallSystemBundleForDualApp` 既有 ret 日志覆盖新分支；DM-003 日志级别 P3 |
| code_review_checklist | ✅ 通过 | 兼容性自检 §A 全过（见 §6.2）；B1-B7 无违反（B2 相关遗留见 DM-002） |
| test_coverage_reviewer | ✅ 通过（优秀） | +304 行：`ShouldUseDualModeCloneName` 4 用例覆盖移除短路的四种组合；`CheckDualModeCrossInstall` 四象限真值表；`ProcessUpdateDualPolicy` 4 场景含"更新先于 move-to-temp"的顺序断言（0300 断言 temp 侧拿到新 policy）；`UpdateBundleInfoPolicy` 4 场景含双侧同步 |
| compatibility（§6） | ⚠️ medium | 行为变化限于双模式设备子模式预置应用域（修复目标）；IPC/错误码/持久化 schema 无变更；命名对查询方可见需按 §6.4 回归 |

---

## 6. 兼容性影响评估 🔥

### 6.1 影响面分析（修改 → 受影响的功能）

| # | 修改点（file:line） | 变更类型 | 直接影响的功能 | 波及的历史功能/调用方 | 影响程度 |
|---|---|---|---|---|---|
| 1 | `base_bundle_installer.cpp:5947`（ShouldUseDualModeCloneName 移除 isPreInstallApp 短路） | 行为变更 | role=NONE 的预置安装（OTA 扫描、异常重试）在子模式对 diff-package 应用启用 clone 命名 | 双模式设备：与 fan-out SECONDARY 通道（role=SECONDARY→clone 名）行为对齐，消除"installStates_ 按原名查找失败→子模式安装失败"（即本 PR 修复目标）；主模式/非双模式设备行为不变（`NeedDualModeHandle = IsSecondaryMode && IsDiffPackage`，`dual_mode_helper.cpp:206`） | 中 |
| 2 | `bundle_mgr_service_event_handler.cpp:6827`（ProcessUpdateDualPolicy 更新提前） | 行为变更 | OTA 时 diff-package 应用 policy 刷新（含应用未更新的场景） | 旧逻辑：temp info 或 preinstall 双模式记录存在即跳过刷新 → policy 变更被吞；新逻辑先刷新再 early-return，已由单测 `ProcessUpdateDualPolicy_NotUpdated*` 覆盖；非双模式/非 diff-package 由函数头 guard 短路（`:6822`），不影响普通应用 | 中 |
| 3 | `bundle_mgr_service_event_handler.cpp:4274`（异常重试新增跨模式分支） | 新增分支 | 预置异常重试（`preInstallExceptionMgr`）路径的跨模式安装 | 仅在 `CheckDualModeCrossInstall` 为真时触发；`OTAInstallSystemBundleForDualApp`/`CrossModeOtaTask` 为既有基础设施（提交前已存在）；`xmlMap_` 分支优先级问题见 DM-004 | 低 |
| 4 | `bundle_data_mgr.cpp:850-860`（UpdateBundleInfoPolicy 双侧刷新） | 功能增强 | policy/sandbox policy 同步刷新 bundleInfos_ 与 tempBundleInfos_ 双侧 | 双侧 Map 同键共存是双模式分类的常态（secondary swap 保留双侧，`bundle_data_mgr.cpp:491-497`）；单侧场景返回契约变更由调用方（ProcessUpdateDualPolicy，唯一调用方，忽略返回值）兼容 | 低 |

> 四条历史链路核对：安装主流程（普通安装不变——`NeedDualModeHandle` 对非预置、主模式、同包策略均为 false）；启动恢复链路（OTA 扫描/异常重试正是修复目标，`ProcessDualModeCrossUpdateIfNeeded` 主通道未动）；查询链路（子模式下预置应用以 clone 名可查——见 §6.2 行为项）；持久化链路（InnerBundleInfo 的 policy 字段为既有持久化字段，无 schema 变更，旧 DB 记录兼容）。

### 6.2 兼容性检查结论

| 兼容性项 | 是否涉及 | 结论 | 证据（file:line） |
|---|---|---|---|
| IPC code | 否 | ✅ 无 IPC 变更 | diff 未触碰 `bundle_framework_core_ipc_interface_code.h` |
| Parcel 序列化 | 否 | ✅ 无变更 | diff 未触碰 Marshalling/Unmarshalling |
| 错误码 | 否 | ✅ 无新增/修改 | diff 无 `appexecfwk_errors.h` 变更 |
| 对外行为 | 是 | ⚠️ ① 双模式设备子模式下预置 diff-package 应用以 clone 名安装（应用自身 bundleName 为 clone 前缀名，按原名查询经分类映射仍可达——`bundleInfos_` 以 originalName 为键持有 clone 信息）；② OTA 未更新应用 policy 现在会刷新。均为修复目标行为，影响面收敛于双模式特性域 | `base_bundle_installer.cpp:5947-5961`、`bundle_data_mgr.cpp:830-862` |
| 持久化数据 | 是 | ✅ 旧 DB 记录可被新代码加载；新写入字段（policy/sandbox）为既有字段，无 schema 变更；temp 侧刷新失败的自愈路径存在（下次 OTA 刷新/MoveBundleInfoToTemp 复制已更新对象） | `bundle_data_mgr.cpp:850-860`、`:825`（Move 复制已更新值） |
| 新特性 flag 五条主流程覆盖 | 是 | ✅ policy 字段在 install（`SetDualModeAppInfo`）/ uninstall（`FillDualModeUninstallEventFields`）/ OTA（本 PR）/ preset（fan-out roles）/ query（分类 + ANY_USERID 查询用例）均有消费，无"遗漏旧分支"残留 | `base_bundle_installer.cpp:6064-6115` 等 |
| 性能 | 是 | ⚠️ `UpdateBundleInfoPolicy` 锁内双次 RDB 写（DM-001，P2）；OTA 扫描窗口内对每个 diff-package 应用生效，并发查询阻塞时长增加 | `bundle_data_mgr.cpp:836-861` |

### 6.3 历史问题核对（对照 bundle_framework_common_issues.md，当前类别 1/2/4/5/6/7/8/9/11/12）

| 问题类别（HIST 编号） | 本 PR 是否涉及 | 核对结论 |
|---|---|---|
| 1. userId 语义混用 | 否 | —（不涉 userId 解析；跨模式安装为系统级无 userId 维度） |
| 2. 并发与锁问题 | 是 | ⚠️ 疑似：新增 temp 保存位于 `bundleInfoMutex_` 写锁临界区内，单次调用锁内 RDB 写 ×2（DM-001，P2）。持锁正确性本身无问题（读写均在同一写锁内，无锁外引用逃逸）；降级理由：锁内保存为主侧既有模式，非本 PR 新引入的模式 |
| 4. 错误码返回遗漏 | 否 | —（无错误码变更） |
| 5. JSON 解析健壮性 | 否 | — |
| 6. IPC/Parcel 参数校验缺失 | 否 | — |
| 7. 路径处理/路径穿越 | 否 | — |
| 8. 安装/卸载数据一致性与 ID 复用 | 是 | ⚠️ 疑似：temp 分支先改内存后落盘、失败不回滚；主/temp 两次保存非原子（DM-002，P3）。降级理由：与同函数主侧既有代码模式一致；影响为 policy 元数据、下次刷新自愈；持锁正确 |
| 9. 预置应用 × OTA 场景 | 是 | ✅ 本 PR 即该域问题的修复，且按检查点覆盖组合：clone 命名决策四组合经新单测验证（子模式/主模式 × 预置/普通 × 单模式策略/未指定 policy，0400/0600/0700）；遗留真机回归首装场景（DM-005） |
| 11. 日志/DFX 规范不达标 | 是 | ⚠️ 部分：单侧缺失中间态用 ERROR 级别（建议 WARN，DM-003）；其余新日志符合 tag/脱敏惯例 |
| 12. 静态告警与 fuzz 用例质量 | 否 | —（本次反向达标：新增 304 行单测，含顺序断言与真值表覆盖） |

> **特别说明**：本 PR 正是问题库 HIST-10（新特性遗漏旧分支——双模式 flag 未覆盖 OTA 旧路径）类别的**修复提交**（问题库代表案例即本提交）。修复本身通过了 HIST-10 检查点的反向验证：新行为在 install/uninstall/OTA/preset/query 五条主流程均有落点。

### 6.4 兼容性结论

- **compat_risk**：**medium**
- **一句话结论**：三处行为变更全部收敛于双模式设备 × different-package 预置应用域，均为修复目标（子模式安装失败、policy 不刷新、异常重试缺跨模式）；无 IPC/错误码/持久化 schema 兼容性破坏；普通应用与主模式/非双模式设备行为不变（有函数头 guard 与单测佐证）。
- **回归建议**：① 双模式设备 OTA 升级（应用不更新）后 diff-package 应用 policy/sandbox 生效性（主/子模式各验一次）；② 子模式下预置 diff-package 应用安装→桌面可见→按名查询→卸载全链路；③ 主/子模式切换后双侧变体可见性互换（含首装仅有单变体的过渡态）；④ 预置安装失败→异常重试（`HandlePreInstallBundleNamesException`）跨模式分支真机触发。

---

## 7. 关键发现详情

### [DM-001] 写锁临界区内执行两次同步 RDB 保存，锁持有时长翻倍 (P2, scanner=logic_analyzer, HIST-2 相关)

- **位置**：`services/bundlemgr/src/bundle_data_mgr.cpp:836-861`（`std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_)` 临界区内，`:846` 主侧保存 + `:858` 新增 temp 侧保存）
- **触发路径**：OTA 扫描 → `ProcessUpdateDualPolicy` → `UpdateBundleInfoPolicy`：持 bundleInfoMutex_ 写锁 → 同步 RDB 写主侧 → 同步 RDB 写 temp 侧 → 释放锁。OTA 期间对每个 diff-package 应用执行一次；期间所有经 dataMgr 的查询/状态操作被阻塞两段 DB 写时长（本 PR 前为一段）
- **影响**：OTA 窗口内查询热路径（launcher、跨应用查询）尾延迟增加；与 HIST-2 检查点"锁内禁止文件与 DB IO（本仓惯例：锁外做文件/DB 操作）"相悖；仓内已有两次同类整改先例（`a6a17b8a2` narrow lock scope、`4142de240` copy-then-replace）
- **证据**：diff 与现行代码 `bundle_data_mgr.cpp:830-862`；锁内保存主侧为既有代码（diff 上下文行），本 PR 在同一临界区追加第二次保存
- **建议**：改为"锁内拷贝并修改副本 → 锁外 `SaveStorageBundleInfo` → 锁内替换"；或至少将 temp 侧保存移出临界区（temp 侧无并发读者路径时风险可控，需确认）

### [DM-002] temp 分支先改内存后落盘、无回滚；双侧保存非原子 (P3, scanner=code_review_checklist B2, HIST-8 疑似)

- **位置**：`bundle_data_mgr.cpp:855-860`
- **触发路径**：`tempItem->second.SetDeviceModeDistributionPolicy/SetAppSandboxPolicy` 原地修改 → `SaveStorageBundleInfo` 失败 → 返回 false，但内存 policy 已改、DB 为旧值；若主侧成功而 temp 失败，双侧 policy 不一致持续到下次刷新
- **影响**：重启后 DB（旧 policy）覆盖内存 → 隐藏变体沿用旧 policy；下次 OTA policy 刷新可自愈。沿用同函数主侧既有模式（`:844-845` 同样原地修改），非新引入反模式
- **证据**：diff；对照 `4142de240`（copy-then-replace 整改先例）
- **建议**：与 DM-001 一并改为拷贝→持久化→替换；两侧保存的失败语义（主成/败 × temp 成/败 四组合）在 `bundle_data_mgr.h:1578` 注释中写明

### [DM-003] 单侧缺失中间态返回 false + ERROR 日志，契约未声明 (P3, scanner=dfx_reviewer/logic_analyzer, HIST-11 相关)

- **位置**：`bundle_data_mgr.cpp:851-854`（"not exist in temp bundle info" ERROR + return false）
- **触发路径**：同→diff 包过渡场景（OTA 首次引入 diff 策略、clone 变体未装）下 policy 刷新：主侧更新成功，temp 侧缺失 → ERROR + false。后续 `MoveBundleInfoToTemp`（event_handler `:6848`）会携带**已更新**的主侧对象进入 temp，最终一致
- **影响**：ERROR 级别描述已知过渡中间态，违反"基本不可能发生的点才打 ERROR"；"主侧必刷新、双侧齐才 true"的契约仅存在于单测 0300 注释，头文件未声明——后续调用方可能据 false 误回滚
- **证据**：`git show` diff；单测 `UpdateBundleInfoPolicyDualMode_0300` 注释 "single-side state fails the both-side sync contract, but the main-side fields must still be refreshed"
- **建议**：日志降 WARN；`bundle_data_mgr.h:1578` 补契约注释

### [DM-004] xmlMap_ 分支优先级压过跨模式安装分支 (P3, scanner=logic_analyzer, HIST-10 检查点)

- **位置**：`bundle_mgr_service_event_handler.cpp:4268-4281`（`if (!xmlMap_.empty()) ... else if (CheckDualModeCrossInstall(...)) ... else ...`）
- **触发路径**：双模式设备 + xmlMap_ 非空（指定用户安装配置）时，异常重试始终走 `OTAInstallSystemBundleTargetUser`，新增跨模式分支不可达
- **影响**：若两场景可同时出现（双模式设备配置了 target-user xml），跨模式重装仍会遗漏——与本 PR 修复的"旧路径未适配"同类；若 xmlMap_ 仅存在于非双模式产品则互斥无风险
- **证据**：分支顺序；`OTAInstallSystemBundleTargetUser` 签名已带 forceClone/distPolicy（`:4271-4274`），但其内部是否处理跨模式存储未在本 PR 验证
- **建议**：确认场景互斥性并加注释；若不互斥，在 TargetUser 路径补跨模式分支或调整分支顺序

### [DM-005] 首装场景与异常重试接线缺真机/集成验证 (P3, scanner=test_coverage_reviewer)

- **位置**：`bundle_mgr_service_event_handler.cpp:4274-4280`；`base_bundle_installer.cpp:5947-5961`
- **触发路径**：① 子模式下预置 diff-package 应用**首装**（非 OTA 升级，设备出厂即为子模式）：clone 命名后主模式侧变体依赖跨模式机制补齐；② `HandlePreInstallBundleNamesException` 分支接线无直接用例（`CheckDualModeCrossInstall` 纯函数已四象限覆盖：NonDualMode/NonDiffPolicy/Secondary/Primary）
- **影响**：纯函数逻辑正确 ≠ 端到端正确；首装单变体过渡态与异常重试路径是 HIST-9 检查点的剩余组合
- **证据**：本次 +304 行用例清单（`bms_dual_mode_install_test.cpp` 8 个新/改用例、`bms_bundle_data_mgr_dual_mode_test.cpp` 4 个新用例），无 exception-retry 集成用例
- **建议**：真机回归（§6.4 ①-④）；补一条 exception-retry → `OTAInstallSystemBundleForDualApp` 的集成用例

---

## 附：检视输入与证据

- 提交：`4ff44f4c2411b16a9150cb1c2754a40ead855985`（【双模式】修复OTA时子模式安装失败 & 应用不更新时policy更新，6 文件 +334/-11）
- 检视依据：`skills/bms-code-check/` 各 SKILL.md v2.x + `bundle_framework_common_issues.md`（当前 HIST 1/2/4/5/6/7/8/9/11/12）+ `codecheck_report_TEMPLATE.md` v1.1 + `conventions.md`
- 评分：100 − (30×0 + 12×0 + 5×1 + 2×4) = **87**；无 P0/P1，评分 87 < 90 → **conditional**
