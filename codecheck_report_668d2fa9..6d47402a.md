# 代码检视报告 — 668d2fa9389781..HEAD+工作区（Round 1 / 最新提交）

> 统一报告由 codecheck 工作台生成，**用于门禁管控**。所有 codecheck 报告（含 orchestrator 合并出的统一报告、单 scanner 直接产出的统一报告）必须遵循本模板：章节顺序、字段名、报告元数据块、评分与门禁规则均为**固定格式**，跨报告保持一致，便于门禁脚本解析与历史对比。
> 生成入口：[`README.md`](README.md) → Step 5；合并逻辑见 [`orchestrator/SKILL.md`](orchestrator/SKILL.md)。
> 权威评分与门禁规则为**通用规则**，不在输出报告中呈现；生成时必须按 [`conventions.md`](conventions.md) §7（等级归一化）/ §8（必检维度）/ §9（评分与决策矩阵）计算，不得自创分值。

---

## 报告元数据

> **门禁脚本只读取本 YAML 块**。字段名与取值域为固定合约，禁止改名、增删或自定义取值。人工阅读部分从「1. 门禁结论」开始。

<!-- codecheck-report-metadata:start -->
```yaml
codecheck_report:
  schema_version: "1.0"
  scope: "668d2fa9389781..HEAD+worktree(bms provision in-device)"
  round: 1
  commit_id: "6d47402a9a0036b20667109a121fe800050b3914"
  change_id: "668d2fa938..6d47402a"
  report_id: "668d2fa938..6d47402a-R1"
  date: "2026-09-04"
  gate_decision: "conditional"
  risk_level: "medium"
  score: 71
  dimensions_required: 5
  dimensions_executed: 5
  findings_total: 5
  findings_by_severity: "P0:0, P1:1, P2:3, P3:1"
  gate_blockers: 0
  must_fix: 1
  followups: 4
```
<!-- codecheck-report-metadata:end -->


---

## 1. 门禁结论

| 项目 | 结论 |
|---|---|
| 决策 | **conditional** |
| 风险等级 | 🟡 medium |
| 评分 | **71/100** |
| 阻塞项 | 无 P0 阻塞项；1 项 P1 必须修复 |
| 必须修复（P0/P1） | 1 项 |
| 建议跟进（P2/P3） | 4 项 |

**一句话结论**：新增 in-device 型号 AppProvision 查询能力整体可用、错误码/默认实现同步一致，但 Public 兼容边界（错误码、接口默认值）未经兼容评估，且新增逻辑与系统测试覆盖不足，需修复 P1 后再合入。

---

## 2. 扣分原因（仅 gate_decision=block 时呈现；approve/conditional/insufficient 时本节省略）

> 本报告 gate_decision=conditional，按模板省略扣分明细表格。

---

## 3. 必须立即处理（P0/P1）

| ID | 优先级 | Scanner | 问题 | file:line | 触发路径 | 影响 |
|---|---|---|---|---|---|---|
| FIND-001 | P1 | checklist | Public 错误码与接口默认实现语义变更未做兼容评估 | `bundle_mgr_interface.h:1670,1675`；`bundle_mgr_proxy.cpp:4666`；`bundle_data_mgr.cpp:10839` | `IBundleMgr::GetAppProvisionInfoInDevice/GetAllAppProvisionInfoInDevice` 默认实现 ERR_OK→ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR；空 bundleName PARAM_ERROR→BUNDLE_NOT_EXIST | 公共兼容边界：未覆写默认实现的 stub/派生对象及仓外调用方行为改变，可能破坏既有契约 |

---

## 4. 建议本轮或下一补档处理（P2/P3）

| ID | 优先级 | 问题 | 建议行动 | 排期 |
|---|---|---|---|---|
| FIND-002 | P2 | `GetAppProvisionInfoInDevice` 自身两个子路径返回语义不一致（未找到→NOT_EXIST；命中但被 SHARED/SKILL/INVALID_USERID 过滤→ERR_OK 空数组） | 权衡后固化单函数内契约：或过滤后空结果返回 NOT_EXIST，或用测试固化 ERR_OK 空数组预期 | 下一补档 |
| FIND-003 | P2 | 系统测试 `SetUp` 由空实现改为 `ASSERT_TRUE(SetParameter("persist.bms.test_dual_mode","false"))`，失败中断整个 fixture；新增 `parameters.h` 与 `init:libbegetutil` 依赖 | 确认该参数在目标环境可写；必要时降级为 `EXPECT_TRUE` 或注释说明失败影响面 | 下一补档 |
| FIND-004 | P2 | 新增逻辑缺少正向/双 map 覆盖：`GetBundleInfoList` 双 map 命中、双模双变体、SHARED/SKILL/INVALID_USERID 过滤分支均无单测 | 为双 map 命中/双模变体/过滤分支补正向用例；`GetAppProvisionInfoInDevice` 过滤后空结果路径补用例 | 下一补档 |
| FIND-005 | P3 | 过滤分支日志文案与触发条件不完全对应：SHARED/SKILL 时误报 "userId invalid"；不打印被过滤 bundleName | 拆分 SHARED/SKILL 与 INVALID_USERID 日志，或追加 `bundleName:%{public}s` | 可选 |

---

## 5. 分维度速览

| 维度 | 结果 | 关键说明 |
|---|---|---|
| 逻辑与流程 | ⚠️ | `GetBundleInfoList` 双 map 合并合理（bundle_data_mgr.h:1936,1942）；但单函数内过滤后空结果返回 ERR_OK 与未找到返回 NOT_EXIST 不一致（FIND-002） |
| 并发与安全 | ✅ | `GetBundleInfoList` 使用 `std::shared_lock<std::shared_mutex>` 保护读取；未越权、无特权文件操作，符合双进程分层 |
| 错误处理 | ⚠️ | 空 bundleName 与未安装返回码改动已在 proxy/data_mgr/测试三处同步；但 `IBundleMgr` 默认实现返回码为公共默认值，需兼容评估（FIND-001） |
| DFX | ✅ | 错误路径均有 APP_LOGW/APP_LOGE 标注，`%{public}`/`%{private}` 基本正确；仅 FIND-005 文案语义低级偏差 |
| 测试质量 | ⚠️ | 新增负向用例与错误码同步正确；但核心新增逻辑正向/双 map/过滤分支覆盖不足（FIND-004），系统测试 SetUp 影响面扩大（FIND-003） |

---

## 6. 关键发现详情

> P0/P1 必出全量卡片；P2/P3 按需精选或全出。每条 finding 按以下固定卡片格式呈现：

### [FIND-001] Public 错误码与接口默认实现语义变更（P1, scanner=checklist）

- **位置**：`bundle_mgr_interface.h:1670,1675`；`bundle_mgr_proxy.cpp:4666`；`bundle_data_mgr.cpp:10839`
- **触发路径**：调用方 → `BundleMgrProxy::GetAppProvisionInfoInDevice`（代理层空名早退）→ IPC → `BundleMgrHostImpl` → `BundleDataMgr::GetAppProvisionInfoInDevice`；`IBundleMgr` 基类默认实现为未覆写者提供返回码
- **影响**：空 bundleName 返回码 PARAM_ERROR→BUNDLE_NOT_EXIST；`IBundleMgr` 两个默认实现 ERR_OK→SERVICE_INTERNAL_ERROR。两处均为公共兼容边界，未覆写默认实现的 stub/派生对象与仓外调用方行为改变
- **证据**：`bundle_mgr_proxy.cpp:4666` 与 `bundle_data_mgr.cpp:10839` 同步为 `ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST`；`bundle_mgr_interface.h:1670,1675` 同步为 `ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR`；测试 `bms_bundle_mgr_proxy_test.cpp:1601`、`bms_data_mgr_test.cpp:7433,7447` 已同步新断言
- **建议**：按公共变更流程补充兼容性评估；若需保留既有 PARAM_ERROR 语义，考虑在代理层/接口默认实现处恢复，或在 release note 中显式声明行为变更

### [FIND-002] `GetAppProvisionInfoInDevice` 自身两子路径返回语义不一致（P2, scanner=logic）

- **位置**：`bundle_data_mgr.cpp:10843-10846` vs `10847-10868`
- **触发路径**：bundle 不在双 map → 返回 NOT_EXIST；bundle 存在但 SHARED/SKILL/INVALID_USERID 过滤 → 循环后无条件 `return ERR_OK`（空数组）
- **影响**：同函数内对"无输出结果"给了两种返回码，上层无法统一区分
- **证据**：`:10845` 早退 NOT_EXIST；过滤器 `continue` 后 `:10867` 附近 `return ERR_OK`
- **建议**：确认单函数内所需契约并固化（过滤后空结果返回 NOT_EXIST 或 ERR_OK 皆可），补充对应测试

### [FIND-004] 新增逻辑缺少正向/双 map 覆盖（P2, scanner=test）

- **位置**：`bms_bundle_mgr_proxy_test.cpp:1592-1609`；`bms_data_mgr_test.cpp:7429-7447`
- **触发路径**：新增用例仅覆盖空 bundleName 负向与未安装 NOT_EXIST；未覆盖 `GetBundleInfoList` 双 map 命中、双模双变体、SHARED/SKILL/INVALID_USERID 过滤分支
- **影响**：核心新增逻辑（双 map 合并、过滤、双模）正向路径无回归保障
- **建议**：为正反两向补用例；至少覆盖主 map + temp map 同时存在、仅 temp 存在、双模变体、过滤后空结果

### [FIND-003] 系统测试 SetUp 行为变更（P2, scanner=test）

- **位置**：`acts_bms_kit_system_test.cpp:419-422`、`:47`；`BUILD.gn:72`
- **触发路径**：每个用例 SetUp 调 `ASSERT_TRUE(SetParameter("persist.bms.test_dual_mode","false"))`；失败即中断整个 fixture
- **影响**：失败影响面从无扩大到全部用例；新增 `init:libbegetutil` 依赖可能影响测试环境部署
- **证据**：`SetUp` 由空实现 `{}` 改为 `ASSERT_TRUE(...)`；`#include "parameters.h"` 与依赖项新增
- **建议**：确认目标环境可写该参数；必要时降级 `EXPECT_TRUE` 或说明失败影响

### [FIND-005] 过滤分支日志文案与触发条件不完全对应（P3, scanner=dfx）

- **位置**：`bundle_data_mgr.cpp:10850-10853`
- **触发路径**：SHARED/SKILL/INVALID_USERID 三条件或进入分支，日志无条件打印 "userId invalid"；不打印被过滤 bundleName
- **影响**：SHARED/SKILL 情况下 userId 未必无效，文案误导；定位被过滤包困难
- **证据**：`APP_LOGW("userId: %{public}d is invalid...", userId)` 位于三条件或分支内
- **建议**：拆分 SHARED/SKILL 与 INVALID_USERID 日志，或追加 `bundleName:%{public}s`（格式符 `%d`↔`int` 已正确）
