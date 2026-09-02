# 代码检视报告 — eb333af^..HEAD（Round 3 / 最新提交 4fdb15890）

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
  scope: "eb333af^..HEAD (双模式适配新增方法 GetAppProvisionInfoInDevice & GetAllAppProvisionInfoInDevice)"
  round: 3
  commit_id: "4fdb15890a57a1793cc0c078580e0e8dd48cccc1"
  change_id: "4fdb15890a57a1793cc0c078580e0e8dd48cccc1"
  report_id: "4fdb15890a57a1793cc0c078580e0e8dd48cccc1-R3"
  date: "2026-09-02"
  gate_decision: "conditional"
  risk_level: "medium"
  score: 93
  dimensions_required: 5
  dimensions_executed: 5
  findings_total: 2
  findings_by_severity: "P0:0,P1:0,P2:1,P3:1"
  gate_blockers: 0
  must_fix: 0
  followups: 2
```
<!-- codecheck-report-metadata:end -->


---

## 1. 门禁结论

| 项目 | 结论 |
|---|---|
| 决策 | **conditional** |
| 风险等级 | 🟡 medium |
| 评分 | **93/100** |
| 阻塞项 | 无 |
| 必须修复（P0/P1） | 0 项 |
| 建议跟进（P2/P3） | 2 项（1 P2 + 1 P3） |

**一句话结论**：IPC 全链路结构、权限校验与服务层逻辑正确；此前 3 项 P3（数据集合口径、空结果语义、HiSysEvent 打点）经作者澄清为有意设计，已按 refute 规则移出报告。剩余仅 1 项 P2 权限字符串拼接笔误（已给修复文案）与 1 项 P3 测试覆盖建议。

---

## 3. 必须立即处理（P0/P1）

**无。**　详情见第 6 节。

---

## 4. 建议本轮或下一补档处理（P2/P3）

| ID | 优先级 | 问题 | 建议行动 | 排期 |
|---|---|---|---|---|
| BIND-002 | P2 | 常量 `PERMISSION_GET_INSTALLED_BUNDLE_LIST_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS` 值误拼入 `PERMISSION_` 前缀，得到不存在的权限名 `ohos.permission.PERMISSION_GET_INSTALLED_BUNDLE_LIST`；真实权限名为 `ohos.permission.GET_INSTALLED_BUNDLE_LIST` | 将 :144-146 三行值更正为 `"ohos.permission.GET_INSTALLED_BUNDLE_LIST or (ohos.permission.GET_INSTALLED_BUNDLE_LIST and ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS)"` | 本轮 |
| TEST-001 | P3 | UT 缺成功路径（有 provisioning 数据）与双模式 clone 分支覆盖；现有 9 例均为拒绝/非法参数/空结果 | 补 mock `AppProvisionInfoManager` 的返回数据用例与 `appIndex == DUAL_MODE_CLONE_APP_INDEX` 校验 | 下补档 |

---

## 5. 分维度速览

| 维度 | 结果 | 关键说明 |
|---|---|---|
| security_review | ⚠️ 1 项 P2 | 新增权限常量值拼接笔误（`ohos.permission.PERMISSION_GET_INSTALLED_BUNDLE_LIST` 含多余前缀）；执法仍由 HostImpl `VerifyCallingPermissionForAll` 保证，无安全绕过 |
| logic_analyzer | ✅ 通过 | 跨模式扫全量（`isCurrentMode=false`）与空结果返回经作者确认为设计语义 |
| dfx_reviewer | ✅ 通过 | 新接口不打 HiSysEvent 为有意裁剪（refute 已记录）；日志敏感标注、LOGE_NOFUNC、HITRACE 均规范 |
| code_review_checklist | ✅ 通过 | IPC 枚举末尾追加、host/proxy 对称、bindings 完整；仅权限串笔误计入 security |
| test_coverage_reviewer | ⚠️ 1 项 P3 | 缺成功路径/克隆分支 UT（建议项） |

---

## 6. 关键发现详情

### [BIND-002] 新增权限常量字符串误拼入常量名前缀 (P2, scanner=security_review)

- **位置**：`interfaces/inner_api/appexecfwk_base/include/bundle_constants.h:144-146`
- **触发路径**：`GetAppProvisionInfoInDeviceNative`（ani_bundle_manager.cpp:1531）返回非 OK → `ThrowCommonNewError` 携带该常量，错误文案输出不存在的权限名
- **影响**：开发者按错误提示授权时会寻找并不存在的权限名 `ohos.permission.PERMISSION_GET_INSTALLED_BUNDLE_LIST`，排障误导；不影响服务端强制校验
- **证据**：对比 `bundle_constants.h:106` 真实常量值 `"ohos.permission.GET_INSTALLED_BUNDLE_LIST"`（无 `PERMISSION_` 前缀）；参考同文件 :134-136 `PERMISSION_GET_BUNDLE_INFO_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS` 正确取值 `"ohos.permission.GET_BUNDLE_INFO_PRIVILEGED or (...)"`
- **建议**：:144-146 改为
  ```cpp
  constexpr const char* PERMISSION_GET_INSTALLED_BUNDLE_LIST_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS =
      "ohos.permission.GET_INSTALLED_BUNDLE_LIST or "
      "(ohos.permission.GET_INSTALLED_BUNDLE_LIST and ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS)";
  ```

### [TEST-001] UT 覆盖成功路径与双模式 clone 分支缺失 (P3, scanner=test_coverage_reviewer)

- **位置**：`services/bundlemgr/test/unittest/bms_data_mgr_test/bms_data_mgr_test.cpp` 等
- **触发路径**：现有 9 例 UT 均覆盖 proxy 拒绝（空 remote）、permission 拒绝、非法 userId、空 bundleName、未安装空结果；无"存在 provisioning 数据"的成功用例，无 `appIndex == DUAL_MODE_CLONE_APP_INDEX` 校验
- **影响**：两个新接口正常业务路径（返回非空 vector、clone 条目标记）无回归防护
- **建议**：mock `DelayedSingleton<AppProvisionInfoManager>` 增加成功用例与 clone appIndex 校验