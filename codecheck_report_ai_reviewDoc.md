# 代码检视报告 — eb333af^..HEAD（Round 1 / 最新提交 a900ef51f）

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
  round: 1
  commit_id: "a900ef51f49a0ea52c2c5e0fd234a3f5c503298b"
  change_id: "a900ef51f49a0ea52c2c5e0fd234a3f5c503298b"
  report_id: "a900ef51f49a0ea52c2c5e0fd234a3f5c503298b-R1"
  date: "2026-09-02"
  gate_decision: "approve"
  risk_level: "low"
  score: 90
  dimensions_required: 5
  dimensions_executed: 5
  findings_total: 5
  findings_by_severity: "P0:0,P1:0,P2:0,P3:5"
  gate_blockers: 0
  must_fix: 0
  followups: 5
```
<!-- codecheck-report-metadata:end -->


---

## 1. 门禁结论

| 项目 | 结论 |
|---|---|
| 决策 | **approve** |
| 风险等级 | 🟢 low |
| 评分 | **90/100** |
| 阻塞项 | 无 |
| 必须修复（P0/P1） | 0 项 |
| 建议跟进（P2/P3） | 5 项 |

**一句话结论**：IPC 新增接口全链路（枚举＋host/proxy＋HostImpl 权限校验＋dataMgr＋JS/ANI/ETS 绑定＋UT）完整对称，安全边界正确；存在 5 个 P3 级语义/口径/DFX/测试观察项，均为低风险建议项，不影响上库。

---

## 3. 必须立即处理（P0/P1）

**无。**　详情见第 6 节。

---

## 4. 建议本轮或下一补档处理（P2/P3）

| ID | 优先级 | 问题 | 建议行动 | 排期 |
|---|---|---|---|---|
| BIND-001 | P3 | JS/ANI 抛错附带的权限字符串 `PERMISSION_GET_BUNDLE_INFO_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS` 与实际服务端校验权限（`PRIVILEGED`/`GET_INSTALLED_BUNDLE_LIST`）不一致，会误导开发者为错误的权限授权 | 与 BMS 接口负责人确认提示文案口径；若确需与老接口一致则保留并在 API 文档注明真实权限 | 下补档 |
| LOGIC-001 | P3 | 两个新 dataMgr 接口用 `GetListForBundleInfo(userId, false, ...)` 覆盖 `tempBundleInfos_`，与老 `GetAllAppProvisionInfoForDualMode`（`true`，仅 `bundleInfos_`）口径不同，"设备内全量"范围需确认为有意 | 确认 temp 数据在当前用户下的预期可见性；若应排除则改 `true` 或补注释说明 | 下补档 |
| LOGIC-002 | P3 | `GetAppProvisionInfoInDevice` 对"未安装/无 provisioning 文件"返回 `ERR_OK`＋空列表，调用方无法区分两类情形（已被 UT 固化） | 确认该语义为设计决策；若需区分，可对"未安装"返回明确错误码 | 下补档 |
| DFX-001 | P3 | HostImpl 新接口失败路径未发送 `QueryBundleInfoEvent` HiSysEvent（老 `GetAppProvisionInfo` 有），查询失败可观测性缺口 | 对齐老接口失败时 `SendQueryBundleInfoEvent` 事件补齐 | 下补档 |
| TEST-001 | P3 | 新增 UT 仅覆盖拒绝/非法参数/空结果路径，缺成功路径（有 provisioning 数据）、双模式 clone 分支覆盖 | 补充 mock `AppProvisionInfoManager` 的成功用例及 clone appIndex 校验 | 下补档 |

---

## 5. 分维度速览

| 维度 | 结果 | 关键说明 |
|---|---|---|
| security_review | ✅ 通过 | IPC 枚举末尾追加（252/253，不重排）、host/proxy 读写对称；HostImpl 入口 `IsSystemApp`＋权限校验＋`CheckAcrossUserPermission` 齐全；日志 `%{public}s/%{public}d` 标注正确；无越权文件操作 |
| logic_analyzer | ⚠️ 3 项 P3 | 数据集合口径（isCurrentMode=false 覆盖 temp）、空结果语义、单数查询无法区分未安装 |
| dfx_reviewer | ⚠️ 1 项 P3 | 新接口失败路径缺 HiSysEvent 查询事件（老接口有） |
| code_review_checklist | ⚠️ 1 项 P3 | 抛错权限提示与实际校验权限不一致（旧接口同模式的延续） |
| test_coverage_reviewer | ⚠️ 1 项 P3 | UT 已覆盖代理/permission/非法参数/空结果 9 例，缺成功路径与 clone 分支 |

---

## 6. 关键发现详情

### [BIND-001] JS/ANI 抛错附带的权限字符串与实际服务端校验权限不一致 (P3, scanner=security_review/code_review_checklist)

- **位置**：`interfaces/kits/js/bundle_manager/bundle_manager.cpp:5164`、`interfaces/kits/ani/bundle_manager/ani_bundle_manager.cpp:1519,1546`；对照 `services/bundlemgr/src/bundle_mgr_host_impl.cpp:5333,5363`
- **触发路径**：系统应用调用 `getAppProvisionInfoInDevice`/`getAllAppProvisionInfoInDevice` 被服务端拒绝（权限不足）→ JS/ANI 抛 BusinessError，错误字符串携带 `Constants::PERMISSION_GET_BUNDLE_INFO_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS`
- **影响**：错误提示引导开发者为 `ohos.permission.GET_BUNDLE_INFO_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS` 授权，而实际生效权限是 `ohos.permission.GET_BUNDLE_INFO_PRIVILEGED`（单数）/`ohos.permission.GET_INSTALLED_BUNDLE_LIST`（全量），易误导排障
- **证据**：`CreateNewCommonError(..., GET_APP_PROVISION_INFO_IN_DEVICE, Constants::PERMISSION_GET_BUNDLE_INFO_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS)` 与 `VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED / GET_INSTALLED_BUNDLE_LIST)`；老接口 `GetAllAppProvisionInfo` 亦沿用同一提示（bundle_manager.cpp:4939），属模式延续非本次引入
- **建议**：确认提示文案口径；若保持与老接口一致，应在 API 文档注明真实校验权限

### [LOGIC-001] InDevice 类接口数据集合口径与老 DualMode 全量接口不一致 (P3, scanner=logic_analyzer)

- **位置**：`services/bundlemgr/src/bundle_data_mgr.cpp:10829,10858`；对照 `:10764`
- **触发路径**：双模式设备上调用 `GetAppProvisionInfoInDevice`/`GetAllAppProvisionInfoInDevice` → `GetListForBundleInfo(userId, false, ...)` → 同时遍历 `bundleInfos_` 与 `tempBundleInfos_`
- **影响**：新接口"设备内全量"包含 temp 预装数据，而老 `GetAllAppProvisionInfoForDualMode` 仅扫 `bundleInfos_`，两接口口径漂移；若同一 bundle 同时存在于两集合或 temp 包含未激活数据，可能产生额外条目
- **证据**：`GetListForBundleInfo` 实现 `bundleInfos_` 恒遍历、`tempBundleInfos_` 仅在 `!isCurrentMode` 时遍历；两个新接口均传 `false`
- **建议**：确认 temp 数据可见性为有意设计；否则改 `true` 或补充注释说明

### [LOGIC-002] 单数查询无法区分"未安装"与"无 provisioning 文件" (P3, scanner=logic_analyzer)

- **位置**：`services/bundlemgr/src/bundle_data_mgr.cpp:10830-10847`
- **触发路径**：系统应用查询未安装 bundle / 已安装但无 provisioning 的 bundle → 遍历无命中或 `GetAppProvisionInfo` 失败 `continue` → 返回 `ERR_OK`＋空列表
- **影响**：调用方无法区分"该 bundle 不存在（真正的错误）"与"存在但取不到 provisioning"，语义模糊；`GetAppProvisionInfoInDevice_0003` UT 已固化该行为（`EXPECT_EQ(ret, ERR_OK)`＋`EXPECT_TRUE(empty)`）
- **证据**：`for` 内 `if (bundleNameStr != bundleName) continue;` 与 `GetAppProvisionInfo` 失败 `continue`，函数尾无条件 `return ERR_OK`
- **建议**：若属设计决策请在注释/测试说明中注明；若需区分，对未命中返回明确错误码

### [DFX-001] 新接口失败路径缺少 HiSysEvent 查询事件 (P3, scanner=dfx_reviewer)

- **位置**：`services/bundlemgr/src/bundle_mgr_host_impl.cpp:5349,5371`
- **触发路径**：`GetAppProvisionInfoInDevice`/`GetAllAppProvisionInfoInDevice` 返回非 OK → 仅 `APP_LOGE`，未发送 `QueryBundleInfoEvent`；老 `GetAppProvisionInfo` 在此路径调用 `SendQueryBundleInfoEvent`
- **影响**：查询类失败在 DFX 侧不可观测，无法通过 HiSysEvent 做失败率统计/排障
- **证据**：`:5316-5321` 老接口 `if (ret != ERR_OK) { ... SendQueryBundleInfoEvent(...) }`；新接口 `:5349-5351` 仅 `APP_LOGE`
- **建议**：对齐老接口补充失败事件上报

### [TEST-001] UT 覆盖成功路径与双模式 clone 分支缺失 (P3, scanner=test_coverage_reviewer)

- **位置**：`services/bundlemgr/test/unittest/`（`bms_data_mgr_test`、`bms_bundle_mgr_proxy_test`、`bms_bundle_permission_system_app_test`）
- **触发路径**：9 例 UT 均覆盖 proxy 拒绝（空 remote）、permission 拒绝、非法 userId、空 bundleName、未安装空结果；无"存在 provisioning 数据"的成功用例，无 `appIndex == DUAL_MODE_CLONE_APP_INDEX` 校验
- **影响**：两个新接口的正常业务路径（返回非空 vector、clone 条目标记）无回归防护，未来改动易破坏而单测不报警
- **证据**：`GetAppProvisionInfoInDevice_0001/0002/0003`、`GetAllAppProvisionInfoInDevice_0001/0002` 均为负向/空用例
- **建议**：mock `DelayedSingleton<AppProvisionInfoManager>` 增加成功用例与 clone appIndex 校验