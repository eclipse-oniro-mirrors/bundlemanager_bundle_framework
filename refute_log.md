# Refute 审查记录

> 检视范围（最终状态）：提交段 `668d2fa9389781b673fd931aefe1c1b448846a34（含）..6d47402a9`（HEAD）**含工作区未提交改动**
> 编排器：codecheck-orchestrator
> 审查日期：2026-09-04

## 审查概要

| 指标 | 数值 |
|------|------|
| 审查范围 | security: 0 条, logic: 1 条, checklist: 1 条, dfx: 1 条, test: 2 条 |
| P0/P1 全审 | 1 条 |
| 维持 | 5 条 |
| 降级 | 0 条 |
| 推翻 | 0 条 |
| 合并 | 0 组 |
| **进入最终报告** | **5 条** (P0: 0, P1: 1, P2: 3, P3: 1) |

---

## 逐条审查

### ✅ 维持 — FIND-001：Public 错误码与接口默认实现语义变更（P1）

- 位置：`bundle_mgr_interface.h:1670,1675`、`bundle_mgr_proxy.cpp:4666`、`bundle_data_mgr.cpp:10839`
- 发现：空 bundleName 返回码 PARAM_ERROR→BUNDLE_NOT_EXIST；`IBundleMgr` 两处默认实现 ERR_OK→ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR。
- 审查结论：`IBundleMgr` 为 proxy 与 host/stub 的公共基类，默认实现返回码变更影响未覆写该接口的 stub/派生对象及仓外调用方；本仓测试已同步新码，但兼容评估未完成。属公共兼容边界。**维持 P1**。

### ✅ 维持 — FIND-002：`GetAppProvisionInfoInDevice` 自身两分支返回语义不一致（P2）

- 位置：`bundle_data_mgr.cpp:10843-10846`（未找到→NOT_EXIST）vs `10847-10868`（命中但被过滤→ERR_OK 空数组）
- 发现：同函数内，"bundle 不在双 map"返回 NOT_EXIST；"bundle 在但被 SHARED/SKILL/INVALID_USERID 过滤"返回 ERR_OK 空数组。二者对"本函数无输出结果"给了不同返回码。
- 审查结论：这是单函数内两个子路径的不一致（非跨函数对比），影响上层对 "NOT_EXIST" 与 "空成功" 的区分。**维持 P2**，建议测试固化预期。

### ✅ 维持 — FIND-003：系统测试 SetUp 行为变更（P2）

- 位置：`acts_bms_kit_system_test.cpp:419-422`、`BUILD.gn:72`、`acts_bms_kit_system_test.cpp:47`
- 发现：`SetUp` 由空实现改为 `ASSERT_TRUE(SetParameter("persist.bms.test_dual_mode","false"))`，失败中断整个 fixture；新增 `parameters.h` 与 `init:libbegetutil` 依赖。
- 审查结论：依赖已配套、功能可用；失败影响面从无扩大到全 fixture。**维持 P2**。

### ✅ 维持 — FIND-004：新增逻辑缺少正向/双 map 覆盖（P2）

- 位置：`bms_bundle_mgr_proxy_test.cpp:1592-1609`、`bms_data_mgr_test.cpp:7429-7434`
- 发现：新增用例仅覆盖空 bundleName 负向与未安装(matches NOT_EXIST)；未覆盖 `GetBundleInfoList` 双 map 命中/双模双变体/SHARED·SKILL·INVALID_USERID 过滤分支。
- 审查结论：核心新增逻辑正向覆盖不足。**维持 P2**。

### ✅ 维持 — FIND-005：过滤分支日志文案与触发条件不完全对应（P3）

- 位置：`bundle_data_mgr.cpp:10850-10853`
- 发现：分支为 SHARED/SKILL/INVALID_USERID 三条件或，日志却无条件打印 `"userId: %d is invalid"`；SHARED/SKILL 情况下 userId 未必 invalid。
- 审查结论：格式符 `%d`↔`int` 正确（无 UB），仅文案语义在小概率分支有误导；不打印被过滤的 bundleName，定位帮助有限。低级。**维持 P3**。

### ❌ 无推翻项

- 本轮未推翻任何发现。

## refute 耗时与统计

- 审查耗时：~8s（人工静态复核）
- 调用链追踪：`BundleMgrHostImpl` → `BundleDataMgr` → `GetBundleInfoList`/`GetListForBundleInfo`；`IBundleMgr` 基类影响面；JS helper/complete 回调映射。
- 源码二次验证：`bundle_data_mgr.cpp:10713-10868`、`bundle_mgr_interface.h:1667-1675`、`git diff 668d2fa93^` 最终状态。
- 注：`GetAppProvisionInfoInDevice` 与 `GetAppProvisionInfo` 为独立契约函数，本报告不做跨函数返回对比。
