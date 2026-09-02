# Refute Log — eb333af^..HEAD（Round 3）

> 对抗性验证记录，与统一报告一并交付。判定：✅ 维持 | ⬇️ 降级 | ❌ 推翻 | 🔀 合并。

## 本轮 Refute 汇总

| Finding | 上一轮判定 | 本轮判定 | 依据 |
|---|---|---|---|
| LOGIC-001 数据集合口径（isCurrentMode=false 扫全量） | P3 | ❌ 推翻 | 作者澄清：InDevice 接口为跨模式语义，须扫全量（含 tempBundleInfos_），`false` 为刻意设计 |
| LOGIC-002 未安装返回空列表 | P3 | ❌ 推翻 | 作者澄清：无数据时返回空即为预期语义，无需区分"未安装"与"无 provisioning 文件" |
| DFX-001 新接口缺 HiSysEvent 打点 | P3 | ❌ 推翻 | 作者澄清：新接口暂不提供 HiSysEvent 打点，属有意的范围裁剪 |
| BIND-002 权限字符串拼接笔误 | P2 | ✅ 维持 | 与设计无关的纯笔误：常量值 `ohos.permission.PERMISSION_GET_INSTALLED_BUNDLE_LIST` 多拼入 `PERMISSION_` 前缀；作者未反对 |
| TEST-001 缺成功路径/克隆分支 UT | P3 | ✅ 维持 | 作者未澄清；属测试覆盖建议，与设计决策无关 |

## 推翻项明细（不进入报告正文，供人工复核捞回）

### LOGIC-001 — 数据集合口径（已推翻）
- **原判定**：P3，`GetListForBundleInfo(userId, false)` 同时扫 `bundleInfos_` 与 `tempBundleInfos_`，与老 `GetAllAppProvisionInfoForDualMode`（`true`）口径不一致。
- **作者回应**：InDevice 接口是跨模式，需要扫全量，所以使用了 `false`。
- **Refute 结论**：`false` 为设计语义（跨模式全量扫描），非缺陷。

### LOGIC-002 — 未安装/无数据返回空（已推翻）
- **原判定**：P3，单数查询未安装/无 provisioning 返回 `ERR_OK`＋空列表，调用方无法区分。
- **作者回应**：在没有数据的时候就是返回空。
- **Refute 结论**：空列表为预期契约行为，`GetAppProvisionInfoInDevice_0003` UT 固化行为与其一致，非缺陷。

### DFX-001 — 缺 HiSysEvent 打点（已推翻）
- **原判定**：P3，新接口失败路径未发 `QueryBundleInfoEvent`，老接口有。
- **作者回应**：新接口暂不提供 HiSysEvent 打点。
- **Refute 结论**：有意的范围裁剪，非缺陷。若后续需要查询失败率统计，建议再评估补齐。

## 维持项（进入报告正文）

### BIND-002 — 权限字符串拼接笔误（✅ 维持 P2）
- 位置：`interfaces/inner_api/appexecfwk_base/include/bundle_constants.h:144-146`
- 证据：常量值 `"ohos.permission.PERMISSION_GET_INSTALLED_BUNDLE_LIST or ..."` 相对真实权限名 `"ohos.permission.GET_INSTALLED_BUNDLE_LIST"`（bundle_constants.h:106）多拼入 `PERMISSION_` 前缀，实际不存在该权限名。属笔误，与跨模式扫描设计无关，作者未反对。

### TEST-001 — 成功路径/克隆分支 UT 缺失（✅ 维持 P3）
- 位置：`services/bundlemgr/test/unittest/bms_data_mgr_test/bms_data_mgr_test.cpp` 等
- 证据：现有 9 例 UT 均为拒绝/非法参数/空结果用例；缺有 provisioning 数据的成功用例与 `appIndex == DUAL_MODE_CLONE_APP_INDEX` 校验。作者未澄清该点。