# bundle_framework 历史典型问题库（Common Issues）

> 本文件是 bundle_framework 仓代码检视的**强制输入**之一。它从本仓 git 提交历史（截至 2026-09，约 16767 提交，其中 fix 类约 37%）中归纳出反复出现的典型问题。
>
> **使用规则**：任何维度检视（security / logic / dfx / checklist / test / architecture / 兼容性）在出具结论前，必须将本次变更与下述问题类别逐一对照，回答"**本 PR 是否会复发同类历史问题**"。结论写入检视报告「兼容性影响评估」章节的"历史问题核对"小节。
> 数据来源：`git log` 真实提交（每类均给出可复核的代表性提交 hash）。发现新的重复模式时按 §维护 增补。

---

## 0. 热点文件（加权检查目标）

以下文件的修复密度全仓最高，变更落入这些文件时检视强度上调（必须逐条过 §1-§12 检查点）：

| 文件 | 2024 以来修复次数 | 主要风险域 |
|------|-----------------|-----------|
| `services/bundlemgr/src/base_bundle_installer.cpp` | 673+ | 安装/卸载状态机、三方一致性、ScopeGuard |
| `services/bundlemgr/src/bundle_data_mgr.cpp` | 662+ | 并发锁、userId 语义、bundleInfos_/DB 一致性 |
| `services/bundlemgr/src/bundle_mgr_host_impl.cpp` | 430+ | IPC 入参校验、错误码透传、权限校验 |
| `interfaces/inner_api/appexecfwk_base/src/*`（Marshalling/JSON） | 高频 | Parcel 容量校验、JSON 解析健壮性 |
| `services/bundlemgr/src/bundle_util.cpp` | 高频 | 路径校验、临时资源命名、工具函数边界 |

另注意：仓内约 25 笔 Revert 集中在**并行化/缓存类重构**（如 `183f7eb97` 回退安装流程并行化、`8e8c2ab04` revert GetBundleInfoForSelf cache）——此类 PR 检视时应重点审并发与缓存失效逻辑。

---

## 1. userId / 多用户语义混用

- **典型表现**：`requestUserId`（调用方传入）与 `responseUserId`（多用户映射后）混用；0 用户（user 0）特殊逻辑漏判；从字符串/uid 解析 userId 未兜底（`std::stoi` 异常/越界）。
- **根因类型**：userId 未透传/映射不一致；`Constants::INVALID_USERID` 未校验；字符串解析不当。
- **代表性提交**：
  - `9557928a6` fix usr id 0 修复0用户问题（8 处 CloneForAccountUtil 调用点 requestUserId→responseUserId，`bundle_data_mgr.cpp`）
  - `f09860073` fix: derive userId from uid instead of parsing from userInfos key
  - `198da84d3` fix: use migration-style userId parsing with OHOS::StrToInt
  - `d1362cb36` 修复SwitchUninstallStateByUserId
  - `5d199e242` IssueNo:#8412 修复多用户卸载保留数据问题
- **检视检查点**：
  1. 新接口/新分支中每个 userId 使用点，确认用的是 requestUserId 还是 responseUserId，与同函数既有分支一致；
  2. userId 进入逻辑前必须经 `OHOS::StrToInt` 等安全解析并校验 INVALID_USERID；
  3. `Constants::ALL_USERID`、`Constants::ANY_USERID`、user 0 三个特殊值都有显式分支（参考 `bundle_data_mgr.cpp:3311` 等既有 ANY_USERID 分支写法）。

## 2. 并发与锁问题（死锁 / 锁范围 / lost wakeup / 临时名冲突）

- **典型表现**：`bundleInfos_`、`uidMap_`、`installdProxy_` 等共享资源锁缺失或锁粒度过大；`condition_variable` notify 不持锁导致 lost wakeup 死锁；锁外引用在锁释放后继续使用；临时文件名仅用时间戳并发冲突。
- **根因类型**：notify 与 mutex 未配对；读-改-写跨越锁边界；锁内调用重入/IPC/长 IO；共享临时资源命名不唯一。
- **代表性提交**：
  - `2aecf8dad` 修复元服务lost wakeup死锁（notify_all 不持锁 → 永久阻塞，`free_install/service_center_connection.cpp`）
  - `b2c211568` fix GetJsonProfile lock（锁外引用在锁释放后使用，`bundle_data_mgr.cpp`）
  - `98691ab33` 修复单测失败用例及uidMap_死锁风险
  - `20f547b17` IssueNo:#8633 修复补丁安装并发问题（临时目录仅用纳秒时间戳，并发重名，`bundle_util.cpp`）
  - `a6a17b8a2` refactor: narrow lock scope in UpdateInnerBundleInfo
- **检视检查点**：
  1. `condition_variable` 的状态修改与 notify 必须在同一 mutex 临界区内；
  2. 锁内禁止 IPC/递归加锁/文件与 DB IO（本仓惯例：锁外做文件/DB 操作，参考 `GetBundleMutex` 的使用模式 `bundle_data_mgr.cpp:8176`）；
  3. 共享临时资源（临时目录/文件）命名必须含原子计数或进程内唯一 ID，不能只靠时间戳。


## 4. 错误码返回遗漏 / 映射不合理

- **典型表现**：底层失败向上返回笼统错误码甚至 ERR_OK；JS/NAPI 层错误码缺 message 映射；同场景不同接口错误码不一致。2024 年以来约 70 笔此类修复，**最高频整改项**。
- **根因类型**：错误码未细分（复用笼统码）；proxy/host 层返回值被中间日志分支覆盖；新增接口漏登记错误码映射表。
- **代表性提交**：
  - `39436c4e0` IssueNo:#ICBUYV 修复错误码映射不合理
  - `da1831229` IssueNo:#9621 InstallPreexistingApp返回子错误码
  - `e6a3993a9` fix-filter-permission-error-msg
  - `cfbe7ef69` IssueNo:#ICUCIG 修正recover错误码
- **检视检查点**：
  1. 新接口每个失败分支都要有明确错误码，并在 `interfaces/inner_api/appexecfwk_base/include/appexecfwk_errors.h`（及 JS 侧映射）登记；
  2. proxy → host 透传返回值不得被日志等中间分支覆盖；
  3. 修改既有错误码属于**兼容性破坏**，必须走兼容性影响评估（新码只能追加，如 `ERR_APPEXECFWK_DUAL_MODE_* = 8519944+` 的追加方式）。

## 5. JSON 解析 / 反序列化健壮性（null / 类型不符即 crash）

- **典型表现**：nlohmann JSON 解析配置文件、pending 数据、资源信息时字段为 null 或类型不匹配，裸 `get<T>()` 抛异常导致进程 crash；加载被篡改的持久化数据无校验。
- **根因类型**：模板工具未做 null/discarded/type 前置校验；try-catch 缺失或放错层。
- **代表性提交**：
  - `97c1f527f` fix: prevent crash when map-type JSON values are null or type-mismatched（25 处调用统一迁移 GetMapObject，`appexecfwk_base` json_util / `inner_bundle_info.cpp`）
  - `b22b37216` fix: prevent crash when loading tampered pending bundles data
  - `89056be7e` 修复资源解析时的crash问题（`bundle_resource_image_info.cpp`）
  - `2b9f12515` add want check nullptr
- **检视检查点**：
  1. 新增 JSON 字段解析必须走 `BMSJsonUtil` 封装（GetValueIfFindKey / GetMapObject），禁止裸 `nlohmann::json::get<T>()`；
  2. 对 map/array 值先 `is_null()` / `is_object()` 校验；
  3. 持久化文件（DB 记录、pending 数据）加载一律当作**不可信输入**处理。

## 6. IPC / Parcel 参数校验缺失

- **典型表现**：`ReadFromParcel` 读容器 size 未做上限校验 → 恶意 parcel 触发超大内存分配/OOM；新增 IPC 接口漏校验入参；IPC code 冲突/漏赋值；大数据接口超 parcel 容量上限。
- **根因类型**：`CONTAINER_SECURITY_VERIFY` 缺失；size 直接信任；序列化/反序列化不对称。
- **代表性提交**：
  - `48a727b67` check capadity when reading from parcel（多处补 CONTAINER_SECURITY_VERIFY：`application_info.cpp`、`target_ability_info.cpp`、`install_param.cpp`）
  - `3329b44c7` / `cda9a6598` IssueNo:#IAEZWT fix ipc bug（`bundle_resource_host` 等）
  - `337d78221` IssueNo:#8742 修复GetHapModuleInfo数据过大IPC失败
  - `d1faedd1d` 给ipc code赋值（漏赋值导致 code 冲突）
- **检视检查点**：
  1. 新 IPC 接口的 proxy/stub 两端 code 必须同步登记且唯一（`interfaces/inner_api/appexecfwk_core/include/bundle_framework_core_ipc_interface_code.h`，新 code 只能追加在枚举末尾）；
  2. `ReadFromParcel` 中所有容器 size 必须先过 `CONTAINER_SECURITY_VERIFY`；
  3. 大数据接口（profile、resource）需评估 parcel 容量上限（异步/分片，参考 `337d78221`）。

## 7. 路径处理 / 路径穿越

- **典型表现**：安装路径、so 子目录、zip 解压路径未校验 `../` 或符号链接导致路径穿越；realpath 未规范化；拼接路径时目录不存在未兜底。
- **根因类型**：边界未校验（`../`、绝对路径注入）；未做 IsFileNameValid/PathIsValid 前置检查。
- **代表性提交**：
  - `7024a8200` IssueNo:#IARLCD 修复zlib路径穿越问题（`interfaces/kits/js/zip/src/zip.cpp`）
  - `c7f57fa51` fix so子目录路径穿越（installd so 提取）
  - `583fd97c3` 防止路径穿越
  - `0df786f50` / `00ba5c790` fix: security hardening for path validation（installd 路径校验 + 原子 DB 操作）
  - `e03727f22` installd RenameFile add path Verification
- **检视检查点**：
  1. 所有拼进文件操作的路径必须过 `IsFileNameValid` / `PathIsValid` 并显式拒绝 `../`；
  2. installd 侧对来自 BMS 的路径要做前缀白名单校验（不能因同仓调用就信任）；
  3. 解压类操作逐项校验目标路径（zip slip）。

## 8. 安装/卸载数据一致性与 ID 复用（状态机）

- **典型表现**：卸载后 bundleId/uid 立即被复用导致缓存/权限串应用；内存 map 原地修改后 DB 写失败无法回滚；卸载保留数据/分身清理遗漏孤儿记录。
- **根因类型**：先改内存后落盘无回滚；ID 分配只依赖内存 map 状态；卸载清理路径与安装路径不对称。
- **代表性提交**：
  - `8ae3d8d95` fix: avoid immediate bundleId reuse after uninstall（游标 + 持久化 lastAllocatedBundleId，`bundle_data_mgr.cpp`）
  - `4142de240` fix: copy-then-replace pattern for AddInnerBundleUserInfo/RemoveInnerBundleUserInfo（先拷贝、落盘、再替换）
  - `94cc23baa` fixUidDuplicated
  - `c39cbb635` / `5d199e242` 修复多用户(保留数据)卸载问题
  - `69fb5c5d4` fix: CleanUninstallBundleInfo skip orphaned user records（`bundle_mgr_service_event_handler.cpp`）
- **检视检查点**：
  1. 修改 `bundleInfos_` 内条目的新代码必须采用"拷贝 → 持久化 → 替换"三段式，禁止拿可变引用直接改（对应 checklist B1/B2）；
  2. bundleId/uid 等 ID 分配要有防立即复用的持久化游标；
  3. 卸载清理要覆盖所有 user × appIndex 组合，并考虑孤儿记录清理。

## 9. 预置应用 × OTA 场景安装错误

- **典型表现**：OTA 时预置三方应用被错误安装/重复安装、data 分区应用 OTA 丢失、取消预置后残留图标、按需安装失败。预置相关修复 2024 年以来约 59 笔。
- **根因类型**：OTA 扫描路径与预置目录判断边界错误；多用户下"只装一次"标记丢失；removable/版本比较逻辑反向。
- **代表性提交**：
  - `944d879cb` IssueNo:#ICUE2C 修复预置三方应用OTA错误安装
  - `cfb684b90` IssueNo:#ICTQGF 修复预置三方应用错误安装
  - `3422de687` IssueNo:#ICW27N 修复预置应用按需安装问题
  - `54e5d2062` fix_dataPreloadOta 修改data分区应用ota丢失问题
  - `42685697f` / `e3c8a31ce` 修复多用户预置应用安装问题
- **检视检查点**：
  1. 改动预置/OTA 扫描逻辑必须覆盖四组合：三方/系统 × 新装/升级 × user 0/普通用户；
  2. `isPreInstallApp` 判断要在 NeedDualModeHandle、clone、skip 判断之前显式短路；
  3. 取消预置场景要验证旧数据/图标残留清理。


## 11. 日志 / DFX 规范不达标（持续整改型）

- **典型表现**：仓内长期滚动"日志整改"系列（2024-08 至 2026-09 共 30+ 笔）：敏感信息未脱敏、错误日志级别滥用、tag 不规范、errCode 只打文案不打数值等。
- **根因类型**：新增日志未按 BMS_TAG/APP_LOG 规范写；private 信息未脱敏；级别语义错误（ERROR 描述正常分支）。
- **代表性提交**：
  - `be439c4d0` 日志整改13（`bundle_mgr_proxy.cpp`、`inner_bundle_info.h` 等）
  - `69eedc436` 日志整改12、`501a81f32` 日志整改11、`33d686ba2` 日志整改8（系列）
  - `ca8052268` fix print log errCode
- **检视检查点**：
  1. 新增 APP_LOG 必须带 BMS_TAG 与 `%{public}`/`%{private}` 标注，userId/bundleName/路径按敏感级别脱敏；
  2. 禁止循环内打印、禁止 ERROR 级别描述正常分支；
  3. errCode 优先打印数值（`errCode=%{public}d`），避免只打文案（参考 `ca8052268`）。

## 12. 静态告警与 fuzz 用例质量（工程整改型）

- **典型表现**：告警修复/codecheck 类提交 2024 年以来 53+ 笔（数组未判空、悬空指针、未初始化、strcpy 失败未 free）；fuzz 相关 145 笔（含 fuzz crash 修复与冗余用例清理），说明 fuzz 曾多次暴露真实解析崩溃；测试代码自身有 bug（`==` 误用为 `=`、flag 枚举错配）。
- **根因类型**：告警只修不防；fuzz 入口参数构造与真实调用不一致；测试代码缺少自身审查。
- **代表性提交**：
  - `4246cf705` 避免content为悬空指针下读取无效内存
  - `d02132e86` fix warning 数组使用前判空
  - `64c85a7a0` free pointer if strcpy failed（`bundle_util` 等）
  - `005267e0f` / `36406e48b` / `89c8d45ad` fuzz crash修复（多笔）
  - `98691ab33` 修复单测失败用例（测试代码 `==` 误用、枚举错配）
- **检视检查点**：
  1. 提交前本地跑 codecheck 并清零**新增**告警，不留"告警修复"欠账；
  2. 指针在可能被释放/置空的调用（回调、跨线程查询接口）之后禁止继续解引用，需拷贝或重新获取；
  3. fuzz 入口要覆盖 JSON/parcel 解析与路径参数；测试代码本身也按生产代码标准检视。

---

## 检视报告中的核对输出要求

每次检视必须在报告「兼容性影响评估」章节包含**历史问题核对**小节，格式如下：

```markdown
### 历史问题核对（对照 bundle_framework_common_issues.md）
| 问题类别 | 本 PR 是否涉及 | 核对结论 |
|---------|--------------|---------|
| 1. userId 语义混用 | 是 | ✅ 未复发：新分支 responseUserId 与既有分支一致（bundle_data_mgr.cpp:xxxx） |
| 2. 并发与锁 | 否 | —（未触碰共享资源） |
| ... | ... | ... |
```

- 涉及热点文件（§0）时，§1-§12 **全部必核**；
- 非热点文件变更，可按改动内容仅核对相关类别，但需在表中列出"未核对项及理由"；
- 判定为"复发"或"疑似复发"的问题按 P1 起评级，并标注对应类别编号（如 `HIST-2`）。

## 维护

- 发现**同一根因第 3 次出现**的修复模式时，应增补为新类别或并入现有类别，附代表性提交 hash；
- 每季度复核一次代表提交是否仍可checkout；
- 增补/修订走普通 PR，检视 skill（8 个 SKILL.md）通过引用文件路径自动生效，无需逐个修改。
