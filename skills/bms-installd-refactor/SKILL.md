---
name: bms-installd-refactor
description: Installd 接口下沉重构专用 skill。当用户需要将某个 installd 通用接口调用点改造为专用接口时使用，核心原则是将不必要的路径传递去除，路径拼接逻辑下沉到 installd 进程内部完成。
---

# Installd 接口下沉重构

本 skill 提供将 BMS 侧 installd 调用点重构为"不传路径、下沉构造"模式的完整指导流程。

## 触发条件

当用户提出以下需求时，使用此 skill：

- "把这里的 ExtractFiles 调用改为专用方法，不要传路径给 installd"
- "将路径拼接下沉到 installd 进程中"
- "新增一个 installd 专用接口，替代通用 ExtractFiles"
- 用户指定了某个 `InstalldClient::GetInstance()->XXX()` 调用点要求改造

## 核心原则

> **不要从 BMS 传递路径给 installd，仅传入必要的路径拼接参数，在 installd 进程中进行拼接完成业务，做好参数校验。**

## 工作流程

```
Phase 1: 分析 → 追溯每条路径的完整构造链
   ↓
Phase 2: 设计 → 确定新接口签名（标识符 vs 外部输入）
   ↓
Phase 3: 实现 → 全链路 14+ 文件修改
   ↓
Phase 4: 验证 → 业务逻辑一致性对比
   ↓
Phase 5: 归档 → 生成总结文档
```

## Phase 1: 分析 — 追溯路径来源

### 1.1 定位调用点

找到 BMS 侧调用 `InstalldClient::GetInstance()->XXX()` 的代码，提取所有传入参数。

### 1.2 对每个路径字段向上追溯

```bash
grep -rn "字段名\s*=" --include="*.cpp" --include="*.h"
```

### 1.3 区分路径类型

| 类型 | 判断标准 | 处理方式 |
|---|---|---|
| **构造路径** | 由已知常量（`BUNDLE_CODE_DIR`、`PATCH_PATH` 等）+ 标识符（`bundleName`、`versionCode` 等）拼接 | 下沉到 installd，改为传递标识符参数 |
| **外部输入** | 由用户/系统外部提供，无法从标识符推断（如原始文件路径） | 保留为参数，在 installd 侧校验 |
| **元数据** | 来自文件解析的数据（如 `nativeLibraryPath`、`cpuAbi`），不是路径拼接产物 | 保留为参数，不下沉 |

**判断关键问题**：
- 路径中是否包含 `Constants::BUNDLE_CODE_DIR`、`ServiceConstants::PATCH_PATH`、`"patch/"`、`"patch_"` 等已知常量？
- 路径中是否包含 `bundleName`、`versionCode`、`moduleName` 等可从上下文获取的标识符？
- 路径的调用方是否也在构造它（如 `ProcessXxxDeployEnd` 中先构造再传入）？

### 1.4 输出路径来源表

| 路径字段 | 来源 | 类型 | 下沉方案 |
|---|---|---|---|
| `targetPath` | `hqfSoPath + "/" + libraryPath` | 构造路径 | 拆为 `bundleName` + `isReplace` + `versionCode` + `targetPathSuffix` + `nativeLibraryPath` |
| `srcPath` | `hqf.hqfFilePath`（外部 HQF 文件） | 外部输入 | 保留为 `hqfFilePath` 参数 |

## Phase 2: 设计 — 确定新接口签名

### 2.1 规则

1. **构造路径 → 拆解为标识符参数**：路径 = `BUNDLE_CODE_DIR + "/" + bundleName + "/" + subDir` → 传递 `bundleName` + 子目录类型枚举
2. **外部输入路径 → 保留**：如源文件路径，保留并在 installd 做 `IsFileNameValid` 校验
3. **元数据 → 保留**：如 `nativeLibraryPath`、`cpuAbi`（来自 HQF 解析，不是路径构造产物）
4. **参数数量**：≤8 个平铺参数，超过则考虑 Parcelable struct

### 2.2 确认清单

- [ ] 签名中不再包含"由标识符+常量拼接"的完整路径
- [ ] 所有外部输入和元数据保留了参数
- [ ] 标识符参数覆盖路径构造所需的所有变量
- [ ] 参数数量合理
- [ ] 检查同文件内是否有同类已有方法需要同步加固（如新增 `ExtractHqfModuleSoFiles` 时也检查 `ExtractQuickFixSoFile` 是否需要补 `IsFileNameValid`）

## Phase 3: 实现 — 全链路修改

详细步骤参考：
- **IPC 链路实现**: [Installs 进程步骤指南](references/installs-steps.md)
- **路径下沉实现**: [路径下沉模板与校验](references/path-sink-template.md)

### 文件清单

```
services/bundlemgr/
├── include/
│   ├── bundle_framework_services_ipc_interface_code.h   ← 添加 IPC 枚举值
│   ├── installd_client.h                                 ← Client 声明
│   ├── ipc/
│   │   ├── installd_interface.h                          ← IInstalld virtual 方法
│   │   ├── installd_proxy.h                              ← Proxy override 声明
│   │   └── installd_host.h                               ← HandleXxx 声明
│   └── installd/
│       └── installd_host_impl.h                          ← HostImpl override 声明
├── src/
│   ├── installd_client.cpp                               ← Client 校验 + CallService
│   ├── ipc/
│   │   ├── installd_proxy.cpp                            ← Proxy 序列化
│   │   └── installd_host.cpp                             ← Host 反序列化 + dispatch
│   └── installd/
│       └── installd_host_impl.cpp                        ← 核心：权限 + 校验 + 路径构造 + 委托
└── test/mock/src/
    ├── installd_client.cpp                               ← Mock（CallService 模式）
    ├── mock_install_client.cpp                           ← Mock（return 0 模式）
    └── mock_installd_host_impl.cpp                        ← Mock（return ERR_OK 模式）
```

**注意**：还需检查 `test/unittest/*/mock/` 下是否有额外的 mock 文件。使用以下命令搜索：

```bash
grep -rn "InstalldClient::ExtractFiles\|InstalldClient::ExtractQuickFixSoFile" test/unittest/*/mock/
```

### 序列化规则

Proxy 写入顺序与 Host 读取顺序**必须完全一致**：

| 参数类型 | Proxy Write | Host Read |
|---|---|---|
| string | `INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(val))` | `Str16ToStr8(data.ReadString16())` |
| bool | `INSTALLD_PARCEL_WRITE(data, Bool, val)` | `data.ReadBool()` |
| int32 | `INSTALLD_PARCEL_WRITE(data, Int32, val)` | `data.ReadInt32()` |

### 校验责任分层

| 层级 | 职责 | 校验内容 |
|---|---|---|
| **InstalldClient** | 轻量第一道防线 | 外部输入非空（`hapPath`、`cpuAbi` 等）。**不**做 `IsFileNameValid`（那是 HostImpl 的职责） |
| **InstalldHostImpl** | 深度安全校验 | 权限 + `IsValidBundleName` + `IsFileNameValid`（含空检查 + 路径穿越）+ 构造后路径前缀白名单 |

> **关键**：`IsFileNameValid` 内部首行已执行 `if (fileName.empty()) return false;`，因此 HostImpl 中**不要**在 `IsFileNameValid` 前单独做空检查——那是冗余代码。Client 侧的轻量空校验保留即可。

### InstalldHostImpl 实现模板

```cpp
ErrCode InstalldHostImpl::NewMethod(/* 标识符参数 */)
{
    // 1. 权限校验（必须，不可省略）
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    // 2. bundleName 校验
    if (!InstalldOperator::IsValidBundleName(bundleName)) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    // 3. 外部输入和标识符路径穿越防护（IsFileNameValid 已涵盖空检查）
    if (!InstalldOperator::IsFileNameValid(externalFilePath) ||
        !InstalldOperator::IsFileNameValid(metadataField) ||
        !InstalldOperator::IsFileNameValid(cpuAbi)) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    // 可选参数按需校验：(!suffix.empty() && !IsFileNameValid(suffix))

    // 4. 路径构造（下沉自 BMS）
    std::string basePath = std::string(Constants::BUNDLE_CODE_DIR) +
        ServiceConstants::PATH_SEPARATOR + bundleName + ServiceConstants::PATH_SEPARATOR;
    std::string targetPath = /* 使用标识符 + 已知常量拼接 */;

    // 5. 路径前缀白名单校验
    if (!InstalldOperator::IsValidPathByBundleDirScene(
            BundleDirScene::XXX, targetPath)) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    // 6. 委托现有 operator
    ExtractParam extractParam;
    extractParam.bundleName = bundleName;
    extractParam.extractFileType = ExtractFileType::XX;
    extractParam.srcPath = /* 源路径 */;
    extractParam.targetPath = targetPath;
    extractParam.cpuAbi = cpuAbi;
    extractParam.needRemoveOld = /* 按需 */;

    if (!InstalldOperator::ExtractFiles(extractParam)) {
        return ERR_APPEXECFWK_INSTALLD_EXTRACT_FAILED;
    }
    return ERR_OK;
}
```

### Client 校验模板

```cpp
ErrCode InstalldClient::NewMethod(/* 标识符参数 */)
{
    // 仅校验外部输入非空（轻量第一道防线）
    if (externalFilePath.empty() || cpuAbi.empty()) {
        APP_LOGE("externalFilePath or cpuAbi is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::NewMethod, bundleName, externalFilePath, ...);
}
```

### BMS 侧简化

删除的内容：
- `std::string soPath = basePath + "/" + libraryPath;` （路径拼接）
- `ExtractParam extractParam; extractParam.xxx = xxx;` （参数打包）
- `InstalldClient::GetInstance()->ExtractFiles(extractParam)` （通用调用）

替换为：
```cpp
InstalldClient::GetInstance()->NewMethod(bundleName, hqfFilePath,
    nativeLibraryPath, cpuAbi, isReplace, versionCode, targetPathSuffix);
```

## Phase 4: 验证 — 业务逻辑一致性

### 4.1 IPC 序列化校验
```bash
git diff | grep -E "INSTALLD_PARCEL_WRITE|ReadString16|ReadBool|ReadInt32"
```
Proxy write 顺序 ≡ Host read 顺序

### 4.2 路径等价性逐场景验证

用具体值代入三种场景，确认新旧路径完全一致：

| 场景 | 旧路径（BMS） | 新路径（installd） |
|---|---|---|
| Replace | `basePath + "/" + libraryPath` | `basePath + nativeLibraryPath` |
| Patch+Suffix | `basePath + "patch/" + targetPath_ + "/" + libraryPath` | 同上 |
| Patch+Version | `basePath + "patch_" + versionCode + "/" + libraryPath` | 同上 |

### 4.3 ExtractParam 字段对比

逐字段确认修改前后填入的值相同。

### 4.4 错误处理路径对比

每个异常分支确认返回相同错误码。

### 4.5 TDD 单元测试（必须）

新增或修改的 InstalldHostImpl 方法必须编写 TDD 单元测试，确保分支覆盖率 >80%。

#### 测试文件位置

| 测试层 | 文件 | 测试对象 |
|---|---|---|
| IPC Handle 层 | `test/unittest/bms_installd_host_test/bms_installd_host_test.cpp` | `HandleXxx` 方法（MessageParcel 序列化校验） |
| HostImpl 业务层 | `test/unittest/bms_install_daemon_test/bms_install_daemon_test.cpp` | `InstalldHostImpl::Xxx` 方法（分支覆盖） |

#### 分支覆盖分析流程

1. 列出 `InstalldHostImpl` 新方法中所有条件分支
2. 为每个分支设计至少一个测试用例
3. 计算覆盖率：`覆盖分支数 / 总分支数 > 80%`
4. 无法覆盖的分支（如 `VerifyCallingPermission`）需在文档中说明原因

#### 测试命名规范

- 文件名不变，追加到现有 `bms_install_daemon_test.cpp` 和 `bms_installd_host_test.cpp`
- 测试方法名：`{MethodName}_0X00`，递增编号
- 测试注释包含 `@tc.number`、`@tc.name`、`@tc.desc`

#### 测试用例设计模板

每个校验分支设计一个测试用例，覆盖以下场景：

| 分支类型 | 测试输入 | 预期结果 |
|---|---|---|
| 权限校验失败 | 无法在单元测试中覆盖（需 root） | 说明原因 |
| 参数为空 | 依次传入空字符串 | `ERR_APPEXECFWK_INSTALLD_PARAM_ERROR` |
| `IsValidBundleName` 失败 | 传入包含 `../` 的 bundleName | `ERR_APPEXECFWK_INSTALLD_PARAM_ERROR` |
| `IsFileNameValid` 失败 | 传入包含 `../`、`\\`、`\0` 或控制字符的字符串 | `ERR_APPEXECFWK_INSTALLD_PARAM_ERROR` |
| `IsValidPathByBundleDirScene` 失败 | 传入不满足前缀白名单的标识符组合 | `ERR_APPEXECFWK_INSTALLD_PARAM_ERROR` |
| 操作成功/失败 | 传入合法参数 | `ERR_OK` 或对应错误码 |

#### 示例：InstalldHostImpl 测试

```cpp
/**
 * @tc.number: NewMethod_0100
 * @tc.name: test NewMethod with invalid bundle name
 * @tc.desc: 1. bundleName contains ../
 */
HWTEST_F(BmsInstallDaemonTest, NewMethod_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    ErrCode ret = hostImpl.NewMethod("../invalid", ...);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}
```

#### 示例：InstalldHost IPC 测试

```cpp
HWTEST_F(BmsInstalldHostTest, HandleNewMethod_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    bool res = installdHost.HandleNewMethod(data, reply);
    EXPECT_FALSE(res);
}
```

### 4.6 编译验证
```bash
./build.sh --product-name xxx --target bundle_framework
```

## Phase 5: 归档

将完整分析过程记录为文档，建议存放在 `ohdesign/installdRefactor/`。文档结构参考 [快速参考](references/quick-reference.md) 中的归档模板。

## 反模式

1. ❌ 把 BMS 拼好的路径字符串整个传给 installd
2. ❌ 创建新 Parcelable struct 但内部仍包含完整路径
3. ❌ 将 HQF 解析等元数据提取逻辑下沉（它们不属于路径构造）
4. ❌ 下沉需要 `InnerBundleInfo` 的逻辑（installd 无数据库访问权限）
5. ❌ 忘记更新 mock 文件导致测试编译失败
6. ❌ Proxy/Host 读写顺序不一致
7. ❌ 在 HostImpl 中 `IsFileNameValid` 前重复做空检查（`IsFileNameValid` 已内含空检查）
8. ❌ 重构时忽略同类已有方法的安全加固（如只加固新方法，不加固已有 `ExtractQuickFixSoFile`）

## 常用常量

| 常量 | 值 | 位置 |
|---|---|---|
| `Constants::BUNDLE_CODE_DIR` | `/data/app/el1/bundle/public` | `bundle_constants.h` |
| `ServiceConstants::HAP_COPY_PATH` | `/data/service/el1/public/bms/bundle_manager_service` | `bundle_service_constants.h` |
| `ServiceConstants::TMP_SUFFIX` | `_tmp` | `bundle_service_constants.h` |
| `ServiceConstants::LIBS` | `libs/` | `bundle_service_constants.h` |
| `ServiceConstants::PATCH_PATH` | `patch_` | `bundle_service_constants.h` |
| `ServiceConstants::HOT_RELOAD_PATH` | `hotreload_` | `bundle_service_constants.h` |
| `ServiceConstants::PATH_SEPARATOR` | `/` | `bundle_service_constants.h` |
| `PATCH_DIR` | `patch/` | `quick_fix_deployer.cpp`（局部常量） |

## 常用校验函数

| 函数 | 用途 |
|---|---|
| `InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)` | 权限校验 |
| `InstalldOperator::IsValidBundleName(name)` | 包名校验 |
| `InstalldOperator::IsValidPathByBundleDirScene(scene, path)` | 路径前缀校验 |
| `InstalldOperator::IsFileNameValid(name)` | 文件名合法性校验 |

## 参考案例

- `ohdesign/installdRefactor/ExtractQuickFixSoFile归档.md` — 首个下沉重构案例（7 参数，BUNDLE_CODE_DIR 路径）
- `ohdesign/installdRefactor/ExtractHqfModuleSoFiles归档.md` — 4 参数轻量重构（HAP_COPY_PATH 路径，含同步加固 + TDD）

## 参考资料

- [Installs 进程 IPC 步骤指南](references/installs-steps.md) — IPC 链路各文件修改模板
- [路径下沉模板与校验](references/path-sink-template.md) — 路径构造与校验的详细模板
- [快速参考](references/quick-reference.md) — 常用代码片段、文件索引、归档模板
