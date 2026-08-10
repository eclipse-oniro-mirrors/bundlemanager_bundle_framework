---
name: test_coverage_reviewer
description: 用例测试覆盖度检视专家，检查修改点是否有已有用例覆盖、是否新增了必要的测试用例、评估用例覆盖完备度
version: 1.0.0
author: AI Assistant
tags:
  - test coverage
  - unit test
  - test case
  - code review
  - coverage evaluation
triggers:
  - 测试覆盖
  - 用例覆盖
  - 测试情况
  - 测试用例
  - 用例测试
  - test coverage
  - test case review
  - coverage check
  - 用例检查
  - 单测覆盖
---

# Test Coverage Reviewer - 用例测试覆盖度检视

## 1. 技能概述

本技能专注于评估代码修改点的测试覆盖情况，回答三个核心问题：

1. **已有覆盖**: 修改点涉及的旧逻辑是否已有测试用例覆盖？
2. **新增覆盖**: 如果旧逻辑无覆盖，本次变更是否添加了新的测试用例？
3. **完备度评价**: 修改点的用例覆盖是否完备？是否存在遗漏的测试场景？

---

## 2. 检查维度

### 2.1 修改点识别

首先，需要将代码 diff 分解为离散的"修改点"，每个修改点是一个独立的逻辑变更：

```
修改点分类：
├── 删除代码路径
│   └── 被删除的函数/方法/代码块
├── 新增代码路径
│   └── 新增的函数/方法/代码块
├── 修改代码路径
│   ├── 条件分支变更
│   ├── 循环逻辑变更
│   ├── 返回值变更
│   └── 参数/签名变更
└── 接口变更
    ├── 虚接口方法增删
    └── 方法签名变更
```

### 2.2 已有用例覆盖分析

对每个修改点，分析修改前的旧代码是否被已有测试覆盖：

#### 分析方法

```bash
# 1. 提取旧代码中的关键函数/方法
git show HEAD:path/to/file.cpp

# 2. 搜索测试文件中是否引用了这些函数/方法
grep -rn "FunctionName" test/

# 3. 使用 codegraph 搜索调用链
codegraph_callers OldFunctionName

# 4. 检查测试文件中对修改路径的覆盖
grep -rn "TestName" test/  # 查看测试用例描述
```

#### 覆盖判定标准

| 覆盖程度 | 判定标准 |
|---------|---------|
| 🟢 **直接覆盖** | 存在测试用例直接调用修改的函数并验证其行为 |
| 🟡 **间接覆盖** | 存在测试用例间接经过该代码路径（如通过上层接口调用） |
| 🔴 **未覆盖** | 无任何测试用例经过该代码路径 |

### 2.3 新增用例检查

检查本次 diff 中的测试文件变更：

#### 检查内容

- [ ] 测试文件中是否新增了 `HWTEST_F` / `TEST_F` / `TEST` 等测试用例
- [ ] 新增用例的 `@tc.desc` 是否描述了覆盖的修改点场景
- [ ] 新增用例是否覆盖了被删除旧逻辑原本处理的业务路径
- [ ] 新增用例是否覆盖了新逻辑的所有关键分支
- [ ] **innerkit接口Fuzz要求**: 如果修改涉及新增innerkit接口，且接口存在入参，必须补充对应的Fuzz测试用例

#### 新增用例质量评估

| 质量等级 | 标准 |
|---------|------|
| 🟢 **良好** | 用例清晰覆盖修改点，包含正常路径和异常边界 |
| 🟡 **基本合格** | 用例覆盖了修改点的主要路径，但部分边界遗漏 |
| 🔴 **不足** | 用例与修改点关联弱、无断言验证核心行为、或缺失关键分支 |

#### innerkit接口Fuzz用例要求

当修改涉及**新增innerkit接口**时，需进行专项检查：

**触发条件**（需同时满足）：
1. 修改涉及 `.idl` 后缀文件中新增了接口函数
2. 接口函数入参存在 `in` 类型修饰

**Fuzz用例要求**：
- 必须新增至少一个Fuzz测试用例，使用 libfuzzer 框架（`FUZZ_TEST` 宏或 `extern "C" int LLVMFuzzerTestOneInput`）
- Fuzz用例应覆盖以下输入变异场景：
  - 随机字节流注入
  - 边界值（空指针、空字符串、极值、零值）
  - 畸形数据结构

**判定标准**：

| 状态 | 说明 |
|------|------|
| ✅ **满足** | `.idl` 中新增接口函数的每个 `[in]` 入参均已通过 `FuzzData` 生成随机数据并传入，并在 `LLVMFuzzerTestOneInput` 中最终调用到目标接口 |
| ⚠️ **部分满足** | 存在Fuzz用例但未覆盖所有 `[in]` 入参或缺少边界场景 |
| ❌ **不满足** | 完全缺少Fuzz用例，或Fuzz用例中未实际调用目标接口 |

**示例**：

以 `IBundleMgr.idl` 中新增的 `Install` 接口为例：

```cpp
// IBundleMgr.idl 中的接口定义（interfaces/inner_api/appexecfwk_core/src/bundlemgr/IBundleMgr.idl）
void Install([in] String bundleFilePath, [in] InstallParam installParam, [in] IStatusReceiver statusReceiver);
```

对应的Fuzz用例（`installbundle_fuzzer.cpp`）：

```cpp
#include "installbundle_fuzzer.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_interface.h"
#include "fuzz_data.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
    bool InstallBundleFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        if ((data != nullptr) && (size != 0)) {
            FuzzData fuzzData(data, size);
            std::string testBundlePath(fuzzData.GenerateString());
            InstallParam installParam;
            // 每个 [in] 入参均通过 FuzzData 生成随机值
            auto bundleMgr = DelayedSingleton<BundleMgrClient>::GetInstance();
            if (bundleMgr != nullptr) {
                sptr<IStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
                result = (bundleMgr->Install(testBundlePath, installParam, receiver) == ERR_OK);
            }
        }
        return result;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::InstallBundleFuzzTest(data, size);
    return 0;
}
```

关键检查点：
1. `LLVMFuzzerTestOneInput` 入口 → 调用 Fuzz 测试函数 → 最终调用到 `.idl` 声明的目标接口
2. 每个 `[in]` 入参均通过 `FuzzData` 生成随机数据后传入
3. Fuzz 用例文件命名遵循 `{interface_name_lower}_fuzzer.cpp` 规范，目录结构为 `test/fuzztest/{module}/{name}_fuzzer/`

### 2.4 覆盖完备度评价

综合评估每个修改点的测试覆盖完备程度：

#### 评价维度

1. **路径覆盖**: 修改点涉及的所有代码分支是否被测试触达
2. **边界覆盖**: 边界条件（空值、极值、异常输入）是否有测试
3. **错误路径覆盖**: 修改点中的错误返回路径是否有测试
4. **回归覆盖**: 被修改/删除的旧行为是否有对应的测试更新
5. **Fuzz覆盖**: 新增innerkit接口的入参是否有对应的Fuzz用例（参见 2.3 innerkit接口Fuzz用例要求）

#### 完备度等级

| 等级 | 评分 | 说明 |
|------|------|------|
| 🟢 **完备** | 90-100 | 所有修改点均有直接测试覆盖，边界和错误路径完整 |
| 🟡 **基本完备** | 70-89 | 主要修改点有覆盖，部分边界或错误路径缺失 |
| 🟠 **不足** | 50-69 | 仅部分修改点有覆盖，存在明显的测试缺口 |
| 🔴 **严重不足** | 0-49 | 核心修改点完全无覆盖 |

---

## 3. 执行流程

### 步骤1: 提取修改点列表

```bash
# 获取完整 diff
git diff HEAD

# 从 diff 中提取修改点:
# - 删除的函数/方法
# - 新增的函数/方法
# - 修改的函数/方法
# - 条件逻辑变更
```

输出: **修改点清单**

```
修改点 M1: 删除 RemoveOldHapIfOTA() 调用 (ProcessBundleInstall)
修改点 M2: 修改 MarkInstallFinish() - 调整 CommitAppSkills 调用顺序
修改点 M3: 删除 CheckHspInstallCondition() 函数及其调用
修改点 M4: 修改 ProcessBundleUninstall() - 改用 CheckHspVersionIsRelied 替代 GetHspDependency
修改点 M5: 新增 ScopeGuard Dismiss() 调用
...
```

### 步骤2: 对每个修改点分析已有覆盖

```bash
# 对每个修改点，搜索旧逻辑是否被测试覆盖
git show HEAD:test_file.cpp | grep -A 30 "TestName"
```

输出: **已有覆盖分析表**

| 修改点 | 旧逻辑 | 已有覆盖? | 覆盖用例 | 覆盖程度 |
|--------|--------|----------|---------|---------|
| M1 | RemoveOldHapIfOTA 调用 | 🔴 无 | - | - |
| M2 | MarkInstallFinish 顺序 | 🔴 无 | - | - |

### 步骤3: 检查新增用例

分析测试文件的 diff 变更：

```bash
git diff HEAD -- test/
```

输出: **新增用例清单**

### 步骤4: 匹配修改点与测试用例

建立修改点 → 测试用例的映射关系，识别未被覆盖的修改点。

### 步骤5: 输出完备度评价

综合判断，给出覆盖完备度等级和改进建议。

---

## 4. 输出报告模板

```markdown
## 🧪 Test Coverage Reviewer 检查结果

### 检查概览
- **修改点总数**: {N} 个
- **已有覆盖修改点**: {N} 个 (🟢{N} / 🟡{N} / 🔴{N})
- **新增测试用例**: {N} 个
- **未覆盖修改点**: {N} 个
- **覆盖完备度**: {PERCENTAGE}% (🟢/🟡/🟠/🔴 {等级})

---

### 修改点清单与覆盖分析

| ID | 修改点 | 文件 | 旧逻辑已有覆盖 | 新增覆盖 | 完备度 |
|----|--------|------|:------------:|:------:|:----:|
| M1 | {描述} | {文件}:{行} | 🔴 无 | ✅ 有 | 🟢 |
| M2 | {描述} | {文件}:{行} | 🔴 无 | 🔴 无 | 🔴 |

---

### 已有覆盖详情

#### 已有覆盖的修改点

| 修改点 | 已有测试用例 | 覆盖程度 | 备注 |
|--------|------------|---------|------|
| {Mx} | {TestCaseName} | 🟢 直接 | {说明} |

#### 无已有覆盖的修改点

| 修改点 | 旧逻辑说明 | 缺失影响 |
|--------|-----------|---------|
| {Mx} | {旧逻辑描述} | {缺失覆盖的影响} |

---

### 新增用例详情

#### 用例清单

| 用例名称 | 覆盖修改点 | 测试场景 | 质量评价 |
|---------|-----------|---------|---------|
| {TestCaseName} | M1, M4 | {场景描述} | 🟢 良好 |

#### 用例质量分析

**{TestCaseName}**:
- **覆盖修改点**: M4 (CheckHspVersionIsRelied 依赖检查)
- **测试场景**: {正常路径/边界/异常}
- **断言有效性**: {是否验证了核心行为}
- **评价**: {🟢/🟡/🔴} {说明}
- **遗漏场景**: {如有}

---

### 覆盖完备度评价

#### 综合评分

| 维度 | 得分 | 说明 |
|------|------|------|
| 路径覆盖 | {N}/100 | {说明} |
| 边界覆盖 | {N}/100 | {说明} |
| 错误路径覆盖 | {N}/100 | {说明} |
| 回归覆盖 | {N}/100 | {说明} |
| **综合评分** | **{N}/100** | **{等级}** |

#### 未覆盖修改点

| ID | 修改点 | 风险 | 建议 |
|----|--------|------|------|
| {Mx} | {描述} | {🟠/🟡} | {应补充的测试场景} |

#### 改进建议

1. **缺少覆盖的修改点**: {应补充用例的建议}
2. **现有用例可增强的场景**: {建议补充的边界或错误路径}
3. **测试用例设计建议**: {通用改进建议}

---

### 总结

**覆盖完备度**: {评分}/100 ({等级})
**是否建议补充用例**: {是/否}
**补充用例优先级**:
- P0: {必须补充的场景}
- P1: {建议补充的场景}
- P2: {可选补充的场景}
```

---

## 5. 问题严重等级

- 🔴 **致命**: 核心业务逻辑修改点完全无测试覆盖，且本次未补充用例；新增innerkit接口存在入参但完全缺少Fuzz用例
- 🟠 **严重**: 关键修改点仅有间接覆盖，缺少直接验证；新增innerkit接口的Fuzz用例未覆盖所有入参
- 🟡 **警告**: 边界条件或错误路径缺少测试覆盖
- 🟢 **优化**: 测试质量可提升，但不影响基本验证

---

## 6. 使用示例

```bash
# 对当前分支进行测试覆盖度检查
"使用 test_coverage_reviewer 检查当前分支的用例覆盖情况"

# 对特定文件进行覆盖度检查
"使用 test_coverage_reviewer 检查 base_bundle_installer.cpp 的修改点用例覆盖"
```

---

**版本历史**

| 版本 | 日期 | 变更 | 维护者 |
|---------|------|---------|------------|
| v1.0 | 2026-05-29 | 初始版本 | AI Assistant |
