---
name: comprehensive_review
description: 综合代码修改检视工具，整合 Security Review、Logic Analyzer、DFX Reviewer、Code Review Checklist、Test Coverage Reviewer 和 Coding Style Review，提供全方位的代码质量检查
version: 1.3.0
author: AI Assistant
tags:
  - code review
  - comprehensive
  - security
  - logic
  - dfx
  - checklist
triggers:
  - 检视
  - 代码检视
  - 综合检视
  - 全面检视
  - 审查
  - 代码审查
  - 全面审查
  - review
  - 代码review
  - code review
  - review code
  - comprehensive review
  - check code
  - inspect code
  - audit code
---

# Comprehensive Code Review Skill - 综合代码修改检视

## 触发关键词

当用户请求中包含以下关键词时，应触发本技能：

**中文关键词**：
- `检视`
- `代码检视`
- `综合检视`
- `全面检视`
- `审查`
- `代码审查`
- `全面审查`
- `review`
- `代码review`

**英文关键词**：
- `code review`
- `review code`
- `comprehensive review`
- `check code`
- `inspect code`
- `audit code`

**触发示例**：
- "请检视一下我的代码"
- "对当前分支进行代码检视"
- "帮我code review这个PR"
- "检视以下文件的安全问题"
- "对 feature-xxx 分支进行综合检视"

## 技能概述

本技能是**综合代码修改检视工具**，整合了5个专门的skills，提供全方位的代码质量检查：

1. **Security Review** - 安全问题检查
2. **Logic Analyzer** - 逻辑问题检查
3. **DFX Reviewer** - DFX覆盖检查
4. **Code Review Checklist** - 已知易犯错误检查
5. **Test Coverage Reviewer** - 用例测试覆盖度检查
6. **Coding Style Review** - 编码风格/格式/命名/注释/类设计检查

所有检查完成后，生成包含**Summary部分的全量报告**，提供完整的问题清单和修复建议。

---

## 检视框架

```
┌─────────────────────────────────────────────────────────────┐
│  第一阶段：准备 (Preparation)                                │
│  ├─ 识别变更范围                                            │
│  ├─ 确定检查策略                                            │
│  └─ 准备检查环境                                            │
├─────────────────────────────────────────────────────────────┤
│  第二阶段：执行 (Execution)                                  │
│  ├─ 1. Security Review (安全检查)                           │
│  ├─ 2. Logic Analyzer (逻辑分析)                            │
│  ├─ 3. DFX Reviewer (DFX检查)                               │
│  ├─ 4. Code Review Checklist (规范检查)                     │
│  ├─ 5. Test Coverage Reviewer (测试覆盖度检查)              │
│  └─ 6. Coding Style Review (编码风格检查)                   │
├─────────────────────────────────────────────────────────────┤
│  第三阶段：汇总 (Aggregation)                                │
│  ├─ 收集所有检查结果                                        │
│  ├─ 去重和分类问题                                          │
│  ├─ 评估严重程度和影响                                      │
│  └─ 生成综合报告                                            │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. 检查维度详解

### 1.1 Security Review（安全检查）

**检查目标**: 发现代码中的安全漏洞和风险

**检查内容**:
- **内存安全**: 空指针、缓冲区溢出、内存泄漏
- **输入验证**: 外部数据污染、路径穿越、注入攻击
- **权限控制**: 权限校验、访问控制、特权提升
- **敏感信息**: 凭据泄漏、数据加密、隐私保护
- **并发安全**: 死锁、竞态条件、数据竞争
- **整数安全**: 溢出、反转、除零

**问题严重等级**:
- 🔴 **致命**: 内存安全漏洞、权限提升、敏感数据泄漏
- 🟠 **严重**: 输入验证缺失、并发安全问题
- 🟡 **警告**: 加密算法不当、日志敏感信息

**参考文档**: `.refdocs/skills/srcurity_review/SKILL.md`

---

### 1.2 Logic Analyzer（逻辑分析）

**检查目标**: 发现代码逻辑层面的错误和缺陷

**检查内容**:
- **控制流**: 死代码、逻辑矛盾、条件覆盖不完整
- **数据流**: 未初始化变量、数据污染、类型不匹配
- **状态机**: 非法状态转换、状态不一致、死锁
- **边界条件**: 数组越界、空指针解引用、整数溢出
- **错误处理**: 遗漏错误路径、资源泄漏
- **并发控制**: 死锁、竞态条件、数据竞争
- **业务规则**: 不变性破坏、契约违反

**问题严重等级**:
- 🔴 **致命**: 非法状态转换、资源泄漏、死锁
- 🟠 **严重**: 未初始化变量、竞态条件、边界错误
- 🟡 **警告**: 死代码、冗余检查

**参考文档**: `.refdocs/skills/logic_analyzer/SKILL.md`

---

### 1.3 DFX Reviewer（DFX检查）

**检查目标**: 确保DFX（HiSysEvent/HiTrace）覆盖完整且规范

**检查内容**:
- **客户端禁令**: 客户端代码禁止打点
- **场景区分**: 不同业务场景使用不同事件名
- **事件覆盖**: 所有错误路径和成功路径都有事件
- **错误报告**: 错误信息包含上下文，错误码具体
- **数据隐私**: 敏感数据匿名化处理
- **HiTrace使用**: 长操作（>10ms）有trace span
- **条件编译**: HAS_HISYSEVENT_PART检查

**问题严重等级**:
- 🔴 **致命**: 客户端打点、敏感数据泄漏
- 🟠 **严重**: 场景未区分、事件覆盖不完整
- 🟡 **警告**: 错误信息不清楚、trace缺失

**参考文档**: `.refdocs/skills/dfx_reviewer/dfx_reviewer_universal.md`

---

### 1.4 Code Review Checklist（规范检查）

**检查目标**: 检查已知易犯错误和规范要求

**检查内容**:
- **兼容性**: API破坏性变更、错误码变更、性能劣化
- **日志规范**: 日志格式、高频代码日志、基本不可能发生点的日志
- **安全编码**: 指针使用、类型安全、数组安全、路径安全、内存管理
- **常见陷阱**:
  - Pitfall 1: SA初始化阻塞
  - Pitfall 2: 数据一致性
  - Pitfall 3: 敏感数据保护
  - Pitfall 4: 错误码处理
  - Pitfall 5: SA启动流程保护
  - Pitfall 6: 锁性能优化
  - Pitfall 7: IDL接口顺序
- **bundle_framework 特有陷阱**:
  - B1: Per-bundle Mutex 串行化
  - B2: bundleInfos_/DB/文件系统三方一致性
  - B3: InstallState 状态机合法转换
  - B4: OTA 升级幂等性
  - B5: 克隆应用多 appIndex 隔离
  - B6: IDL 接口与 Parcel 序列化兼容性
  - B7: ScopeGuard 使用模式

**问题严重等级**:
- 🔴 **致命**: API破坏性变更、SA初始化阻塞、IDL接口插入
- 🟠 **严重**: 日志格式错误、数据一致性问题、错误码处理不当
- 🟡 **警告**: 锁内性能问题、可优化但不影响功能

**参考文档**: `.refdocs/skills/code_review_checklist/SKILL.md`

---

### 1.5 Test Coverage Reviewer（测试覆盖度检查）

**检查目标**: 评估代码修改点的测试覆盖情况，识别测试缺口

**检查内容**:
- **已有覆盖分析**: 修改点涉及的旧逻辑是否已有测试用例覆盖
- **新增覆盖检查**: 如果旧逻辑无覆盖，本次变更是否添加了新用例
- **覆盖完备度评价**: 修改点的测试覆盖是否完备（路径、边界、错误路径、回归）
- **用例质量评估**: 新增用例的断言有效性、场景覆盖范围

**问题严重等级**:
- 🔴 **致命**: 核心业务逻辑修改点完全无测试覆盖，且本次未补充用例
- 🟠 **严重**: 关键修改点仅有间接覆盖，缺少直接验证
- 🟡 **警告**: 边界条件或错误路径缺少测试覆盖
- 🟢 **优化**: 测试质量可提升，但不影响基本验证

**参考文档**: `.refdocs/skills/test_coverage_reviewer/SKILL.md`

---

### 1.6 Coding Style Review（编码风格检查）

**检查目标**: 检查代码是否符合 OpenHarmony C/C++ 编码风格规范

**检查内容**:
- **格式化规则**: 行宽（120字符）、缩进（4空格）、大括号（K&R风格）、函数声明/调用格式、条件/循环语句大括号
- **命名规范**: 文件命名（小写+下划线）、变量命名（g_前缀/类成员_后缀）、函数命名（大驼峰）、类型命名、宏/常量/枚举命名（全大写）
- **注释规范**: 文件头版权声明、函数头注释、代码注释格式、英文注释
- **编码风格**: switch缩进、表达式换行、多变量定义分行、初始化格式、指针/引用格式
- **编译预处理**: #放行首、禁用宏表示常量、禁用函数式宏
- **空格空行**: 关键字/操作符/逗号前后空格规则、连续空行限制
- **类设计规范**（C++特有）: 类访问控制块顺序、初始化列表格式、成员变量命名、三/五/零法则、虚析构函数、对象切片防护、移动语义安全、成员初始化

**问题严重等级**:
- 🔴 **致命**: 无（编码风格不阻塞上库）→ 使用 🟡 **警告**
- 🟡 **警告**: 格式化违规、命名不规范、注释缺失、类设计违规

**参考文档**: `.refdocs/skills/code_review_checklist/SKILL.md`（F/G/H/I 节）

---

---

## 2. 检查执行流程

### 2.1 准备阶段

```bash
# 1. 确定检查范围
git diff main...your-branch --name-only

# 2. 识别变更类型
# - 新增代码
# - 修改现有代码
# - 删除代码
# - IDL文件变更

# 3. 确定检查策略
# - 小型变更（1-5文件）：快速检查
# - 中型变更（5-20文件）：详细检查
# - 大型变更（20+文件）：全面检查
```

### 2.2 执行阶段

#### 步骤1: Security Review

```bash
# 执行安全检查
"使用 security_review 检查以下文件的安全问题：
- services/bundlemgr/src/base_bundle_installer.cpp
- services/bundlemgr/src/bundle_data_mgr.cpp
- services/bundlemgr/src/bundle_mgr_service.cpp"
```

**检查重点**:
- 内存安全（指针、缓冲区）
- 输入验证（外部数据）
- 权限校验（访问控制）
- 敏感信息（凭据、日志）
- 并发安全（锁、竞态）

**输出**: Security Report
```
安全问题: N 个
- 致命: N 个
- 严重: N 个
- 警告: N 个
```

---

#### 步骤2: Logic Analyzer

```bash
# 执行逻辑分析
"使用 logic_analyzer 分析以下文件的逻辑问题：
- services/bundlemgr/src/base_bundle_installer.cpp
- services/bundlemgr/src/bundle_data_mgr.cpp
- services/bundlemgr/src/bundle_mgr_service.cpp"
```

**检查重点**:
- 控制流（死代码、逻辑矛盾）
- 数据流（未初始化、数据污染）
- 状态机（非法转换、状态不一致）
- 边界条件（越界、空指针、溢出）
- 错误处理（遗漏错误路径）
- 并发控制（死锁、竞态）
- 业务规则（不变性、契约）

**输出**: Logic Analysis Report
```
逻辑问题: N 个
- 致命: N 个
- 严重: N 个
- 警告: N 个
```

---

#### 步骤3: DFX Reviewer

```bash
# 执行DFX检查
"使用 dfx_reviewer 检查以下文件的DFX覆盖：
- services/bundlemgr/src/bundle_mgr_service.cpp
- services/bundlemgr/src/base_bundle_installer.cpp"
```

**检查重点**:
- 客户端禁令（frameworks/代码禁止打点）
- 场景区分（boot/settings/api/mdm）
- 事件覆盖（错误路径、成功路径）
- 错误报告（上下文、错误码）
- 数据隐私（匿名化）
- HiTrace使用（>10ms操作）

**输出**: DFX Review Report
```
DFX问题: N 个
- 致命: N 个
- 严重: N 个
- 警告: N 个
```

---

#### 步骤4: Code Review Checklist

```bash
# 执行规范检查
"使用 code_review_checklist 检查以下文件：
- 所有变更的.cpp和.h文件
- 所有变更的.idl文件"
```

**检查重点**:
- 兼容性（API变更、错误码）
- 日志规范（格式、高频代码）
- 安全编码（指针、类型、数组）
- 常见陷阱（Pitfall 1-7）
- bundle_framework 特有陷阱（B1-B7）

**输出**: Checklist Review Report
```
规范问题: N 个
- 致命: N 个
- 严重: N 个
- 警告: N 个
```

---

#### 步骤5: Test Coverage Reviewer

```bash
# 执行测试覆盖度检查
"使用 test_coverage_reviewer 检查以下文件的测试覆盖情况：
- 所有变更的 .cpp 和 .h 文件
- 所有变更的测试文件"
```

**检查重点**:
- 修改点识别（删除/新增/修改的代码路径）
- 已有覆盖分析（旧逻辑是否有测试）
- 新增覆盖检查（本次是否补充用例）
- 覆盖完备度（路径、边界、错误路径、回归）
- 用例质量（断言有效性、场景覆盖范围）

**输出**: Test Coverage Review Report
```
测试覆盖问题: N 个
- 致命: N 个
- 严重: N 个
- 警告: N 个
```

---

#### 步骤6: Coding Style Review

```bash
# 执行编码风格检查
"使用 code_review_checklist 的 F/G/H/I 节检查以下文件的编码风格：
- 所有变更的 .cpp 和 .h 文件
- 所有变更的 .c 和 .h 文件"
```

**检查重点**:
- 格式化规则（行宽、缩进、大括号、空格、空行）
- 命名规范（文件、变量、函数、类型、宏）
- 注释规范（文件头、函数头、代码注释）
- 类设计规范（成员命名、特殊成员函数、继承安全）
- 编译预处理规范（宏使用、#位置）

**输出**: Coding Style Review Report
```
编码风格问题: N 个
- 警告: N 个
- 建议: N 个
```

---

### 2.3 汇总阶段

#### 问题收集与分类

```python
# 伪代码：问题汇总流程
def aggregate_reports():
    all_issues = []

    # 收集Security Review问题
    security_issues = run_security_review()
    all_issues.extend(security_issues)

    # 收集Logic Analyzer问题
    logic_issues = run_logic_analyzer()
    all_issues.extend(logic_issues)

    # 收集DFX Review问题
    dfx_issues = run_dfx_reviewer()
    all_issues.extend(dfx_issues)

    # 收集Checklist问题
    checklist_issues = run_code_review_checklist()
    all_issues.extend(checklist_issues)

    # 收集Test Coverage Review问题
    test_coverage_issues = run_test_coverage_reviewer()
    all_issues.extend(test_coverage_issues)

    # 收集Coding Style Review问题
    coding_style_issues = run_coding_style_review()
    all_issues.extend(coding_style_issues)

    # 去重
    unique_issues = remove_duplicates(all_issues)

    # 分类
    categorized = categorize_issues(unique_issues)

    # 评估严重程度
    prioritized = prioritize_issues(categorized)

    # 生成报告
    report = generate_comprehensive_report(prioritized)

    return report
```

---

## 3. 综合报告模板

### 3.1 报告结构说明

综合报告采用分层结构，包含以下主要部分：

```markdown
# 综合代码修改检视报告

## 📋 检视摘要 (Executive Summary)
### 基本信息
### ✅ 检查项目清单（checklist形式）
### 🎯 总体评价
### 📊 问题统计

## 🔐 Security Review 检查结果
### 检查概览
### 问题详情
### 总结

## 🔍 Logic Analyzer 检查结果
### 检查概览
### 问题详情
### 总结

## 📊 DFX Reviewer 检查结果
### 检查概览
### 问题详情
### 总结

## 📋 Code Review Checklist 检查结果
### 检查概览
### 问题详情
### 总结

## 问题汇总与优先级
### 按严重程度汇总
### 修复优先级
### 修复建议

## 总结与建议
### 关键发现
### 改进建议
### 最终评价

## 附录
### 检查文件列表
### 参考文档
```

---

### 3.2 报告示例模板（通用版）

以下是一个通用化的报告模板，适用于任何代码检视场景：

```markdown
# 综合代码修改检视报告

## 📋 检视摘要 (Executive Summary)

### 基本信息
- **提交哈希**: `{COMMIT_HASH}`
- **提交信息**: `{COMMIT_MESSAGE}`
- **检视日期**: {REVIEW_DATE}
- **变更文件**: {FILE_COUNT} 个
- **变更行数**: +{ADDED_LINES} / -{DELETED_LINES}

---

### ✅ 检查项目清单

#### 🔐 Security Review（安全检查）

- ✅ **内存安全**: {内存安全检查结果}
- ❌ **并发安全**: {并发安全问题描述}（S-{ID}），{影响描述}
- ✅ **输入验证**: {输入验证检查结果}
- ✅ **权限控制**: {权限控制检查结果}
- ❌ **数据一致性**: {数据一致性问题}（S-{ID}），{影响描述}
- ✅ **敏感信息**: {敏感信息检查结果}

**小计**: {PASSED_COUNT}/{TOTAL_COUNT} 通过 {STATUS_ICON}

---

#### 🔍 Logic Analyzer（逻辑分析）

- ❌ **控制流**: {控制流问题描述}（L-{ID}），{影响描述}
- ✅ **状态机**: {状态机检查结果}
- ❌ **边界条件**: {边界条件描述}（L-{ID}）
- ✅ **错误处理**: {错误处理检查结果}
- ❌ **并发控制**: {并发控制问题}（L-{ID}）
- ✅ **业务规则**: {业务规则检查结果}

**小计**: {PASSED_COUNT}/{TOTAL_COUNT} 通过 {STATUS_ICON}

---

#### 📊 DFX Reviewer（DFX检查）

- ✅ **客户端禁令**: {客户端打点检查结果}
- ✅ **场景区分**: {场景区分检查结果}
- ❌ **事件覆盖**: {事件覆盖问题}（D-{ID}）
- ✅ **错误报告**: {错误报告检查结果}
- ✅ **数据隐私**: {数据隐私检查结果}
- ✅ **条件编译**: {条件编译检查结果}

**小计**: {PASSED_COUNT}/{TOTAL_COUNT} 通过 {STATUS_ICON}

---

#### 📋 Code Review Checklist（规范检查）

**兼容性检查**:
- ✅ **API变更**: {API变更检查结果}
- ✅ **IDL接口**: {IDL接口检查结果}
- ✅ **错误码**: {错误码检查结果}

**日志规范**:
- ✅ **日志格式**: {日志格式检查结果}
- ❌ **日志级别**: {日志级别问题}（C-{ID}）

**常见陷阱**:
- ❌ **Pitfall {N} {名称}**: {问题描述}（C-{ID}）
- ✅ **Pitfall {N} {名称}**: {检查结果}
- ✅ **Pitfall {N} {名称}**: {检查结果}

**小计**: {PASSED_COUNT}/{TOTAL_COUNT} 通过 {STATUS_ICON}

---

### 🎯 总体评价

| 维度 | 通过率 | 等级 | 评价 |
|------|--------|------|------|
| Security Review | {PERCENTAGE}% ({PASSED}/{TOTAL}) | {GRADE_ICON} {LEVEL} | {COMMENT} |
| Logic Analyzer | {PERCENTAGE}% ({PASSED}/{TOTAL}) | {GRADE_ICON} {LEVEL} | {COMMENT} |
| DFX Reviewer | {PERCENTAGE}% ({PASSED}/{TOTAL}) | {GRADE_ICON} {LEVEL} | {COMMENT} |
| Code Review Checklist | {PERCENTAGE}% ({PASSED}/{TOTAL}) | {GRADE_ICON} {LEVEL} | {COMMENT} |
| Coding Style Review | {PERCENTAGE}% ({PASSED}/{TOTAL}) | {GRADE_ICON} {LEVEL} | {COMMENT} |

**整体评分**: {SCORE}/100 ({GRADE_ICON} {LEVEL})

**整体风险等级**: {RISK_ICON} **{RISK_LEVEL}**

**是否建议上库**: {DECISION_ICON} **{DECISION}**

**阻塞原因**:
{BLOCKING_REASONS}

---

### 📊 问题统计

| 检查维度 | 问题总数 | 🔴 致命 | 🟠 严重 | 🟡 警告 |
|---------|---------|---------|---------|---------|
| Security Review | {COUNT} | {CRITICAL} | {MAJOR} | {MINOR} |
| Logic Analyzer | {COUNT} | {CRITICAL} | {MAJOR} | {MINOR} |
| DFX Reviewer | {COUNT} | {CRITICAL} | {MAJOR} | {MINOR} |
| Code Review Checklist | {COUNT} | {CRITICAL} | {MAJOR} | {MINOR} |
| Coding Style Review | {COUNT} | {CRITICAL} | {MAJOR} | {MINOR} |
| **总计** | **{TOTAL}** | **{TOTAL_CRITICAL}** | **{TOTAL_MAJOR}** | **{TOTAL_MINOR}** |

---

## 🔐 Security Review 检查结果

### 检查概览
- **检查文件数**: {FILE_COUNT} 个
- **发现问题数**: {ISSUE_COUNT} 个
- **致命问题**: {CRITICAL_COUNT} 个
- **严重问题**: {MAJOR_COUNT} 个
- **警告问题**: {MINOR_COUNT} 个
- **建议优化**: {SUGGESTION_COUNT} 个

### 问题详情

#### 问题 1: {问题标题} ({严重等级})

**位置**: `{FILE_PATH}:{LINE_NUMBER}`

**问题描述**:
{问题描述}

**当前代码**:
```cpp
{CURRENT_CODE}
```

**影响**:
- {影响1}
- {影响2}

**修复建议**:
```cpp
{SUGGESTED_CODE}
```

**严重等级**: {SEVERITY_ICON} {SEVERITY}
**来源**: Security Review

---

### Security Review 总结

#### 修复优先级
- 🔴 **立即修复（P0）**: {P0_COUNT} 个致命问题
- 🟠 **本周修复（P1）**: {P1_COUNT} 个严重问题
- 🟡 **逐步优化（P2）**: {P2_COUNT} 个警告问题

#### 关键问题
1. **S-{ID}**: {问题描述} - {影响}
2. **S-{ID}**: {问题描述} - {影响}
3. **S-{ID}**: {问题描述} - {影响}

---

## 🔍 Logic Analyzer 检查结果
## 📊 DFX Reviewer 检查结果
## 📋 Code Review Checklist 检查结果

（格式与 Security Review 类似，省略详细内容）

---

## 问题汇总与优先级

### 🔴 致命问题 (必须修复 - 阻塞上库)

| ID | 类型 | 位置 | 问题描述 | 来源 |
|----|------|------|----------|------|
| {ID} | {TYPE} | {LOCATION} | {DESCRIPTION} | {SOURCE} |
| {ID} | {TYPE} | {LOCATION} | {DESCRIPTION} | {SOURCE} |

**小计**: {COUNT} 个致命问题

---

### 🟠 严重问题 (强烈建议修复)

（格式同上）

---

### 🟡 警告问题 (建议修复)

（格式同上）

---

### 修复优先级

#### 第一优先级：立即修复 (P0)

**目标**: {TARGET}

**问题列表**:
1. {ID}: {问题描述}
2. {ID}: {问题描述}

**预计工作量**: {ESTIMATE}
**预期收益**: {BENEFIT}

---

#### 第二优先级：本周修复 (P1)

（格式同上）

---

#### 第三优先级：逐步优化 (P2)

（格式同上）

---

## 总结与建议

### 关键发现

#### 🔴 最严重的问题（必须修复）

| ID | 问题 | 位置 | 影响 | 优先级 |
|----|------|------|------|--------|
| {ID} | {PROBLEM} | {LOCATION} | {IMPACT} | P0 |

---

### 最终评价

#### 代码质量评分

**整体评分**: {SCORE}/100 ({GRADE_ICON} {LEVEL})

| 维度 | 得分 | 等级 | 说明 |
|------|------|------|------|
| 安全性 | {SCORE}/100 | {GRADE} | {COMMENT} |
| 逻辑正确性 | {SCORE}/100 | {GRADE} | {COMMENT} |
| DFX规范性 | {SCORE}/100 | {GRADE} | {COMMENT} |
| 代码规范性 | {SCORE}/100 | {GRADE} | {COMMENT} |

#### 上库决策

**是否建议上库**: {DECISION_ICON} **{DECISION}**

#### 阻塞原因检查清单

{CHECKLIST_ITEMS}

#### 上库前置条件

- [ ] {CONDITION_1}
- [ ] {CONDITION_2}
- [ ] {CONDITION_3}

---

## 附录

### A. 检查文件列表

```
{FILE_TREE}
```

### B. 参考文档

- **Security Review**: `{PATH_TO_SECURITY_SKILL}`
- **Logic Analyzer**: `{PATH_TO_LOGIC_SKILL}`
- **DFX Reviewer**: `{PATH_TO_DFX_SKILL}`
- **Code Review Checklist**: `{PATH_TO_CHECKLIST_SKILL}`

### C. 联系方式

- **检视者**: {REVIEWER}
- **检视日期**: {REVIEW_DATE}
- **报告版本**: {VERSION}

---

**报告生成时间**: {GENERATION_TIME}
**报告生成工具**: Comprehensive Code Review Skill {TOOL_VERSION}
**下次检视建议**: {NEXT_REVIEW_SUGGESTION}
```

---

## 4. 报告格式说明（v1.1新增）

### 4.1 报告特点

本次优化的报告模板具有以下特点：

#### 📋 Checklist 形式的 Summary

- ✅ **通过的项目**: 简洁打勾，一目了然
- ❌ **未通过的项目**: 简要描述问题并打叉
- 📊 **通过率统计**: 每个维度显示通过率
- 🎯 **总体评价**: 清晰的风险等级和上库建议

#### 🔍 分层结构

```
┌─────────────────────────────────────┐
│  📋 检视摘要 (Executive Summary)    │
│  ├─ 基本信息                          │
│  ├─ ✅ 检查项目清单（checklist）      │
│  ├─ 🎯 总体评价                       │
│  └─ 📊 问题统计                       │
├─────────────────────────────────────┤
│  详细问题分析（按维度）                │
│  ├─ 🔐 Security Review               │
│  ├─ 🔍 Logic Analyzer                │
│  ├─ 📊 DFX Reviewer                  │
│  └─ 📋 Code Review Checklist         │
├─────────────────────────────────────┤
│  📝 总结与建议                        │
│  ├─ 关键发现                          │
│  ├─ 修复优先级                        │
│  └─ 上库决策检查清单                   │
└─────────────────────────────────────┘
```

#### 🎨 视觉元素

- 🔴 **致命问题**: 阻塞上库
- 🟠 **严重问题**: 强烈建议修复
- 🟡 **警告问题**: 建议修复
- ✅ **通过**: 无问题
- ❌ **未通过**: 有问题
- ⚠️ **警告**: 需要注意

### 4.2 报告字段说明

#### 占位符说明

通用模板中使用的占位符及其含义：

| 占位符 | 含义 | 示例值 |
|--------|------|--------|
| `{COMMIT_HASH}` | Git提交哈希 | `abc1234` 或 `90f207a8` |
| `{COMMIT_MESSAGE}` | 提交信息 | `feat: add rollback mechanism` |
| `{REVIEW_DATE}` | 检视日期 | `2026-04-01` |
| `{FILE_COUNT}` | 变更文件数量 | `5 个` |
| `{ADDED_LINES}` | 新增行数 | `200` |
| `{DELETED_LINES}` | 删除行数 | `50` |
| `{PASSED_COUNT}` | 通过项数量 | `4` |
| `{TOTAL_COUNT}` | 总检查项数量 | `6` |
| `{STATUS_ICON}` | 状态图标 | ⚠️ / ✅ / ❌ |
| `{ID}` | 问题ID | `001` / `S-001` |
| `{PERCENTAGE}` | 通过率 | `67` |
| `{GRADE_ICON}` | 等级图标 | 🟡 / 🟢 / 🔴 |
| `{LEVEL}` | 等级名称 | `及格` / `良好` / `优秀` |
| `{COMMENT}` | 评价说明 | `存在数据一致性风险` |
| `{SCORE}` | 评分 | `65` |
| `{RISK_ICON}` | 风险图标 | 🔴 / 🟠 / 🟡 / 🟢 |
| `{RISK_LEVEL}` | 风险等级 | `高风险` / `中风险` / `低风险` |
| `{DECISION_ICON}` | 决策图标 | ❌ / ⚠️ / ✅ |
| `{DECISION}` | 决策结果 | `否` / `建议修复后上库` / `是` |
| `{SEVERITY}` | 严重等级 | `致命` / `严重` / `警告` |
| `{FILE_PATH}` | 文件路径 | `services/bundlemgr/src/base_bundle_installer.cpp` |
| `{LINE_NUMBER}` | 行号 | `145` |
| `{TYPE}` | 问题类型 | `Security` / `Logic` / `DFX` / `Checklist` |
| `{LOCATION}` | 问题位置 | `file.cpp:123` |
| `{SOURCE}` | 来源 | `Security Review` |
| `{P0_COUNT}` | P0问题数 | `1` |
| `{ESTIMATE}` | 预计工作量 | `2-3 天` |
| `{BENEFIT}` | 预期收益 | `消除崩溃风险` |
| `{REVIEWER}` | 检视者 | `AI Assistant` |
| `{VERSION}` | 报告版本 | `v1.0` |

#### 问题编号规则

不同检查维度使用不同的前缀：

- **S-{NN}**: Security Review 问题
- **L-{NN}**: Logic Analyzer 问题
- **D-{NN}**: DFX Reviewer 问题
- **C-{NN}**: Code Review Checklist 问题
- **T-{NN}**: Test Coverage Reviewer 问题
- **F-{NN}**: Coding Style Review 问题（编码风格/格式）

其中 NN 为两位数字序号（01, 02, 03...）

#### 严重等级图标

| 图标 | 等级 | 含义 | 阻塞上库 |
|------|------|------|----------|
| 🔴 | 致命 | 必须修复，否则阻塞上库 | ✅ |
| 🟠 | 严重 | 强烈建议修复 | ⚠️ |
| 🟡 | 警告 | 建议修复 | ❌ |
| 🟢 | 优化 | 可选优化 | ❌ |

#### 等级图标说明

| 图标 | 等级 | 评分范围 |
|------|------|----------|
| 🔴 | 差 | 0-59 |
| 🟡 | 及格 | 60-75 |
| 🟢 | 良好 | 76-89 |
| 🟢 | 优秀 | 90-100 |

---

### 4.3 简化示例（用于快速参考）

以下是一个简化的报告摘要示例，用于快速参考：

```markdown
## 📋 检视摘要 (Executive Summary)

### 基本信息
- **提交哈希**: `abc1234`
- **提交信息**: feat: some feature description
- **检视日期**: 2026-04-01
- **变更文件**: 5 个
- **变更行数**: +200 / -50

---

### ✅ 检查项目清单

#### 🔐 Security Review（安全检查）
- ✅ 内存安全: 无问题
- ❌ 并发安全: 存在锁使用问题（S-001），可能死锁
- ✅ 输入验证: 无问题
- ✅ 权限控制: 无问题
- ❌ 数据一致性: 操作缺少回滚机制（S-002）
- ✅ 敏感信息: 无问题

**小计**: 4/6 通过 ⚠️

---

#### 🔍 Logic Analyzer（逻辑分析）
- ✅ 控制流: 无问题
- ❌ 状态机: 状态转换不完整（L-001）
- ✅ 边界条件: 无问题
- ❌ 错误处理: 错误路径未处理（L-002）
- ✅ 并发控制: 无问题
- ✅ 业务规则: 无问题

**小计**: 4/6 通过 ⚠️

---

#### 📊 DFX Reviewer（DFX检查）
- ✅ 客户端禁令: 无问题
- ✅ 场景区分: 无问题
- ❌ 事件覆盖: 缺少DFX事件（D-001）
- ✅ 错误报告: 无问题
- ✅ 数据隐私: 无问题
- ✅ 条件编译: 无问题

**小计**: 5/6 通过 ⚠️

---

#### 📋 Code Review Checklist（规范检查）
- ✅ API变更: 无破坏性变更
- ✅ IDL接口: 无IDL变更
- ✅ 错误码: 无问题
- ✅ 日志格式: 符合规范
- ❌ 日志级别: 级别不当（C-001）
- ❌ Pitfall 2: 数据一致性问题（C-002）
- ✅ Pitfall 6: 无锁性能问题

**小计**: 6/7 通过 ⚠️

---

### 🎯 总体评价

| 维度 | 通过率 | 等级 | 评价 |
|------|--------|------|------|
| Security Review | 67% (4/6) | 🟡 及格 | 存在并发风险 |
| Logic Analyzer | 67% (4/6) | 🟡 及格 | 逻辑不完整 |
| DFX Reviewer | 83% (5/6) | 🟢 良好 | 基本符合规范 |
| Code Review Checklist | 86% (6/7) | 🟢 良好 | 少量规范问题 |
| Test Coverage Reviewer | 80% (4/5) | 🟢 良好 | 关键场景已覆盖 |

**整体评分**: 77/100 (🟢 良好)
**整体风险等级**: 🟡 **中风险**
**是否建议上库**: ⚠️ **建议修复后上库**

**阻塞原因**:
- ⚠️ 存在2个严重问题需要修复
- ⚠️ 建议修复所有警告问题后上库

---

### 📊 问题统计

| 检查维度 | 问题总数 | 🔴 致命 | 🟠 严重 | 🟡 警告 |
|---------|---------|---------|---------|---------|
| Security Review | 2 | 0 | 1 | 1 |
| Logic Analyzer | 2 | 0 | 1 | 1 |
| DFX Reviewer | 1 | 0 | 0 | 1 |
| Code Review Checklist | 2 | 0 | 1 | 1 |
| Test Coverage Reviewer | 1 | 0 | 0 | 1 |
| **总计** | **8** | **0** | **3** | **5** |
```

---

## 5. 使用指南

### 5.1 基本用法

```bash
# 综合检视分支变更
"使用 comprehensive_review 对分支 feature-xxx 进行综合代码检视"

# 综合检视特定文件
"使用 comprehensive_review 对以下文件进行综合检视：
- services/bundlemgr/src/base_bundle_installer.cpp
- services/bundlemgr/src/bundle_data_mgr.cpp"

# 只执行某个检查
"使用 comprehensive_review 只执行 security_review 检查"
```

### 5.2 输出说明

综合检视会生成以下输出：

1. **控制台输出**: 实时进度和关键发现
2. **综合报告**: 完整的Markdown格式报告
3. **问题清单**: 按优先级排序的问题列表
4. **修复建议**: 每个问题的具体修复方案

### 5.3 报告保存

```bash
# 保存报告到文件
"使用 comprehensive_review 对分支 feature-xxx 进行综合检视，
并将报告保存到 review_report.md"

# 生成JSON格式报告
"使用 comprehensive_review 对分支 feature-xxx 进行综合检视，
并生成JSON格式报告"
```

---

## 6. 版本历史

| 版本 | 日期 | 变更 | 维护者 |
|---------|------|---------|------------|
| v1.0 | 2026-04-01 | 初始版本，整合4个skills | AI Assistant |
| v1.1 | 2026-04-01 | 优化报告模板：Summary改为checklist形式 | AI Assistant |
| v1.2 | 2026-05-29 | 新增第5个检查维度：Test Coverage Reviewer（测试覆盖度检查） | AI Assistant |
| v1.3 | 2026-06-09 | 新增第6个检查维度：Coding Style Review（编码风格检查），涵盖格式化、命名、注释、类设计规范 | AI Assistant |

---

**文档结束**
