# Comprehensive Code Review - 使用指南

## 快速触发

在对话中使用以下任一关键词即可触发本技能：

**中文关键词**：检视、代码检视、综合检视、审查、代码审查、review、代码review

**英文关键词**：code review、comprehensive review、check code、inspect code

**使用示例**：
```
"请检视一下当前分支的代码变更"
"帮我code review这个PR"
"对以下文件进行综合检视：..."
```

---

## 简介

**Comprehensive Code Review** 是一个综合代码修改检视工具，整合了4个专门的skills，提供全方位的代码质量检查：

- 🔒 **Security Review** - 安全问题检查
- 🧠 **Logic Analyzer** - 逻辑问题检查
- 📊 **DFX Reviewer** - DFX覆盖检查
- ✅ **Code Review Checklist** - 规范检查

**特点**：
- ✅ **全面性**: 覆盖安全、逻辑、DFX、规范4个维度
- ✅ **自动化**: 自动执行所有检查并生成报告
- ✅ **汇总报告**: 生成包含Summary的全量报告
- ✅ **优先级排序**: 按严重程度自动排序问题
- ✅ **修复建议**: 每个问题都提供具体的修复方案

---

## 快速开始

### 基本用法

```bash
# 检视分支变更
"使用 comprehensive_review 对分支 feature-xxx 进行综合代码检视"

# 检视特定文件
"使用 comprehensive_review 对以下文件进行综合检视：
- services/bundlemgr/src/base_bundle_installer.cpp
- services/bundlemgr/src/bundle_data_mgr.cpp"

# 只执行特定检查
"使用 comprehensive_review 只执行 security_review 和 logic_analyzer"
```

### 示例输出

```
📋 综合代码修改检视报告

## Executive Summary

### 检视统计
| 检查维度 | 问题数 | 致命 | 严重 | 警告 |
|---------|-------|------|------|------|
| Security Review | 5 | 1 | 2 | 1 |
| Logic Analyzer | 8 | 2 | 3 | 2 |
| DFX Reviewer | 3 | 0 | 2 | 1 |
| Code Review Checklist | 6 | 1 | 3 | 1 |
| **总计** | **22** | **4** | **10** | **5** |

### 风险评估
- 整体风险等级: 🔴 高风险
- 阻塞问题数: 4 个（必须修复）
- 总体评价: ❌ 建议修复后再上库
```

---

## 检查流程

### 三阶段流程

```
┌─────────────────────────────────────────┐
│  第一阶段：准备                          │
│  ├─ 识别变更范围                        │
│  ├─ 确定检查策略                        │
│  └─ 准备检查环境                        │
├─────────────────────────────────────────┤
│  第二阶段：执行                          │
│  ├─ 1. Security Review                  │
│  ├─ 2. Logic Analyzer                   │
│  ├─ 3. DFX Reviewer                     │
│  └─ 4. Code Review Checklist            │
├─────────────────────────────────────────┤
│  第三阶段：汇总                          │
│  ├─ 收集所有检查结果                    │
│  ├─ 去重和分类问题                      │
│  ├─ 评估严重程度和影响                  │
│  └─ 生成综合报告                        │
└─────────────────────────────────────────┘
```

### 执行时间估算

| 变更规模 | 文件数 | 检查时间 | 说明 |
|---------|-------|---------|------|
| 小型变更 | 1-5 | 10-15 分钟 | 快速检查 |
| 中型变更 | 5-20 | 30-45 分钟 | 详细检查 |
| 大型变更 | 20+ | 60-90 分钟 | 全面检查 |

---

## 检查维度详解

### 1. Security Review（安全检查）

**目标**: 发现代码中的安全漏洞和风险

**检查内容**:
- 内存安全（指针、缓冲区）
- 输入验证（外部数据）
- 权限校验（访问控制）
- 敏感信息（凭据、日志）
- 并发安全（锁、竞态）

**输出示例**:
```
Security Review 检查结果:
- 检查文件数: 15
- 发现问题数: 5
  - 致命: 1 个（空指针解引用）
  - 严重: 2 个（权限校验缺失、数据污染）
  - 警告: 1 个（日志敏感信息）
  - 建议: 1 个（加密算法优化）
```

**详细文档**: `.refdocs/skills/srcurity_review/SKILL.md`

---

### 2. Logic Analyzer（逻辑分析）

**目标**: 发现代码逻辑层面的错误和缺陷

**检查内容**:
- 控制流（死代码、逻辑矛盾）
- 数据流（未初始化、数据污染）
- 状态机（非法转换、状态不一致）
- 边界条件（越界、空指针、溢出）
- 错误处理（遗漏错误路径）
- 并发控制（死锁、竞态）
- 业务规则（不变性、契约）

**输出示例**:
```
Logic Analyzer 检查结果:
- 检查文件数: 15
- 发现问题数: 8
  - 致命: 2 个（非法状态转换、竞态条件）
  - 严重: 3 个（错误路径遗漏、数组越界）
  - 警告: 2 个（死代码、逻辑矛盾）
  - 建议: 1 个（冗余检查）
```

**详细文档**: `.refdocs/skills/logic_analyzer/SKILL.md`

---

### 3. DFX Reviewer（DFX检查）

**目标**: 确保DFX（HiSysEvent/HiTrace）覆盖完整且规范

**检查内容**:
- 客户端禁令（frameworks/代码禁止打点）
- 场景区分（boot/settings/api/mdm）
- 事件覆盖（错误路径、成功路径）
- 错误报告（上下文、错误码）
- 数据隐私（匿名化）
- HiTrace使用（>10ms操作）

**输出示例**:
```
DFX Reviewer 检查结果:
- 检查文件数: 15
- 发现问题数: 3
  - 致命: 0 个
  - 严重: 2 个（客户端打点、场景未区分）
  - 警告: 1 个（错误信息不清楚）
  - 建议: 0 个
```

**详细文档**: `.refdocs/skills/dfx_reviewer/dfx_reviewer_universal.md`

---

### 4. Code Review Checklist（规范检查）

**目标**: 检查已知易犯错误和规范要求

**检查内容**:
- 兼容性（API变更、错误码）
- 日志规范（格式、高频代码）
- 安全编码（指针、类型、数组）
- 常见陷阱（Pitfall 1-7）
- bundle_framework 特有陷阱（B1-B7）

**输出示例**:
```
Code Review Checklist 检查结果:
- 检查文件数: 18（包含.idl）
- 发现问题数: 6
  - 致命: 1 个（IDL接口中间插入）
  - 严重: 3 个（日志格式、锁性能、错误处理）
  - 警告: 1 个（变量命名）
  - 建议: 1 个（性能优化）
```

**详细文档**: `.refdocs/skills/code_review_checklist/SKILL.md`

---

## 报告结构

### 完整报告结构

```markdown
# 综合代码修改检视报告

## Executive Summary (执行摘要)
### 检视概览
### 检视统计
### 风险评估
### 总体评价

## 1. Security Review 检查结果
### 1.1 检查概览
### 1.2 问题详情
### 1.3 总结

## 2. Logic Analyzer 检查结果
### 2.1 检查概览
### 2.2 问题详情
### 2.3 总结

## 3. DFX Reviewer 检查结果
### 3.1 检查概览
### 3.2 问题详情
### 3.3 总结

## 4. Code Review Checklist 检查结果
### 4.1 检查概览
### 4.2 问题详情
### 4.3 总结

## 5. 问题汇总与优先级
### 5.1 按严重程度汇总
#### 🔴 致命问题
#### 🟠 严重问题
#### 🟡 警告问题
#### 🟢 建议优化

## 6. 修复优先级与建议
### 6.1 修复优先级
#### 第一优先级：立即修复 (P0)
#### 第二优先级：本周修复 (P1)
#### 第三优先级：逐步优化 (P2)

## 7. 总结与建议
### 7.1 检视总结
### 7.2 关键发现
### 7.3 改进建议
### 7.4 最终评价

## 附录
### A. 检查文件列表
### B. 参考文档
### C. 联系方式
```

### 报告特点

1. **Executive Summary**: 提供快速概览和关键指标
2. **详细分析**: 每个检查维度的完整结果
3. **问题汇总**: 按严重程度统一排序
4. **修复建议**: 具体的修复方案和时间表
5. **总结评价**: 整体评分和是否建议上库

---

## 严重等级说明

| 等级 | 图标 | 说明 | 是否阻塞上库 | 示例 |
|------|------|------|-------------|------|
| **致命** | 🔴 | 必须修复，否则影响系统安全性或稳定性 | ✅ 是 | 空指针解引用、非法状态转换、死锁 |
| **严重** | 🟠 | 强烈建议修复，可能导致问题 | ✅ 是 | 权限校验缺失、错误路径遗漏 |
| **警告** | 🟡 | 建议修复，不影响基本功能 | ⚠️ 视情况 | 日志格式错误、死代码 |
| **建议** | 🟢 | 可选优化，改进代码质量 | ❌ 否 | 代码风格、性能优化 |

---

## 使用场景

### 场景1: PR审查前自我检查

```bash
# 在提交PR前进行自我检视
"使用 comprehensive_review 对当前分支进行综合检视，
重点检查安全问题和逻辑问题"
```

**预期结果**:
- 发现潜在问题
- 提前修复
- 提高PR通过率

---

### 场景2: 代码审查

```bash
# 审查他人的PR
"使用 comprehensive_review 对分支 feature/user-management
进行综合检视，生成详细的审查报告"
```

**预期结果**:
- 全面的问题清单
- 客观的评价
- 具体的修复建议

---

### 场景3: 重构后验证

```bash
# 重构完成后验证
"使用 comprehensive_review 对重构后的代码进行全面检视，
特别关注逻辑正确性和状态机"
```

**预期结果**:
- 验证重构正确性
- 发现引入的问题
- 确保质量不下降

---

### 场景4: 上线前检查

```bash
# 上线前的最后检查
"使用 comprehensive_review 对即将上线的代码进行最终检视，
重点检查安全问题和规范问题"
```

**预期结果**:
- 确保无致命问题
- 降低上线风险
- 提供上线决策依据

---

## 最佳实践

### 1. 检视前准备

```bash
# 确保在正确的分支
git checkout your-feature-branch

# 确保代码已编译
./build.sh

# 运行现有测试
./test.sh

# 查看变更文件
git diff --name-only main...HEAD
```

### 2. 检视时注意

- 📌 **关注变更的上下文**: 理解为什么这样修改
- 📌 **考虑所有可能路径**: 不要遗漏边界条件
- 📌 **验证假设**: 不要假设变量总是有效
- 📌 **检查并发场景**: 多线程环境下的行为
- 📌 **验证业务规则**: 确保符合业务约束

### 3. 检视后处理

- ✅ **创建Issue**: 为每个问题创建跟踪Issue
- ✅ **制定修复计划**: 按优先级排序
- ✅ **编写单元测试**: 覆盖发现的问题
- ✅ **代码审查**: 修复后的代码需要审查
- ✅ **验证关闭**: 测试通过后关闭Issue

---

## 常见问题 FAQ

### Q1: Comprehensive Review 与单独使用各个skill有什么区别？

**A**: Comprehensive Review 提供了：

1. **一站式检查**: 一次调用执行所有4个检查
2. **统一报告**: 整合所有检查结果到一个报告
3. **问题去重**: 自动识别和合并重复问题
4. **优先级排序**: 按严重程度统一排序
5. **Summary部分**: 提供快速概览和关键指标

而单独使用各个skill需要：
- 分别调用4次
- 手动整合报告
- 手动去重
- 手动排序

---

### Q2: 检查需要多长时间？

**A**: 取决于变更规模：

| 变更规模 | 检查时间 |
|---------|---------|
| 小型（1-5文件） | 10-15分钟 |
| 中型（5-20文件） | 30-45分钟 |
| 大型（20+文件） | 60-90分钟 |

---

### Q3: 所有发现的问题都必须修复吗？

**A**: 根据严重等级决定：

- 🔴 **致命问题**: 必须修复，否则阻塞上库
- 🟠 **严重问题**: 强烈建议修复
- 🟡 **警告问题**: 建议修复
- 🟢 **建议优化**: 可选

---

### Q4: 如何处理误报？

**A**: 如果发现误报：

1. **添加注释**: 在代码中添加清晰的注释
2. **更新分析**: 调整检查逻辑避免类似误报
3. **记录例外**: 在文档中记录已知的例外情况

---

### Q5: 能否只执行某些检查？

**A**: 可以！使用以下方式：

```bash
# 只执行安全和逻辑检查
"使用 comprehensive_review 只执行 security_review 和 logic_analyzer"

# 只执行DFX检查
"使用 comprehensive_review 只执行 dfx_reviewer"

# 自定义组合
"使用 comprehensive_review 执行 security_review、logic_analyzer 和 dfx_reviewer"
```

---

## 集成到工作流

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running Comprehensive Code Review..."

# 获取暂存的文件
FILES=$(git diff --cached --name-only --diff-filter=ACM '*.cpp' '*.h' '*.idl')

if [ -n "$FILES" ]; then
    echo "Analyzing files:"
    echo "$FILES"

    # 调用Comprehensive Review
    claude-code "使用 comprehensive_review 对以下文件进行快速检视: $FILES"

    # 检查是否有致命问题
    if [ $? -ne 0 ]; then
        echo "发现致命问题，请修复后再提交"
        exit 1
    fi
fi
```

### CI/CD 集成

```yaml
# .github/workflows/comprehensive-review.yml
name: Comprehensive Code Review

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run Comprehensive Review
        run: |
          claude-code "使用 comprehensive_review 对 PR #${{ github.event.number }} 进行综合检视"

      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: review-report
          path: review-report.md
```

---

## 相关资源

### 内部资源

- **Security Review**: `.refdocs/skills/srcurity_review/SKILL.md`
- **Logic Analyzer**: `.refdocs/skills/logic_analyzer/SKILL.md`
- **DFX Reviewer**: `.refdocs/skills/dfx_reviewer/dfx_reviewer_universal.md`
- **Code Review Checklist**: `.refdocs/skills/code_review_checklist/SKILL.md`

### 外部资源

- **OpenHarmony 编码规范**: 官方文档
- **C++ 安全编码规范**: CERT C++
- **DFX 开发指南**: OpenHarmony DFX文档

---

## 贡献

如果您发现Comprehensive Review有改进空间，欢迎：

1. **提出建议**: 创建issue描述改进方向
2. **提交PR**: 直接改进检查逻辑和文档
3. **分享案例**: 分享实际使用中发现的问题案例

---

## 版本历史

| 版本 | 日期 | 变更 |
|---------|------|---------|
| v1.0 | 2026-04-01 | 初始版本，整合4个skills |

---

**维护者**: AI Assistant
**最后更新**: 2026-04-01
**许可证**: 项目内部使用
