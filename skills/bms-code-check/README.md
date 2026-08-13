# Bundle Framework Code Review Skills

本目录包含 OpenHarmony Bundle Framework 项目的代码审查和分析技能（Skills）工具链。

> **🎯 快速触发**: 在对话中使用"检视"、"code review"等关键词即可自动触发综合代码检视！

---

## 📁 目录结构

```
skills/
├── README.md                         # 本文件 - Skills 总索引
│
├── codecheck_report_TEMPLATE.md      # 📋 统一报告模板（门禁固定格式）
│
├── orchestrator/                     # 🎯 代码检视编排器（自动触发入口）
│   ├── SKILL.md                       # 编排器配置与工作流
│   └── refute-rules.md                # 对抗性验证规则
│
├── comprehensive_review/             # ⭐ 综合代码检视 Skill（推荐）
│   ├── README.md                      # 综合检视使用指南
│   ├── SKILL.md                       # 综合检视详细指南
│   └── QUICKSTART.md                  # 快速参考指南
│
├── security_review/                  # 🔒 安全审计 Skill
│   ├── README.md                      # 安全审计使用指南
│   └── SKILL.md                       # 安全审计详细指南
│
├── logic_analyzer/                   # 🧠 逻辑分析 Skill
│   ├── README.md                      # 逻辑分析使用指南
│   ├── SKILL.md                       # 逻辑分析详细指南
│   └── QUICKSTART.md                  # 快速参考指南
│
├── dfx_reviewer/                     # 📊 DFX 检查 Skill
│   ├── README.md                      # DFX 使用指南
│   ├── dfx_reviewer_universal.md      # 通用 DFX 文档
│   ├── DFX_Adaptation_Guide.md        # DFX 适配指南
│   ├── dfx_skill_config_template.yaml # 配置模板
│   └── SKILL.md                       # bundle_framework 专用版本
│
├── code_review_checklist/            # ✅ 规范检查 Skill
│   ├── README.md                      # 规范检查使用指南
│   └── SKILL.md                       # 规范检查详细指南
│
└── architecture_analyzer/            # 🏗️ 架构分析 Skill
    ├── README.md                      # 架构分析使用指南
    └── code_architecture_analyzer.md  # 架构分析与优化指南
```

---

## 🚀 快速开始

### 代码检视编排器（自动触发）🎯

**自动触发关键词**：
- 中文: `检视一下代码`、`帮我审一下`、`代码检视`、`全面检视`、`深度扫描`、`代码审查`、`review`
- 英文: `code review`、`codecheck`、`comprehensive review`、`deep scan`、`audit`

**使用示例**：
```bash
# 以下任一表达都会自动触发编排器
"请检视一下当前分支的代码"
"帮我code review这个PR"
"对 services/bundlemgr/ 进行全面检视"
"深度扫描 feature-xxx 分支"
```

**Codecheck Orchestrator** 会自动执行：
1. 🔍 **并行调度** — 同时运行所有检视 skill 获取结果
2. 📋 **检视维度** — security + logic + dfx + checklist + test（可选 + architecture）
3. 🛡️ **对抗性验证** — Refute 三层质疑（触发路径/影响夸大/根因去重）
4. 📊 **统一报告** — 生成符合门禁规范的综合报告

**默认调用的检视 skill**：
- `security_review` — 内存安全、输入验证、权限、敏感信息、并发
- `logic_analyzer` — 控制流、数据流、状态机、边界条件、错误处理
- `dfx_reviewer` — HiLog、HiSysEvent、HiTrace 覆盖
- `code_review_checklist` — 兼容性、日志规范、编码风格、命名、注释
- `test_coverage_reviewer` — 测试用例覆盖度

**输出**：
- `codecheck_report_{change_id}.md` — 统一检视报告
- `refute_log.md` — 对抗性验证记录
- 各 scanner 原始产出

**详细文档**: [`orchestrator/SKILL.md`](orchestrator/SKILL.md)

---

### 一站式综合检视（推荐）⭐

**自动触发关键词**：
- 中文: `检视`、`代码检视`、`综合检视`、`审查`、`代码审查`、`review`
- 英文: `code review`、`comprehensive review`、`check code`、`inspect code`

**使用示例**：
```bash
# 以下任一表达都会自动触发综合检视
"请检视一下当前分支的代码"
"帮我code review这个PR"
"对以下文件进行综合检视："
"审查一下 feature-xxx 分支的代码变更"
```

**Comprehensive Review** 会自动执行：
1. 🔒 **Security Review** - 安全问题检查
2. 🧠 **Logic Analyzer** - 逻辑问题检查
3. 📊 **DFX Reviewer** - DFX 覆盖检查
4. ✅ **Code Review Checklist** - 规范检查

**输出**：
- Executive Summary（执行摘要）
- 检视统计表
- 风险评估
- 按严重程度排序的问题清单
- 修复建议和优先级

**详细文档**: `.refdocs/skills/comprehensive_review/`

---

### 单独使用各个 Skill

如果你只需要执行某个特定检查：

#### 1. Security Review（安全审计）

```bash
"使用 security_review 检查以下文件的安全问题"
```

**检查内容**：
- 内存安全（指针、缓冲区）
- 输入验证（外部数据）
- 权限校验（访问控制）
- 敏感信息（凭据、日志）
- 并发安全（锁、竞态）

**适用场景**：
- 安全审计
- 处理敏感数据的代码
- 权限管理相关功能

---

#### 2. Logic Analyzer（逻辑分析）

```bash
"使用 logic_analyzer 分析分支 feature-xxx 的逻辑变更"
```

**检查内容**：
- 控制流（死代码、逻辑矛盾）
- 数据流（未初始化、数据污染）
- 状态机（非法转换、状态不一致）
- 边界条件（越界、空指针、溢出）
- 错误处理（遗漏错误路径）
- 并发控制（死锁、竞态）
- 业务规则（不变性、契约）

**适用场景**：
- 复杂功能开发
- 状态机实现
- 并发逻辑处理
- 重构项目

---

#### 3. DFX Reviewer（DFX 检查）

```bash
"使用 dfx_reviewer 检查DFX覆盖是否完整"
```

**检查内容**：
- 客户端禁令（frameworks/代码禁止打点）
- 场景区分（boot/settings/api/mdm）
- 事件覆盖（错误路径、成功路径）
- 错误报告（上下文、错误码）
- 数据隐私（匿名化）
- HiTrace 使用（>10ms 操作）

**适用场景**：
- DFX 实现质量保证
- 可观测性要求
- 问题诊断和监控

---

#### 4. Code Review Checklist（规范检查）

```bash
"使用 code_review_checklist 检查常见陷阱"
```

**检查内容**：
- 兼容性（API 变更、错误码）
- 日志规范（格式、高频代码）
- 安全编码（指针、类型、数组）
- 常见陷阱（Pitfall 1-7）
- bundle_framework 特有陷阱（B1-B7）

**适用场景**：
- PR 审查
- 规范符合性检查
- 新手上路指导

---

#### 5. Architecture Analyzer（架构分析）

```bash
"使用 architecture_analyzer 评估架构设计"
```

**检查内容**：
- 模块化程度
- 依赖关系
- 接口设计
- 可扩展性
- 可测试性
- 性能考虑

**适用场景**：
- 架构评审
- 重构项目
- 技术债务评估

---

## 📊 Skills 对比

| 特性 | **Orchestrator** 🎯 | **Comprehensive** ⭐ | Security | Logic | DFX | Checklist | Architecture |
|------|--------------------|---------------------|----------|-------|-----|-----------|--------------|
| **主要目标** | 门禁报告 | 全面质量 | 安全漏洞 | 逻辑正确 | DFX规范 | 规范符合 | 架构质量 |
| **检查维度** | 自动选择 | 4个全部 | 安全 | 逻辑 | DFX | 规范 | 架构 |
| **自动触发** | ✅ 是 | ✅ 是 | ❌ | ❌ | ❌ | ❌ | ❌ |
| **特征探测** | ✅ 是 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **对抗验证** | ✅ Refute | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **门禁报告** | ✅ 固定格式 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Summary** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **去重功能** | ✅ 根因去重 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **优先级排序** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **使用时机** | 门禁/全阶段 | 全阶段 | 安全审计 | 复杂功能 | DFX实现 | PR审查 | 架构评审 |
| **学习曲线** | 低 | 低 | 中 | 高 | 中 | 中 | 高 |
| **自动化程度** | 高 | 高 | 中 | 低 | 高 | 中 | 低 |

**推荐使用顺序**：
1. ⭐ **Comprehensive Review** - 首选，一站式全面检视
2. 单个 Skill - 针对特定问题深度分析
3. 组合使用 - 完整的质量保障流程

---

## 🎯 使用建议

### 推荐工作流

#### 方案 A: 一站式检视（推荐）⭐

```bash
# 适用于: PR审查、上线前检查、重要功能开发
"请检视一下分支 feature-xxx 的代码变更"
```

**优点**：
- ✅ 一次调用执行所有检查
- ✅ 自动生成汇总报告
- ✅ 问题去重和优先级排序
- ✅ 提供修复建议和时间表

#### 方案 B: 分步检视

适用于需要深入了解特定问题或学习各个 Skill 的场景：

```bash
# 1. 安全检查
"使用 security_review 检查安全问题"

# 2. 逻辑分析
"使用 logic_analyzer 分析逻辑变更"

# 3. DFX 检查
"使用 dfx_reviewer 检查DFX覆盖"

# 4. 规范检查
"使用 code_review_checklist 检查规范"
```

**优点**：
- ✅ 深入了解每个检查维度
- ✅ 可以单独关注特定问题
- ✅ 适合学习和培训

#### 方案 C: 架构优先

适用于新功能设计或重构项目：

```bash
# 1. 先进行架构评审
"使用 architecture_analyzer 评估架构设计"

# 2. 再进行综合检视
"请检视一下实现代码"
```

**优点**：
- ✅ 从架构层面保证质量
- ✅ 及早发现设计问题
- ✅ 避免重大返工

---

### 开发阶段建议

#### 1. 需求分析阶段

- 使用 **Architecture Analyzer** 评估架构设计
- 识别潜在的技术债务

#### 2. 开发实现阶段

- 参考 **DFX Reviewer** 文档实现 DFX
- 使用 **Code Review Checklist** 避免常见陷阱
- 复杂逻辑使用 **Logic Analyzer** 分析

#### 3. PR 提交前

- ⭐ **使用 Comprehensive Review 进行全面检视**
- 修复所有致命和严重问题
- 确保符合所有规范

#### 4. 上线前

- ⭐ **再次使用 Comprehensive Review 进行最终检视**
- 重点检查安全问题和性能影响
- 验证 DFX 覆盖完整

#### 5. 定期维护

- 使用 **Security Review** 进行安全审计
- 使用 **Architecture Analyzer** 评估架构健康度
- 建立质量度量体系

---

## 📈 质量提升路径

### 第一阶段：基础规范（1-2周）

**目标**: 建立基本的代码规范意识

**行动**:
1. 阅读 CLAUDE.md 了解项目规范
2. 学习触发关键词，尝试使用综合检视
3. 阅读 Code Review Checklist 了解常见陷阱
4. 理解 DFX 基本规范

**预期结果**:
- ✅ 会使用触发关键词自动检视代码
- ✅ 修复明显的规范问题
- ✅ 了解综合报告的各个部分

### 第二阶段：深入理解（2-4周）

**目标**: 深入理解各个检查维度

**行动**:
1. 学习 Security Review 的检查内容
2. 学习 Logic Analyzer 的分析方法
3. 理解 DFX 的场景区分原则
4. 深入研究综合报告的每个部分

**预期结果**:
- ✅ 能够解读综合报告的所有内容
- ✅ 理解问题的严重等级分类
- ✅ 能够根据报告制定修复计划

### 第三阶段：独立分析（1-2个月）

**目标**: 能够独立进行代码分析

**行动**:
1. 尝试单独使用各个 Skill
2. 对比综合报告和单独报告的差异
3. 学习架构分析方法
4. 参与代码审查，积累经验

**预期结果**:
- ✅ 能够选择合适的 Skill 解决问题
- ✅ 能够进行架构分析
- ✅ 能够指导他人使用这些工具

### 第四阶段：持续改进（长期）

**目标**: 建立持续改进机制

**行动**:
1. 将综合检视集成到开发流程
2. 建立质量度量体系
3. 定期进行架构健康检查
4. 根据反馈优化检查规则

**预期结果**:
- ✅ 建立全面的质量保障体系
- ✅ 持续提升代码质量
- ✅ 形成最佳实践知识库

---

## 🛠️ 自动化工具

### 检查脚本

位于 `.refdocs/scripts/` 目录：

```bash
# IDL 接口顺序检查
./.refdocs/scripts/check_idl_interface_order.sh

# 其他检查脚本（如有）
ls .refdocs/scripts/
```

### CI/CD 集成建议

可以将 Comprehensive Review 集成到 CI/CD 流程中：

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
          # 触发综合检视
          echo "触发代码检视: 检视 PR #${{ github.event.number }}"
```

---

## 🤝 贡献指南

### 改进现有 Skill

如果你发现某个 Skill 需要改进：

1. 阅读 Skill 的文档
2. 提出改进建议或 Issue
3. 提交 PR 并说明改进理由
4. 更新相关文档

### 添加新 Skill

如果你想添加新的代码审查 Skill：

1. 在 `skills/` 下创建新的子目录
2. 编写 README.md 和 SKILL.md
3. 保持与现有 Skill 一致的结构
4. 在本 README.md 中添加说明
5. 更新 Skills 对比表

### 优化触发关键词

如果需要调整自动触发关键词：

1. 编辑项目根目录的 `CLAUDE.md`
2. 更新 `skills/comprehensive_review/SKILL.md`
3. 测试触发效果
4. 更新本文档

---

## 📞 支持和反馈

### 获取帮助

- **综合检视**: 查看 `comprehensive_review/README.md`
- **安全检查**: 查看 `security_review/README.md`
- **逻辑分析**: 查看 `logic_analyzer/README.md`
- **DFX 检查**: 查看 `dfx_reviewer/README.md`
- **规范检查**: 查看 `code_review_checklist/README.md`
- **架构分析**: 查看 `architecture_analyzer/README.md`

### 提供反馈

如果你有任何改进建议：

1. **小改进**: 直接提交 PR
2. **大改进**: 先讨论再实施
3. **新需求**: 与团队讨论
4. **Bug 报告**: 提交 Issue

---

## 📝 更新日志

### v7.0 (2026-04-01) - 自动触发功能 🎯

**新增**:
- ✅ 添加自动触发关键词配置
- ✅ 创建项目 CLAUDE.md 配置文件
- ✅ 支持中英文触发关键词
- ✅ 优化快速开始指南
- ✅ 添加触发示例

**改进**:
- ✅ 更新 Skills 对比表
- ✅ 优化使用建议和工作流
- ✅ 改进质量提升路径
- ✅ 添加 CI/CD 集成建议

### v6.0 (2026-04-01) - Comprehensive Review Skill

**新增**:
- ✅ 新增 Comprehensive Review Skill
- ✅ 整合 4 个专门 Skills
- ✅ 三阶段流程（准备→执行→汇总）
- ✅ 自动去重和优先级排序
- ✅ Executive Summary

### v5.0 (2026-04-01) - Logic Analyzer Skill

**新增**:
- ✅ 新增 Logic Analyzer Skill
- ✅ 三层分析模型
- ✅ 七大分析维度
- ✅ 完整的问题检测模式

### v4.0 (2026-03-24) - Skills 目录重组

**改进**:
- ✅ 将各个 Skill 拆分到独立目录
- ✅ 为每个 Skill 创建独立文档
- ✅ 改进整体目录结构

---

## ⭐ 推荐使用

**对于大多数场景，推荐使用 Comprehensive Review**：

```bash
# 一句话触发全面检视
"请检视一下当前分支的代码"
```

**Comprehensive Review 的优势**：
- ✅ 一次调用执行所有检查
- ✅ 自动生成汇总报告
- ✅ 问题去重和优先级排序
- ✅ 提供修复建议
- ✅ 支持自动触发

---

**最后更新**: 2026-06-22
**维护**: Bundle Framework 开发团队
**许可**: 项目内部使用
**推荐**: Comprehensive Review（一站式综合检视）⭐
