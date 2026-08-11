---
name: codecheck-orchestrator
description: |
  代码检视唯一编排器：默认调用所有可用检视 skill（security/logic/dfx/checklist/test/architecture），
  并行调度各 scanner 执行扫描，收集原始产出后执行 Refute 对抗性验证（触发路径证伪 + 影响夸大证伪 + 跨 scanner 根因去重），
  过滤后的发现按 codecheck_report_TEMPLATE.md 合并为一份统一报告。
version: 1.0.0
author: BMS CodeCheck Team
tags:
  - codecheck
  - orchestrator
  - review
  - audit
  - security
  - logic
  - dfx
  - comprehensive
triggers:
  - 检视一下代码
  - 帮我审一下
  - 做一次 code review
  - 代码审查
  - review 一下
  - 审一下这块代码
  - codecheck
  - 代码检视
  - 全面检视
  - 生成检视报告
  - 深度扫描
  - 全面排查
  - 安全审计
  - bug audit
  - 编排器
  - orchestrator
scope: bms
---

# Codecheck Orchestrator — 唯一编排器入口

# Codecheck Orchestrator — 唯一编排器

## 定位

本 skill 是 [`skills/codecheck/`](..) 工作台的**唯一调度与报告合并层**。它解决一个问题：用户说"检视一下代码"或"深度扫描"时，按范围**自动探测路径特征、选择 scanner 组合、并行调度、Refute 对抗性验证、合并成一份统一报告**。

> 导航中枢是 [README.md](../README.md)。本 skill 是 README 中"检视流程"的可执行版本。

## 与 scanner 的关系

本编排器默认调用**所有可用检视 skill**，并行执行后合并结果。

| Scanner Skill | 目录 | 检查维度 | 调用条件 |
|--------------|------|---------|---------|
| `security_review` | security_review/ | 内存安全、输入验证、权限、敏感信息、并发 | ✅ 默认调用 |
| `logic_analyzer` | logic_analyzer/ | 控制流、数据流、状态机、边界条件、错误处理 | ✅ 默认调用 |
| `dfx_reviewer` | dfx_reviewer/ | HiLog、HiSysEvent、HiTrace 覆盖 | ✅ 默认调用 |
| `code_review_checklist` | code_review_checklist/ | 兼容性、日志规范、编码风格、命名、注释 | ✅ 默认调用 |
| `test_coverage_reviewer` | test_coverage_reviewer/ | 测试用例覆盖度 | ✅ 默认调用 |
| `architecture_analyzer` | architecture_analyzer/ | 模块化、依赖、接口设计、可扩展性 | 用户指定或大型变更 |

**原则**：
- scanner 之间无数据依赖，全部并行执行
- 保留各 scanner 原始产出，不在中间改写
- 用户指定单一维度时，可绕过编排器直接调用对应 scanner

---

## 工作流

### Step 1: 界定范围（缺则向用户确认）

必明确三项：
1. **目标**：路径（如 `services/abilitymgr/src/`）或 Kit 名（如 `abilityKit`）。
2. **检视重点**：未指定时默认"通用检视"。
3. **版本信息**：从 git 获取完整 commit-id（full SHA, 40 位十六进制）和 Change-Id，记入报告头部。

```bash
# 获取 commit-id（完整 40 位）
git rev-parse HEAD
# 获取 Change-Id
git log -1 --format="%b" | grep -o 'Change-Id: I[0-9a-f]\{40\}'
# 获取 commit message 第一行（subject）
git log -1 --format="%s"
```

若用户只说"检视一下代码"未给范围，**必须先问**，不要默认全仓。

### Step 2: 选择 scanner 组合

#### 2.1 默认组合（通用检视）

**默认调用所有 5 个核心检视 skill**：

```
security_review → logic_analyzer → dfx_reviewer → code_review_checklist → test_coverage_reviewer
                     ↓              ↓               ↓                      ↓
                    并行执行全部 skill
```

#### 2.2 按用户意图调整

| 用户意图 | 调用组合 |
|---------|---------|
| 默认（"检视一下代码"） | **全部 5 个** skill |
| 用户指定单一维度（如"只检查安全"） | 只调 `security_review` |
| 大型架构变更 | **全部 6 个** skill + `architecture_analyzer` |
| 用户说"快速检视" | `security_review` + `logic_analyzer` + `code_review_checklist` |

#### 2.3 告知用户选择结果

选定的 scanner 组合写入报告元数据 YAML 块（dimensions_executed）。

### Step 3: 并行调度 scanner

子 scanner 之间无数据依赖，全部并行执行（多个 Agent 或多个工具调用并发）。保留各 scanner 原始产出（md/csv/excel），不在中间改写。

记录每个 scanner 的：
- 产出文件路径
- 发现总数与分级（P0/P1/P2/P3 或 Confirmed/Likely/Suspicious）

### Step 4: 收集各 scanner 原始产出

### Step 5: Refute — 对抗性验证 🔥 新增

对每条发现执行三层质疑。详细规则见 [`refute-rules.md`](refute-rules.md)。

**第一层：触发路径证伪** — "真的能被触发吗？"
- 上游空指针防护：追溯发现点函数的调用者，检查传入参数前是否有 `if (ptr == nullptr) return`
- 不可达路径：检查发现点是否在 `#ifdef DEBUG`、已废弃函数、仅测试代码路径
- 数据来源为常量：标注为"外部输入"的变量，上游是否为 `static const` 或编译期已知值
- IPC 接口暴露面：检查 IPC 接口的调用方权限（是否仅系统进程可调、是否有 SELinux 策略保护）
- 断言/protobuf 防护：上游有 `assert` 或 protobuf 解析自带边界校验（assert release 不生效 → 维持；protobuf 可靠 → 推翻）
- 弱防护：上游有检查但不完整（如仅检查 nullptr 但没检查空字符串、仅检查长度上限但没检查下限）

**第二层：影响夸大证伪** — "后果真的这么严重吗？"
- Defensive double-free：`free(ptr); ptr = nullptr;` 再 free → 检查两次 free 之间 ptr 是否被置 null → 有 → 推翻
- 进程退出时资源泄漏：静态资源在进程退出时未释放 → 检查是否在 exit() 路径 → OS 自动回收 → 降级为 P3
- 整数溢出不可达：`int a = b + c` 溢出，但 b 和 c 均来自 `uint8_t` → 计算实际输入范围 → 不可溢出 → 推翻
- UAF 仅涉及日志打印：释放后使用仅在 `HILOG_INFO` 中读整数值 → 检查 use 点是否影响控制流 → 仅日志 → 降两级
- 回调泄漏但数量有限：回调总数有上限 → 计算实际泄漏上限 → 上限小 → 降级
- 静态 bool 标志位无锁：标志位用于一次性初始化 → 检查是否只在单线程初始化阶段设置 → 单次设置 → 降级为 P3

**第三层：跨 scanner 根因去重** — "这两个发现本质是同一个根因吗？"
- 不同于 `file:line` 机械去重，基于修复方案反推
- 同一修复改动 → 合并（例：SEC-005 空指针 + LOG-004 状态更新异常 + SEC-007 异常路径未释放锁 → 根因是 `mission_list_manager.cpp:412` 缺一次 nullptr 检查，合并为一条）
- 连锁影响 → 合并到根因（例：缺少边界校验 → 越界写入 → 相邻内存损坏 → 合并为一条"缺少边界校验"）
- 独立发现（即使同文件，修复需改动不同位置）→ 维持独立

**产出 `refute_log.md`**，记录每条发现的判定：✅ 维持 | ⬇️ 降级 | ❌ 推翻 | 🔀 合并。详见 [`refute-rules.md`](refute-rules.md)。

### Step 6: 合并为统一报告

基于 `refute_log.md` 过滤后的发现列表，按 [`codecheck_report_TEMPLATE.md`](../codecheck_report_TEMPLATE.md) 生成最终报告。

**必须使用权威模板**。模板固定了：
- 头部 **YAML 报告元数据块**（机器可读，字段名/取值域固定，`risk_level` 仅 `low|medium|high|unknown`，`gate_decision` 仅 `approve|conditional|block|insufficient`）。
- **固定章节**：1 门禁结论 → 2 扣分原因 → 3 必须立即处理（P0/P1）→ 4 建议跟进（P2/P3）→ 5 分维度速览 → 6 关键发现详情。评分与门禁规则见 conventions.md §9。
- **评分与决策矩阵**（见 conventions.md §9）：`评分 = max(0, 100 − (30×P0 + 12×P1 + 5×P2 + 2×P3))`；存在 P0 → block，存在 P1 → conditional，评分 ≥90 → approve，≥70 → conditional，否则 block；必检维度缺失 → insufficient。严重等级统一归一化为 P0–P3。

**执行合并时**：
1. 跨维度去重以 `file:line` 为第一键；同位置多维度命中合并为一条，标注全部维度来源。
2. 不同 `file:line` 但同根因 → 由 refuter 在 Step 5 合并。
3. 按 conventions.md §9 计算 `score` / `risk_level` / `gate_decision`，同时写入 YAML 元数据块与第 1 节门禁结论表格（两者必须一致）。
4. 必检维度缺失时，决策为 `insufficient`；维度无适用面（如文档仅提交无代码）时该维度仍计入 `dimensions_executed` 并在 §5 分维度速览注明 N/A 理由，不计为缺失。

### Step 7: 交付

向用户交付：
1. 统一报告路径。
2. Executive Summary 摘要：各维度结果、总分、上库决策。
3. Top 高危项（P0 问题）及其阻塞原因。
4. 各 scanner 原始产出路径（便于深入查阅）。
5. `refute_log.md` 路径（对抗性验证记录）。

不直接改源码——修复由用户确认后另起任务。

---

## 必检维度

| 目标类型 | 必检维度（默认执行） |
|---------|---------------------|
| **代码变更**（默认） | `security_review` + `logic_analyzer` + `dfx_reviewer` + `code_review_checklist` + `test_coverage_reviewer` |
| **大型架构变更** | 上述全部 + `architecture_analyzer` |
| **纯文档变更** | 仅文档规范检查，跳过代码 scanner |

**维度说明**：
- `security_review`：内存安全、输入验证、权限、敏感信息、并发
- `logic_analyzer`：控制流、数据流、状态机、边界条件、错误处理
- `dfx_reviewer`：HiLog、HiSysEvent、HiTrace 覆盖
- `code_review_checklist`：兼容性、日志规范、编码风格、命名、注释
- `test_coverage_reviewer`：测试用例覆盖度
- `architecture_analyzer`：模块化、依赖、接口设计、可扩展性

---

## 约定

- **静态语言实现默认排除**：`frameworks/ets/ani/`、`frameworks/ets/ets/`、`frameworks/cj/ffi/`、`ets_*.cpp`、`cj_*.cpp`，除非用户明确要求包含。
- **证据要求**：每条发现可追溯到 `file:line` + 触发路径，不收无证据代码气味项。
- **去重**：跨 scanner 去重以 `file:line` 为第一键；同位置多 scanner 命中合并为一条，标注全部维度来源。
- **让位**：用户指定单一维度（纯安全/纯 API/纯外部输入/纯逻辑）时，可绕过本编排器，直接路由到对应 scanner。
- **不动代码**：检视阶段只产出报告与建议，不直接改源码；修复由用户确认后另起任务。
- **Refute 只质疑不发现**：refuter 不能新增任何 scanner 未报告的发现。
- **Refute 必须有代码证据**：推翻或降级必须引用具体 file:line。
- **被推翻的发现保留在 refute_log.md**：不进入统一报告正文，仅在 refute_log.md 记录条目和理由，便于人工复核捞回。
- **P0 推翻需更严格证据**：不能仅凭"极难触发"推翻 P0，必须是"确认不可达"（上游硬 guard 或编译器保证）。
- **refute_log.md 与最终报告一并交付**。
