---
name: architecture_analyzer
description: 系统化的代码架构分析方法，识别架构问题并提供具体的优化建议
version: 1.0.0
author: Architecture Team
tags:
  - architecture
  - design
  - dependency
  - performance
  - refactoring
triggers:
  - 架构分析
  - architecture analysis
  - code architecture
  - design review
  - 架构审查
  - dependency analysis
  - 模块化
  - 分层架构
  - design pattern
---

# Code Architecture Analyzer & Optimization Advisor Skill

**版本**: v1.0
**更新日期**: 2026-03-23
**状态**: ✅ 通用架构分析工具

---

## 📚 Skill 概述

本 skill 提供系统化的代码架构分析方法，能够识别架构问题并提供具体的优化建议。

### 任务目标
你是一位拥有 15 年经验的资深系统架构工程师。你的任务是对给定的代码库进行商用前的地毯式架构审查。你必须识别出所有潜在的架构问题、代码循环依赖、代码耦合度、代码扩展能力、可维护性等问题，并生成一份极其详尽的 report.md。

### 核心能力

1. **架构模式识别** - 识别设计模式和反模式
2. **依赖分析** - 分析模块间依赖关系
3. **分层架构审查** - 检查分层是否合理
4. **耦合度评估** - 评估模块间耦合程度
5. **代码组织评估** - 检查文件和目录结构
6. **接口设计评审** - 评估 API 设计质量
7. **性能架构分析** - 识别性能瓶颈点
8. **可维护性评估** - 评估代码的可维护性

---

## 🎯 架构分析维度

### 1. 分层架构分析

#### 🏗️ 分层原则

**标准分层结构**:

```
┌─────────────────────────────────────┐
│         Presentation Layer          │  UI/CLI/API
├─────────────────────────────────────┤
│         Business Logic Layer        │  业务逻辑
├─────────────────────────────────────┤
│         Service/Domain Layer        │  领域服务
├─────────────────────────────────────┤
│         Data Access Layer           │  数据访问
├─────────────────────────────────────┤
│         Infrastructure Layer        │  基础设施
└─────────────────────────────────────┘
```

#### 检查规则

**✅ 正确的分层**:
- 上层可以调用下层
- 下层不能调用上层
- 同层之间通过接口通信
- 依赖方向单向流动

**❌ 常见违规**:
- 数据层直接调用业务层
- UI 层直接访问数据库
- 循环依赖
- 跨层调用

#### OpenHarmony 特定分层

**服务端分层**:
```
services/{module}/
├── interfaces/          # 接口定义
│   ├── innerkits/      # 内部接口
│   └── kits/           # 公共接口
├── sa_profile/         # SA 配置
└── src/
    ├── domain/         # 领域层
    ├── service/        # 服务层
    └── data/           # 数据层
```

**客户端分层**:
```
frameworks/{module}/
├── include/            # 头文件
└── src/
    ├── client/         # 客户端实现
    ├── proxy/          # IPC 代理
    └── callback/       # 回调处理
```

---

### 2. 依赖关系分析

#### 依赖方向规则

**✅ 合理的依赖**:
```cpp
// ✅ 正确: 客户端依赖服务接口
// interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_proxy.cpp
#include "ibundle_mgr.h"

// ✅ 正确: 服务依赖数据层
// services/bundlemgr/src/base_bundle_installer.cpp
#include "bundle_data_mgr.h"

// ✅ 正确: 业务逻辑依赖基础设施
// services/bundlemgr/src/bundle_mgr_service.cpp
#include "bundle_util.h"
```

**❌ 不合理的依赖**:
```cpp
// ❌ 错误: 数据层依赖业务层
// services/bundlemgr/src/bundle_data_mgr.cpp
#include "base_bundle_installer.h"  // 违规!

// ❌ 错误: 服务依赖客户端
// services/bundlemgr/src/bundle_mgr_service.cpp
#include "interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_proxy.h"  // 违规!

// ❌ 错误: 循环依赖
// A 依赖 B，B 又依赖 A
```

#### 依赖分析检查项

- [ ] 无循环依赖
- [ ] 依赖方向符合分层原则
- [ ] 接口与实现分离
- [ ] 依赖倒置原则（高层不依赖低层，都依赖抽象）
- [ ] 无不必要的跨模块依赖

---

### 3. 模块化设计评估

#### 模块边界

**好的模块特征**:
- ✅ 单一职责
- ✅ 高内聚
- ✅ 低耦合
- ✅ 清晰的接口
- ✅ 独立可测试

**评估指标**:

| 指标 | 描述 | 良好值 |
|------|------|--------|
| **内聚性** | 模块内部相关性 | 高 (>70%) |
| **耦合度** | 模块间依赖程度 | 低 (<30%) |
| **接口稳定性** | 接口变更频率 | 低 |
| **依赖深度** | 依赖链长度 | ≤5层 |

#### 模块划分检查

**✅ 合理的模块划分**:

```
bundle_framework/
├── services/bundlemgr/         # BMS 服务端
│   ├── src/                   # 服务实现
│   │   ├── shared/            # 跨应用 HSP
│   │   ├── clone/             # 克隆应用
│   │   └── installd/          # installd 客户端
│   └── include/               # 服务头文件
├── interfaces/                # 接口定义
│   ├── inner_api/             # 内部 API（IDL）
│   │   └── appexecfwk_core/   # inner API 实现
│   └── kits/                  # 公共 SDK
│       ├── appkit/            # 应用 Kit
│       ├── js/                # JS 接口
│       ├── ndk/               # NDK 接口
│       └── cj/                # CJ 接口
└── hisysevent.yaml            # HiSysEvent 事件定义
```

**❌ 常见问题**:
- 模块职责不清
- 模块过大（>5000行）
- 模块间功能重叠
- 缺少明确的边界

---

### 4. 接口设计评审

#### API 设计原则

**好的 API 设计**:

```cpp
// ✅ 好的接口设计
// 1. 清晰的命名
class IAccountManager {
public:
    // 2. 单一职责
    ErrCode CreateAccount(const std::string& name, const AccountInfo& info);
    ErrCode RemoveAccount(int32_t id);

    // 3. 参数合理
    ErrCode QueryAccount(int32_t id, AccountInfo& info);

    // 4. 返回值明确
    ErrCode UpdateAccount(const AccountInfo& info);

    // 5. 接口稳定
    static constexpr int32_t MAX_ACCOUNT_NAME_LEN = 256;
};
```

**❌ 常见接口问题**:

```cpp
// ❌ 问题1: 职责不清
class IAccountManager {
    ErrCode CreateAccount(...);
    ErrCode SendEmail(...);        // 不相关功能
    ErrCode ProcessPayment(...);   // 不相关功能
};

// ❌ 问题2: 参数过多
ErrCode CreateAccount(
    const std::string& name,
    const std::string& email,
    const std::string& phone,
    const std::string& address,
    const std::string& avatar,
    const std::string& signature,
    // ... 10+ parameters
);

// ❌ 问题3: 返回值不明确
bool CreateAccount(...);  // 失败原因不清楚

// ❌ 问题4: 接口不稳定（频繁变更）
class IAccountManager {
    ErrCode CreateAccountV1(...);
    ErrCode CreateAccountV2(...);
    ErrCode CreateAccountV3(...);
};
```

#### 接口设计检查清单

- [ ] **命名清晰**: 接口名称准确描述功能
- [ ] **单一职责**: 每个接口只做一件事
- [ ] **参数合理**: 参数数量适中（≤5个）
- [ ] **返回值明确**: 使用 ErrCode 而非 bool
- [ ] **版本管理**: 接口变更考虑兼容性
- [ ] **文档完整**: 有清晰的接口文档
- [ ] **错误处理**: 定义所有可能的错误码

---

### 5. 设计模式识别

#### 常见设计模式

**创建型模式**:
- **单例模式** - 配置管理器、日志记录器
- **工厂模式** - 对象创建逻辑复杂
- **建造者模式** - 复杂对象构建

**结构型模式**:
- **适配器模式** - 接口转换
- **代理模式** - IPC 客户端
- **装饰器模式** - 动态添加功能

**行为型模式**:
- **观察者模式** - 事件通知
- **策略模式** - 算法族封装
- **命令模式** - 操作封装

#### 反模式识别

**常见反模式**:

| 反模式 | 描述 | 影响 | 改进建议 |
|--------|------|------|----------|
| **God Object** | 一个类做太多事 | 难以维护 | 拆分职责 |
| **Spaghetti Code** | 控制流混乱 | 难以理解 | 简化逻辑 |
| **Golden Hammer** | 滥用某种方案 | 不灵活 | 选择合适的工具 |
| **Lava Flow** | 死代码未清理 | 增加复杂度 | 定期清理 |
| **Copy-Paste** | 重复代码 | 维护困难 | 提取公共逻辑 |

---

### 6. 性能架构分析

#### 性能关键点

**需要关注的性能点**:

1. **数据库操作**
   - N+1 查询问题
   - 缺少索引
   - 事务使用不当

2. **网络/IPC 通信**
   - 过多的网络往返
   - 缺少批量操作
   - 未使用异步

3. **内存管理**
   - 内存泄漏
   - 不必要的拷贝
   - 频繁的分配/释放

4. **并发处理**
   - 锁竞争
   - 死锁风险
   - 线程池使用不当

#### 性能优化建议

```cpp
// ❌ 性能问题: N+1 查询
for (auto& account : accounts) {
    auto info = GetAccountInfo(account.id);  // N次查询
}

// ✅ 优化: 批量查询
auto infos = GetAccountInfos(accountIds);  // 1次查询

// ❌ 性能问题: 不必要的拷贝
std::string ProcessData(std::string data) {
    return data + "processed";
}

// ✅ 优化: 使用引用
std::string ProcessData(const std::string& data) {
    return data + "processed";
}

// ❌ 性能问题: 频繁分配
for (int i = 0; i < 1000; i++) {
    auto buffer = new char[1024];
    // use buffer
    delete[] buffer;
}

// ✅ 优化: 复用缓冲区
std::vector<char> buffer(1024);
for (int i = 0; i < 1000; i++) {
    // use buffer
}
```

---

## 🔍 架构分析方法

### 方法1: 静态代码分析

**工具**: 使用代码分析工具

```bash
# 依赖分析
grep -r "#include" --include="*.h" --include="*.cpp" | \
  awk '{print $2}' | sort | uniq -c | sort -rn

# 查找循环依赖
# (使用专用工具如 depcheck, ldd 等)

# 查找大文件
find . -name "*.cpp" -o -name "*.h" | \
  xargs wc -l | sort -rn | head -20
```

### 方法2: 依赖图绘制

**手动分析步骤**:

1. 列出所有主要模块
2. 识别模块间的依赖
3. 绘制依赖图
4. 检查循环依赖
5. 评估依赖深度

### 方法3: 架构评审会议

**评审议程**:

1. 架构概述 (15 min)
2. 分层审查 (20 min)
3. 依赖分析 (20 min)
4. 接口评审 (20 min)
5. 问题讨论 (30 min)
6. 行动项总结 (15 min)

---

## 📋 架构检查清单

### 整体架构

- [ ] **分层清晰**: 每层职责明确
- [ ] **依赖合理**: 无循环依赖
- [ ] **模块独立**: 高内聚低耦合
- [ ] **扩展性好**: 易于添加新功能
- [ ] **可测试性**: 便于单元测试

### 代码组织

- [ ] **目录结构**: 符合项目规范
- [ ] **命名规范**: 统一的命名风格
- [ ] **文件大小**: 单文件不超过 500 行
- [ ] **类的职责**: 单一职责原则
- [ ] **代码复用**: 避免重复代码

### 接口设计

- [ ] **API 清晰**: 接口易于理解
- [ ] **版本管理**: 有版本控制策略
- [ ] **向后兼容**: 变更考虑兼容性
- [ ] **错误处理**: 完善的错误处理
- [ ] **文档完整**: 有清晰的文档

### 性能考虑

- [ ] **性能目标**: 有明确的性能指标
- [ ] **热点识别**: 知道性能瓶颈
- [ ] **资源管理**: 合理的资源使用
- [ ] **并发安全**: 正确的同步机制
- [ ] **缓存策略**: 合理使用缓存

---

## 🛠️ 架构优化建议

### 建议1: 分层优化

**当前问题**: 分层不清晰

**优化方案**:

```
Before:
services/bundlemgr/
└── src/
    ├── bundle_mgr_service.cpp     # 混合了业务逻辑
    ├── bundle_data_mgr.cpp        # 和数据访问
    └── bundle_util.cpp

After:
services/bundlemgr/
└── src/
    ├── domain/                   # 领域层
    │   ├── inner_bundle_info.cpp
    │   └── bundle_entity.cpp
    ├── application/              # 应用层
    │   ├── base_bundle_installer.cpp
    │   └── bundle_command.cpp
    ├── infrastructure/           # 基础设施层
    │   ├── persistence/
    │   │   └── bundle_data_storage.cpp
    │   └── messaging/
    │       └── bundle_event_publisher.cpp
    └── interfaces/               # 接口层
        └── account_dto.cpp
```

### 建议2: 依赖解耦

**当前问题**: 模块间耦合度高

**优化方案**: 使用依赖注入

```cpp
// Before: 紧耦合
class AccountService {
    AccountDatabase db_;  // 直接依赖具体实现
public:
    ErrCode CreateAccount(const AccountInfo& info) {
        return db_.Insert(info);
    }
};

// After: 松耦合
class IAccountRepository {
public:
    virtual ~IAccountRepository() = default;
    virtual ErrCode Insert(const AccountInfo& info) = 0;
};

class AccountService {
    std::unique_ptr<IAccountRepository> repo_;
public:
    explicit AccountService(std::unique_ptr<IAccountRepository> repo)
        : repo_(std::move(repo)) {}

    ErrCode CreateAccount(const AccountInfo& info) {
        return repo_->Insert(info);
    }
};
```

### 建议3: 接口稳定化

**当前问题**: 接口频繁变更

**优化方案**:

1. **版本化接口**
```cpp
namespace V1 {
    class IAccountManager {
        virtual ErrCode CreateAccount(...) = 0;
    };
}

namespace V2 {
    class IAccountManager : public V1::IAccountManager {
        virtual ErrCode CreateAccountWithExtra(...) = 0;
    };
}
```

2. **使用 DTO 隔离变化**
```cpp
// DTO 作为接口边界
class AccountDTO {
public:
    int32_t id;
    std::string name;
    // ... 字段

    static AccountDTO FromDomain(const Account& account);
    Account ToDomain() const;
};
```

### 建议4: 引入设计模式

**场景1: 需要多种创建方式**

```cpp
// 使用工厂模式
class IAccountFactory {
public:
    virtual ~IAccountFactory() = default;
    virtual std::unique_ptr<Account> Create(const AccountInfo& info) = 0;
};

class AdminAccountFactory : public IAccountFactory { ... };
class GuestAccountFactory : public IAccountFactory { ... };
```

**场景2: 需要事件通知**

```cpp
// 使用观察者模式
class IAccountObserver {
public:
    virtual void OnAccountCreated(const Account& account) = 0;
    virtual void OnAccountRemoved(int32_t id) = 0;
};

class AccountManager {
    std::vector<IAccountObserver*> observers_;
public:
    void AddObserver(IAccountObserver* observer) {
        observers_.push_back(observer);
    }

    void NotifyAccountCreated(const Account& account) {
        for (auto* observer : observers_) {
            observer->OnAccountCreated(account);
        }
    }
};
```

---

## 📊 架构质量度量

### 定量指标

| 指标 | 计算方法 | 目标值 |
|------|----------|--------|
| **圈复杂度** | 每函数的分支数 | ≤10 |
| **内聚性** | 模块内关联度 | >70% |
| **耦合度** | 模块间依赖度 | <30% |
| **抽象度** | 抽象类比例 | >20% |
| ** instability** | efferent/(afferent+efferent) | 0-1 |

### 定性评估

**优秀架构特征**:
- ✅ 易于理解
- ✅ 易于修改
- ✅ 易于测试
- ✅ 易于部署
- ✅ 性能良好
- ✅ 安全可靠

**架构成熟度等级**:

| 等级 | 描述 | 特征 |
|------|------|------|
| **Level 1** | 初始级 | 无架构设计 |
| **Level 2** | 已管理级 | 有基本分层 |
| **Level 3** | 已定义级 | 架构规范化 |
| **Level 4** | 量化管理级 | 架构可度量 |
| **Level 5** | 优化级 | 持续改进 |

---

## 🎯 架构优化路线图

### 短期目标 (1-2 个月)

1. **修复关键问题**
   - 消除循环依赖
   - 修复严重的架构违规
   - 重构超大的类

2. **建立规范**
   - 制定架构规范文档
   - 建立代码审查流程
   - 引入架构检查工具

### 中期目标 (3-6 个月)

1. **架构重构**
   - 优化分层结构
   - 实施依赖解耦
   - 改进接口设计

2. **质量提升**
   - 提高测试覆盖率
   - 优化性能瓶颈
   - 完善文档

### 长期目标 (6-12 个月)

1. **持续改进**
   - 建立架构度量体系
   - 实施自动化检查
   - 定期架构评审

2. **技术演进**
   - 引入新的设计模式
   - 采用更好的架构风格
   - 持续优化

---

## 🔧 使用方法

### 作为代码审查指南

在代码审查时，使用本 skill 检查：

1. **新代码的架构影响**
   - 是否遵循分层原则
   - 是否引入循环依赖
   - 是否符合模块边界

2. **接口设计的合理性**
   - API 是否清晰
   - 参数是否合理
   - 错误处理是否完善

3. **性能和可维护性**
   - 是否有性能隐患
   - 是否易于测试
   - 是否符合规范

### 作为架构评审工具

在架构评审时：

1. **准备阶段**
   - 收集架构文档
   - 绘制依赖图
   - 准备检查清单

2. **评审阶段**
   - 逐项检查清单
   - 记录发现的问题
   - 讨论改进方案

3. **总结阶段**
   - 整理问题清单
   - 制定改进计划
   - 分配责任人

### 作为重构指导

在进行重构时：

1. **分析当前架构**
   - 识别架构问题
   - 评估影响范围
   - 确定重构目标

2. **制定重构计划**
   - 优先级排序
   - 分步实施
   - 风险控制

3. **执行重构**
   - 小步快跑
   - 持续测试
   - 及时调整

---

## 📚 参考资料

### 架构设计原则

- **SOLID 原则**
  - Single Responsibility Principle
  - Open/Closed Principle
  - Liskov Substitution Principle
  - Interface Segregation Principle
  - Dependency Inversion Principle

- **DRY 原则** - Don't Repeat Yourself
- **KISS 原则** - Keep It Simple, Stupid
- **YAGNI 原则** - You Aren't Gonna Need It

### 推荐书籍

1. *Clean Architecture* - Robert C. Martin
2. *Patterns of Enterprise Application Architecture* - Martin Fowler
3. *Domain-Driven Design* - Eric Evans
4. *Software Architecture: The Hard Parts* - Neal Ford

### 相关工具

- **依赖分析**: depcheck, ldd, dependency-check
- **代码度量**: SonarQube, CodeQL
- **架构图**: PlantUML, Mermaid, Structurizr
- **重构工具**: clang-tidy, clang-rename

---

## 📝 版本历史

**v1.0** (2026-03-23)
- ✅ 初始版本
- ✅ 架构分析框架
- ✅ 检查清单和优化建议

---

## 🤝 贡献指南

欢迎改进本 skill：

1. **添加新的架构模式**
2. **补充更多反模式**
3. **提供具体的优化示例**
4. **分享架构评审经验**

---

**维护者**: Architecture Team
**许可**: 开源，可自由使用和修改
**版本**: v1.0
