---
---
name: logic_analyzer
description: 深度分析代码修改的逻辑影响，系统化地发现所有逻辑问题
version: 1.0.0
author: AI Assistant
tags:
  - logic
  - analysis
  - state machine
  - data flow
  - control flow
  - boundary condition
  - error handling
triggers:
  - 逻辑分析
  - logic analysis
  - 逻辑检查
  - logic check
  - 状态机
  - state machine
  - 数据流
  - data flow
  - 控制流
  - control flow
  - 边界条件
  - boundary condition
  - 错误处理
  - error handling
---

# Logic Analyzer Skill - 代码逻辑变更分析

## 技能概述

本技能专注于**深度分析代码修改的逻辑影响**，系统化地发现所有逻辑问题。不同于常规的代码审查，本技能重点关注：

- **逻辑影响范围分析**：修改会影响哪些代码路径和数据流
- **逻辑一致性检查**：发现逻辑矛盾、不一致和缺陷
- **状态转换验证**：验证状态机转换的正确性
- **边界条件分析**：发现边界条件处理不当的问题
- **业务规则验证**：确保业务逻辑规则的正确性

---

## 1. 分析框架

### 1.1 三层分析模型

```
┌─────────────────────────────────────────────────┐
│  第一层：变更识别 (What Changed)                 │
│  - 识别变更的代码位置                            │
│  - 分类变更类型（新增/修改/删除）                │
│  - 识别变更的影响范围                            │
├─────────────────────────────────────────────────┤
│  第二层：逻辑分析 (Logic Analysis)               │
│  - 控制流分析                                    │
│  - 数据流分析                                    │
│  - 状态机分析                                    │
│  - 约束条件分析                                  │
├─────────────────────────────────────────────────┤
│  第三层：影响评估 (Impact Assessment)            │
│  - 影响范围评估                                  │
│  - 风险等级评定                                  │
│  - 修复建议生成                                  │
└─────────────────────────────────────────────────┘
```

### 1.2 分析维度

| 维度 | 检查内容 | 问题类型 |
|------|----------|----------|
| **控制流** | 分支、循环、条件判断 | 死代码、不可达代码、逻辑矛盾 |
| **数据流** | 变量定义、赋值、使用 | 未初始化、数据污染、类型不匹配 |
| **状态机** | 状态转换、转换条件 | 非法转换、状态不一致、死锁 |
| **边界条件** | 数组边界、空值、极值 | 越界、空指针、溢出 |
| **错误处理** | 错误码、异常、清理 | 遗漏错误路径、资源泄漏 |
| **并发控制** | 锁、原子操作、竞态 | 死锁、竞态条件、数据竞争 |
| **业务规则** | 约束、不变性、契约 | 规则违反、不变性破坏 |

---

## 2. 变更识别与分类

### 2.1 变更类型分类

```diff
#### 类型 1: 控制流变更
+ if (newCondition) {        // 新增条件分支
      doSomething();
  }

#### 类型 2: 数据流变更
- int result = processA();   // 删除原有计算
+ int result = processB();   // 替换为新计算

#### 类型 3: 状态转换变更
- state = ACTIVE;            // 修改状态转换目标
+ state = SUSPENDED;

#### 类型 4: 函数签名变更
- ErrCode Function(int id);
+ ErrCode Function(int id, Config config);  // 新增参数

#### 类型 5: 错误处理变更
  ret = DoSomething();
+ if (ret != ERR_OK) {        // 新增错误处理
      return ret;
+ }
```

### 2.2 影响范围识别

**直接影响的代码：**
- 被修改的函数及其调用者
- 被修改的成员变量及其访问者
- 被修改的状态及其转换逻辑

**间接影响的代码：**
- 依赖修改函数返回值的代码
- 依赖修改状态的条件分支
- 调用链上的所有上层函数

**可能影响的边界：**
- 接口兼容性边界
- 性能边界
- 资源使用边界
- 并发安全边界

---

## 3. 逻辑问题检测模式

### 3.1 控制流问题

#### 问题 1: 死代码 (Dead Code)

**检测模式：**
```cpp
// ❌ 问题：永不为真的条件
if (constexpr_condition) {  // constexpr_value 总是 false
    // 这段代码永远不会执行
    NeverExecuted();
}

// ❌ 问题：不可达的代码
return ERR_OK;
DoSomething();  // 永远不会执行

// ❌ 问题：重复的条件
if (condition) {
    return A;
} else {
    if (condition) {  // 重复的条件
        return B;
    }
}
```

**检测方法：**
- 分析条件表达式的常量性
- 构建控制流图(CFG)检测不可达节点
- 检查return/break后的代码

**影响分析：**
- 代码维护性降低
- 可能隐藏未测试的逻辑
- 造成代码混淆

---

#### 问题 2: 逻辑矛盾 (Logic Contradiction)

**检测模式：**
```cpp
// ❌ 问题：互斥条件同时为真
if (x > 10 && x < 5) {  // 永远不会为真
    Impossible();
}

// ❌ 问题：冗余条件
if (value != nullptr) {
    if (value != nullptr) {  // 重复检查
        use(value);
    }
}

// ❌ 问题：条件覆盖矛盾
if (state == ACTIVE) {
    return;
}
if (state == ACTIVE) {  // 前面已经return，这里永远不会执行
    doSomething();
}
```

**检测方法：**
- 使用SMT求解器验证条件可满足性
- 数据流分析追踪变量约束
- 符号执行验证路径可行性

---

#### 问题 3: 条件覆盖不完整 (Incomplete Condition Coverage)

**检测模式：**
```cpp
// ❌ 问题：遗漏分支
enum State { ACTIVE, INACTIVE, SUSPENDED };
void HandleState(State state) {
    if (state == ACTIVE) {
        HandleActive();
    } else if (state == INACTIVE) {
        HandleInactive();
    }
    // 遗漏了 SUSPENDED 状态的处理！
}

// ❌ 问题：默认情况缺失
switch (type) {
    case TYPE_A:
        DoA();
        break;
    case TYPE_B:
        DoB();
        break;
    // 缺少 default 分支！
}

// ✅ 正确：完整的条件覆盖
void HandleState(State state) {
    if (state == ACTIVE) {
        HandleActive();
    } else if (state == INACTIVE) {
        HandleInactive();
    } else {
        HILOG_ERROR("Unknown state: %{public}d", state);
        HandleUnknown();
    }
}
```

**检测方法：**
- 枚举类型完整性检查
- switch-case分支完整性检查
- if-else链完整性检查

---

### 3.2 数据流问题

#### 问题 1: 未初始化变量 (Uninitialized Variable)

**检测模式：**
```cpp
// ❌ 问题：使用未初始化的变量
int result;
if (condition) {
    result = 10;
}
// 如果condition为false，result未初始化
return result;  // 使用未初始化的值

// ❌ 问题：条件初始化
std::string data;
if (needData) {
    data = GetData();
}
// 如果needData为false，data为空
ProcessData(data);  // 可能处理空数据

// ✅ 正确：确保初始化
int result = DEFAULT_VALUE;  // 默认值
if (condition) {
    result = 10;
}
return result;
```

**检测方法：**
- 数据流分析追踪变量定义-使用链
- 检查所有可能路径的初始化
- 验证构造函数中的成员初始化列表

---

#### 问题 2: 数据污染 (Data Tainting)

**检测模式：**
```cpp
// ❌ 问题：外部数据未验证直接使用
void ProcessInput(const char* input) {
    char buffer[100];
    strcpy(buffer, input);  // 危险：input可能超过100字节
    ProcessBuffer(buffer);
}

// ❌ 问题：污染数据传播到敏感操作
void ExecuteCommand(const std::string& userCmd) {
    std::string cmd = "sh -c '" + userCmd + "'";  // 危险：命令注入
    system(cmd.c_str());
}

// ✅ 正确：验证和净化外部数据
void ProcessInput(const char* input) {
    if (input == nullptr || strlen(input) >= 100) {
        HILOG_ERROR("Invalid input");
        return;
    }
    char buffer[100];
    strncpy_s(buffer, sizeof(buffer), input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    ProcessBuffer(buffer);
}
```

**检测方法：**
- 污点分析(taint analysis)追踪外部数据
- 识别敏感操作(sink points)：系统调用、文件操作、SQL执行
- 验证数据净化点(sanitization)

---

#### 问题 3: 类型不匹配 (Type Mismatch)

**检测模式：**
```cpp
// ❌ 问题：有符号/无符号比较
int count = -1;
if (count < vector.size()) {  // 危险：有符号与无符号比较
    vector[count];
}

// ❌ 问题：枚举类型混用
enum Type { A = 0, B = 1 };
int value = 2;
Type type = static_cast<Type>(value);  // 危险：无有效枚举值

// ❌ 问题：指针类型强转
void* ptr = malloc(100);
int* intPtr = static_cast<int*>(ptr);
*intPtr = 0x12345678;  // 可能未对齐

// ✅ 正确：类型安全比较
size_t count = 0;
if (count < vector.size()) {
    // 安全
}
```

**检测方法：**
- 类型推导和约束检查
- 检查隐式类型转换
- 验证枚举值的有效性

---

### 3.3 状态机问题

#### 问题 1: 非法状态转换 (Illegal State Transition)

**检测模式：**
```cpp
// ❌ 问题：不合法的状态转换
enum State { CREATED, ACTIVATING, ACTIVE, DEACTIVATING };
void ChangeState(State newState) {
    // 允许任何转换，包括非法的
    currentState_ = newState;
}

// 示例非法转换：
// CREATED -> DEACTIVATING (跳过ACTIVATING和ACTIVE)
// ACTIVE -> CREATED (跳过DEACTIVATING)

// ✅ 正确：验证状态转换
bool ChangeState(State newState) {
    switch (currentState_) {
        case CREATED:
            if (newState != ACTIVATING) {
                HILOG_ERROR("Invalid transition: CREATED -> %{public}d", newState);
                return false;
            }
            break;
        case ACTIVATING:
            if (newState != ACTIVE && newState != CREATED) {
                return false;
            }
            break;
        // ... 其他状态验证
    }
    currentState_ = newState;
    return true;
}
```

**检测方法：**
- 构建状态转换图
- 验证所有转换的合法性
- 检查是否遗漏中间状态

---

#### 问题 2: 状态不一致 (State Inconsistency)

**检测模式：**
```cpp
// ❌ 问题：状态与实际数据不一致
class Account {
    State state_;
    bool isActive_;

    void Activate() {
        state_ = ACTIVE;
        // 忘记更新 isActive_
    }

    bool IsActive() {
        return isActive_;  // 返回旧值
    }
};

// ❌ 问题：多状态变量不同步
class Connection {
    bool isConnected_;
    bool isReady_;
    bool hasError_;

    void Connect() {
        isConnected_ = true;
        // isReady_ 未更新，导致不一致
    }
};

// ✅ 正确：确保状态一致性
class Account {
    State state_;

    void Activate() {
        state_ = ACTIVE;
        // 单一状态源，无需同步多个变量
    }

    bool IsActive() {
        return state_ == ACTIVE;
    }
};
```

**检测方法：**
- 识别所有表示状态的相关变量
- 验证状态更新时的一致性
- 检查状态读取点的一致性

---

#### 问题 3: 状态机死锁 (State Machine Deadlock)

**检测模式：**
```cpp
// ❌ 问题：无法到达最终状态
enum State { INIT, WAITING, PROCESSING, DONE };
void ProcessData() {
    switch (state_) {
        case INIT:
            state_ = WAITING;
            break;
        case WAITING:
            if (HasData()) {
                state_ = PROCESSING;
            }
            // 如果没有数据，永远停留在WAITING
            break;
        case PROCESSING:
            if (Success()) {
                state_ = DONE;
            } else {
                state_ = WAITING;  // 失败后回到WAITING
            }
            break;
    }
    // 没有超时机制，可能永远无法到达DONE
}

// ✅ 正确：添加超时和错误处理
void ProcessData() {
    switch (state_) {
        case INIT:
            state_ = WAITING;
            startTime_ = GetCurrentTime();
            break;
        case WAITING:
            if (HasData()) {
                state_ = PROCESSING;
            } else if (GetCurrentTime() - startTime_ > TIMEOUT) {
                state_ = DONE;  // 超时退出
                errorCode_ = ETIMEDOUT;
            }
            break;
        // ...
    }
}
```

**检测方法：**
- 构建状态转换图并检查强连通分量
- 验证是否存在无法到达终态的循环
- 检查超时和错误恢复机制

---

### 3.4 边界条件问题

#### 问题 1: 数组越界 (Array Out of Bounds)

**检测模式：**
```cpp
// ❌ 问题：索引未验证
void ProcessArray(int* data, int size) {
    for (int i = 0; i <= size; i++) {  // 错误：应该是 i < size
        data[i] = 0;  // 越界访问
    }
}

// ❌ 问题：边界计算错误
void CopyData(const std::vector<int>& src, int* dest, int destSize) {
    memcpy(dest, src.data(), src.size() * sizeof(int));  // 未检查destSize
}

// ✅ 正确：边界验证
void ProcessArray(int* data, int size) {
    if (data == nullptr || size <= 0) {
        return;
    }
    for (int i = 0; i < size; i++) {
        data[i] = 0;
    }
}

void CopyData(const std::vector<int>& src, int* dest, int destSize) {
    if (dest == nullptr || destSize < static_cast<int>(src.size())) {
        HILOG_ERROR("Invalid buffer size");
        return;
    }
    memcpy(dest, src.data(), src.size() * sizeof(int));
}
```

**检测方法：**
- 符号执行验证数组访问的边界
- 检查循环边界条件
- 验证memcpy/strcpy等函数的长度参数

---

#### 问题 2: 空指针解引用 (Null Pointer Dereference)

**检测模式：**
```cpp
// ❌ 问题：未检查空指针
void ProcessData(Account* account) {
    account->Update();  // account可能为nullptr
}

// ❌ 问题：检查后再次使用
void Process(Account* account) {
    if (account != nullptr) {
        DoSomething(account);
    }
    account->Update();  // 可能已经是nullptr
}

// ❌ 问题：函数调用后未验证返回值
Account* GetAccount(int id);
void UseAccount(int id) {
    Account* account = GetAccount(id);
    account->Process();  // GetAccount可能返回nullptr
}

// ✅ 正确：完整的空指针检查
void ProcessData(Account* account) {
    if (account == nullptr) {
        HILOG_ERROR("Account is null");
        return;
    }
    account->Update();
}

void UseAccount(int id) {
    Account* account = GetAccount(id);
    if (account == nullptr) {
        HILOG_ERROR("Account not found: %{public}d", id);
        return;
    }
    account->Process();
}
```

**检测方法：**
- 数据流分析追踪指针的空值状态
- 识别所有解引用点
- 验证解引用前的空值检查

---

#### 问题 3: 整数溢出 (Integer Overflow)

**检测模式：**
```cpp
// ❌ 问题：加法溢出
int AllocateSize(int count, int itemSize) {
    return count * itemSize;  // 可能溢出
}

// ❌ 问题：索引计算溢出
void AccessArray(std::vector<int>& data, int offset, int index) {
    int pos = offset + index;  // 可能溢出为负数
    data[pos] = 0;  // 负数转换为巨大的无符号数
}

// ❌ 问题：循环计数器溢出
for (int i = 0; i < count; i++) {
    // 如果count是INT_MAX，i会溢出
    ProcessItem(i);
}

// ✅ 正确：溢出检查
int AllocateSize(int count, int itemSize) {
    if (count < 0 || itemSize < 0) {
        return -1;
    }
    if (count > INT_MAX / itemSize) {
        HILOG_ERROR("Size overflow");
        return -1;
    }
    return count * itemSize;
}
```

**检测方法：**
- 识别所有算术运算
- 使用边界值分析方法
- 检查溢出前的条件验证

---

### 3.5 错误处理问题

#### 问题 1: 遗漏错误路径 (Missing Error Path)

**检测模式：**
```cpp
// ❌ 问题：不检查返回值
void ProcessFile(const std::string& path) {
    FILE* file = fopen(path.c_str(), "r");  // 未检查是否成功
    char buffer[100];
    fread(buffer, 1, 100, file);  // file可能是nullptr
    fclose(file);
}

// ❌ 问题：部分错误处理
ErrCode CreateAccount(const AccountInfo& info) {
    if (!ValidateInfo(info)) {
        return ERR_INVALID;
    }
    // 未检查数据库写入是否成功
    database_->Insert(info);
    // 未检查文件写入是否成功
    WriteToFile(info);
    return ERR_OK;
}

// ✅ 正确：完整的错误处理
ErrCode CreateAccount(const AccountInfo& info) {
    if (!ValidateInfo(info)) {
        return ERR_INVALID;
    }

    ErrCode ret = database_->Insert(info);
    if (ret != ERR_OK) {
        HILOG_ERROR("Database insert failed: %{public}d", ret);
        return ret;
    }

    ret = WriteToFile(info);
    if (ret != ERR_OK) {
        HILOG_ERROR("File write failed: %{public}d", ret);
        // 回滚数据库操作
        database_->Delete(info.id);
        return ret;
    }

    return ERR_OK;
}
```

**检测方法：**
- 识别所有可能失败的函数调用
- 检查调用点是否有错误处理
- 验证错误处理的完整性

---

#### 问题 2: 资源泄漏 (Resource Leak)

**检测模式：**
```cpp
// ❌ 问题：错误路径未释放资源
void ProcessData() {
    char* buffer = new char[1024];
    if (!ReadData(buffer)) {
        return;  // 泄漏buffer
    }
    delete[] buffer;
}

// ❌ 问题：文件句柄泄漏
void ProcessFile(const std::string& path) {
    FILE* file = fopen(path.c_str(), "r");
    if (file == nullptr) {
        return;
    }

    char buffer[100];
    if (fread(buffer, 1, 100, file) < 100) {
        return;  // 泄漏file句柄
    }

    fclose(file);
}

// ✅ 正确：使用RAII确保资源释放
void ProcessData() {
    std::unique_ptr<char[]> buffer(new char[1024]);
    if (!ReadData(buffer.get())) {
        return;  // 自动释放
    }
}

void ProcessFile(const std::string& path) {
    FILE* file = fopen(path.c_str(), "r");
    if (file == nullptr) {
        return;
    }

    // 使用RAII包装器
    std::unique_ptr<FILE, decltype(&fclose)> fileGuard(file, fclose);

    char buffer[100];
    if (fread(buffer, 1, 100, file) < 100) {
        return;  // 自动关闭文件
    }
}
```

**检测方法：**
- 识别所有资源分配点（malloc、new、fopen等）
- 构建控制流图检查所有可能的退出路径
- 验证每个退出路径是否释放资源

---

### 3.6 并发控制问题

#### 问题 1: 死锁 (Deadlock)

**检测模式：**
```cpp
// ❌ 问题：锁顺序不一致
void Thread1() {
    std::lock_guard<std::mutex> lock1(mutex1_);
    std::lock_guard<std::mutex> lock2(mutex2_);
    // 操作
}

void Thread2() {
    std::lock_guard<std::mutex> lock2(mutex2_);  // 不同顺序
    std::lock_guard<std::mutex> lock1(mutex1_);
    // 可能死锁
}

// ❌ 问题：循环等待
void Process() {
    std::lock_guard<std::mutex> lock(globalMutex_);
    // 在持有锁的情况下调用可能获取同一锁的函数
    Callback();  // 如果Callback也尝试获取globalMutex_，死锁
}

// ✅ 正确：一致的锁顺序
void Thread1() {
    std::lock(mutex1_, mutex2_);  // C++17 std::lock
    std::lock_guard<std::mutex> lock1(mutex1_, std::adopt_lock);
    std::lock_guard<std::mutex> lock2(mutex2_, std::adopt_lock);
    // 操作
}

void Thread2() {
    std::lock(mutex1_, mutex2_);  // 相同顺序
    std::lock_guard<std::mutex> lock1(mutex1_, std::adopt_lock);
    std::lock_guard<std::mutex> lock2(mutex2_, std::adopt_lock);
    // 操作
}
```

**检测方法：**
- 构建锁依赖图
- 检查是否存在循环依赖
- 验证锁顺序的一致性

---

#### 问题 2: 竞态条件 (Race Condition)

**检测模式：**
```cpp
// ❌ 问题：检查-使用(Check-Then-Act)模式
if (instance_ == nullptr) {  // 检查
    instance_ = new Instance();  // 使用：多个线程可能同时执行
}

// ❌ 问题：非原子操作
int count_;
void Increment() {
    count_++;  // 非原子操作，三个步骤：读取、增加、写入
}

// ❌ 问题：状态不一致读取
class Account {
    int balance_;
    void Deposit(int amount) {
        balance_ += amount;
    }
    int GetBalance() {
        return balance_;  // 可能读到部分更新的值
    }
};

// ✅ 正确：使用原子操作或锁
std::atomic<int> count_;
void Increment() {
    count_.fetch_add(1, std::memory_order_relaxed);
}

// 或使用锁
std::mutex mutex_;
int count_;
void Increment() {
    std::lock_guard<std::mutex> lock(mutex_);
    count_++;
}
```

**检测方法：**
- 识别共享变量的访问点
- 检查是否有适当的同步机制
- 验证操作的原子性

---

#### 问题 3: 数据竞争 (Data Race)

**检测模式：**
```cpp
// ❌ 问题：无保护的并发访问
int sharedData = 0;

void Thread1() {
    sharedData = 100;  // 写入，无保护
}

void Thread2() {
    int value = sharedData;  // 读取，无保护
    // 数据竞争：未定义行为
}

// ❌ 问题：部分保护的访问
class Buffer {
    std::mutex mutex_;
    std::vector<int> data_;

    void Add(int value) {
        std::lock_guard<std::mutex> lock(mutex_);
        data_.push_back(value);
    }

    int Size() {
        return data_.size();  // 无保护读取
    }
};

// ✅ 正确：完全保护的访问
class Buffer {
    std::mutex mutex_;
    std::vector<int> data_;

    void Add(int value) {
        std::lock_guard<std::mutex> lock(mutex_);
        data_.push_back(value);
    }

    int Size() {
        std::lock_guard<std::mutex> lock(mutex_);
        return data_.size();
    }
};
```

**检测方法：**
- 数据流分析识别共享变量
- 检查所有访问点的同步状态
- 验证内存序(Memory Order)的正确性

---

### 3.7 业务规则违反

#### 问题 1: 不变性破坏 (Invariant Violation)

**检测模式：**
```cpp
// ❌ 问题：破坏不变性
class AccountManager {
    std::map<int, Account> accounts_;
    int maxAccounts_;  // 不变性：accounts_.size() <= maxAccounts_

    ErrCode AddAccount(const Account& account) {
        accounts_[account.id] = account;
        // 未检查是否超过maxAccounts_
        return ERR_OK;
    }
};

// ❌ 问题：约束条件违反
class PriorityQueue {
    std::vector<int> data_;

    void Add(int value) {
        data_.push_back(value);
        // 忘记调整堆结构，破坏堆性质
    }
};

// ✅ 正确：维护不变性
class AccountManager {
    std::map<int, Account> accounts_;
    int maxAccounts_;

    ErrCode AddAccount(const Account& account) {
        if (accounts_.size() >= maxAccounts_) {
            HILOG_ERROR("Max accounts limit reached");
            return ERR_LIMIT_REACHED;
        }
        accounts_[account.id] = account;
        return ERR_OK;
    }
};
```

**检测方法：**
- 识别类/模块的不变性
- 检查每个操作后是否保持不变性
- 验证构造函数是否建立不变性

---

#### 问题 2: 契约违反 (Contract Violation)

**检测模式：**
```cpp
// ❌ 问题：前置条件未验证
int Divide(int a, int b) {
    // 前置条件：b != 0
    return a / b;  // 未验证前置条件
}

// ❌ 问题：后置条件不保证
int GetNextId() {
    int nextId = currentId_++;
    // 后置条件：返回的ID应该是唯一的
    // 但如果currentId_溢出，可能返回已使用的ID
    return nextId;
}

// ✅ 正确：契约式编程
int Divide(int a, int b) {
    if (b == 0) {
        HILOG_ERROR("Division by zero");
        return 0;  // 或抛出异常
    }
    return a / b;
}

int GetNextId() {
    int nextId = currentId_;
    if (currentId_ == INT_MAX) {
        HILOG_ERROR("ID overflow");
        return -1;
    }
    currentId_++;
    return nextId;
}
```

**检测方法：**
- 识别函数的前置/后置条件
- 检查前置条件验证
- 验证后置条件保证

---

## 4. 分析检查清单

### 4.1 控制流检查清单

- [ ] **死代码检测**
  - [ ] 识别永不为真的条件
  - [ ] 检测不可达的代码段
  - [ ] 验证return/break后的代码

- [ ] **逻辑矛盾检测**
  - [ ] 检查互斥条件
  - [ ] 识别冗余条件
  - [ ] 验证条件覆盖

- [ ] **条件覆盖完整性**
  - [ ] 枚举类型完整性
  - [ ] switch-case分支完整性
  - [ ] if-else链完整性

### 4.2 数据流检查清单

- [ ] **变量初始化**
  - [ ] 所有路径上的初始化
  - [ ] 成员变量初始化
  - [ ] 数组/容器初始化

- [ ] **数据污染分析**
  - [ ] 外部数据来源识别
  - [ ] 数据净化点验证
  - [ ] 敏感操作保护

- [ ] **类型安全**
  - [ ] 有符号/无符号比较
  - [ ] 枚举值有效性
  - [ ] 指针类型转换

### 4.3 状态机检查清单

- [ ] **状态转换合法性**
  - [ ] 验证每个转换的合法性
  - [ ] 检查非法转换
  - [ ] 确认中间状态

- [ ] **状态一致性**
  - [ ] 单一状态源
  - [ ] 相关状态变量同步
  - [ ] 状态读取一致性

- [ ] **状态机活性**
  - [ ] 可达性分析
  - [ ] 终态可达性
  - [ ] 超时机制

### 4.4 边界条件检查清单

- [ ] **数组边界**
  - [ ] 索引范围验证
  - [ ] 循环边界检查
  - [ ] 缓冲区大小验证

- [ ] **空指针检查**
  - [ ] 解引用前验证
  - [ ] 函数返回值验证
  - [ ] 智能指针使用

- [ ] **整数溢出**
  - [ ] 算术运算验证
  - [ ] 边界值检查
  - [ ] 溢出保护

### 4.5 错误处理检查清单

- [ ] **错误路径完整性**
  - [ ] 所有可能失败的操作
  - [ ] 错误码传递
  - [ ] 错误日志记录

- [ ] **资源管理**
  - [ ] 资源释放配对
  - [ ] 错误路径释放
  - [ ] RAII使用

### 4.6 并发控制检查清单

- [ ] **死锁预防**
  - [ ] 锁顺序一致性
  - [ ] 循环等待检测
  - [ ] 超时机制

- [ ] **竞态条件**
  - [ ] 共享变量保护
  - [ ] 原子操作
  - [ ] 同步机制

- [ ] **数据竞争**
  - [ ] 访问同步
  - [ ] 内存序验证
  - [ ] 读写锁使用

### 4.7 业务规则检查清单

- [ ] **不变性维护**
  - [ ] 识别不变性
  - [ ] 验证操作后不变性
  - [ ] 构造函数建立

- [ ] **契约遵守**
  - [ ] 前置条件验证
  - [ ] 后置条件保证
  - [ ] 异常安全性

---

## 5. 分析报告模板

### 5.1 报告结构

```markdown
# 代码逻辑变更分析报告

## 1. 变更概览

### 变更文件
- `src/account_manager.cpp`: 45 行变更
- `include/account_manager.h`: 3 行变更

### 变更类型
- 控制流变更: 2 处
- 数据流变更: 1 处
- 状态转换变更: 1 处

### 影响范围评估
- 直接影响: AccountManager类及其3个调用者
- 间接影响: 可能影响所有依赖账户状态的模块
- 风险等级: **高** ⚠️

---

## 2. 逻辑问题详细分析

### 问题 1: 状态转换非法 (致命)

**位置**: `src/account_manager.cpp:123-127`

**问题描述**:
从CREATED状态直接转换到DEACTIVATED状态，跳过了ACTIVE状态。

**当前代码**:
```cpp
ErrCode AccountManager::DeactivateAccount(int id) {
    accounts_[id].state_ = DEACTIVATED;  // 非法转换
    return ERR_OK;
}
```

**影响**:
- 破坏状态机完整性
- 可能导致后续操作异常
- 账户数据不一致

**修复建议**:
```cpp
ErrCode AccountManager::DeactivateAccount(int id) {
    if (accounts_[id].state_ != ACTIVE) {
        HILOG_ERROR("Cannot deactivate non-active account");
        return ERR_INVALID_STATE;
    }
    accounts_[id].state_ = DEACTIVATED;
    return ERR_OK;
}
```

**严重等级**: 🔴 致命

---

### 问题 2: 错误路径遗漏 (严重)

**位置**: `src/account_manager.cpp:145-152`

**问题描述**:
CreateAccount函数未检查数据库插入是否成功。

**当前代码**:
```cpp
ErrCode AccountManager::CreateAccount(const AccountInfo& info) {
    if (!ValidateInfo(info)) {
        return ERR_INVALID;
    }
    database_->Insert(info);  // 未检查返回值
    WriteToFile(info);
    return ERR_OK;
}
```

**影响**:
- 数据库失败时状态不一致
- 文件已写入但数据库未记录
- 数据恢复困难

**修复建议**:
```cpp
ErrCode AccountManager::CreateAccount(const AccountInfo& info) {
    if (!ValidateInfo(info)) {
        return ERR_INVALID;
    }

    ErrCode ret = database_->Insert(info);
    if (ret != ERR_OK) {
        HILOG_ERROR("Database insert failed: %{public}d", ret);
        return ret;
    }

    ret = WriteToFile(info);
    if (ret != ERR_OK) {
        HILOG_ERROR("File write failed: %{public}d", ret);
        database_->Delete(info.id);  // 回滚
        return ret;
    }

    return ERR_OK;
}
```

**严重等级**: 🟠 严重

---

### 问题 3: 竞态条件 (严重)

**位置**: `src/account_manager.cpp:89-93`

**问题描述**:
Check-Then-Act模式导致竞态条件。

**当前代码**:
```cpp
bool AccountManager::HasAccount(int id) {
    if (accounts_.find(id) == accounts_.end()) {
        return false;
    }
    return true;
}
```

**影响**:
- 多线程环境下结果不准确
- 可能导致重复创建账户

**修复建议**:
```cpp
bool AccountManager::HasAccount(int id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return accounts_.find(id) != accounts_.end();
}
```

**严重等级**: 🟠 严重

---

## 3. 影响分析

### 直接影响
- `AccountManager::DeactivateAccount()`: 行为改变
- `AccountManager::CreateAccount()`: 错误处理不完整
- `AccountManager::HasAccount()`: 线程不安全

### 间接影响
- 所有调用`HasAccount()`的代码可能受影响
- 依赖账户状态的下游模块
- 可能触发数据不一致问题

### 风险评估
- **数据一致性**: 高风险 🔴
- **线程安全**: 高风险 🔴
- **状态机完整性**: 高风险 🔴

---

## 4. 修复优先级

### 必须修复 (阻塞上库)
1. 问题1: 状态转换非法
2. 问题2: 错误路径遗漏
3. 问题3: 竞态条件

### 应该修复 (建议)
- 添加单元测试覆盖边界条件
- 增加日志记录便于调试

### 可以考虑 (优化)
- 重构状态机使用状态模式
- 引入契约式编程库

---

## 5. 总结

本次代码变更引入了**3个严重的逻辑问题**，主要涉及：
1. 状态机完整性
2. 错误处理完整性
3. 并发安全性

**建议**: 修复所有致命和严重问题后再合并到主分支。

**风险等级**: 🔴 高风险

**总体评价**: ❌ 需要修复
```

---

## 6. 使用指南

### 6.1 调用技能

```bash
# 分析特定分支的代码变更
claude-code "使用logic_analyzer技能分析分支feature-xxx相对于main的代码逻辑变更"

# 分析特定文件的变更
claude-code "使用logic_analyzer技能分析src/account_manager.cpp文件的逻辑变更"

# 分析特定问题类型
claude-code "使用logic_analyzer技能检查状态机相关的逻辑问题"
```

### 6.2 分析流程

```
1. 识别变更
   ├─ 获取变更文件列表
   ├─ 分类变更类型
   └─ 识别影响范围

2. 执行分析
   ├─ 控制流分析
   ├─ 数据流分析
   ├─ 状态机分析
   ├─ 边界条件分析
   ├─ 错误处理分析
   ├─ 并发控制分析
   └─ 业务规则分析

3. 生成报告
   ├─ 问题发现与分类
   ├─ 影响分析
   ├─ 风险评估
   └─ 修复建议
```

---

## 7. 版本历史

| 版本 | 日期 | 变更 | 维护者 |
|---------|------|---------|------------|
| v1.0 | 2026-04-01 | 初始版本，完整的逻辑分析框架 | AI Assistant |

---

**文档结束**
