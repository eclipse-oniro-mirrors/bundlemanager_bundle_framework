# 执行计划

> 将 Approved Spec 拆成可独立执行、可验证、可审查的 Task。每个 Task 自包含，交接信息不依赖文件路径引用。

## Plan 元数据

| 字段 | 内容 |
|------|------|
| Plan ID | PLAN-PRINT-001 |
| 关联 Feature/Bug | FEAT-20260525-001 |
| 关联文档 | [proposal.md](proposal.md) / [design.md](design.md) / [spec.md](spec.md) |
| 复杂度 | 标准 |
| 状态 | Approved |
| Owner | [待确认] |

## 输入状态

| 输入 | 路径 | 要求状态 |
|------|------|----------|
| Requirement | [proposal.md](proposal.md) | Approved ✓ |
| Design | [design.md](design.md) | Approved ✓ |
| Spec | [spec.md](spec.md) | Approved ✓ |

## AC 到 Task 追溯

| AC | 来源 | Task | 验证方式 | 覆盖？ |
|----|------|------|----------|--------|
| AC-1 | spec.md US-1 | TASK-1.1, TASK-2.2 | 单元测试/集成测试 | 是 |
| AC-2 | spec.md US-1 | TASK-1.1 | 单元测试 | 是 |
| AC-3 | spec.md US-1 | TASK-1.1 | 单元测试 | 是 |
| AC-4 | spec.md US-1 | TASK-1.1 | 单元测试 | 是 |
| AC-5 | spec.md US-1 | TASK-1.1, TASK-1.3 | 单元测试 | 是 |
| AC-6 | spec.md US-2 | TASK-1.2, TASK-3.1 | 单元测试/集成测试 | 是 |
| AC-7 | spec.md US-3 | TASK-2.3 | 单元测试 | 是 |
| AC-8 | spec.md US-4 | TASK-4.1, TASK-4.2 | 集成测试 | 是 |
| AC-9 | spec.md US-2 | TASK-1.1, TASK-2.2, TASK-3.1 | 单元测试 | 是 |

## 首批实现边界

**首批必须实现：** InstalldService 接口扩展（CreatePrintServiceDir/RemovePrintServiceDir）、安装流程集成、卸载流程集成、错误码定义
**可后置：** OTA 场景支持（TASK-4.1/4.2）、权限验证修复集成（TASK-2.4）
**不建议延后：** TASK-1.4（InstalldClient 封装）——主链路依赖此 Task

## 阶段计划

| 阶段 | 目标 | 关键 Task | 结束门槛 | 最小验证 |
|------|------|-----------|----------|----------|
| Phase-1 | Installd 接口扩展 | TASK-1.1, TASK-1.2, TASK-1.3, TASK-1.4 | IPC 接口编译通过，单元测试通过 | `ctest -R installd_operator` |
| Phase-2 | 安装流程集成 | TASK-2.1, TASK-2.2, TASK-2.3, TASK-2.4 | 驱动应用安装时目录创建成功 | `ctest -R bundle_installer` |
| Phase-3 | 卸载流程集成 | TASK-3.1 | 驱动应用卸载时目录删除成功 | `ctest -R bundle_installer` |
| Phase-4 | OTA 场景支持 | TASK-4.1, TASK-4.2 | 设备重启后存量应用目录修复 | `ctest -R reboot_handler` |
| Phase-5 | 错误码和日志 | TASK-5.1, TASK-5.2 | 错误码定义完整，日志覆盖所有路径 | 编译通过 + 日志检查 |
| Phase-6 | 测试 | TASK-6.1, TASK-6.2, TASK-6.3 | 覆盖率 ≥ 80%，所有 AC 验证通过 | `ctest -R print_service` |

## Task 粒度原则

- 每个 Task 对应一个可独立验收的最小能力闭环
- 两项改动共享同一规则上下文和同一最小验证闭环 → 合并为一张 Task Card
- 文件范围、验证闭环和风险边界足够分离 → 拆分为多张 Task Card
- 简单变更：1-2 张 Task Card；复杂变更：按接线层/规则层/恢复层拆分
- 每个 Task 是可独立验证的最小能力闭环，任务边界由能力闭环决定，不单纯按代码行数或预估时间划定

## 禁止项

执行计划和 Task 不得出现以下内容：

- [x] 没有 TBD / TODO / 占位符
- [x] 没有"根据需要实现""酌情处理"等模糊指令
- [x] 没有跨 Task 隐式依赖（依赖必须显式声明在前置依赖列）
- [x] 没有要求 Agent 自行寻找未列出的上下文文件
- [x] 没有无验证方式的 AC
- [x] 没有"与 Task-N 类似""参考 Task-N 实现"等引用（每个 Task 自包含）

## Task 列表

| Task ID | 目标 | 文件范围 | AC 映射 | 前置依赖 | 完成判据 | 验证命令 |
|---------|------|----------|---------|----------|----------|----------|
| TASK-1.1 | InstalldService 创建打印服务目录接口 | installd_operator.cpp, installd_host_impl.cpp, installd_proxy.cpp, appexecfwk_errors.h | AC-1, AC-2, AC-3, AC-4, AC-5 | 无 | 接口编译通过，核心逻辑实现 | `ctest -R installd_operator` |
| TASK-1.2 | InstalldService 删除打印服务目录接口 | installd_operator.cpp, installd_host_impl.cpp, installd_proxy.cpp | AC-6, AC-9 | 无 | 接口编译通过，删除逻辑实现 | `ctest -R installd_operator` |
| TASK-1.3 | InstalldService 验证/修复目录权限接口 | installd_operator.cpp, installd_host_impl.cpp, installd_proxy.cpp | AC-2, AC-3, AC-5 | TASK-1.1 | 验证修复逻辑实现 | `ctest -R installd_operator` |
| TASK-1.4 | InstalldClient 封装接口调用 | installd_client.h, installd_client.cpp | AC-1, AC-6 | TASK-1.1, TASK-1.2, TASK-1.3 | 3 个 Client 接口实现 | `ctest -R installd_client` |
| TASK-2.1 | 驱动应用检测逻辑 | base_bundle_installer.h, base_bundle_installer.cpp | AC-1, BR-1 | TASK-1.4 | IsDriverApplication 实现 | `ctest -R bundle_installer` |
| TASK-2.2 | 安装流程集成目录创建 | base_bundle_installer.cpp | AC-1, AC-9 | TASK-2.1 | 安装驱动应用时创建目录 | `ctest -R bundle_installer` |
| TASK-2.3 | 分身应用目录名处理 | base_bundle_installer.cpp | AC-7 | TASK-2.2 | 分身目录名格式正确 | `ctest -R bundle_installer` |
| TASK-2.4 | 目录权限验证修复集成 | base_bundle_installer.cpp | AC-2, AC-3, AC-5 | TASK-2.2 | 安装后验证权限 | `ctest -R bundle_installer` |
| TASK-3.1 | 卸载流程集成目录删除 | base_bundle_installer.cpp | AC-6, AC-9 | TASK-1.4 | 卸载时删除目录 | `ctest -R bundle_installer` |
| TASK-4.1 | OTA 存量应用扫描 | bundle_mgr_service_event_handler.h/.cpp | AC-8 | TASK-2.2 | 扫描逻辑实现 | `ctest -R reboot_handler` |
| TASK-4.2 | OTA 目录补建逻辑 | bundle_mgr_service_event_handler.cpp | AC-8 | TASK-4.1 | 补建逻辑实现 | `ctest -R reboot_handler` |
| TASK-5.1 | 新增错误码定义 | appexecfwk_errors.h | AC-4 | 无 | 5 个错误码定义 | 编译通过 |
| TASK-5.2 | 日志记录 | base_bundle_installer.cpp, bundle_mgr_service_event_handler.cpp, installd_operator.cpp | 全部 | TASK-2.2, TASK-3.1, TASK-4.2 | 日志覆盖所有路径 | `hilog -T BMS` |
| TASK-6.1 | 单元测试 | bms_print_service_operator_test.cpp | 全部 AC | TASK-5.2 | 覆盖率 ≥ 80% | `ctest -R print_service` |
| TASK-6.2 | 集成测试 | bms_print_service_integration_test.cpp | AC-1, AC-6, AC-7 | TASK-6.1 | 集成场景通过 | `ctest -R print_service_integration` |
| TASK-6.3 | OTA 升级测试 | bms_print_service_ota_test.cpp | AC-8 | TASK-6.2 | OTA 场景通过 | `ctest -R print_service_ota` |

## Task 详情

> 每个 Task 的详细规格见 [task.md](task.md)。Task 详情采用自包含格式，包含 Handoff Summary，AI Agent 可据此独立执行。

## 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| Installd 接口变更影响其他模块 | 中 | 接口设计向后兼容，不影响现有功能 |
| 权限设置失败导致安全问题 | 高 | 充分测试权限设置逻辑，添加日志记录 |
| OTA 场景测试不充分 | 中 | 模拟多种升级场景进行测试 |

## Plan 自审清单

- [x] 每个 P0/P1 AC 至少映射到一个 Task
- [x] 每个 Task 文件范围明确
- [x] 每个 Task 明确前置依赖、非目标、完成判据和停止条件
- [x] 每个 Task 有验证命令
- [x] Task 粒度形成能力闭环
- [x] 没有 TBD/TODO/占位符
- [x] 没有要求 Agent 自行寻找未列出的上下文
- [x] 交接信息自包含（Handoff Summary 完整）
- [x] 每个 Task 验证在完成时立即执行并记录证据，不得积压到阶段末尾批量补验
- [x] 超 3000 行阈值的 Task 已拆分或已说明不拆分理由
