# AGENTS.md

本文件是给 AI 编码助手使用的仓库工作指南。所有在本仓库中进行的分析、修改、测试和提交说明，都应优先遵循这里的约定。

## 项目定位

本仓库属于 OpenHarmony Bundle Manager Bundle Framework，主要负责应用包管理相关能力，包括应用安装、更新、卸载、查询、资源管理、权限校验、分布式管理以及若干扩展能力。

工作时请把它视为系统级基础组件：接口稳定性、权限边界、用户隔离、数据一致性和错误码兼容性都很重要。

## 工作原则

- 修改前先阅读相关目录、调用链和已有测试，优先沿用现有风格。
- 保持改动范围收敛，不做与任务无关的重构、格式化或命名调整。
- 不回滚用户已有改动；遇到工作区脏文件时，只处理与当前任务直接相关的文件。
- 对系统能力、安装卸载流程、权限、数据库、IPC、用户态隔离等逻辑保持谨慎。
- 新增行为应尽量有测试或至少说明无法测试的原因。
- 日志、错误码、权限检查和空指针检查应遵循仓库已有模式。

## 工程 Skill 位置

本工程的专用 skill 放在仓库根目录的 `skills/` 下。需要使用工程内 skill 时，应优先从该目录读取对应的 `SKILL.md` 及其 `references/` 资料。

## 目录速览

- `interfaces/`：对外或内部接口定义。
- `services/bundlemgr/`：Bundle Manager 服务主体实现。
- `services/bundlemgr/include/`：服务层头文件。
- `services/bundlemgr/src/`：服务层实现代码。
- `services/bundlemgr/src/installd/`：与安装守护进程相关的客户端和特权操作协作逻辑。
- `services/bundlemgr/src/rdb/`：持久化数据库相关实现。
- `services/bundlemgr/src/verify/`：签名、完整性等校验相关逻辑。
- `services/bundlemgr/test/`：服务层测试。
- `test/`：单元、模块、系统、性能、模糊等测试资源。
- `sa_profile/`：系统能力配置。
- `bundle.json`：组件元信息和依赖声明。

## 构建与测试

本仓库通常依赖完整 OpenHarmony 构建环境。常见命令示例：

```bash
./build.sh --product-name rk3568 --build-target bundle_framework
./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target
./build.sh --product-name rk3568 --build-target services/bundlemgr/test:unittest
```

如果当前环境缺少 OpenHarmony 构建链、产品配置或依赖仓库，请不要伪造构建结果；在最终说明中明确写出未能运行的命令和原因。

## 代码风格

- C++ 代码遵循仓库既有命名、文件组织、错误处理和日志写法。
- 优先使用已有工具类、宏、常量和错误码映射。
- 日志避免输出敏感信息，按现有规则区分 `public` 与 `private`。
- 对外接口变更要检查调用方、IDL、序列化、权限和兼容性影响。
- 多用户相关逻辑必须明确处理 `userId`，不要默认只考虑当前用户。
- 涉及文件系统特权操作时，应通过安装服务或已有封装处理，不要在 BundleMgrService 中直接绕过权限边界。

## 常见关注点

- 安装、更新、卸载流程中的状态回滚和异常路径。
- RDB 事务、并发安装、数据迁移和缓存一致性。
- Bundle 信息、Ability 信息、Extension 信息的查询条件和过滤规则。
- 签名校验、权限授予、配置解析和错误码映射。
- SA 401 与 SA 511 的 IPC 调用、死亡回调和超时处理。
- Quick Fix、Overlay、Sandbox、Clone、Shared Bundle 等扩展能力的特殊约束。

## 提交前检查

完成修改后，至少进行以下检查：

- `git diff` 确认只包含预期改动。
- 能运行的最小相关测试已经运行。
- 无法运行测试时，说明环境限制。
- 新增或修改的错误路径有清晰返回值和日志。
- 修改接口、配置或构建文件时，检查相关依赖和目标。

## 回复约定

向用户汇报时请简洁说明：

- 改了哪些文件。
- 行为上解决了什么问题。
- 运行了哪些验证。
- 哪些验证因环境限制未运行。
