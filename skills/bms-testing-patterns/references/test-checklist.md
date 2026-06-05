# BMS 测试检查清单

## 找已有测试

```powershell
rg --files services/bundlemgr/test test interfaces/inner_api/test common/test | rg "feature|class|method"
rg -n "ClassName|MethodName|ErrorCode|ApiName" services/bundlemgr/test test interfaces/inner_api/test common/test
```

## 检查 BUILD.gn

```powershell
rg -n "target_name|sources|deps|external_deps|include_dirs" services/bundlemgr/test test interfaces/inner_api/test common/test
rg -n "test_suite|unittest|systemtest|fuzztest|benchmark" services/bundlemgr/test test
```

## 单测建议

- 复用相邻测试 fixture。
- 使用 `services/bundlemgr/test/mock/` 下已有 mock。
- 覆盖成功路径、关键失败路径、边界参数。
- 对权限/IPC/RDB 改动，至少覆盖失败路径。
- 避免依赖真实设备状态，除非已有测试目录就是系统测试。

## 系统测试建议

- 复用 `test/systemtest/common/bms/` 现有工具和资源。
- 安装/卸载类场景确认 HAP 资源是否已存在。
- 使用已有 `BUILD.gn` 模式注册测试。
- 增加清理逻辑，避免测试间污染 bundle/user 状态。

## Fuzz 建议

- 优先针对解析、反序列化、IPC 读取、profile/json 输入。
- 保持 corpus 小而代表性明确。
- 查找相近 fuzzer 的 `project.xml` 和 `BUILD.gn`。

## 修改后验证

如果完整 OpenHarmony 构建环境不可用：

- 至少运行 `rg` 确认新增源文件进入对应 `BUILD.gn`。
- 检查 include 路径和 mock 依赖是否与相邻测试一致。
- 检查测试名、suite 名、宏名是否符合目录现有风格。

完整环境可用时，优先跑最小相关 target，再考虑更大范围测试。
