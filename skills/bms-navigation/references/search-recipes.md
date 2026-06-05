# BMS 搜索速查

从仓库根目录运行搜索。优先使用 `rg` 和 `rg --files`。

## 查找符号

```powershell
rg -n "SymbolName" services interfaces common test
```

同时搜索声明和实现：

```powershell
rg -n "class SymbolName|struct SymbolName|SymbolName::|virtual .*SymbolName" services interfaces
```

查找匹配的头文件/源文件：

```powershell
rg --files | rg "symbol_name|SymbolName"
```

## 从接口追踪到服务实现

```powershell
rg -n "ApiName" interfaces/inner_api interfaces/kits
rg -n "ApiName" services/bundlemgr/include services/bundlemgr/src
```

针对 `IBundleMgr` IPC：

```powershell
rg -n "ApiName|API_NAME|Message" interfaces/inner_api/appexecfwk_core services/bundlemgr
```

针对 `IInstalld` IPC：

```powershell
rg -n "ApiName|API_NAME|Message" services/bundlemgr/include/ipc services/bundlemgr/src/ipc services/bundlemgr/src/installd
```

## 定位安装流程

```powershell
rg -n "Install|Uninstall|Update|Recover|Hap|Hsp" services/bundlemgr/include services/bundlemgr/src
rg -n "userId|bundleName|modulePackage|installParam" services/bundlemgr/src/base_bundle_installer.cpp services/bundlemgr/src/bundle_installer.cpp
```

优先从这些文件开始：

- `services/bundlemgr/src/bundle_installer.cpp`
- `services/bundlemgr/src/base_bundle_installer.cpp`
- `services/bundlemgr/src/bundle_install_checker.cpp`
- `services/bundlemgr/src/bundle_parser.cpp`
- `services/bundlemgr/src/installd_client.cpp`

## 定位数据和持久化代码

```powershell
rg -n "InnerBundleInfo|ApplicationInfo|AbilityInfo|ExtensionAbilityInfo" services interfaces
rg -n "Rdb|Storage|Save|Delete|Query|Update" services/bundlemgr/include services/bundlemgr/src
```

优先从这些位置开始：

- `services/bundlemgr/src/bundle_data_mgr.cpp`
- `services/bundlemgr/src/bundle_data_storage_rdb.cpp`
- `services/bundlemgr/src/rdb/`

## 定位功能模块代码

用目录名作为锚点：

```powershell
rg --files services/bundlemgr/src/<feature> services/bundlemgr/include/<feature>
rg -n "ClassOrMethod" services/bundlemgr/src/<feature> services/bundlemgr/include/<feature>
```

常见功能目录名：

```text
app_control, bundle_resource, clone, default_app, distributed_manager,
extend_resource, free_install, navigation, on_demand_install, overlay,
plugin, quick_fix, sandbox_app, shared, verify
```

## 定位测试

```powershell
rg --files services/bundlemgr/test test interfaces/inner_api/test common/test | rg "feature|class|method"
rg -n "ClassOrMethod|ApiName" services/bundlemgr/test test interfaces/inner_api/test common/test
```

系统测试常见位置：

```text
test/systemtest/common/bms/
```

单元测试常见位置：

```text
services/bundlemgr/test/unittest/
```

## 检查构建归属

```powershell
rg -n "source_file_name|target_name|feature_flag" BUILD.gn services/bundlemgr/BUILD.gn **/BUILD.gn
rg -n "bundle_framework_" appexecfwk.gni services/bundlemgr/appexecfwk_bundlemgr.gni
```

如果 PowerShell 的 glob 不好用，先列出构建文件：

```powershell
rg --files -g "BUILD.gn" -g "*.gni"
```

再在返回的文件中搜索 source 或 target 名称。
