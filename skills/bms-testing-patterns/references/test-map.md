# BMS 测试地图

## 单元测试

主目录：`services/bundlemgr/test/unittest/`

常见目录：

- Installer：`bms_bundle_installer_test`, `bms_bundle_installers_test`, `bms_bundle_installer_manager_test`
- Uninstall/update：`bms_bundle_uninstaller_test`, `bms_bundle_updater_test`
- Parser/checker：`bms_bundle_parser_test`, `bundle_install_checker_test`
- Data：`bms_data_mgr_test`, `bms_bundle_data_storage_test`, `bms_bundle_rdb_data_manager_test`
- IPC/proxy/host：`bms_bundle_mgr_proxy_test`, `bms_bundle_installer_proxy_test`, `bms_installd_client_test`, `bms_installd_host_test`
- Permission/security：`bms_bundle_permission_test`, `bms_bundle_permission_grant_test`, `bms_host_impl_permission_test`, `bms_bundle_hap_verify_test`, `bms_bundle_verifymanager_test`
- Feature tests：按功能名搜索，如 `quick_fix`, `overlay`, `sandbox`, `resource`, `default_app`, `navigation`, `free_install`

Mocks：

- Mock 源码：`services/bundlemgr/test/mock/src/`
- Mock 头文件：`services/bundlemgr/test/mock/include/`

## Inner API 测试

- `interfaces/inner_api/test/unittest/`
- 适合 proxy/host、inner API 数据结构和接口行为。

## System Tests

主目录：`test/systemtest/common/bms/`

常见目录：

- 安装：`bms_install_system_test`
- 卸载：`bms_uninstall_system_test`
- 权限授权：`bms_permission_grant_system_test`
- 校验：`bms_verify_manager_host_test`, `bms_code_signature_test`
- Overlay：`bms_overlay_install_test`
- Sandbox：`bms_sandbox_app_system_test`
- BundleMgr host/client：`bms_bundle_mgr_host_test`, `bms_client_system_test`
- 资源和扩展资源：`bms_bundle_resource_host_test`, `extend_resource_manager_host_test`

## Fuzz Tests

主目录：`test/fuzztest/`

适合：

- parcel 反序列化。
- 权限校验。
- profile/json 解析。
- install/uninstall 参数异常。

## Benchmark Tests

主目录：`test/benchmarktest/`

适合：

- Info 结构体转换。
- 常用 query 数据结构。
- proxy/installer 性能基准。

## Test Resources

- `test/resource/`
- `test/sceneProject/`
- `test/resource/bundlemgrservice/`
- `test/resource/bmssystemtestability/`

涉及真实 HAP、profile、signature 或 ability 行为时，先搜索这些资源目录。
