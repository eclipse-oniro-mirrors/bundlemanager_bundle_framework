# 安全与校验地图

## 权限和调用方校验

- Host 业务入口：`services/bundlemgr/src/bundle_mgr_host_impl.cpp`
- 权限管理：`services/bundlemgr/include/bundle_permission_mgr.h`, `services/bundlemgr/src/bundle_permission_mgr.cpp`
- Permission mock/test：`services/bundlemgr/test/mock/src/mock_permission_mgr.cpp`, `services/bundlemgr/test/mock/src/bundle_permission_mgr.cpp`
- Access token mock：`services/bundlemgr/test/mock/src/accesstoken_kit.cpp`
- IPCSkeleton mock：`services/bundlemgr/test/mock/src/mock_ipc_skeleton.cpp`

## Verify / 签名 / 完整性

- Verify util：`services/bundlemgr/include/verify/verify_util.h`, `services/bundlemgr/src/verify/verify_util.cpp`
- Verify manager host：`services/bundlemgr/include/verify/verify_manager_host_impl.h`, `services/bundlemgr/src/verify/verify_manager_host_impl.cpp`
- Bundle verify manager：`services/bundlemgr/include/bundle_verify_mgr.h`
- 安装检查：`services/bundlemgr/src/bundle_install_checker.cpp`
- Bundle 解析：`services/bundlemgr/src/bundle_parser.cpp`

## Provision Profile

- Manager：`services/bundlemgr/include/app_provision_info/app_provision_info_manager.h`, `services/bundlemgr/src/app_provision_info/app_provision_info_manager.cpp`
- RDB：`services/bundlemgr/include/app_provision_info/app_provision_info_rdb.h`, `services/bundlemgr/src/app_provision_info/app_provision_info_rdb.cpp`

## App Control

- App control：`services/bundlemgr/src/app_control/`, `services/bundlemgr/include/app_control/`
- 常用于应用管控、跳转拦截、disposed 状态等策略相关需求。

## Installs 权限边界

- Installs host impl：`services/bundlemgr/src/installd/installd_host_impl.cpp`
- Permission manager mock/source：搜索 `InstalldPermissionMgr`
- 常见校验：`Constants::FOUNDATION_UID`

## 错误码和事件

- 错误码：`interfaces/kits/native/inner_api/appexecfwk_errors.h`
- HiSysEvent：`hisysevent.yaml`, `bundle_hisysevent.yaml`
- 日志：`common/log/`

## 常见测试

- `services/bundlemgr/test/unittest/bms_bundle_permission_test/`
- `services/bundlemgr/test/unittest/bms_bundle_permission_grant_test/`
- `services/bundlemgr/test/unittest/bms_host_impl_permission_test/`
- `services/bundlemgr/test/unittest/bms_bundle_hap_verify_test/`
- `services/bundlemgr/test/unittest/bms_bundle_verifymanager_test/`
- `test/systemtest/common/bms/bms_verify_manager_host_test/`
- `test/systemtest/common/bms/bms_code_signature_test/`
- `test/systemtest/common/bms/bms_permission_grant_system_test/`
- `test/fuzztest/fuzztest_others/verifycallingpermission_fuzzer/`
