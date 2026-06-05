# 用户相关代码地图

## 常量和基础结构

- 用户常量：`interfaces/inner_api/appexecfwk_base/include/bundle_constants.h`
- 对外用户信息：`interfaces/inner_api/appexecfwk_base/include/bundle_user_info.h`
- 对外用户信息实现：`interfaces/inner_api/appexecfwk_base/src/bundle_user_info.cpp`
- 内部用户信息：`services/bundlemgr/include/inner_bundle_user_info.h`
- 内部用户信息序列化：`services/bundlemgr/src/inner_bundle_user_info.cpp`

## 用户管理 IPC

- Interface：`interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_user_mgr_interface.h`
- Proxy：`interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_user_mgr_proxy.h`
- Proxy 实现：`interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_user_mgr_proxy.cpp`
- Host：`interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_user_mgr_host.h`
- Host 实现：`interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_user_mgr_host.cpp`
- 服务实现：`services/bundlemgr/include/bundle_user_mgr_host_impl.h`, `services/bundlemgr/src/bundle_user_mgr_host_impl.cpp`

## 用户创建和删除

- 创建/删除用户主流程：`services/bundlemgr/src/bundle_user_mgr_host_impl.cpp`
- 用户解锁事件：`services/bundlemgr/include/user_unlocked_event_subscriber.h`, `services/bundlemgr/src/user_unlocked_event_subscriber.cpp`
- 账户辅助：`services/bundlemgr/include/account_helper.h`, `services/bundlemgr/src/account_helper.cpp`

## 多用户安装

- 多用户安装：`services/bundlemgr/include/bundle_multiuser_installer.h`, `services/bundlemgr/src/bundle_multiuser_installer.cpp`
- 安装主流程：`services/bundlemgr/src/bundle_installer.cpp`, `services/bundlemgr/src/base_bundle_installer.cpp`
- 安装参数：搜索 `InstallParam.userId`
- 数据目录/Installs 操作：`services/bundlemgr/src/installd_client.cpp`, `services/bundlemgr/src/installd/`

## 数据和状态

- 主数据管理：`services/bundlemgr/include/bundle_data_mgr.h`, `services/bundlemgr/src/bundle_data_mgr.cpp`
- RDB：`services/bundlemgr/src/bundle_data_storage_rdb.cpp`, `services/bundlemgr/src/rdb/`
- 每用户状态：`InnerBundleUserInfo` 中的 enabled、uid、accessTokenId、installTime、updateTime、cloneInfos、installedPluginSet。

## 相关功能

- Sandbox app：`services/bundlemgr/src/sandbox_app/`, `services/bundlemgr/include/sandbox_app/`
- Clone app：搜索 `cloneInfos`、`appIndex`、`CLONE_APP_INDEX_MAX`
- App control：`services/bundlemgr/src/app_control/`
- Permission：`services/bundlemgr/src/bundle_permission_mgr.cpp`
- Bundle event：`services/bundlemgr/src/bundle_common_event_mgr.cpp`

## 测试位置

- 多用户安装单测：`services/bundlemgr/test/unittest/bms_bundle_multiuser_install_test/`
- 账户约束单测：`services/bundlemgr/test/unittest/bms_account_constraint_test/`
- Sandbox 单测：`services/bundlemgr/test/unittest/bms_bundle_sandbox_app_test/`
- 用户信息 benchmark：`test/benchmarktest/bundle_user_info_test/`
- 多用户 fuzz：`test/fuzztest/fuzztest_others/bundlemutiuserinstaller_fuzzer/`
- Bundle user manager fuzz：`test/fuzztest/fuzztest_bundlemanager/bmsbundleusermgrproxy_fuzzer/`, `bmsbundleusermgrhost_fuzzer/`
- 多用户系统测试资源：`test/sceneProject/systemtest/multiUser/`

## 常见依赖开关

账户能力相关代码常受 `ACCOUNT_ENABLE` 影响。测试或 GN 改动时搜索：

```text
ACCOUNT_ENABLE
```
