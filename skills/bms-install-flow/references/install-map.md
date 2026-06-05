# 安装流程地图

## 核心文件

| 关注点 | 文件 |
| --- | --- |
| 安装 IPC/host 入口 | `services/bundlemgr/src/bundle_mgr_host_impl.cpp` |
| Installer 门面 | `services/bundlemgr/include/bundle_installer.h`, `services/bundlemgr/src/bundle_installer.cpp` |
| Installer 管理 | `services/bundlemgr/include/bundle_installer_manager.h`, `services/bundlemgr/src/bundle_installer_manager.cpp` |
| Installer host | `services/bundlemgr/include/bundle_installer_host.h`, `services/bundlemgr/src/bundle_installer_host.cpp` |
| 基础安装逻辑 | `services/bundlemgr/include/base_bundle_installer.h`, `services/bundlemgr/src/base_bundle_installer.cpp` |
| 安装检查 | `services/bundlemgr/include/bundle_install_checker.h`, `services/bundlemgr/src/bundle_install_checker.cpp` |
| Bundle 解析 | `services/bundlemgr/include/bundle_parser.h`, `services/bundlemgr/src/bundle_parser.cpp` |
| 系统 bundle 安装 | `services/bundlemgr/include/system_bundle_installer.h`, `services/bundlemgr/src/system_bundle_installer.cpp` |
| 多用户安装 | `services/bundlemgr/include/bundle_multiuser_installer.h` |
| 安装异常管理 | `services/bundlemgr/include/install_exception_mgr.h`, `services/bundlemgr/src/install_exception_mgr.cpp` |
| 临时安装信息 | `services/bundlemgr/include/installer_bundle_tmp_info.h`, `services/bundlemgr/src/installer_bundle_tmp_info.cpp` |

## Installs 进程文件操作

- Client：`services/bundlemgr/include/installd_client.h`, `services/bundlemgr/src/installd_client.cpp`
- IPC interface/proxy/host：`services/bundlemgr/include/ipc/`, `services/bundlemgr/src/ipc/`
- 实际文件操作：`services/bundlemgr/src/installd/`
- SA 配置：`sa_profile/511.json`

常见原则：安装流程在 Foundation 进程组织，目录创建、文件提取、权限设置、删除等特权操作走 Installs 进程。

## 数据和资源同步

- 主数据管理：`services/bundlemgr/src/bundle_data_mgr.cpp`
- 主 RDB：`services/bundlemgr/src/bundle_data_storage_rdb.cpp`
- RDB 公共封装：`services/bundlemgr/src/rdb/`
- Bundle 资源：`services/bundlemgr/src/bundle_resource/`
- 卸载数据：`services/bundlemgr/src/uninstall_data_mgr/`
- 首次安装数据：`services/bundlemgr/src/first_install_data_mgr/`

## 相关特殊流程

- HSP/shared bundle：`services/bundlemgr/src/shared/`
- Clone app：`services/bundlemgr/src/clone/`
- Sandbox app：`services/bundlemgr/src/sandbox_app/`
- Overlay：`services/bundlemgr/src/overlay/`
- Quick fix：`services/bundlemgr/src/quick_fix/`
- Free install/on-demand install：`services/bundlemgr/src/free_install/`, `services/bundlemgr/src/on_demand_install/`
- App service framework：`services/bundlemgr/src/app_service_fwk/`

## 常见测试位置

- 单元测试：
  - `services/bundlemgr/test/unittest/bms_bundle_installer_test/`
  - `services/bundlemgr/test/unittest/bms_bundle_installers_test/`
  - `services/bundlemgr/test/unittest/bms_bundle_installer_manager_test/`
  - `services/bundlemgr/test/unittest/bundle_install_checker_test/`
  - `services/bundlemgr/test/unittest/bms_bundle_parser_test/`
  - `services/bundlemgr/test/unittest/bms_bundle_uninstaller_test/`
  - `services/bundlemgr/test/unittest/bms_bundle_updater_test/`
  - `services/bundlemgr/test/unittest/bms_installd_client_test/`
- 系统测试：
  - `test/systemtest/common/bms/bms_install_system_test/`
  - `test/systemtest/common/bms/bms_uninstall_system_test/`
  - `test/systemtest/common/bms/bms_stream_installer_host_test/`
