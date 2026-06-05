# BMS 代码地图

## 仓库根目录

- `interfaces/`：提供给其他子系统和应用侧 kit 的接口。
- `services/bundlemgr/`：Bundle Manager Service 主实现。
- `common/`：公共日志和工具。
- `test/`：系统测试、模块测试、性能测试、模糊测试和测试资源。
- `services/bundlemgr/test/`：服务层单元测试。
- `sa_profile/`：BundleMgrService 和 InstalldService 的系统能力配置。
- `etc/`：运行配置。

## 核心服务文件

| 关注点 | 主要文件 |
| --- | --- |
| 系统能力服务 | `services/bundlemgr/include/bundle_mgr_service.h`, `services/bundlemgr/src/bundle_mgr_service.cpp` |
| IPC host 业务实现 | `services/bundlemgr/include/bundle_mgr_host_impl.h`, `services/bundlemgr/src/bundle_mgr_host_impl.cpp` |
| Bundle 数据管理 | `services/bundlemgr/include/bundle_data_mgr.h`, `services/bundlemgr/src/bundle_data_mgr.cpp` |
| Installer 门面 | `services/bundlemgr/include/bundle_installer.h`, `services/bundlemgr/src/bundle_installer.cpp` |
| 安装、更新、卸载基础逻辑 | `services/bundlemgr/include/base_bundle_installer.h`, `services/bundlemgr/src/base_bundle_installer.cpp` |
| 安装检查 | `services/bundlemgr/include/bundle_install_checker.h`, `services/bundlemgr/src/bundle_install_checker.cpp` |
| Bundle 解析 | `services/bundlemgr/include/bundle_parser.h`, `services/bundlemgr/src/bundle_parser.cpp` |
| 权限辅助 | `services/bundlemgr/include/bundle_permission_mgr.h`, `services/bundlemgr/src/bundle_permission_mgr.cpp` |

## IPC 与进程边界

### BundleMgrService / Foundation 进程 / SA 401

- Interface：`interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_interface.h`
- Proxy：`interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_proxy.h`
- Proxy 实现：`interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_proxy.cpp`
- Host：`interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_host.h`
- Host 分发/服务侧：`services/bundlemgr/src/bundle_mgr_host.cpp`
- 业务实现：`services/bundlemgr/src/bundle_mgr_host_impl.cpp`
- IPC 枚举：`interfaces/inner_api/appexecfwk_core/include/bundle_framework_core_ipc_interface_code.h`
- SA 配置：`sa_profile/401.json`

### InstalldService / Installs 进程 / SA 511

- Client：`services/bundlemgr/include/installd_client.h`, `services/bundlemgr/src/installd_client.cpp`
- Interface：`services/bundlemgr/include/ipc/installd_interface.h`
- Proxy：`services/bundlemgr/include/ipc/installd_proxy.h`, `services/bundlemgr/src/ipc/installd_proxy.cpp`
- Host：`services/bundlemgr/include/ipc/installd_host.h`, `services/bundlemgr/src/ipc/installd_host.cpp`
- 业务实现：`services/bundlemgr/include/installd/installd_host_impl.h`, `services/bundlemgr/src/installd/installd_host_impl.cpp`
- IPC 枚举：`services/bundlemgr/include/bundle_framework_services_ipc_interface_code.h`
- SA 配置：`sa_profile/511.json`

## 功能模块地图

| 功能 | 服务目录 |
| --- | --- |
| Aging 清理 | `services/bundlemgr/src/aging`, `services/bundlemgr/include/aging` |
| AOT | `services/bundlemgr/src/aot`, `services/bundlemgr/include/aot` |
| 应用管控和跳转拦截 | `services/bundlemgr/src/app_control`, `services/bundlemgr/include/app_control` |
| Provision profile 数据 | `services/bundlemgr/src/app_provision_info`, `services/bundlemgr/include/app_provision_info` |
| App service framework | `services/bundlemgr/src/app_service_fwk`, `services/bundlemgr/include/app_service_fwk` |
| 备份与恢复 | `services/bundlemgr/src/bundle_backup`, `services/bundlemgr/include/bundle_backup` |
| Bundle 资源 | `services/bundlemgr/src/bundle_resource`, `services/bundlemgr/include/bundle_resource` |
| Clone app | `services/bundlemgr/src/clone`, `services/bundlemgr/include/clone` |
| 默认应用 | `services/bundlemgr/src/default_app`, `services/bundlemgr/include/default_app` |
| 分布式管理 | `services/bundlemgr/src/distributed_manager`, `services/bundlemgr/include/distributed_manager` |
| Driver 安装 | `services/bundlemgr/src/driver`, `services/bundlemgr/include/driver` |
| 扩展资源 | `services/bundlemgr/src/extend_resource`, `services/bundlemgr/include/extend_resource` |
| 首次安装数据 | `services/bundlemgr/src/first_install_data_mgr`, `services/bundlemgr/include/first_install_data_mgr` |
| Free install | `services/bundlemgr/src/free_install`, `services/bundlemgr/include/free_install` |
| Navigation/router 数据 | `services/bundlemgr/src/navigation`, `services/bundlemgr/include/navigation` |
| On-demand install | `services/bundlemgr/src/on_demand_install`, `services/bundlemgr/include/on_demand_install` |
| Overlay | `services/bundlemgr/src/overlay`, `services/bundlemgr/include/overlay` |
| Plugin | `services/bundlemgr/src/plugin`, `services/bundlemgr/include/plugin` |
| Quick fix | `services/bundlemgr/src/quick_fix`, `services/bundlemgr/include/quick_fix` |
| RDB 封装 | `services/bundlemgr/src/rdb`, `services/bundlemgr/include/rdb` |
| Sandbox app | `services/bundlemgr/src/sandbox_app`, `services/bundlemgr/include/sandbox_app` |
| Shared bundle | `services/bundlemgr/src/shared`, `services/bundlemgr/include/shared` |
| 卸载数据 | `services/bundlemgr/src/uninstall_data_mgr`, `services/bundlemgr/include/uninstall_data_mgr` |
| UTD | `services/bundlemgr/src/utd`, `services/bundlemgr/include/utd` |
| 校验 | `services/bundlemgr/src/verify`, `services/bundlemgr/include/verify` |

## API 入口地图

- Inner native APIs：`interfaces/inner_api/appexecfwk_core/`
- Native kit：`interfaces/kits/native/bundle/`
- JS kits：`interfaces/kits/js/`
- Cangjie kits：`interfaces/kits/cj/`
- ANI kits：`interfaces/kits/ani/`

当需求提到外部 API 名称时，先在 `interfaces/` 搜索，再沿 proxy/host 调用进入 `services/bundlemgr/`。

## 构建与配置文件

- 根 target：`BUILD.gn`
- 服务 target：`services/bundlemgr/BUILD.gn`
- 常见功能开关：`appexecfwk.gni`
- Bundle service GN 参数：`services/bundlemgr/appexecfwk_bundlemgr.gni`
- 组件元数据：`bundle.json`
- HiSysEvent schema：`hisysevent.yaml`, `bundle_hisysevent.yaml`

## 测试地图

- 服务单元测试：`services/bundlemgr/test/unittest/`
- Common 单元测试：`common/test/unittest/`
- Inner API 单元测试：`interfaces/inner_api/test/unittest/`
- 系统测试：`test/systemtest/common/bms/`
- 模块测试：`test/moduletest/`
- 性能测试：`test/benchmarktest/`
- 模糊测试：`test/fuzztest/`
- 测试 HAP 和资源：`test/resource/`, `test/sceneProject/`

新增测试前，先按功能名或类名查找已有测试目录。
