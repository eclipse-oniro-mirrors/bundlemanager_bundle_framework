# 安装流程搜索速查

## 找入口

```powershell
rg -n "Install|Uninstall|Update|Recover|StreamInstall" services/bundlemgr/src/bundle_mgr_host_impl.cpp services/bundlemgr/include/bundle_mgr_host_impl.h
rg -n "Install|Uninstall|Update|Recover" services/bundlemgr/src/bundle_installer.cpp services/bundlemgr/src/base_bundle_installer.cpp
```

## 找安装参数和用户维度

```powershell
rg -n "InstallParam|userId|bundleName|modulePackage|hapPath|hsp" services/bundlemgr/src services/bundlemgr/include
```

## 找安装检查

```powershell
rg -n "Check|Verify|Parse|Signature|Provision|Permission" services/bundlemgr/src/bundle_install_checker.cpp services/bundlemgr/src/bundle_parser.cpp
```

## 找 Installs 文件操作

```powershell
rg -n "Create|Remove|Extract|Copy|Move|Chmod|Mkdir|Dir|File" services/bundlemgr/src/installd_client.cpp services/bundlemgr/src/ipc services/bundlemgr/src/installd
```

## 找错误码

```powershell
rg -n "ERR_APPEXECFWK_INSTALL|ERR_APPEXECFWK_UNINSTALL|ERR_APPEXECFWK_UPDATE|ERR_APPEXECFWK_INSTALLD" interfaces services
```

## 找测试

```powershell
rg -n "Install|Uninstall|Update|Recover|InstallParam" services/bundlemgr/test test/systemtest/common/bms
rg --files services/bundlemgr/test test/systemtest/common/bms | rg "install|uninstall|update|installd|parser|checker"
```
