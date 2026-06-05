# 用户相关搜索速查

## 查 userId 和特殊常量

```powershell
rg -n "userId|requestUserId|responseUserId|GetResponseUserId" services/bundlemgr/src services/bundlemgr/include interfaces
rg -n "DEFAULT_USERID|U1|START_USERID|INVALID_USERID|UNSPECIFIED_USERID|ALL_USERID|ANY_USERID" services interfaces test
```

## 查 0/1/100 用户语义

```powershell
rg -n "DEFAULT_USERID|Constants::U1|IsU1Enable|PERMISSION_U1_ENABLED|START_USERID" services/bundlemgr/src services/bundlemgr/include
rg -n "userId = 100|USERID = 100|const int32_t USERID|START_USERID" services/bundlemgr/test test interfaces/inner_api/test
```

## 查用户管理入口

```powershell
rg -n "CreateNewUser|RemoveUser|BundleUserMgr|bundle_user_mgr" services interfaces test
rg -n "BeforeCreateNewUser|OnCreateNewUser|AfterCreateNewUser|InnerRemoveUser|ProcessRemoveUser" services/bundlemgr/src/bundle_user_mgr_host_impl.cpp
```

## 查多用户安装

```powershell
rg -n "BundleMultiUserInstaller|InstallExistedApp|ProcessBundleInstall|InstallParam.*userId|installParam.userId" services interfaces test
```

## 查账户和调用者用户

```powershell
rg -n "AccountHelper|GetCurrentActiveUserId|GetUserIdByCallerType|GetOsAccountLocalIdFromUid|GetCallingUid|BASE_USER_RANGE" services interfaces test
```

## 查跨用户权限

```powershell
rg -n "INTERACT_ACROSS_LOCAL_ACCOUNTS|PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS|cross.*account|Across" services interfaces test
```

## 查用户数据状态

```powershell
rg -n "InnerBundleUserInfo|BundleUserInfo|HasInnerBundleUserInfo|AddInnerBundleUserInfo|RemoveInnerBundleUserInfo|bundleUserInfo" services interfaces test
```

## 查 clone/sandbox/appIndex 与用户组合

```powershell
rg -n "appIndex|cloneInfos|sandbox|CLONE_APP_INDEX|SANDBOX_APP_INDEX|ALL_CLONE_APP_INDEX" services interfaces test
```

## 查测试

```powershell
rg --files services/bundlemgr/test test interfaces/inner_api/test | rg "user|multiuser|account|sandbox|bundle_user"
rg -n "USERID|START_USERID|DEFAULT_USERID|U1|ALL_USERID|INVALID_USERID" services/bundlemgr/test test interfaces/inner_api/test
```
