# 日志搜索速查

## 查找日志宏使用

```powershell
rg -n "APP_LOGD|APP_LOGI|APP_LOGW|APP_LOGE|APP_LOGF|LOG_D\\(|LOG_I\\(|LOG_W\\(|LOG_E\\(|LOG_F\\(" common services interfaces test
```

## 查找 NOFUNC 日志

```powershell
rg -n "APP_LOGI_NOFUNC|APP_LOGW_NOFUNC|APP_LOGE_NOFUNC|LOG_NOFUNC_D|LOG_NOFUNC_I|LOG_NOFUNC_W|LOG_NOFUNC_E|LOG_NOFUNC_F" common services interfaces test
```

## 查找 tag 和 domain

```powershell
rg -n "APP_LOG_TAG|LOG_DOMAIN|BMS_TAG_" -g "BUILD.gn" -g "*.gni" -g "*.h" -g "*.cpp"
```

## 查找 public/private 标注

```powershell
rg -n "%\\{public\\}|%\\{private\\}" common services interfaces test
```

## 查找 HiSysEvent

```powershell
rg -n "HiSysEvent|HISYSEVENT|HiSysEventWrite|hisysevent" common services interfaces test *.yaml
```

## 查找某模块相邻风格

```powershell
rg -n "APP_LOG|LOG_|BMS_TAG" services/bundlemgr/src/<feature> services/bundlemgr/include/<feature>
```

常见 feature：

```text
installd, bundle_resource, quick_fix, overlay, sandbox_app,
default_app, app_control, verify, free_install, rdb
```
