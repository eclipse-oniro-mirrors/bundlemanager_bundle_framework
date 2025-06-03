/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <unordered_map>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "common_func.h"
#include "installer_helper.h"
#include "status_receiver_interface.h"

namespace OHOS {
namespace AppExecFwk {

void InstallerHelper::CreateErrCodeMap(std::unordered_map<int32_t, int32_t>& errCodeMap)
{
    errCodeMap = {
        { IStatusReceiver::SUCCESS, SUCCESS},
        { IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALL_HOST_INSTALLER_FAILED, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALLD_PARAM_ERROR, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALLD_GET_PROXY_ERROR, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALL_INSTALLD_SERVICE_ERROR, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_FAILED_SERVICE_DIED, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_FAILED_GET_INSTALLER_PROXY, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_USER_CREATE_FAILED, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_USER_REMOVE_FAILED, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_UNINSTALL_KILLING_APP_ERROR, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALL_GENERATE_UID_ERROR, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALL_STATE_ERROR, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_RECOVER_NOT_ALLOWED, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_RECOVER_GET_BUNDLEPATH_ERROR, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_UNINSTALL_AND_RECOVER_NOT_PREINSTALLED_BUNDLE, ERROR_BUNDLE_NOT_PREINSTALLED },
        { IStatusReceiver::ERR_UNINSTALL_SYSTEM_APP_ERROR, ERROR_UNINSTALL_PREINSTALL_APP_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_FAILED, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_UNEXPECTED, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_MISSING_BUNDLE, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_NO_PROFILE, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_BAD_PROFILE, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_PROFILE_PROP_TYPE_ERROR, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_PROFILE_MISSING_PROP, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_PERMISSION_ERROR, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_PROFILE_PROP_CHECK_ERROR, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_RPCID_FAILED, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_NATIVE_SO_FAILED, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_AN_FAILED, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_MISSING_ABILITY, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_PROFILE_PARSE_FAIL, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_VERIFICATION_FAILED, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_INVALID_SIGNATURE_FILE_PATH, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE_FILE, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_NO_BUNDLE_SIGNATURE, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_VERIFY_APP_PKCS7_FAIL, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_APP_SOURCE_NOT_TRUESTED, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_BAD_DIGEST, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_BUNDLE_INTEGRITY_VERIFICATION_FAILURE,
            ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_BAD_PUBLICKEY, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_NO_PROFILE_BLOCK_FAIL, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE,
            ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_VERIFY_SOURCE_INIT_FAIL, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_SINGLETON_INCOMPATIBLE, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_INCONSISTENT_SIGNATURE, ERROR_INSTALL_FAILED_INCONSISTENT_SIGNATURE },
        { IStatusReceiver::ERR_INSTALL_PARAM_ERROR, ERROR_BUNDLE_NOT_EXIST },
        { IStatusReceiver::ERR_UNINSTALL_PARAM_ERROR, ERROR_BUNDLE_NOT_EXIST },
        { IStatusReceiver::ERR_RECOVER_INVALID_BUNDLE_NAME, ERROR_BUNDLE_NOT_EXIST },
        { IStatusReceiver::ERR_UNINSTALL_INVALID_NAME, ERROR_BUNDLE_NOT_EXIST },
        { IStatusReceiver::ERR_INSTALL_INVALID_BUNDLE_FILE, ERROR_INSTALL_HAP_FILEPATH_INVALID },
        { IStatusReceiver::ERR_INSTALL_FAILED_MODULE_NAME_EMPTY, ERROR_MODULE_NOT_EXIST },
        { IStatusReceiver::ERR_INSTALL_FAILED_MODULE_NAME_DUPLICATE, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_FAILED_CHECK_HAP_HASH_PARAM, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_UNINSTALL_MISSING_INSTALLED_BUNDLE, ERROR_BUNDLE_NOT_EXIST },
        { IStatusReceiver::ERR_UNINSTALL_MISSING_INSTALLED_MODULE, ERROR_MODULE_NOT_EXIST },
        { IStatusReceiver::ERR_USER_NOT_INSTALL_HAP, ERROR_BUNDLE_NOT_EXIST },
        { IStatusReceiver::ERR_INSTALL_FILE_PATH_INVALID, ERROR_INSTALL_HAP_FILEPATH_INVALID },
        { IStatusReceiver::ERR_INSTALL_PERMISSION_DENIED, ERROR_PERMISSION_DENIED_ERROR },
        { IStatusReceiver::ERR_UNINSTALL_PERMISSION_DENIED, ERROR_PERMISSION_DENIED_ERROR },
        { IStatusReceiver::ERR_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED, ERROR_INSTALL_PERMISSION_CHECK_ERROR },
        { IStatusReceiver::ERR_INSTALL_UPDATE_HAP_TOKEN_FAILED, ERROR_INSTALL_PERMISSION_CHECK_ERROR },
        { IStatusReceiver::ERR_INSTALLD_CREATE_DIR_FAILED, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALLD_CHOWN_FAILED, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALLD_CREATE_DIR_EXIST, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALLD_REMOVE_DIR_FAILED, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALLD_EXTRACT_FILES_FAILED, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALLD_RNAME_DIR_FAILED, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALLD_CLEAN_DIR_FAILED, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_INSTALL_ENTRY_ALREADY_EXIST, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_ALREADY_EXIST, ERROR_INSTALL_ALREADY_EXIST },
        { IStatusReceiver::ERR_INSTALL_BUNDLENAME_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_VERSIONCODE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_VERSIONNAME_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_MINCOMPATIBLE_VERSIONCODE_NOT_SAME,
            ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_VENDOR_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_RELEASETYPE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_RELEASETYPE_TARGET_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_RELEASETYPE_COMPATIBLE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_SINGLETON_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_ZERO_USER_WITH_NO_SINGLETON, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_CHECK_SYSCAP_FAILED, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_APPTYPE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_URI_DUPLICATE, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_VERSION_NOT_COMPATIBLE, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_APP_DISTRIBUTION_TYPE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_APP_PROVISION_TYPE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_SO_INCOMPATIBLE, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_AN_INCOMPATIBLE, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_TYPE_ERROR, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_TYPE_ERROR, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_INCONSISTENT_MODULE_NAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_INVALID_NUMBER_OF_ENTRY_HAP, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_ASAN_ENABLED_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_ASAN_ENABLED_NOT_SUPPORT, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_BUNDLE_TYPE_NOT_SAME, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_DISK_MEM_INSUFFICIENT, ERROR_INSTALL_NO_DISK_SPACE_LEFT },
        { IStatusReceiver::ERR_USER_NOT_EXIST, ERROR_INVALID_USER_ID },
        { IStatusReceiver::ERR_INSTALL_VERSION_DOWNGRADE, ERROR_INSTALL_VERSION_DOWNGRADE },
        { IStatusReceiver::ERR_INSTALL_DEVICE_TYPE_NOT_SUPPORTED, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_CHECK_SYSCAP_FAILED_AND_DEVICE_TYPE_NOT_SUPPORTED, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_DEPENDENT_MODULE_NOT_EXIST, ERROR_INSTALL_DEPENDENT_MODULE_NOT_EXIST },
        { IStatusReceiver::ERR_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED, ERROR_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED },
        { IStatusReceiver::ERR_INSTALL_COMPATIBLE_POLICY_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_FILE_IS_SHARED_LIBRARY, ERROR_INSTALL_FILE_IS_SHARED_LIBRARY },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INVALID_BUNDLE_NAME, ERROR_BUNDLE_NOT_EXIST },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INVALID_MODULE_NAME, ERROR_MODULE_NOT_EXIST },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_ERROR_HAP_TYPE, ERROR_INVALID_TYPE },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_ERROR_BUNDLE_TYPE, ERROR_INVALID_TYPE },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_NAME_MISSED, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_TARGET_MODULE_NAME_MISSED, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_NAME_NOT_SAME,
            ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INTERNAL_EXTERNAL_OVERLAY_EXISTED_SIMULTANEOUSLY,
            ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_TARGET_PRIORITY_NOT_SAME,
            ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INVALID_PRIORITY, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INCONSISTENT_VERSION_CODE,
            ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_SERVICE_EXCEPTION, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_BUNDLE_NAME_SAME_WITH_TARGET_BUNDLE_NAME,
            ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_NO_SYSTEM_APPLICATION_FOR_EXTERNAL_OVERLAY,
            ERROR_INSTALL_HAP_OVERLAY_CHECK_FAILED },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_DIFFERENT_SIGNATURE_CERTIFICATE,
            ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_IS_OVERLAY_BUNDLE,
            ERROR_INSTALL_HAP_OVERLAY_CHECK_FAILED },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_TARGET_MODULE_IS_OVERLAY_MODULE,
            ERROR_INSTALL_HAP_OVERLAY_CHECK_FAILED },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_OVERLAY_TYPE_NOT_SAME,
            ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_OVERLAY_INSTALLATION_FAILED_INVALID_BUNDLE_DIR, ERROR_BUNDLE_SERVICE_EXCEPTION },
        { IStatusReceiver::ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST,
            ERROR_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST },
        { IStatusReceiver::ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_RELIED,
            ERROR_UNINSTALL_SHARE_APP_LIBRARY_IS_RELIED },
        { IStatusReceiver::ERR_APPEXECFWK_UNINSTALL_BUNDLE_IS_SHARED_LIBRARY, ERROR_UNINSTALL_BUNDLE_IS_SHARED_BUNDLE },
        { IStatusReceiver::ERR_INSATLL_CHECK_PROXY_DATA_URI_FAILED, ERROR_INSTALL_WRONG_DATA_PROXY_URI },
        { IStatusReceiver::ERR_INSATLL_CHECK_PROXY_DATA_PERMISSION_FAILED, ERROR_INSTALL_WRONG_DATA_PROXY_PERMISSION },
        { IStatusReceiver::ERR_INSTALL_FAILED_DEBUG_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_DISALLOWED, ERROR_DISALLOW_INSTALL },
        { IStatusReceiver::ERR_INSTALL_ISOLATION_MODE_FAILED, ERROR_INSTALL_WRONG_MODE_ISOLATION },
        { IStatusReceiver::ERR_UNINSTALL_DISALLOWED, ERROR_DISALLOW_UNINSTALL },
        { IStatusReceiver::ERR_INSTALL_CODE_SIGNATURE_FAILED, ERROR_INSTALL_CODE_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID, ERROR_INSTALL_CODE_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_UNINSTALL_FROM_BMS_EXTENSION_FAILED, ERROR_BUNDLE_NOT_EXIST },
        { IStatusReceiver::ERR_INSTALL_SELF_UPDATE_NOT_MDM, ERROR_INSTALL_SELF_UPDATE_NOT_MDM },
        { IStatusReceiver::ERR_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED, ERROR_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED },
        { IStatusReceiver::ERR_INSTALL_EXISTED_ENTERPRISE_BUNDLE_NOT_ALLOWED,
            ERROR_INSTALL_EXISTED_ENTERPRISE_NOT_ALLOWED_ERROR },
        { IStatusReceiver::ERR_INSTALL_SELF_UPDATE_BUNDLENAME_NOT_SAME, ERROR_INSTALL_SELF_UPDATE_BUNDLENAME_NOT_SAME },
        { IStatusReceiver::ERR_INSTALL_GWP_ASAN_ENABLED_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
        { IStatusReceiver::ERR_INSTALL_DEBUG_BUNDLE_NOT_ALLOWED, ERROR_INSTALL_DEBUG_BUNDLE_NOT_ALLOWED },
        { IStatusReceiver::ERR_INSTALL_CHECK_ENCRYPTION_FAILED, ERROR_INSTALL_CODE_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_CODE_SIGNATURE_DELIVERY_FILE_FAILED, ERROR_INSTALL_CODE_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_CODE_SIGNATURE_REMOVE_FILE_FAILED, ERROR_INSTALL_CODE_SIGNATURE_FAILED },
        { IStatusReceiver::ERR_INSTALL_CODE_APP_CONTROLLED_FAILED, ERROR_INSTALL_FAILED_CONTROLLED },
        { IStatusReceiver::ERR_APPEXECFWK_INSTALL_FORCE_UNINSTALLED_BUNDLE_NOT_ALLOW_RECOVER,
            ERROR_INSTALL_FAILED_CONTROLLED},
        { IStatusReceiver::ERR_APPEXECFWK_INSTALL_PREINSTALL_BUNDLE_ONLY_ALLOW_FORCE_UNINSTALLED_BY_EDC,
            ERROR_INSTALL_FAILED_CONTROLLED},
        { IStatusReceiver::ERR_INSTALL_NATIVE_FAILED, ERROR_INSTALL_NATIVE_FAILED },
        { IStatusReceiver::ERR_UNINSTALL_NATIVE_FAILED, ERROR_UNINSTALL_NATIVE_FAILED },
        { IStatusReceiver::ERR_UNINSTALL_DISPOSED_RULE_DENIED, ERROR_APPLICATION_UNINSTALL},
        { IStatusReceiver::ERR_NATIVE_HNP_EXTRACT_FAILED, ERROR_INSTALL_NATIVE_FAILED },
        { IStatusReceiver::ERR_UNINSTALL_CONTROLLED, ERROR_BUNDLE_CAN_NOT_BE_UNINSTALLED },
        { IStatusReceiver::ERR_INSTALL_DEBUG_ENCRYPTED_BUNDLE_FAILED, ERROR_INSTALL_PARSE_FAILED },
        { IStatusReceiver::ERR_INSTALL_FAILED_AND_RESTORE_TO_PREINSTALLED,
            ERROR_INSTALL_FAILED_AND_RESTORE_TO_PREINSTALLED },
        { IStatusReceiver::ERR_APP_DISTRIBUTION_TYPE_NOT_ALLOW_INSTALL_ISR,
            ERROR_APP_DISTRIBUTION_TYPE_NOT_ALLOW_INSTALL},
    };
}

void InstallerHelper::ConvertInstallResult(InstallResult& installResult)
{
    APP_LOGD("ConvertInstallResult msg %{public}s, errCode is %{public}d", installResult.resultMsg.c_str(),
        installResult.resultCode);
    std::unordered_map<int32_t, int32_t> errCodeMap;
    CreateErrCodeMap(errCodeMap);
    auto iter = errCodeMap.find(installResult.resultCode);
    if (iter != errCodeMap.end()) {
        installResult.resultCode = iter->second;
        return;
    }
    installResult.resultCode = ERROR_BUNDLE_SERVICE_EXCEPTION;
}

void InstallerHelper::CreateProxyErrCode(std::unordered_map<int32_t, int32_t>& errCodeMap)
{
    errCodeMap = {
        { ERR_APPEXECFWK_INSTALL_PARAM_ERROR, IStatusReceiver::ERR_INSTALL_PARAM_ERROR },
        { ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR },
        { ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID, IStatusReceiver::ERR_INSTALL_FILE_PATH_INVALID },
        { ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT, IStatusReceiver::ERR_INSTALL_DISK_MEM_INSUFFICIENT },
        { ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID,
            IStatusReceiver::ERR_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID}
    };
}

ErrCode InstallerHelper::InnerCreateAppClone(std::string& bundleName, int32_t userId, int32_t& appIndex)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode result = iBundleInstaller->InstallCloneApp(bundleName, userId, appIndex);
    APP_LOGD("InstallCloneApp result is %{public}d", result);
    return result;
}

ErrCode InstallerHelper::InnerDestroyAppClone(
    std::string& bundleName, int32_t userId, int32_t appIndex, DestroyAppCloneParam& destroyAppCloneParam)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode result = iBundleInstaller->UninstallCloneApp(bundleName, userId, appIndex, destroyAppCloneParam);
    APP_LOGD("UninstallCloneApp result is %{public}d", result);
    return result;
}

ErrCode InstallerHelper::InnerAddExtResource(const std::string& bundleName, const std::vector<std::string>& filePaths)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    std::vector<std::string> destFiles;
    ErrCode ret = extResourceManager->CopyFiles(filePaths, destFiles);
    if (ret != ERR_OK) {
        APP_LOGE("CopyFiles failed");
        return CommonFunc::ConvertErrCode(ret);
    }

    ret = extResourceManager->AddExtResource(bundleName, destFiles);
    if (ret != ERR_OK) {
        APP_LOGE("AddExtResource failed");
    }

    return CommonFunc::ConvertErrCode(ret);
}

ErrCode InstallerHelper::InnerRemoveExtResource(
    const std::string& bundleName, const std::vector<std::string>& moduleNames)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ErrCode ret = extResourceManager->RemoveExtResource(bundleName, moduleNames);
    if (ret != ERR_OK) {
        APP_LOGE("RemoveExtResource failed");
    }

    return CommonFunc::ConvertErrCode(ret);
}

ErrCode InstallerHelper::InnerInstallPreexistingApp(std::string& bundleName, int32_t userId)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode result = iBundleInstaller->InstallExisted(bundleName, userId);
    APP_LOGD("result is %{public}d", result);
    return result;
}

ErrCode InstallerHelper::InnerInstallPlugin(const std::string& hostBundleName,
    const std::vector<std::string>& pluginFilePaths, const InstallPluginParam& installPluginParam)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode result = iBundleInstaller->InstallPlugin(hostBundleName, pluginFilePaths, installPluginParam);
    APP_LOGD("InstallPlugin result is %{public}d", result);
    return result;
}

ErrCode InstallerHelper::InnerUninstallPlugin(const std::string& hostBundleName, const std::string& pluginBundleName,
    const InstallPluginParam& installPluginParam)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode result = iBundleInstaller->UninstallPlugin(hostBundleName, pluginBundleName, installPluginParam);
    APP_LOGD("UninstallPlugin result is %{public}d", result);
    return result;
}
} // namespace AppExecFwk
} // namespace OHOS