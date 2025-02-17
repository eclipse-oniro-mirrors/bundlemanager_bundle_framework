/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "bundle_verify_mgr.h"

#include "app_log_wrapper.h"
#include "bms_extension_data_mgr.h"

using namespace OHOS::Security::Verify;

namespace OHOS {
namespace AppExecFwk {

const std::unordered_map<Security::Verify::AppDistType, std::string> APP_DISTRIBUTION_TYPE_MAPS = {
    { Security::Verify::AppDistType::NONE_TYPE, Constants::APP_DISTRIBUTION_TYPE_NONE },
    { Security::Verify::AppDistType::APP_GALLERY, Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY },
    { Security::Verify::AppDistType::ENTERPRISE, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE },
    { Security::Verify::AppDistType::ENTERPRISE_NORMAL, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL },
    { Security::Verify::AppDistType::ENTERPRISE_MDM, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM },
    { Security::Verify::AppDistType::INTERNALTESTING, Constants::APP_DISTRIBUTION_TYPE_INTERNALTESTING },
    { Security::Verify::AppDistType::OS_INTEGRATION, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION },
    { Security::Verify::AppDistType::CROWDTESTING, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING },
};

namespace {
const int32_t HAP_VERIFY_ERR_MAP_KEY[] = {
    HapVerifyResultCode::VERIFY_SUCCESS, HapVerifyResultCode::FILE_PATH_INVALID, HapVerifyResultCode::OPEN_FILE_ERROR,
    HapVerifyResultCode::SIGNATURE_NOT_FOUND, HapVerifyResultCode::VERIFY_APP_PKCS7_FAIL,
    HapVerifyResultCode::PROFILE_PARSE_FAIL, HapVerifyResultCode::APP_SOURCE_NOT_TRUSTED,
    HapVerifyResultCode::GET_DIGEST_FAIL, HapVerifyResultCode::VERIFY_INTEGRITY_FAIL,
    HapVerifyResultCode::FILE_SIZE_TOO_LARGE, HapVerifyResultCode::GET_PUBLICKEY_FAIL,
    HapVerifyResultCode::GET_SIGNATURE_FAIL, HapVerifyResultCode::NO_PROFILE_BLOCK_FAIL,
    HapVerifyResultCode::VERIFY_SIGNATURE_FAIL, HapVerifyResultCode::VERIFY_SOURCE_INIT_FAIL
};
const ErrCode HAP_VERIFY_ERR_MAP_VALUE[] = {
    ERR_OK, ERR_APPEXECFWK_INSTALL_FAILED_INVALID_SIGNATURE_FILE_PATH,
    ERR_APPEXECFWK_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE_FILE, ERR_APPEXECFWK_INSTALL_FAILED_NO_BUNDLE_SIGNATURE,
    ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_APP_PKCS7_FAIL, ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL,
    ERR_APPEXECFWK_INSTALL_FAILED_APP_SOURCE_NOT_TRUESTED, ERR_APPEXECFWK_INSTALL_FAILED_BAD_DIGEST,
    ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_INTEGRITY_VERIFICATION_FAILURE,
    ERR_APPEXECFWK_INSTALL_FAILED_FILE_SIZE_TOO_LARGE, ERR_APPEXECFWK_INSTALL_FAILED_BAD_PUBLICKEY,
    ERR_APPEXECFWK_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE, ERR_APPEXECFWK_INSTALL_FAILED_NO_PROFILE_BLOCK_FAIL,
    ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE,
    ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_SOURCE_INIT_FAIL
};
} // namespace

ErrCode BundleVerifyMgr::HapVerify(const std::string &filePath, HapVerifyResult &hapVerifyResult)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    ErrCode res = bmsExtensionDataMgr.HapVerify(filePath, hapVerifyResult);
    if (res == ERR_BUNDLEMANAGER_INSTALL_FAILED_SIGNATURE_EXTENSION_NOT_EXISTED) {
        auto ret = Security::Verify::HapVerify(filePath, hapVerifyResult);
        APP_LOGI("HapVerify result %{public}d", ret);
        size_t len = sizeof(HAP_VERIFY_ERR_MAP_KEY) / sizeof(HAP_VERIFY_ERR_MAP_KEY[0]);
        for (size_t i = 0; i < len; i++) {
            if (ret == HAP_VERIFY_ERR_MAP_KEY[i]) {
                return HAP_VERIFY_ERR_MAP_VALUE[i];
            }
        }
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    return res;
}

bool BundleVerifyMgr::isDebug_ = false;

void BundleVerifyMgr::EnableDebug()
{
    if (isDebug_) {
        APP_LOGD("verify mode is already debug mode");
        return;
    }
    if (!Security::Verify::EnableDebugMode()) {
        APP_LOGE("start debug mode failed");
        return;
    }
    isDebug_ = true;
}

void BundleVerifyMgr::DisableDebug()
{
    if (!isDebug_) {
        APP_LOGD("verify mode is already signature mode");
        return;
    }
    Security::Verify::DisableDebugMode();
    isDebug_ = false;
}

ErrCode BundleVerifyMgr::ParseHapProfile(const std::string &filePath, HapVerifyResult &hapVerifyResult,
    bool readFile)
{
    auto ret = Security::Verify::ParseHapProfile(filePath, hapVerifyResult,
        readFile);
    APP_LOGI("ParseHapProfile result %{public}d", ret);
    size_t len = sizeof(HAP_VERIFY_ERR_MAP_KEY) / sizeof(HAP_VERIFY_ERR_MAP_KEY[0]);
    for (size_t i = 0; i < len; i++) {
        if (ret == HAP_VERIFY_ERR_MAP_KEY[i]) {
            return HAP_VERIFY_ERR_MAP_VALUE[i];
        }
    }
    return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
}
}  // namespace AppExecFwk
}  // namespace OHOS