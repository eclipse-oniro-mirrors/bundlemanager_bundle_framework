/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bundle_manager_ffi.h"

#include <shared_mutex>

#include "app_log_wrapper.h"
#include "bundle_error.h"
#include "bundle_info.h"
#include "bundle_manager.h"
#include "bundle_manager_convert.h"
#include "bundle_manager_utils.h"
#include "cj_common_ffi.h"
#include "ipc_skeleton.h"
#include "securec.h"

using namespace OHOS::CJSystemapi::BundleManager::Convert;
using namespace OHOS::CJSystemapi::BundleManager;

namespace OHOS {
namespace CJSystemapi {
namespace BundleManager {

std::vector<std::string> CharPtrToVector(char** charPtr, int32_t size)
{
    std::vector<std::string> result;
    for (int32_t i = 0; i < size; i++) {
        if (charPtr != nullptr) {
            result.push_back(std::string(charPtr[i]));
        }
    }
    return result;
}

extern "C" {
    int32_t FfiOHOSGetCallingUid()
    {
        return IPCSkeleton::GetCallingUid();
    }

    RetBundleInfo FfiOHOSGetBundleInfoForSelf(int32_t bundleFlags)
    {
        APP_LOGI("BundleManager::FfiOHOSGetBundleInfoForSelf");
        AppExecFwk::BundleInfo bundleInfo = BundleManagerImpl::GetBundleInfoForSelf(bundleFlags);
        RetBundleInfo cjInfo = ConvertBundleInfo(bundleInfo, bundleFlags);
        APP_LOGI("BundleManager::FfiOHOSGetBundleInfoForSelf success");
        return cjInfo;
    }

    RetBundleInfoV2 FfiOHOSGetBundleInfoForSelfV2(int32_t bundleFlags)
    {
        APP_LOGI("BundleManager::FfiOHOSGetBundleInfoForSelf");
        AppExecFwk::BundleInfo bundleInfo = BundleManagerImpl::GetBundleInfoForSelf(bundleFlags);
        RetBundleInfoV2 cjInfo = ConvertBundleInfoV2(bundleInfo, bundleFlags);
        APP_LOGI("BundleManager::FfiOHOSGetBundleInfoForSelf success");
        return cjInfo;
    }
 
    int32_t FfiOHOSVerifyAbc(CArrString cAbcPaths, bool deleteOriginalFiles)
    {
        APP_LOGI("BundleManager::FfiOHOSVerifyAbc");
        std::vector<std::string> abcPaths = CharPtrToVector(cAbcPaths.head, cAbcPaths.size);
        auto code = BundleManagerImpl::VerifyAbc(abcPaths, deleteOriginalFiles);
        if (code != 0) {
            APP_LOGE("FfiOHOSVerifyAbc failed, code is %{public}d", code);
            return code;
        }
        APP_LOGI("BundleManager::FfiOHOSVerifyAbc success");
        return code;
    }

    RetCArrString FfiGetProfileByExtensionAbility(char* moduleName, char* extensionAbilityName, char* metadataName)
    {
        APP_LOGI("BundleManager::FfiGetProfileByExtensionAbility");
        RetCArrString res = { .code = -1, .value = {}};
        auto [status, extensionAbilityInfo] = BundleManagerImpl::GetProfileByExtensionAbility(
            std::string(moduleName), std::string(extensionAbilityName), metadataName);
        if (status != 0) {
            APP_LOGE("FfiGetProfileByExtensionAbility failed, code is %{public}d", status);
            return {status, {}};
        }
        res.code = SUCCESS_CODE;
        res.value = ConvertArrString(extensionAbilityInfo);
        APP_LOGI("BundleManager::FfiGetProfileByExtensionAbility success");
        return res;
    }

    RetCArrString FfiGetProfileByAbility(char* moduleName, char* extensionAbilityName, char* metadataName)
    {
        APP_LOGI("BundleManager::FfiGetProfileByAbility");
        RetCArrString res = { .code = -1, .value = {}};
        auto [status, extensionAbilityInfo] = BundleManagerImpl::GetProfileByAbility(
            std::string(moduleName), std::string(extensionAbilityName), metadataName);
        if (status != 0) {
            APP_LOGE("FfiGetProfileByAbility failed, code is %{public}d", status);
            return {status, {}};
        }
        res.code = SUCCESS_CODE;
        res.value = ConvertArrString(extensionAbilityInfo);
        APP_LOGI("BundleManager::FfiGetProfileByAbility success");
        return res;
    }

    bool FfiBundleManagerCanOpenLink(char* link, int32_t& code)
    {
        std::string cLink(link);
        return BundleManagerImpl::InnerCanOpenLink(link, code);
    }

    uint32_t FfiOHOSGetAPITargetVersion()
    {
        AppExecFwk::BundleInfo bundleInfo = BundleManagerImpl::GetBundleInfoForSelf(
            AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT |
            AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES |
            AppExecFwk::BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION |
            AppExecFwk::BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO |
            AppExecFwk::BundleFlag::GET_BUNDLE_WITH_HASH_VALUE);
        return bundleInfo.targetVersion;
    }

    FFI_EXPORT RetBundleInfoV2 FfiOHOSGetBundleInfo(char* cBundleName, int32_t bundleFlags,
        int32_t userId, int32_t* errcode)
    {
        APP_LOGD("BundleManager::FfiOHOSGetBundleInfo");
        RetBundleInfoV2 ret = {};
        if (errcode == nullptr) {
            APP_LOGE("BundleManager::FfiOHOSGetBundleInfo errcode is nullptr");
            return ret;
        }
        if (cBundleName == nullptr) {
            APP_LOGE("BundleManager::FfiOHOSGetBundleInfo cBundleName is nullptr");
            *errcode = static_cast<int32_t>(ERROR_PARAM_CHECK_ERROR);
            return ret;
        }
        std::string bundleName = std::string(cBundleName);
        AppExecFwk::BundleInfo bundleInfo;
        *errcode = BundleManagerImpl::GetBundleInfo(bundleName, bundleFlags, userId, bundleInfo);
        if (*errcode != SUCCESS_CODE) {
            APP_LOGE("BundleManager::FfiOHOSGetBundleInfo failed");
            return ret;
        }
        return ConvertBundleInfoV2(bundleInfo, bundleFlags);
    }

    FFI_EXPORT void FfiOHOSFreeRetBundleInfoV2(RetBundleInfoV2* bundleInfo)
    {
        APP_LOGD("BundleManager::FfiOHOSFreeRetBundleInfoV2");
        if (bundleInfo == nullptr) {
            return;
        }
        FreeRetBundleInfoV2(*bundleInfo);
    }

    FFI_EXPORT char* FfiOHOSGetBundleNameByUid(int32_t userId, int32_t* errcode)
    {
        APP_LOGD("BundleManager::FfiOHOSGetBundleNameByUid");
        if (errcode == nullptr) {
            return nullptr;
        }
        auto bundleName = BundleManagerImpl::GetBundleNameByUid(userId, errcode);
        if (*errcode != SUCCESS_CODE) {
            APP_LOGE("BundleManager::FfiOHOSGetBundleNameByUid failed");
            return nullptr;
        }
        APP_LOGD("BundleManager::FfiOHOSGetBundleNameByUid success");
        return Convert::MallocCString(bundleName);
    }

    FFI_EXPORT void FfiOHOSFreeCString(char* retCString)
    {
        APP_LOGD("BundleManager::FfiOHOSFreeCString");
        if (retCString == nullptr) {
            return;
        }
        free(retCString);
    }
}

} // BundleManager
} // CJSystemapi
} // OHOS