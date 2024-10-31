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

#include "securec.h"
#include "app_log_wrapper.h"
#include "cj_common_ffi.h"
#include "bundle_manager_utils.h"
#include "bundle_manager.h"
#include "bundle_info.h"
#include "ipc_skeleton.h"
#include "bundle_manager_convert.h"
#include "bundle_manager_ffi.h"
#include <shared_mutex>

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

CArrString VectorToCArrString(std::vector<std::string> &vec)
{
    if (vec.size() == 0) {
        return {nullptr, 0};
    }
    char** result = new char* [vec.size()];
    if (result == nullptr) {
        APP_LOGE("VectorToCArrString malloc failed");
        return {nullptr, 0};
    }
    size_t temp = 0;
    for (size_t i = 0; i < vec.size(); i++) {
        result[i] = new char[vec[i].length() + 1];
        if (result[i] == nullptr) {
            break;
        }
        auto res = strcpy_s(result[i], vec[i].length() + 1, vec[i].c_str());
        if (res != EOK) {
            APP_LOGE("failed to strcpy_s.");
        }
        temp++;
    }

    if (temp != vec.size()) {
        for (size_t j = temp; j > 0; j--) {
            delete result[j - 1];
            result[j - 1] = nullptr;
        }
        delete[] result;
        return {nullptr, 0};
    }
    return {result, vec.size()};
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
        res.value = VectorToCArrString(extensionAbilityInfo);
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
        res.value = VectorToCArrString(extensionAbilityInfo);
        APP_LOGI("BundleManager::FfiGetProfileByAbility success");
        return res;
    }

    bool FfiBundleManagerCanOpenLink(char* link, int32_t& code)
    {
        std::string cLink(link);
        return BundleManagerImpl::InnerCanOpenLink(link, code);
    }
}

} // BundleManager
} // CJSystemapi
} // OHOS