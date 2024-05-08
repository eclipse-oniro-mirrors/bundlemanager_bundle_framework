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
#include "bundle_manager_log.h"
#include "cj_common_ffi.h"
#include "bundle_manager_utils.h"
#include "bundle_manager.h"
#include "bundle_info.h"
#include "ipc_skeleton.h"
#include "bundle_manager_convert.h"

using namespace OHOS::CJSystemapi::BundleManager::Convert;
using namespace OHOS::CJSystemapi::BundleManager;


namespace OHOS {
namespace CJSystemapi {
namespace BundleManager {

std::vector<std::string> g_charPtrToVector(char** charPtr, int32_t size)
{
    std::vector<std::string> result;
    for (int32_t i = 0; i < size; i++) {
        result.push_back(std::string(charPtr[i]));
    }
    return result;
}

CArrString g_vectorToCArrString(std::vector<std::string> &vec)
{
    char** result = new char* [vec.size()];
    for (size_t i = 0; i < vec.size(); i++) {
        result[i] = new char[vec[i].length() + 1];
        auto res = strcpy_s(result[i], vec[i].length() + 1, vec[i].c_str());
        if (res != EOK) {
            LOGE("failed to strcpy_s.")
        }
    }
    return {result, vec.size()};
}

extern "C" {
    RetBundleInfo FfiOHOSGetBundleInfoForSelf(int32_t bundleFlags)
    {
        LOGI("BundleManager::FfiOHOSGetBundleInfoForSelf");
        AppExecFwk::BundleInfo bundleInfo = BundleManagerImpl::GetBundleInfoForSelf(bundleFlags);
        RetBundleInfo cjInfo = ConvertBundleInfo(bundleInfo, bundleFlags);
        LOGI("BundleManager::FfiOHOSGetBundleInfoForSelf success");
        return cjInfo;
    }
 
    int32_t FfiOHOSVerifyAbc(CArrString cAbcPaths, bool deleteOriginalFiles)
    {
        LOGI("BundleManager::FfiOHOSVerifyAbc");
        std::vector<std::string> abcPaths = g_charPtrToVector(cAbcPaths.head, cAbcPaths.size);
        auto code = BundleManagerImpl::VerifyAbc(abcPaths, deleteOriginalFiles);
        if (code != 0) {
            LOGI("FfiOHOSVerifyAbc failed, code is %{public}d", code);
            return code;
        }
        LOGI("BundleManager::FfiOHOSVerifyAbc success");
        return code;
    }

    RetCArrString FfiGetProfileByExtensionAbility(char* moduleName, char* extensionAbilityName, char* metadataName)
    {
        LOGI("BundleManager::FfiGetProfileByExtensionAbility");
        RetCArrString res = { .code = -1, .value = {}};
        auto [status, extensionAbilityInfo] = BundleManagerImpl::GetProfileByExtensionAbility(
            std::string(moduleName), std::string(extensionAbilityName), metadataName);
        if (status != 0) {
            LOGI("FfiGetProfileByExtensionAbility failed, code is %{public}d", status);
            return {status, {}};
        }
        res.code = SUCCESS_CODE;
        res.value = g_vectorToCArrString(extensionAbilityInfo);
        LOGI("BundleManager::FfiGetProfileByExtensionAbility success");
        return res;
    }

    RetCArrString FfiGetProfileByAbility(char* moduleName, char* extensionAbilityName, char* metadataName)
    {
        LOGI("BundleManager::FfiGetProfileByAbility");
        RetCArrString res = { .code = -1, .value = {}};
        auto [status, extensionAbilityInfo] = BundleManagerImpl::GetProfileByAbility(
            std::string(moduleName), std::string(extensionAbilityName), metadataName);
        if (status != 0) {
            LOGI("FfiGetProfileByAbility failed, code is %{public}d", status);
            return {status, {}};
        }
        res.code = SUCCESS_CODE;
        res.value = g_vectorToCArrString(extensionAbilityInfo);
        LOGI("BundleManager::FfiGetProfileByAbility success");
        return res;
    }
}

} // BundleManager
} // CJSystemapi
} // OHOS