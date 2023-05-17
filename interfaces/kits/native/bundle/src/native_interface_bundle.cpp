/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "native_interface_bundle.h"

#include <mutex>
#include <string>

#include "application_info.h"
#include "bundle_info.h"
#include "app_log_wrapper.h"
#include "bundle_mgr_proxy_native.h"
#include "ipc_skeleton.h"
#include "securec.h"
namespace {
    const size_t CHAR_MAX_LENGTH = 10240;
}

OH_NativeBundle_ApplicationInfo OH_NativeBundle_GetCurrentApplicationInfo()
{
    OH_NativeBundle_ApplicationInfo nativeApplicationInfo;
    OHOS::AppExecFwk::BundleMgrProxyNative bundleMgrProxyNative;
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    auto bundleInfoFlag = static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);

    if (!bundleMgrProxyNative.GetBundleInfoForSelf(bundleInfoFlag, bundleInfo)) {
        APP_LOGE("can not get bundleInfo for self");
        return nativeApplicationInfo;
    };
    OHOS::AppExecFwk::ApplicationInfo applicationInfo = bundleInfo.applicationInfo;

    size_t bundleNameLen = applicationInfo.bundleName.size();
    if ((bundleNameLen == 0) || (bundleNameLen + 1) > CHAR_MAX_LENGTH) {
        APP_LOGE("failed due to the length of bundleName is 0 or to long");
        return nativeApplicationInfo;
    }
    nativeApplicationInfo.bundleName = static_cast<char*>(malloc(bundleNameLen + 1));
    if (nativeApplicationInfo.bundleName == nullptr) {
        APP_LOGE("failed due to malloc error");
        return nativeApplicationInfo;
    }

    if (strcpy_s(nativeApplicationInfo.bundleName, bundleNameLen + 1, applicationInfo.bundleName.c_str()) != EOK) {
        APP_LOGE("failed due to strcpy_s error");
        free(nativeApplicationInfo.bundleName);
        nativeApplicationInfo.bundleName = nullptr;
        return nativeApplicationInfo;
    }

    size_t fingerprintLen = applicationInfo.fingerprint.size();
    if ((fingerprintLen == 0) || (fingerprintLen + 1) > CHAR_MAX_LENGTH) {
        APP_LOGE("failed due to the length of fingerprint is 0 or to long");
        free(nativeApplicationInfo.bundleName);
        nativeApplicationInfo.bundleName = nullptr;
        return nativeApplicationInfo;
    }
    nativeApplicationInfo.fingerprint = static_cast<char*>(malloc(fingerprintLen + 1));
    if (nativeApplicationInfo.fingerprint == nullptr) {
        APP_LOGE("failed due to malloc error");
        free(nativeApplicationInfo.bundleName);
        nativeApplicationInfo.bundleName = nullptr;
        return nativeApplicationInfo;
    }

    if (strcpy_s(nativeApplicationInfo.fingerprint, fingerprintLen + 1, applicationInfo.fingerprint.c_str()) != EOK) {
        APP_LOGE("failed due to strcpy_s error");
        free(nativeApplicationInfo.bundleName);
        nativeApplicationInfo.bundleName = nullptr;
        free(nativeApplicationInfo.fingerprint);
        nativeApplicationInfo.fingerprint = nullptr;
        return nativeApplicationInfo;
    }
    APP_LOGI("OH_NativeBundle_GetCurrentApplicationInfo success");
    return nativeApplicationInfo;
}
