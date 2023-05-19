/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <dlfcn.h>

#include "bms_extension_data_mgr.h"
#include "bms_extension_profile.h"
#include "bundle_mgr_ext_register.h"
#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
BmsExtension BmsExtensionDataMgr::bmsExtension;
void* BmsExtensionDataMgr::handler = nullptr;
namespace {
const std::string BMS_EXTENSION_PATH = "/system/etc/app/bms-extensions.json";
}

BmsExtensionDataMgr::BmsExtensionDataMgr()
{
    init();
    APP_LOGI("base bundle installer instance is created");
    auto message = bmsExtension.ToString();
    bool isNullptr = (handler == nullptr);
    APP_LOGD("bms-extension: %{public}s, handler is nullptr: %{public}d", message.c_str(), isNullptr);
}

void BmsExtensionDataMgr::init()
{
    std::lock_guard<std::mutex> stateLock(stateMutex_);
    if (bmsExtension.bmsExtensionBundleMgr.extensionName.empty() || !handler) {
        BmsExtensionProfile bmsExtensionProfile;
        auto res = bmsExtensionProfile.ParseBmsExtension(BMS_EXTENSION_PATH, bmsExtension);
        if (res != ERR_OK) {
            APP_LOGE("ParseBmsExtension failed, errCode is %{public}d", res);
            return;
        }
        APP_LOGD("parse bms-extension.json success, which is: %{public}s", bmsExtension.ToString().c_str());
        if (OpenHandler()) {
            APP_LOGD("dlopen bms-extension so success");
        }
    }
}

bool BmsExtensionDataMgr::OpenHandler()
{
    APP_LOGI("OpenHandler start");
    auto handle = &handler;
    if (handle == nullptr) {
        APP_LOGE("OpenHandler error handle is nullptr.");
        return false;
    }
    auto libPath = bmsExtension.bmsExtensionBundleMgr.libPath.c_str();
    auto lib64Path = bmsExtension.bmsExtensionBundleMgr.lib64Path.c_str();
    *handle = dlopen(lib64Path, RTLD_NOW | RTLD_GLOBAL);
    if (*handle == nullptr) {
        APP_LOGW("failed to open %{public}s, err:%{public}s", lib64Path, dlerror());
        *handle = dlopen(libPath, RTLD_NOW | RTLD_GLOBAL);
    }
    if (*handle == nullptr) {
        APP_LOGE("failed to open %{public}s, err:%{public}s", libPath, dlerror());
        return false;
    }
    APP_LOGI("OpenHandler end");
    return true;
}

bool BmsExtensionDataMgr::CheckApiInfo(const BundleInfo &bundleInfo) const
{
    if (handler) {
        auto bundleMgrExtPtr =
            BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension.bmsExtensionBundleMgr.extensionName);
        return bundleMgrExtPtr->CheckApiInfo(bundleInfo);
    }
    return false;
}
} // AppExecFwk
} // OHOS
