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

#include "patch_data_mgr.h"
#include "app_log_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* QUICK_FIX_ENGINE_PATH = "/data/update/quickfix/app/temp";
}

PatchDataMgr::PatchDataMgr()
{
    APP_LOGI("PatchDataMgr instance is created");
    patchDataStorage_ = std::make_shared<PatchDataStorageRdb>();
}

PatchDataMgr::~PatchDataMgr()
{
    APP_LOGI("PatchDataMgr instance is destroyed");
}

PatchDataMgr& PatchDataMgr::GetInstance()
{
    static PatchDataMgr patchDataMgr;
    return patchDataMgr;
}

bool PatchDataMgr::AddInnerPatchInfo(const std::string &bundleName, const InnerPatchInfo &info)
{
    if (bundleName.empty()) {
        APP_LOGE("AddInnerPatchInfo failed, invalid param");
        return false;
    }
    if (!patchDataStorage_->SaveStoragePatchInfo(bundleName, info)) {
        APP_LOGE("Save InnerPatchInfo failed, bundleName: %{public}s", bundleName.c_str());
        return false;
    }
    return true;
}

bool PatchDataMgr::GetInnerPatchInfo(const std::string &bundleName, InnerPatchInfo &info) const
{
    if (bundleName.empty()) {
        APP_LOGE("GetInnerPatchInfo failed, invalid param");
        return false;
    }
    if (!patchDataStorage_->GetStoragePatchInfo(bundleName, info)) {
        APP_LOGE("Get InnerPatchInfo failed, bundleName: %{public}s", bundleName.c_str());
        return false;
    }
    return true;
}

bool PatchDataMgr::DeleteInnerPatchInfo(const std::string &bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("DeleteInnerPatchInfo failed, invalid param");
        return false;
    }
    if (!patchDataStorage_->DeleteStoragePatchInfo(bundleName)) {
        APP_LOGE("Delete InnerPatchInfo failed, bundleName: %{public}s", bundleName.c_str());
        return false;
    }
    return true;
}

void PatchDataMgr::ProcessPatchInfo(const std::string &bundleName, const std::vector<std::string> &installSources,
    uint32_t versionCode, AppPatchType type, bool isPatch)
{
    if (installSources.empty() || bundleName.empty() || versionCode == 0) {
        APP_LOGE("ProcessPatchInfo failed");
        return;
    }
    std::string installSource = installSources[0];
    InnerPatchInfo innerPatchInfo;
    if (installSource.find(QUICK_FIX_ENGINE_PATH) == 0 || isPatch) {
        APP_LOGI("ProcessPatchInfo, bundleName: %{public}s", bundleName.c_str());
        PatchInfo patchInfo;
        patchInfo.appPatchType = type;
        patchInfo.versionCode = versionCode;
        innerPatchInfo.SetPatchInfo(patchInfo);
        if (!AddInnerPatchInfo(bundleName, innerPatchInfo)) {
            APP_LOGE("AddInnerPatchInfo failed, bundleName: %{public}s", bundleName.c_str());
        }
        return;
    }
    if (!GetInnerPatchInfo(bundleName, innerPatchInfo)) {
        return;
    }
    if (innerPatchInfo.GetVersionCode() >= versionCode) {
        APP_LOGW("patchVersion: %{public}u, newVersion: %{public}u", innerPatchInfo.GetVersionCode(), versionCode);
        return;
    }
    if (!DeleteInnerPatchInfo(bundleName)) {
        APP_LOGE("DeleteInnerPatchInfo failed, bundleName: %{public}s", bundleName.c_str());
        return;
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
