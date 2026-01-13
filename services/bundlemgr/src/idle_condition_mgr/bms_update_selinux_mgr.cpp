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

#include <atomic>
#include <mutex>
#include <shared_mutex>

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "bms_update_selinux_mgr.h"
#include "bundle_mgr_service.h"
#include "inner_bundle_clone_common.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::vector<std::string> BUNDLE_DATA_PATHS_EL1_EL4 = {
    "/data/app/el1/%/base/%",
    "/data/app/el1/%/database/%",
    "/data/app/el2/%/base/%",
    "/data/app/el2/%/database/%",
    "/data/app/el2/%/sharefiles/%",
    "/data/app/el3/%/base/%",
    "/data/app/el3/%/database/%",
    "/data/app/el4/%/base/%",
    "/data/app/el4/%/database/%",
    "/data/service/el1/%/backup/bundles/%",
    "/data/service/el2/%/backup/bundles/%"
};
const std::vector<std::string> BUNDLE_DATA_PATHS_EL5 = {
    "/data/app/el5/%/base/%",
    "/data/app/el5/%/database/%"
};
}
BmsUpdateSelinuxMgr::BmsUpdateSelinuxMgr()
{
    idleManagerRdb_ = std::make_shared<IdleManagerRdb>();
}

BmsUpdateSelinuxMgr::~BmsUpdateSelinuxMgr()
{
}

ErrCode BmsUpdateSelinuxMgr::StartUpdateSelinuxLabel(const int32_t userId)
{
    APP_LOGI("start update selinux label -u %{public}d", userId);
    needStop_.store(false);
    std::vector<BundleOptionInfo> bundleOptionInfos;
    ErrCode ret = idleManagerRdb_->GetAllBundle(userId, bundleOptionInfos);
    if (ret != ERR_OK) {
        APP_LOGE("rdb get all faild -u %{public}d -err %{public}d", userId, ret);
        return ret;
    }
    if (bundleOptionInfos.empty()) {
        APP_LOGI("no bundles in rdb -u %{public}d", userId);
        return ERR_OK;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    CreateDirParam dirParam;
    dirParam.remainingNum = static_cast<uint32_t>(bundleOptionInfos.size());
    for (const auto &bundleOption : bundleOptionInfos) {
        if (needStop_.load()) {
            APP_LOGW("-u %{public}d need stop running", bundleOption.userId);
            return ERR_OK;
        }
        if (dataMgr->GetCreateDirParamByBundleOption(bundleOption, dirParam) != ERR_OK) {
            APP_LOGW("-n %{public}s -u %{public}d -i %{public}d not exist", bundleOption.bundleName.c_str(),
                bundleOption.userId, bundleOption.appIndex);
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(createDirParamMutex_);
            createDirParam_ = dirParam;
        }
        APP_LOGI("start -n %{public}s -u %{public}d -i %{public}d", bundleOption.bundleName.c_str(),
            bundleOption.userId, bundleOption.appIndex);
        auto ret = InstalldClient::GetInstance()->SetFileConForce(GetBundleDataPath(bundleOption.bundleName,
            bundleOption.userId, bundleOption.appIndex, dirParam.isContainsEl5Dir), dirParam);
        if (ret != ERR_OK) {
            APP_LOGW("-n %{public}s -u %{public}d -i %{public}d set failed -err %{public}d",
                bundleOption.bundleName.c_str(), bundleOption.userId, bundleOption.appIndex, ret);
        } else {
            ret = idleManagerRdb_->DeleteBundle(bundleOption);
            if (ret != ERR_OK) {
                APP_LOGW("-n %{public}s -u %{public}d -i %{public}d delete failed -err %{public}d",
                    bundleOption.bundleName.c_str(), bundleOption.userId, bundleOption.appIndex, ret);
            }
            dirParam.remainingNum--;
        }
    }
    return ERR_OK;
}

ErrCode BmsUpdateSelinuxMgr::StopUpdateSelinuxLabel(const int32_t reason, const std::string stopReason)
{
    APP_LOGI("stop update selinux label -r %{public}d -n %{public}s", reason, createDirParam_.bundleName.c_str());
    if (needStop_.load()) {
        APP_LOGI("already stoped -r %{public}d", reason);
        return ERR_OK;
    }
    needStop_.store(true);
    std::lock_guard<std::mutex> lock(createDirParamMutex_);
    createDirParam_.stopReason = stopReason;
    auto ret = InstalldClient::GetInstance()->StopSetFileCon(createDirParam_, reason);
    if (ret != ERR_OK) {
        APP_LOGE("stop update selinux label -r %{public}d failed err:%{public}d", reason, ret);
    }
    return ret;
}

std::vector<std::string> BmsUpdateSelinuxMgr::GetBundleDataPath(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex, const bool isContainsEl5Dir)
{
    std::string pathName = bundleName;
    if (appIndex != 0) {
        pathName = BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
    }
    std::vector<std::string> bundlePaths;
    for (auto path : BUNDLE_DATA_PATHS_EL1_EL4) {
        path = path.replace(path.find('%'), 1, std::to_string(userId));
        path = path.replace(path.find('%'), 1, pathName);
        bundlePaths.emplace_back(path);
    }
    if (isContainsEl5Dir) {
        for (auto path : BUNDLE_DATA_PATHS_EL5) {
            path = path.replace(path.find('%'), 1, std::to_string(userId));
            path = path.replace(path.find('%'), 1, pathName);
            bundlePaths.emplace_back(path);
        }
    }
    return bundlePaths;
}

ErrCode BmsUpdateSelinuxMgr::AddBundles(const std::vector<BundleOptionInfo> &bundleOptionInfos)
{
    if (bundleOptionInfos.empty()) {
        APP_LOGE("bundleOptionInfos is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    return idleManagerRdb_->AddBundles(bundleOptionInfos);
}

ErrCode BmsUpdateSelinuxMgr::DeleteBundle(const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    BundleOptionInfo bundleOptionInfo;
    bundleOptionInfo.bundleName = bundleName;
    bundleOptionInfo.userId = userId;
    bundleOptionInfo.appIndex = appIndex;
    return idleManagerRdb_->DeleteBundle(bundleOptionInfo);
}
} // namespace AppExecFwk
} // namespace OHOS
