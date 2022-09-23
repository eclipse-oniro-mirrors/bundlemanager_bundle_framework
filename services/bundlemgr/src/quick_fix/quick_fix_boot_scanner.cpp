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

#include "quick_fix_boot_scanner.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "bundle_mgr_service.h"
#include "bundle_util.h"
#include "inner_app_quick_fix.h"
#include "inner_bundle_info.h"
#include "installd_client.h"
#include "quick_fix_deleter.h"
#include "quick_fix_delete_state.h"
#include "quick_fix_deployer.h"
#include "quick_fix_deploy_state.h"
#include "quick_fix_switcher.h"
#include "quick_fix_switch_state.h"

namespace OHOS {
namespace AppExecFwk {
void QuickFixBootScanner::ProcessQuickFixBootUp()
{
    APP_LOGI("start to process quick fix boot up");
    quickFixDataMgr_ = DelayedSingleton<QuickFixDataMgr>::GetInstance();
    if (quickFixDataMgr_ == nullptr) {
        APP_LOGE("quickFixDataMgr_ is nullptr");
        return;
    }

    std::map<std::string, InnerAppQuickFix> quickFixInfoMap;
    auto ret = quickFixDataMgr_->QueryAllInnerAppQuickFix(quickFixInfoMap);
    if (!ret || quickFixInfoMap.empty()) {
        APP_LOGW("no quick fix info in db");
        RestoreQuickFix();
        return;
    }

    for (const auto &quickFixInfo : quickFixInfoMap) {
        auto quickFixStatus = quickFixInfo.second.GetQuickFixMark().status;
        APP_LOGD("quick fix scan bundle %{public}s, status is %{public}d", quickFixInfo.first.c_str(), quickFixStatus);
        if ((quickFixStatus == QuickFixStatus::DEFAULT_STATUS) || (quickFixStatus == QuickFixStatus::DELETE_END) ||
            (quickFixStatus == QuickFixStatus::SWITCH_END) || (quickFixStatus== QuickFixStatus::DELETE_START)) {
            state_ = std::make_shared<QuickFixDeleteState>(quickFixInfo.first);
        }
        if (quickFixStatus == QuickFixStatus::DEPLOY_START) {
            state_ = std::make_shared<QuickFixDeployState>(quickFixInfo.second);
        }
        if ((quickFixStatus == QuickFixStatus::DEPLOY_END) || (quickFixStatus == QuickFixStatus::SWITCH_ENABLE_START)) {
            state_ = std::make_shared<QuickFixSwitchState>(quickFixInfo.first, true);
        }
        if (quickFixStatus == QuickFixStatus::SWITCH_DISABLE_START) {
            state_ = std::make_shared<QuickFixSwitchState>(quickFixInfo.first, false);
        }
        auto res = ProcessState();
        if (res != ERR_OK) {
            APP_LOGE("quick fix info %{public}s is processed failed with error %{public}d",
                quickFixInfo.first.c_str(), res);
            quickFixDataMgr_->DeleteInnerAppQuickFix(quickFixInfo.first);
        }
        state_.reset();
    }
    RemoveInvalidDir();
    APP_LOGI("process quick fix boot up completely");
}

void QuickFixBootScanner::SetQuickFixState(const std::shared_ptr<QuickFixState> &state)
{
    state_.reset();
    state_ = state;
}

ErrCode QuickFixBootScanner::ProcessState() const
{
    if (state_ == nullptr) {
        APP_LOGE("state_ is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    return state_->Process();
}

void QuickFixBootScanner::RestoreQuickFix()
{
    APP_LOGI("start to RestoreQuickFix");
    std::vector<std::string> dirVec;
    if (InstalldClient::GetInstance()->ObtainQuickFixFileDir(Constants::BUNDLE_CODE_DIR, dirVec) != ERR_OK) {
        APP_LOGE("RestoreQuickFix failed due to obtained quick fix file dir failed");
        return;
    }
    ProcessQuickFixDir(dirVec);

    if (quickFixInfoMap_.empty()) {
        APP_LOGW("no quick fix info in quickFixInfoMap_");
        return;
    }
    for (const auto &quickFix : quickFixInfoMap_) {
        ApplicationInfo appInfo;
        // 1. no bundleInfo, then to remove the quick fix file
        if (!GetApplicationInfo(quickFix.first, quickFix.second.second, appInfo)) {
            APP_LOGW("appInfo is no existed, the quick info file need to be deleted");
            continue;
        }
        // 2. no quick fix info in appInfo, quick fix need to deploy, switch and delete again
        const auto &qfInfo = appInfo.appQuickFix.deployedAppqfInfo;
        if (qfInfo.hqfInfos.empty()) {
            APP_LOGD("no quikc fix info in the appInfo and reprocess the quick fix");
            if (!ReprocessQuickFix(quickFix.second.second, quickFix.first)) {
                APP_LOGE("ReprocessQuickFix failed");
            }
            continue;
        }
        // 3. appInfo contain quick fix info, there need to check the quick fix info version with the
        //    quick fix file version code
        APP_LOGD("appInfo contains quick fix info");
        int32_t quickFixVersion = qfInfo.versionCode;
        if (!ProcessWithBundleHasQuickFixInfo(quickFix.first, quickFix.second.second, quickFixVersion,
            quickFix.second.first)) {
            APP_LOGE("ProcessWithBundleHasQuickFixInfo failed");
        }
    }

    RemoveInvalidDir();
    APP_LOGI("calling RestoreQuickFix successfully");
}

void QuickFixBootScanner::ProcessQuickFixDir(const std::vector<std::string> &fileDir)
{
    APP_LOGI("start to ObtainQuickFixInfo");
    if (fileDir.empty()) {
        APP_LOGW("no quick fix file");
        return;
    }
    for (const auto &fileStr : fileDir) {
        APP_LOGD("ObtainQuickFixInfo fileStr is %{public}s", fileStr.c_str());
        size_t underlinePos = fileStr.rfind(Constants::FILE_UNDERLINE);
        if (underlinePos == std::string::npos) {
            APP_LOGE("ObtainQuickFixInfo failed due to invalid dir");
            invalidQuickFixDir_.emplace_back(fileStr);
            continue;
        }
        int32_t versionCode;
        bool ret = StrToInt(fileStr.substr(underlinePos + 1), versionCode);
        if (!ret) {
            APP_LOGE("ObtainQuickFixInfo failed due to invalid versionCode in dir");
            invalidQuickFixDir_.emplace_back(fileStr);
            continue;
        }
        APP_LOGD("versionCode of the quick fix file is %{public}d", versionCode);
        size_t firstPos = fileStr.rfind(Constants::PATH_SEPARATOR);
        if (firstPos == std::string::npos) {
            APP_LOGE("ObtainQuickFixInfo failed due to invalid dir");
            invalidQuickFixDir_.emplace_back(fileStr);
            continue;
        }
        size_t secondPos = fileStr.rfind(Constants::PATH_SEPARATOR, firstPos - 1);
        if (secondPos == std::string::npos) {
            APP_LOGE("ObtainQuickFixInfo failed due to invalid dir");
            invalidQuickFixDir_.emplace_back(fileStr);
            continue;
        }
        std::string bundleName = fileStr.substr(secondPos + 1, firstPos - secondPos - 1);
        APP_LOGD("bundleName of the quick fix file is %{public}s", bundleName.c_str());
        auto bundleIter = quickFixInfoMap_.find(bundleName);
        if (bundleIter == quickFixInfoMap_.end()) {
            std::pair<int32_t, std::string> innerPair { versionCode, fileStr };
            quickFixInfoMap_.emplace(bundleName, innerPair);
            continue;
        }
        if (bundleIter->second.first < versionCode) {
            invalidQuickFixDir_.emplace_back(bundleIter->second.second);
            quickFixInfoMap_[bundleName] = { versionCode, fileStr };
        }
    }
    return;
}

bool QuickFixBootScanner::ReprocessQuickFix(const std::string &quickFixPath, const std::string &bundleName) const
{
    APP_LOGD("start to ReprocessQuickFix with bundleName %{public}s", bundleName.c_str());
    std::string destinationDir = Constants::HAP_COPY_PATH;
    destinationDir += Constants::PATH_SEPARATOR + Constants::QUICK_FIX_PATH + Constants::TMP_SUFFIX;
    if (!BundleUtil::CreateDir(destinationDir)) {
        APP_LOGE("create dir failed");
        return false;
    }
    if (InstalldClient::GetInstance()->CopyFiles(quickFixPath, destinationDir) != ERR_OK) {
        APP_LOGE("RestoreQuickFix failed due to copy quick fix files failed");
        return false;
    }

    std::vector<std::string> pathVec { destinationDir };
    std::unique_ptr<QuickFixDeployer> deployer = std::make_unique<QuickFixDeployer>(pathVec);
    auto ret = deployer->Execute();
    if (ret != ERR_OK) {
        APP_LOGE("deploy failed");
        return false;
    }
    std::unique_ptr<IQuickFix> switcher = std::make_unique<QuickFixSwitcher>(bundleName, true);
    ret = switcher->Execute();
    if (ret != ERR_OK) {
        APP_LOGE("switch failed");
        return false;
    }
    std::unique_ptr<IQuickFix> deleter = std::make_unique<QuickFixDeleter>(bundleName);
    ret = deleter->Execute();
    if (ret != ERR_OK) {
        APP_LOGE("delete failed");
        return false;
    }
    return true;
}

bool QuickFixBootScanner::GetApplicationInfo(const std::string &bundleName, const std::string &quickFixPath,
    ApplicationInfo &info)
{
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            APP_LOGE("dataMgr_ is nullptr");
            return false;
        }
    }
    if (!dataMgr_->GetApplicationInfo(bundleName, ApplicationFlag::GET_BASIC_APPLICATION_INFO, Constants::ANY_USERID,
        info)) {
        APP_LOGW("application info is no existed, the quick info file need to be deleted");
        invalidQuickFixDir_.emplace_back(quickFixPath);
        return false;
    }
    return true;
}

bool QuickFixBootScanner::ProcessWithBundleHasQuickFixInfo(const std::string &bundleName, const std::string &hqfPath,
    int32_t quickFixVersion, int32_t fileVersion)
{
    if (quickFixVersion == fileVersion) {
        APP_LOGD("same version code between quick fix file and quick fix info");
    } else if (quickFixVersion < fileVersion) {
        if (!ReprocessQuickFix(hqfPath, bundleName)) {
            APP_LOGE("ReprocessQuickFix failed");
            return false;
        }
    } else {
        invalidQuickFixDir_.emplace_back(hqfPath);
        // remove the quick fix info from memory cache and db
        InnerBundleInfo innerBundleInfo;
        if ((dataMgr_ == nullptr) || (!dataMgr_->GetInnerBundleInfo(bundleName, innerBundleInfo))) {
            APP_LOGE("cannot obtain the innerbundleInfo from data mgr");
            return false;
        }
        AppQuickFix appQuickFix;
        innerBundleInfo.SetAppQuickFix(appQuickFix);
        innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
        dataMgr_->EnableBundle(bundleName);
        if (!dataMgr_->UpdateQuickFixInnerBundleInfo(bundleName, innerBundleInfo)) {
            APP_LOGE("update quickfix innerbundleInfo failed");
            return false;
        }
        APP_LOGI("invalid the quick fix file dir and quick fix info needs to be remove");
    }
    return true;
}

void QuickFixBootScanner::RemoveInvalidDir() const
{
    // remove invalid dir under install dir
    if (!invalidQuickFixDir_.empty()) {
        for_each(invalidQuickFixDir_.begin(), invalidQuickFixDir_.end(), [](const auto &dir) {
            InstalldClient::GetInstance()->RemoveDir(dir);
        });
    }
    // remove invalid temp install dir
    std::string tempInstallDir = Constants::HAP_COPY_PATH + Constants::PATH_SEPARATOR + Constants::STREAM_INSTALL_PATH;
    std::string tempQuickFixDir = Constants::HAP_COPY_PATH + Constants::PATH_SEPARATOR + Constants::QUICK_FIX_PATH;
    BundleUtil::DeleteDir(tempInstallDir);
    BundleUtil::DeleteDir(tempQuickFixDir);
}
} // AppExecFwk
} // OHOS