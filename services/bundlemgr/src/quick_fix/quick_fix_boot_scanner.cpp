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

#include "app_log_tag_wrapper.h"
#include "bundle_mgr_service.h"
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
    LOG_I(BMS_TAG_DEFAULT, "start to process quick fix boot up");
    quickFixDataMgr_ = DelayedSingleton<QuickFixDataMgr>::GetInstance();
    if (quickFixDataMgr_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "quickFixDataMgr_ is nullptr");
        return;
    }

    std::map<std::string, InnerAppQuickFix> quickFixInfoMap;
    auto ret = quickFixDataMgr_->QueryAllInnerAppQuickFix(quickFixInfoMap);
    if (!ret || quickFixInfoMap.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "no quick fix info in db");
        RestoreQuickFix();
        return;
    }

    for (const auto &quickFixInfo : quickFixInfoMap) {
        auto quickFixStatus = quickFixInfo.second.GetQuickFixMark().status;
        LOG_D(BMS_TAG_DEFAULT, "quick fix scan bundle %{public}s, status is %{public}d",
            quickFixInfo.first.c_str(), quickFixStatus);
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
            LOG_E(BMS_TAG_DEFAULT, "quick fix info %{public}s is processed failed with error %{public}d",
                quickFixInfo.first.c_str(), res);
            quickFixDataMgr_->DeleteInnerAppQuickFix(quickFixInfo.first);
        }
        state_.reset();
    }
    RemoveInvalidDir();
    LOG_I(BMS_TAG_DEFAULT, "process quick fix boot up completely");
}

void QuickFixBootScanner::SetQuickFixState(const std::shared_ptr<QuickFixState> &state)
{
    state_.reset();
    state_ = state;
}

ErrCode QuickFixBootScanner::ProcessState() const
{
    if (state_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "state_ is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    return state_->Process();
}

void QuickFixBootScanner::RestoreQuickFix()
{
    LOG_I(BMS_TAG_DEFAULT, "start to RestoreQuickFix");
    std::vector<std::string> dirVec;
    if (InstalldClient::GetInstance()->ObtainQuickFixFileDir(Constants::BUNDLE_CODE_DIR, dirVec) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "RestoreQuickFix failed due to obtained quick fix file dir failed");
        return;
    }
    ProcessQuickFixDir(dirVec);

    if (quickFixInfoMap_.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "no quick fix info in quickFixInfoMap_");
        return;
    }
    for (const auto &quickFix : quickFixInfoMap_) {
        ApplicationInfo appInfo;
        // 1. no bundleInfo, then to remove the quick fix file
        if (!GetApplicationInfo(quickFix.first, quickFix.second.second, appInfo)) {
            LOG_W(BMS_TAG_DEFAULT, "appInfo is no existed, the quick info file need to be deleted");
            continue;
        }
        // 2. no quick fix info in appInfo, quick fix need to deploy, switch and delete again
        const auto &qfInfo = appInfo.appQuickFix.deployedAppqfInfo;
        if (qfInfo.hqfInfos.empty()) {
            LOG_D(BMS_TAG_DEFAULT, "no quikc fix info in the appInfo and reprocess the quick fix");
            if (!ReprocessQuickFix(quickFix.second.second, quickFix.first)) {
                LOG_E(BMS_TAG_DEFAULT, "ReprocessQuickFix failed");
            }
            continue;
        }
        // 3. appInfo contain quick fix info, there need to check the quick fix info version with the
        //    quick fix file version code
        LOG_D(BMS_TAG_DEFAULT, "appInfo contains quick fix info");
        int32_t quickFixVersion = qfInfo.versionCode;
        if (!ProcessWithBundleHasQuickFixInfo(quickFix.first, quickFix.second.second, quickFixVersion,
            quickFix.second.first)) {
            LOG_E(BMS_TAG_DEFAULT, "ProcessWithBundleHasQuickFixInfo failed");
        }
    }

    RemoveInvalidDir();
    LOG_I(BMS_TAG_DEFAULT, "calling RestoreQuickFix successfully");
}

void QuickFixBootScanner::ProcessQuickFixDir(const std::vector<std::string> &fileDir)
{
    LOG_I(BMS_TAG_DEFAULT, "start to ObtainQuickFixInfo");
    if (fileDir.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "no quick fix file");
        return;
    }
    for (const auto &fileStr : fileDir) {
        LOG_D(BMS_TAG_DEFAULT, "ObtainQuickFixInfo fileStr is %{public}s", fileStr.c_str());
        size_t underlinePos = fileStr.rfind(Constants::FILE_UNDERLINE);
        if (underlinePos == std::string::npos) {
            LOG_E(BMS_TAG_DEFAULT, "ObtainQuickFixInfo failed due to invalid dir");
            invalidQuickFixDir_.emplace_back(fileStr);
            continue;
        }
        int32_t versionCode;
        bool ret = StrToInt(fileStr.substr(underlinePos + 1), versionCode);
        if (!ret) {
            LOG_E(BMS_TAG_DEFAULT, "ObtainQuickFixInfo failed due to invalid versionCode in dir");
            invalidQuickFixDir_.emplace_back(fileStr);
            continue;
        }
        LOG_D(BMS_TAG_DEFAULT, "versionCode of the quick fix file is %{public}d", versionCode);
        size_t firstPos = fileStr.rfind(ServiceConstants::PATH_SEPARATOR);
        if (firstPos == std::string::npos) {
            LOG_E(BMS_TAG_DEFAULT, "ObtainQuickFixInfo failed due to invalid dir");
            invalidQuickFixDir_.emplace_back(fileStr);
            continue;
        }
        size_t secondPos = fileStr.rfind(ServiceConstants::PATH_SEPARATOR, firstPos - 1);
        if (secondPos == std::string::npos) {
            LOG_E(BMS_TAG_DEFAULT, "ObtainQuickFixInfo failed due to invalid dir");
            invalidQuickFixDir_.emplace_back(fileStr);
            continue;
        }
        std::string bundleName = fileStr.substr(secondPos + 1, firstPos - secondPos - 1);
        LOG_D(BMS_TAG_DEFAULT, "bundleName of the quick fix file is %{public}s", bundleName.c_str());
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
    LOG_D(BMS_TAG_DEFAULT, "start to ReprocessQuickFix with bundleName %{public}s", bundleName.c_str());
    std::string destinationDir = ServiceConstants::HAP_COPY_PATH;
    destinationDir += std::string(ServiceConstants::PATH_SEPARATOR) + ServiceConstants::SECURITY_QUICK_FIX_PATH +
        ServiceConstants::PATH_SEPARATOR + bundleName + ServiceConstants::PATH_SEPARATOR;
    if (!BundleUtil::CreateDir(destinationDir)) {
        LOG_E(BMS_TAG_DEFAULT, "create dir failed");
        return false;
    }
    if (InstalldClient::GetInstance()->CopyFiles(quickFixPath, destinationDir) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "RestoreQuickFix failed due to copy quick fix files failed");
        return false;
    }

    std::vector<std::string> pathVec { destinationDir };
    std::unique_ptr<QuickFixDeployer> deployer = std::make_unique<QuickFixDeployer>(pathVec);
    auto ret = deployer->Execute();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "deploy failed");
        return false;
    }
    std::unique_ptr<IQuickFix> switcher = std::make_unique<QuickFixSwitcher>(bundleName, true);
    ret = switcher->Execute();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "switch failed");
        return false;
    }
    std::unique_ptr<IQuickFix> deleter = std::make_unique<QuickFixDeleter>(bundleName);
    ret = deleter->Execute();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "delete failed");
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
            LOG_E(BMS_TAG_DEFAULT, "dataMgr_ is nullptr");
            return false;
        }
    }
    if (!dataMgr_->GetApplicationInfo(bundleName, ApplicationFlag::GET_BASIC_APPLICATION_INFO, Constants::ANY_USERID,
        info)) {
        LOG_W(BMS_TAG_DEFAULT, "application info is no existed, the quick info file need to be deleted");
        invalidQuickFixDir_.emplace_back(quickFixPath);
        return false;
    }
    return true;
}

bool QuickFixBootScanner::ProcessWithBundleHasQuickFixInfo(const std::string &bundleName, const std::string &hqfPath,
    int32_t quickFixVersion, int32_t fileVersion)
{
    if (quickFixVersion == fileVersion) {
        LOG_D(BMS_TAG_DEFAULT, "same version code between quick fix file and quick fix info");
    } else if (quickFixVersion < fileVersion) {
        if (!ReprocessQuickFix(hqfPath, bundleName)) {
            LOG_E(BMS_TAG_DEFAULT, "ReprocessQuickFix failed");
            return false;
        }
    } else {
        invalidQuickFixDir_.emplace_back(hqfPath);
        // remove the quick fix info from memory cache and db
        InnerBundleInfo innerBundleInfo;
        if ((dataMgr_ == nullptr) || (!dataMgr_->GetInnerBundleInfo(bundleName, innerBundleInfo))) {
            LOG_E(BMS_TAG_DEFAULT, "cannot obtain the innerbundleInfo from data mgr");
            return false;
        }
        AppQuickFix appQuickFix;
        innerBundleInfo.SetAppQuickFix(appQuickFix);
        innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
        dataMgr_->EnableBundle(bundleName);
        if (!dataMgr_->UpdateQuickFixInnerBundleInfo(bundleName, innerBundleInfo)) {
            LOG_E(BMS_TAG_DEFAULT, "update quickfix innerbundleInfo failed");
            return false;
        }
        LOG_I(BMS_TAG_DEFAULT, "invalid the quick fix file dir and quick fix info needs to be remove");
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
    std::string hapcopypathstring = std::string(ServiceConstants::HAP_COPY_PATH);
    std::string tempInstallDir = hapcopypathstring + ServiceConstants::PATH_SEPARATOR
        + ServiceConstants::STREAM_INSTALL_PATH;
    std::string tempQuickFixDir = hapcopypathstring + ServiceConstants::PATH_SEPARATOR
        + ServiceConstants::QUICK_FIX_PATH;
    std::string tempSecureInstallDir = hapcopypathstring + ServiceConstants::PATH_SEPARATOR +
        ServiceConstants::SECURITY_STREAM_INSTALL_PATH;
    std::string tempSecureQuickFixDir = hapcopypathstring + ServiceConstants::PATH_SEPARATOR +
        ServiceConstants::SECURITY_QUICK_FIX_PATH;
    std::string tempSignatureFileDir = hapcopypathstring + ServiceConstants::PATH_SEPARATOR +
        ServiceConstants::SIGNATURE_FILE_PATH;
    std::string tempSecureSignatureFileDir = hapcopypathstring+ ServiceConstants::PATH_SEPARATOR +
        ServiceConstants::SECURITY_SIGNATURE_FILE_PATH;
    BundleUtil::DeleteDir(tempInstallDir);
    BundleUtil::DeleteDir(tempQuickFixDir);
    BundleUtil::DeleteDir(tempSecureInstallDir);
    BundleUtil::DeleteDir(tempSecureQuickFixDir);
    BundleUtil::DeleteDir(tempSignatureFileDir);
    BundleUtil::DeleteDir(tempSecureSignatureFileDir);
}
} // AppExecFwk
} // OHOS