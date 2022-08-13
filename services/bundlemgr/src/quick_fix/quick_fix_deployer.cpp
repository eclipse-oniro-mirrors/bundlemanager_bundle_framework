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

#include "quick_fix_deployer.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_util.h"
#include "installd_client.h"
#include "patch_extractor.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixDeployer::QuickFixDeployer(const std::vector<std::string> &bundleFilePaths,
    std::shared_ptr<QuickFixDataMgr> &quickFixDataMgr) : patchPaths_(bundleFilePaths), quickFixDataMgr_(quickFixDataMgr)
{}

ErrCode QuickFixDeployer::Execute()
{
    return DeployQuickFix();
}

ErrCode QuickFixDeployer::DeployQuickFix()
{
    if (patchPaths_.empty() || (quickFixDataMgr_ == nullptr)) {
        APP_LOGE("DeployQuickFix wrong parms");
        return ERR_APPEXECFWK_QUICK_FIX_PARAM_ERROR;
    }

    std::vector<std::string> realFilePaths;
    ErrCode ret = BundleUtil::CheckFilePath(patchPaths_, realFilePaths);
    if (ret != ERR_OK) {
        return ret;
    }
    ScopeGuard guardRemovePath([realFilePaths] {
        for (const auto &path: realFilePaths) {
            std::string tempPath = path.substr(0, path.rfind(Constants::PATH_SEPARATOR));
            if (InstalldClient::GetInstance()->RemoveDir(tempPath) != ERR_OK) {
                APP_LOGE("RemovePatchFile failed path: %{private}s", tempPath.c_str());
            }
        }
    });
    // 1. parse check multi hqf files, update status DEPLOY_START
    InnerAppQuickFix newInnerAppQuickFix;
    InnerAppQuickFix oldInnerAppQuickFix;
    ret = ToDeployStartStatus(realFilePaths, newInnerAppQuickFix, oldInnerAppQuickFix);
    if (ret != ERR_OK) {
        return ret;
    }
    // 2. extract diff files, apply diff patch and copy hqf, update status DEPLOY_END
    ret = ToDeployEndStatus(newInnerAppQuickFix, oldInnerAppQuickFix);
    if (ret != ERR_OK) {
        bool isExist = oldInnerAppQuickFix.GetAppQuickFix().bundleName.empty();
        if (isExist) {
            quickFixDataMgr_->SaveInnerAppQuickFix(oldInnerAppQuickFix);
        } else {
            quickFixDataMgr_->DeleteInnerAppQuickFix(newInnerAppQuickFix.GetAppQuickFix().bundleName);
        }
        return ret;
    }
    // 3. callback
    // 4. remove old deploying patch_versionCode
    const AppQuickFix &appQuick = oldInnerAppQuickFix.GetAppQuickFix();
    if (!appQuick.bundleName.empty()) {
        std::string oldPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR +
            appQuick.bundleName + Constants::PATH_SEPARATOR + Constants::PATCH_PATH +
            std::to_string(appQuick.deployingAppqfInfo.versionCode);
        if (InstalldClient::GetInstance()->RemoveDir(oldPath)) {
            APP_LOGE("delete %{private}s failed", oldPath.c_str());
        }
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToDeployStartStatus(const std::vector<std::string> &bundleFilePaths,
    InnerAppQuickFix &newInnerAppQuickFix, InnerAppQuickFix &oldInnerAppQuickFix)
{
    APP_LOGD("ToDeployStartStatus start.");
    if (quickFixDataMgr_ == nullptr) {
        return ERR_APPEXECFWK_QUICK_FIX_INTERNAL_ERROR;
    }
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    std::unordered_map<std::string, AppQuickFix> infos;
    // 1.parse and check multi app quick fix info
    ErrCode ret = ParseAndCheckAppQuickFixInfos(bundleFilePaths, hapVerifyRes, infos);
    if (ret != ERR_OK) {
        return ret;
    }
    std::string &bundleName = infos.begin()->second.bundleName;
    bool isExist = quickFixDataMgr_->QueryInnerAppQuickFix(bundleName, oldInnerAppQuickFix);
    // 2. check current app quick fix version code
    ret = isExist ? CheckPatchVersionCode(infos.begin()->second, oldInnerAppQuickFix.GetAppQuickFix()) : ERR_OK;
    if (ret != ERR_OK) {
        return ret;
    }
    // 3. check with installed bundle
    BundleInfo bundleInfo;
    ret = CheckAppQuickFixInfosWithInstalledBundle(infos, hapVerifyRes, bundleInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    // 4. convert to InnerAppQuickFix
    ret = ToInnerAppQuickFix(infos, oldInnerAppQuickFix, newInnerAppQuickFix);
    if (ret != ERR_OK) {
        return ret;
    }
    // 5. save infos and update status DEPLOY_START
    ret = SaveAppQuickFix(newInnerAppQuickFix);
    if (ret != ERR_OK) {
        return ret;
    }
    APP_LOGD("ToDeployStartStatus end.");
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToDeployEndStatus(InnerAppQuickFix &newInnerAppQuickFix,
    const InnerAppQuickFix &oldInnerAppQuickFix)
{
    APP_LOGD("ToDeployEndStatus start.");
    if (quickFixDataMgr_ == nullptr) {
        return ERR_APPEXECFWK_QUICK_FIX_INTERNAL_ERROR;
    }
    // create patch path
    AppQuickFix newQuickFix = newInnerAppQuickFix.GetAppQuickFix();
    std::string newPatchPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + newQuickFix.bundleName +
        Constants::PATH_SEPARATOR;
    if (newQuickFix.deployingAppqfInfo.type == QuickFixType::PATCH) {
        newPatchPath += Constants::PATCH_PATH + std::to_string(newQuickFix.deployingAppqfInfo.versionCode);
    } else
        newPatchPath += Constants::HOT_RELOAD_PATH + std::to_string(newQuickFix.deployingAppqfInfo.versionCode);
    }
    ErrCode ret = InstalldClient::GetInstance()->CreateBundleDir(newPatchPath);
    if (ret != ERR_OK) {
        return ret;
    }
    ScopeGuard guardRemovePatchPath([newPatchPath] {
        InstalldClient::GetInstance()->RemoveDir(newPatchPath);
    });
    if (newQuickFix.deployingAppqfInfo.type == QuickFixType::PATCH) {
        // 1. extract diff so, diff so path
        std::string diffFilePath = Constants::HAP_COPY_PATH + Constants::PATH_SEPARATOR +
            newQuickFix.bundleName + Constants::TMP_SUFFIX;
        ScopeGuard guardRemoveDiffPath([diffFilePath] { InstalldClient::GetInstance()->RemoveDir(diffFilePath); });
        ret = ExtractDiffFiles(diffFilePath, newQuickFix.deployingAppqfInfo);
        if (ret != ERR_OK) {
            return ret;
        }
        // 2. apply diff patch
        ret = ApplyDiffPatch(newQuickFix.bundleName, newQuickFix.deployingAppqfInfo.nativeLibraryPath,
            diffFilePath, newPatchPath);
        if (ret != ERR_OK) {
            return ret;
        }
    }
    // 3. move hqf files to new patch path
    ret = MoveHqfFiles(newInnerAppQuickFix, newPatchPath);
    if (ret != ERR_OK) {
        return ret;
    }
    // 4. save and update status DEPLOY_END
    ret = SaveAppQuickFix(newInnerAppQuickFix);
    if (ret != ERR_OK) {
        return ret;
    }
    guardRemovePatchPath.Dismiss();
    APP_LOGD("ToDeployEndStatus end.");
    return ERR_OK;
}

ErrCode QuickFixDeployer::ParseAndCheckAppQuickFixInfos(
    const std::vector<std::string> &bundleFilePaths,
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes,
    std::unordered_map<std::string, AppQuickFix> &infos)
{
    QuickFixChecker checker;
    // parse hqf file to AppQuickFix
    ErrCode ret = checker.ParseAppQuickFixFiles(bundleFilePaths, infos);
    if ((ret != ERR_OK) || infos.empty()) {
        APP_LOGE("QuickFixDeployer::ParseAppQuickFixInfos parse AppQuickFixFiles failed");
        return ret;
    }
    // check multiple AppQuickFix
    ret = checker.CheckAppQuickFixInfos(infos);
    if (ret != ERR_OK) {
        APP_LOGE("QuickFixDeployer check AppQuickFixInfos failed");
        return ret;
    }
    const QuickFixType &quickFixType = infos.begin()->second.deployingAppqfInfo.type;
    if (quickFixType == QuickFixType::UNKNOWN) {
        APP_LOGE("error unknown quick fix type");
        return ERR_APPEXECFWK_QUICK_FIX_UNKNOWN_QUICK_FIX_TYPE;
    }
    // hqf file path
    for (auto iter = infos.begin(); iter != infos.end(); ++iter) {
        if (!iter->second.deployingAppqfInfo.hqfInfos.empty()) {
            iter->second.deployingAppqfInfo.hqfInfos[0].hapFilePath = iter->first;
        } else {
            return ERR_APPEXECFWK_QUICK_FIX_PROFILE_PARSE_FAILED;
        }
    }
    // hot reload does not require signature verification and so files
    if (quickFixType == QuickFixType::HOT_RELOAD) {
        return ERR_OK;
    }
    // check multiple native so
    ret = checker.CheckMultiNativeSo(infos);
    if (ret != ERR_OK) {
        APP_LOGE("QuickFixDeployer check native so with installed bundle failed");
        return ret;
    }
    // parse signature info
    ret = checker.CheckMultipleHapsSignInfo(bundleFilePaths, hapVerifyRes);
    if (ret != ERR_OK) {
        APP_LOGE("QuickFixDeployer::ParseAppQuickFixInfos check multiple hqf sign info failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::CheckAppQuickFixInfosWithInstalledBundle(
    const std::unordered_map<std::string, AppQuickFix> &infos,
    const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes,
    BundleInfo &bundleInfo)
{
    if (infos.empty()) {
        return ERR_APPEXECFWK_QUICK_FIX_INTERNAL_ERROR;
    }
    QuickFixChecker checker;
    ErrCode ret = checker.CheckAppQuickFixInfosWithInstalledBundle(infos, bundleInfo);
    if (ret != ERR_OK) {
        APP_LOGE("CheckAppQuickFixInfos check AppQuickFixInfos with installed bundle failed");
        return ret;
    }

    if (!hapVerifyRes.empty() && (infos.begin()->second.deployingAppqfInfo.type != QuickFixType::HOT_RELOAD)) {
        ret = checker.CheckSignatureInfo(bundleInfo, hapVerifyRes[0].GetProvisionInfo());
        if (ret != ERR_OK) {
            return ret;
        }
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToInnerAppQuickFix(const std::unordered_map<std::string, AppQuickFix> infos,
    const InnerAppQuickFix &oldInnerAppQuickFix, InnerAppQuickFix &newInnerAppQuickFix)
{
    if (infos.empty()) {
        return ERR_APPEXECFWK_QUICK_FIX_INTERNAL_ERROR;
    }
    AppQuickFix oldAppQuickFix = oldInnerAppQuickFix.GetAppQuickFix();
    AppQuickFix appQuickFix = infos.begin()->second;
    // copy deployed app qf info
    appQuickFix.deployedAppqfInfo = oldAppQuickFix.deployedAppqfInfo;
    newInnerAppQuickFix.SetAppQuickFix(appQuickFix);
    QuickFixMark mark;
    mark.bundleName = appQuickFix.bundleName;
    mark.status = QuickFixStatus::DEPLOY_START;
    for (auto iter = infos.begin(); iter != infos.end(); ++iter) {
        const auto &quickFix = iter->second;
        if (!newInnerAppQuickFix.AddHqfInfo(quickFix)) {
            return ERR_APPEXECFWK_QUICK_FIX_ADD_HQF_FAILED;
        }
        mark.moduleName = quickFix.deployingAppqfInfo.hqfInfos[0].moduleName;
    }
    newInnerAppQuickFix.SetQuickFixMark(mark);
    return ERR_OK;
}

ErrCode QuickFixDeployer::CheckPatchVersionCode(
    const AppQuickFix &newAppQuickFix,
    const AppQuickFix &oldAppQuickFix)
{
    const AppqfInfo &newInfo = newAppQuickFix.deployingAppqfInfo;
    const AppqfInfo &oldInfoDeployed = oldAppQuickFix.deployedAppqfInfo;
    const AppqfInfo &oldInfoDeploying = oldAppQuickFix.deployingAppqfInfo;
    if ((newInfo.versionCode > oldInfoDeployed.versionCode) &&
        (newInfo.versionCode > oldInfoDeploying.versionCode)) {
        return ERR_OK;
    }
    APP_LOGE("CheckPatchVersionCode failed, version code should be greater than the original");
    return ERR_APPEXECFWK_QUICK_FIX_VERSION_CODE_ERROR;
}

ErrCode QuickFixDeployer::SaveAppQuickFix(const InnerAppQuickFix &innerAppQuickFix)
{
    APP_LOGD("SaveAppQuickFix start.");
    if (quickFixDataMgr_ == nullptr) {
        return ERR_APPEXECFWK_QUICK_FIX_INTERNAL_ERROR;
    }
    if (!quickFixDataMgr_->SaveInnerAppQuickFix(innerAppQuickFix)) {
        APP_LOGE("inner app quick fix save failed");
        return ERR_APPEXECFWK_QUICK_FIX_SAVE_APP_QUICK_FIX_FAILED;
    }
    APP_LOGD("SaveAppQuickFix end.");
    return ERR_OK;
}

ErrCode QuickFixDeployer::ExtractDiffFiles(const std::string &targetPath,
    const AppqfInfo &appQfInfo)
{
    APP_LOGD("ExtractDiffFiles start.");
    if (appQfInfo.nativeLibraryPath.empty()) {
        return ERR_OK;
    }
    for (const auto &hqf : appQfInfo.hqfInfos) {
        if (hqf.hapFilePath.empty()) {
            APP_LOGE("error hapFilePath is empty");
            return ERR_APPEXECFWK_QUICK_FIX_PARAM_ERROR;
        }
        // extract so to targetPath
        ErrCode ret = InstalldClient::GetInstance()->ExtractDiffFiles(hqf.hapFilePath, targetPath, appQfInfo.cpuAbi);
        if (ret != ERR_OK) {
            APP_LOGE("ExtractDiffFiles failed");
            return ret;
        }
    }
    APP_LOGD("ExtractDiffFiles end.");
    return ERR_OK;
}

ErrCode QuickFixDeployer::ApplyDiffPatch(
    const std::string &bundleName,
    const std::string &libraryPath,
    const std::string &diffSoPath,
    const std::string &newPath)
{
    APP_LOGD("ApplyDiffPatch start.");
    if (bundleName.empty()|| libraryPath.empty() || newPath.empty() || diffSoPath.empty()) {
        return ERR_OK;
    }
    std::string oldSoPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName +
        Constants::PATH_SEPARATOR;
    ErrCode ret = InstalldClient::GetInstance()->ApplyDiffPatch(oldSoPath, diffSoPath, newPath);
    if (ret != ERR_OK) {
        APP_LOGE("ApplyDiffPatch failed");
        return ret;
    }
    APP_LOGD("ApplyDiffPatch end.");
    return ERR_OK;
}

ErrCode QuickFixDeployer::MoveHqfFiles(InnerAppQuickFix &innerAppQuickFix, const std::string &targetPath)
{
    APP_LOGD("MoveHqfFiles start.");
    if (targetPath.empty() || (quickFixDataMgr_ == nullptr)) {
        return ERR_APPEXECFWK_QUICK_FIX_PARAM_ERROR;
    }
    QuickFixMark mark = innerAppQuickFix.GetQuickFixMark();
    AppQuickFix appQuickFix = innerAppQuickFix.GetAppQuickFix();
    std::string path = targetPath;
    for (HqfInfo &info : appQuickFix.deployingAppqfInfo.hqfInfos) {
        if (info.hapFilePath.empty()) {
            APP_LOGE("error hapFilePath is empty");
            return ERR_APPEXECFWK_QUICK_FIX_PARAM_ERROR;
        }
        std::string realPath = path + info.hapFilePath.substr(info.hapFilePath.rfind(Constants::PATH_SEPARATOR));
        ErrCode ret = InstalldClient::GetInstance()->MoveFile(info.hapFilePath, realPath);
        if (ret != ERR_OK) {
            APP_LOGE("MoveFile failed");
            return ret;
        }
        info.hapFilePath = realPath;
        mark.moduleName = info.moduleName;
    }
    mark.status = QuickFixStatus::DEPLOY_END;
    innerAppQuickFix.SetQuickFixMark(mark);
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    APP_LOGD("MoveHqfFiles end.");
    return ERR_OK;
}
} // AppExecFwk
} // OHOS