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
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_util.h"
#include "installd_client.h"
#include "patch_extractor.h"
#include "patch_parser.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixDeployer::QuickFixDeployer(const std::vector<std::string> &bundleFilePaths) : patchPaths_(bundleFilePaths)
{}

ErrCode QuickFixDeployer::Execute()
{
    ErrCode ret = DeployQuickFix();
    if (ret != ERR_OK) {
        APP_LOGE("QuickFixDeployer errcode %{public}d", ret);
    }
    return ret;
}

ErrCode QuickFixDeployer::DeployQuickFix()
{
    if (patchPaths_.empty() || (GetQuickFixDataMgr() != ERR_OK)) {
        APP_LOGE("DeployQuickFix wrong parms");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }

    std::vector<std::string> realFilePaths;
    ErrCode ret = ProcessBundleFilePaths(patchPaths_, realFilePaths);
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
    // parse check multi hqf files, update status DEPLOY_START
    InnerAppQuickFix newInnerAppQuickFix;
    InnerAppQuickFix oldInnerAppQuickFix;
    ret = ToDeployStartStatus(realFilePaths, newInnerAppQuickFix, oldInnerAppQuickFix);
    if (ret != ERR_OK) {
        return ret;
    }
    // extract diff files, apply diff patch and copy hqf, update status DEPLOY_END
    ret = ToDeployEndStatus(newInnerAppQuickFix, oldInnerAppQuickFix);
    if (ret != ERR_OK) {
        bool isExist = !oldInnerAppQuickFix.GetAppQuickFix().bundleName.empty();
        if (isExist) {
            quickFixDataMgr_->SaveInnerAppQuickFix(oldInnerAppQuickFix);
        } else {
            quickFixDataMgr_->DeleteInnerAppQuickFix(newInnerAppQuickFix.GetAppQuickFix().bundleName);
        }
        return ret;
    }
    // remove old deploying patch_versionCode
    const AppQuickFix &appQuick = oldInnerAppQuickFix.GetAppQuickFix();
    if (!appQuick.bundleName.empty()) {
        std::string oldPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR +
            appQuick.bundleName + Constants::PATH_SEPARATOR;
        if (appQuick.deployingAppqfInfo.type == QuickFixType::HOT_RELOAD) {
            oldPath += Constants::HOT_RELOAD_PATH + std::to_string(appQuick.deployingAppqfInfo.versionCode);
        } else {
            oldPath += Constants::PATCH_PATH + std::to_string(appQuick.deployingAppqfInfo.versionCode);
        }
        if (InstalldClient::GetInstance()->RemoveDir(oldPath)) {
            APP_LOGE("delete %{private}s failed", oldPath.c_str());
        }
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToDeployStartStatus(const std::vector<std::string> &bundleFilePaths,
    InnerAppQuickFix &newInnerAppQuickFix, InnerAppQuickFix &oldInnerAppQuickFix)
{
    APP_LOGI("ToDeployStartStatus start.");
    if (GetQuickFixDataMgr() != ERR_OK) {
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    std::unordered_map<std::string, AppQuickFix> infos;
    // parse and check multi app quick fix info
    ErrCode ret = ParseAndCheckAppQuickFixInfos(bundleFilePaths, infos);
    if (ret != ERR_OK) {
        return ret;
    }
    const AppQuickFix &appQuickFix = infos.begin()->second;
    bool isExist = quickFixDataMgr_->QueryInnerAppQuickFix(appQuickFix.bundleName, oldInnerAppQuickFix);
    const QuickFixMark &mark = oldInnerAppQuickFix.GetQuickFixMark();
    if (isExist && (mark.status != QuickFixStatus::DEPLOY_START) && (mark.status != QuickFixStatus::DEPLOY_END)) {
        APP_LOGE("error: wrong quick fix status, now status : %{public}d", mark.status);
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATCH_STATUS;
    }
    const AppQuickFix &oldAppQuickFix = oldInnerAppQuickFix.GetAppQuickFix();
    // exist and type same need to check version code
    if (isExist && (appQuickFix.deployingAppqfInfo.type == oldAppQuickFix.deployingAppqfInfo.type)) {
        // check current app quick fix version code
        ret = CheckPatchVersionCode(appQuickFix, oldAppQuickFix);
        if (ret != ERR_OK) {
            return ret;
        }
    }
    // check bundleName exist
    BundleInfo bundleInfo;
    ret = GetBundleInfo(appQuickFix.bundleName, bundleInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleInfo failed, bundleName: %{public}s", appQuickFix.bundleName.c_str());
        return ret;
    }
    // check with installed bundle
    if (appQuickFix.deployingAppqfInfo.type == QuickFixType::PATCH) {
        ret = ProcessPatchDeployStart(bundleFilePaths, bundleInfo, infos);
    } else if (appQuickFix.deployingAppqfInfo.type == QuickFixType::HOT_RELOAD) {
        ret = ProcessHotReloadDeployStart(bundleInfo, appQuickFix);
    } else {
        ret = ERR_BUNDLEMANAGER_QUICK_FIX_UNKNOWN_QUICK_FIX_TYPE;
    }
    if (ret != ERR_OK) {
        return ret;
    }
    // convert to InnerAppQuickFix
    ret = ToInnerAppQuickFix(infos, oldInnerAppQuickFix, newInnerAppQuickFix);
    if (ret != ERR_OK) {
        return ret;
    }
    // save infos and update status DEPLOY_START
    ret = SaveAppQuickFix(newInnerAppQuickFix);
    if (ret != ERR_OK) {
        APP_LOGE("SaveAppQuickFix failed, errcode: %{public}d", ret);
        return ret;
    }
    APP_LOGI("ToDeployStartStatus end.");
    return ERR_OK;
}

void QuickFixDeployer::ToDeployQuickFixResult(const AppQuickFix &appQuickFix)
{
    APP_LOGD("ToDeployQuickFixResult start.");
    deployQuickFixResult_.bundleName = appQuickFix.bundleName;
    deployQuickFixResult_.bundleVersionCode = appQuickFix.versionCode;
    deployQuickFixResult_.patchVersionCode = appQuickFix.deployingAppqfInfo.versionCode;
    deployQuickFixResult_.type = appQuickFix.deployingAppqfInfo.type;
    deployQuickFixResult_.isSoContained = HasNativeSoInBundle(appQuickFix);
    deployQuickFixResult_.moduleNames.clear();
    for (const auto &hqf : appQuickFix.deployingAppqfInfo.hqfInfos) {
        deployQuickFixResult_.moduleNames.emplace_back(hqf.moduleName);
    }
    APP_LOGD("ToDeployQuickFixResult end.");
}

ErrCode QuickFixDeployer::ProcessPatchDeployStart(
    const std::vector<std::string> bundleFilePaths,
    const BundleInfo &bundleInfo,
    std::unordered_map<std::string, AppQuickFix> &infos)
{
    APP_LOGI("ProcessPatchDeployStart start.");
    if (infos.empty()) {
        APP_LOGE("error: appQuickFix infos is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }
    QuickFixChecker checker;
    // check multiple cpuAbi and native library path
    ErrCode ret = checker.CheckMultiNativeSo(infos);
    if (ret != ERR_OK) {
        APP_LOGE("ProcessPatchDeployStart check native so failed");
        return ret;
    }
    // parse signature info
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    ret = checker.CheckMultipleHqfsSignInfo(bundleFilePaths, hapVerifyRes);
    if (ret != ERR_OK) {
        APP_LOGE("ProcessPatchDeployStart check check multiple hqfs signInfo failed");
        return ret;
    }
    if (hapVerifyRes.empty()) {
        APP_LOGE("error: appQuickFix hapVerifyRes is empty");
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
    }
    const auto &provisionInfo = hapVerifyRes[0].GetProvisionInfo();
    const AppQuickFix &appQuickFix = infos.begin()->second;
    // check with installed bundle, signature info, bundleName, versionCode
    ret = checker.CheckPatchWithInstalledBundle(appQuickFix, bundleInfo, provisionInfo);
    if (ret != ERR_OK) {
        APP_LOGE("check AppQuickFixInfos with installed bundle failed, errcode : %{public}d", ret);
        return ret;
    }
    APP_LOGI("ProcessPatchDeployStart end.");
    return ERR_OK;
}

ErrCode QuickFixDeployer::ProcessHotReloadDeployStart(
    const BundleInfo &bundleInfo,
    const AppQuickFix &appQuickFix)
{
    APP_LOGI("ProcessHotReloadDeployStart start.");
    QuickFixChecker checker;
    ErrCode ret = checker.CheckHotReloadWithInstalledBundle(appQuickFix, bundleInfo);
    if (ret != ERR_OK) {
        APP_LOGE("check AppQuickFixInfos with installed bundle failed");
        return ret;
    }
    APP_LOGI("ProcessHotReloadDeployStart end.");
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToDeployEndStatus(InnerAppQuickFix &newInnerAppQuickFix,
    const InnerAppQuickFix &oldInnerAppQuickFix)
{
    APP_LOGI("ToDeployEndStatus start.");
    if ((GetQuickFixDataMgr() != ERR_OK)) {
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    // create patch path
    AppQuickFix newQuickFix = newInnerAppQuickFix.GetAppQuickFix();
    std::string newPatchPath;
    ScopeGuard guardRemovePatchPath([&newPatchPath] {
        InstalldClient::GetInstance()->RemoveDir(newPatchPath);
    });
    ErrCode ret = ERR_OK;
    if (newQuickFix.deployingAppqfInfo.type == QuickFixType::PATCH) {
        // extract diff files and apply diff patch
        ret = ProcessPatchDeployEnd(newQuickFix, newPatchPath);
    } else if (newQuickFix.deployingAppqfInfo.type == QuickFixType::HOT_RELOAD) {
        ret = ProcessHotReloadDeployEnd(newQuickFix, newPatchPath);
    } else {
        APP_LOGE("error: unknown QuickFixType");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }
    if (ret != ERR_OK) {
        APP_LOGE("Process Patch or HotReload DeployEnd failed, bundleName:%{public}s",
            newQuickFix.bundleName.c_str());
        return ret;
    }

    // if so files exist, library path add patch_versionCode;
    // if so files not exist, modify library path to empty.
    ProcessNativeLibraryPath(newPatchPath, newInnerAppQuickFix);

    // move hqf files to new patch path
    ret = MoveHqfFiles(newInnerAppQuickFix, newPatchPath);
    if (ret != ERR_OK) {
        APP_LOGE("error MoveHqfFiles failed, bundleName: %{public}s", newQuickFix.bundleName.c_str());
        return ret;
    }
    // save and update status DEPLOY_END
    ret = SaveAppQuickFix(newInnerAppQuickFix);
    if (ret != ERR_OK) {
        return ret;
    }
    ToDeployQuickFixResult(newQuickFix);
    ret = SaveToInnerBundleInfo(newInnerAppQuickFix);
    if (ret != ERR_OK) {
        APP_LOGE("error: bundleName %{public}s update deploying quick fix info to innerBundleInfo failed",
            newQuickFix.bundleName.c_str());
        return ret;
    }
    guardRemovePatchPath.Dismiss();
    APP_LOGI("ToDeployEndStatus end.");
    return ERR_OK;
}

void QuickFixDeployer::ProcessNativeLibraryPath(const std::string &patchPath, InnerAppQuickFix &innerAppQuickFix)
{
    AppQuickFix appQuickFix = innerAppQuickFix.GetAppQuickFix();
    if (!appQuickFix.deployingAppqfInfo.nativeLibraryPath.empty()) {
        std::string nativeLibraryPath = appQuickFix.deployingAppqfInfo.nativeLibraryPath;
        ProcessNativeLibraryPath(patchPath, innerAppQuickFix, nativeLibraryPath);
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = nativeLibraryPath;
    }

    for (auto &hqfInfo : appQuickFix.deployingAppqfInfo.hqfInfos) {
        if (!hqfInfo.nativeLibraryPath.empty()) {
            std::string nativeLibraryPath = hqfInfo.nativeLibraryPath;
            ProcessNativeLibraryPath(patchPath, innerAppQuickFix, nativeLibraryPath);
            hqfInfo.nativeLibraryPath = nativeLibraryPath;
        }
    }

    innerAppQuickFix.SetAppQuickFix(appQuickFix);
}

void QuickFixDeployer::ProcessNativeLibraryPath(
    const std::string &patchPath, const InnerAppQuickFix &innerAppQuickFix, std::string &nativeLibraryPath)
{
    bool isSoExist = false;
    auto libraryPath = nativeLibraryPath;
    std::string soPath = patchPath + Constants::PATH_SEPARATOR + libraryPath;
    if (InstalldClient::GetInstance()->IsExistDir(soPath, isSoExist) != ERR_OK) {
        APP_LOGE("ProcessNativeLibraryPath InstalldClient IsExistDir(%{public}s) failed", soPath.c_str());
        return;
    }

    AppQuickFix appQuickFix = innerAppQuickFix.GetAppQuickFix();
    if (isSoExist) {
        nativeLibraryPath = Constants::PATCH_PATH +
            std::to_string(appQuickFix.deployingAppqfInfo.versionCode) + Constants::PATH_SEPARATOR + libraryPath;
    } else {
        APP_LOGI("So(%{public}s) is not exist and set nativeLibraryPath(%{public}s) empty",
            soPath.c_str(), nativeLibraryPath.c_str());
        nativeLibraryPath.clear();
    }
}

ErrCode QuickFixDeployer::ProcessPatchDeployEnd(const AppQuickFix &appQuickFix, std::string &patchPath)
{
    patchPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + appQuickFix.bundleName +
        Constants::PATH_SEPARATOR + Constants::PATCH_PATH +
        std::to_string(appQuickFix.deployingAppqfInfo.versionCode);
    ErrCode ret = InstalldClient::GetInstance()->CreateBundleDir(patchPath);
    if (ret != ERR_OK) {
        APP_LOGE("error: creat patch path failed, errcode %{public}d", ret);
        return ERR_BUNDLEMANAGER_QUICK_FIX_CREATE_PATCH_PATH_FAILED;
    }

    auto &appQfInfo = appQuickFix.deployingAppqfInfo;
    for (const auto &hqf : appQfInfo.hqfInfos) {
        if (hqf.hqfFilePath.empty()) {
            APP_LOGE("error: hapFilePath is empty");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
        }

        std::string libraryPath;
        std::string cpuAbi;
        bool isLibIsolated = IsLibIsolated(appQuickFix.bundleName, hqf.moduleName);
        if (!FetchPatchNativeSoAttrs(
            appQuickFix.deployingAppqfInfo, hqf, isLibIsolated, libraryPath, cpuAbi)) {
            continue;
        }

        std::string oldSoPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + appQuickFix.bundleName +
            Constants::PATH_SEPARATOR + libraryPath;
        APP_LOGD("ProcessPatchDeployEnd oldPath %{public}s", oldSoPath.c_str());
        bool pathExist = false;
        // if old so path does not exist then return ERR_OK
        ret = InstalldClient::GetInstance()->IsExistDir(oldSoPath, pathExist);
        if (!pathExist && (ret == ERR_OK)) {
            APP_LOGD("bundleName: %{public}s no so path", appQuickFix.bundleName.c_str());
            return ERR_OK;
        }

        // extract diff so, diff so path
        std::string diffFilePath = Constants::HAP_COPY_PATH + Constants::PATH_SEPARATOR +
            appQuickFix.bundleName + Constants::TMP_SUFFIX;
        ScopeGuard guardRemoveDiffPath([diffFilePath] { InstalldClient::GetInstance()->RemoveDir(diffFilePath); });

        // extract so to targetPath
        ret = InstalldClient::GetInstance()->ExtractDiffFiles(hqf.hqfFilePath, diffFilePath, cpuAbi);
        if (ret != ERR_OK) {
            APP_LOGE("error: ExtractDiffFiles failed errcode :%{public}d", ret);
            return ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED;
        }

        // apply diff patch
        std::string newSoPath = patchPath + Constants::PATH_SEPARATOR + libraryPath;
        ret = InstalldClient::GetInstance()->ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
        if (ret != ERR_OK) {
            APP_LOGE("ApplyDiffPatch failed, bundleName:%{public}s, errcode: %{public}d",
                appQuickFix.bundleName.c_str(), ret);
            return ERR_BUNDLEMANAGER_QUICK_FIX_APPLY_DIFF_PATCH_FAILED;
        }
    }

    return ERR_OK;
}

ErrCode QuickFixDeployer::ProcessHotReloadDeployEnd(const AppQuickFix &appQuickFix, std::string &patchPath)
{
    patchPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + appQuickFix.bundleName +
        Constants::PATH_SEPARATOR + Constants::HOT_RELOAD_PATH +
        std::to_string(appQuickFix.deployingAppqfInfo.versionCode);
    ErrCode ret = InstalldClient::GetInstance()->CreateBundleDir(patchPath);
    if (ret != ERR_OK) {
        APP_LOGE("error: creat hotreload path failed, errcode %{public}d", ret);
        return ERR_BUNDLEMANAGER_QUICK_FIX_CREATE_PATCH_PATH_FAILED;
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ParseAndCheckAppQuickFixInfos(
    const std::vector<std::string> &bundleFilePaths,
    std::unordered_map<std::string, AppQuickFix> &infos)
{
    // parse hqf file to AppQuickFix
    PatchParser patchParser;
    ErrCode ret = patchParser.ParsePatchInfo(bundleFilePaths, infos);
    if ((ret != ERR_OK) || infos.empty()) {
        APP_LOGE("parse AppQuickFixFiles failed, errcode %{public}d", ret);
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }

    ResetNativeSoAttrs(infos);
    QuickFixChecker checker;
    // check multiple AppQuickFix
    ret = checker.CheckAppQuickFixInfos(infos);
    if (ret != ERR_OK) {
        APP_LOGE("check AppQuickFixInfos failed");
        return ret;
    }
    const QuickFixType &quickFixType = infos.begin()->second.deployingAppqfInfo.type;
    if (quickFixType == QuickFixType::UNKNOWN) {
        APP_LOGE("error unknown quick fix type");
        return ERR_BUNDLEMANAGER_QUICK_FIX_UNKNOWN_QUICK_FIX_TYPE;
    }
    // hqf file path
    for (auto iter = infos.begin(); iter != infos.end(); ++iter) {
        if (!iter->second.deployingAppqfInfo.hqfInfos.empty()) {
            iter->second.deployingAppqfInfo.hqfInfos[0].hqfFilePath = iter->first;
        } else {
            return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
        }
    }
    return ERR_OK;
}

void QuickFixDeployer::ResetNativeSoAttrs(std::unordered_map<std::string, AppQuickFix> &infos)
{
    for (auto &info : infos) {
        ResetNativeSoAttrs(info.second);
    }
}

void QuickFixDeployer::ResetNativeSoAttrs(AppQuickFix &appQuickFix)
{
    auto &appqfInfo = appQuickFix.deployingAppqfInfo;
    if (appqfInfo.hqfInfos.size() != 1) {
        APP_LOGW("The number of hqfInfos is not one.");
        return;
    }

    bool isLibIsolated = IsLibIsolated(appQuickFix.bundleName, appqfInfo.hqfInfos[0].moduleName);
    if (!isLibIsolated) {
        APP_LOGW("Lib is not isolated.");
        return;
    }

    appqfInfo.hqfInfos[0].cpuAbi = appqfInfo.cpuAbi;
    appqfInfo.hqfInfos[0].nativeLibraryPath =
        appqfInfo.hqfInfos[0].moduleName + Constants::PATH_SEPARATOR + appqfInfo.nativeLibraryPath;
    appqfInfo.nativeLibraryPath.clear();
}

bool QuickFixDeployer::IsLibIsolated(
    const std::string &bundleName, const std::string &moduleName)
{
    InnerBundleInfo innerBundleInfo;
    if (!FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
        APP_LOGE("Fetch bundleInfo(%{public}s) failed.", bundleName.c_str());
        return false;
    }

    return innerBundleInfo.IsLibIsolated(moduleName);
}

bool QuickFixDeployer::FetchInnerBundleInfo(
    const std::string &bundleName, InnerBundleInfo &innerBundleInfo)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("error dataMgr is nullptr");
        return false;
    }

    if (!dataMgr->FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
        APP_LOGE("Fetch bundleInfo(%{public}s) failed.", bundleName.c_str());
        return false;
    }

    return true;
}

bool QuickFixDeployer::FetchPatchNativeSoAttrs(const AppqfInfo &appqfInfo,
    const HqfInfo hqfInfo, bool isLibIsolated, std::string &nativeLibraryPath, std::string &cpuAbi)
{
    if (isLibIsolated) {
        nativeLibraryPath = hqfInfo.nativeLibraryPath;
        cpuAbi = hqfInfo.cpuAbi;
    } else {
        nativeLibraryPath = appqfInfo.nativeLibraryPath;
        cpuAbi = appqfInfo.cpuAbi;
    }

    return !nativeLibraryPath.empty();
}

bool QuickFixDeployer::HasNativeSoInBundle(const AppQuickFix &appQuickFix)
{
    if (!appQuickFix.deployingAppqfInfo.nativeLibraryPath.empty()) {
        return true;
    }

    for (const auto &hqfInfo : appQuickFix.deployingAppqfInfo.hqfInfos) {
        if (!hqfInfo.nativeLibraryPath.empty()) {
            return true;
        }
    }

    return false;
}

ErrCode QuickFixDeployer::GetBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo)
{
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    if (bms == nullptr) {
        APP_LOGE("error: bms is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = bms->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("error: dataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    // check bundleName is exists
    if (!dataMgr->GetBundleInfo(bundleName, BundleFlag::GET_BUNDLE_DEFAULT,
        bundleInfo, Constants::ANY_USERID)) {
        APP_LOGE("error: GetBundleInfo failed, bundleName: %{public}s not exist", bundleName.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToInnerAppQuickFix(const std::unordered_map<std::string, AppQuickFix> infos,
    const InnerAppQuickFix &oldInnerAppQuickFix, InnerAppQuickFix &newInnerAppQuickFix)
{
    APP_LOGD("ToInnerAppQuickFix start");
    if (infos.empty()) {
        APP_LOGE("error: appQuickFix is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
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
        // hqfInfos will not be empty, it has been judged before.
        const std::string &moduleName = quickFix.deployingAppqfInfo.hqfInfos[0].moduleName;
        if (!newInnerAppQuickFix.AddHqfInfo(quickFix)) {
            APP_LOGE("error: appQuickFix add hqf moduleName: %{public}s failed", moduleName.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_ADD_HQF_FAILED;
        }
    }
    newInnerAppQuickFix.SetQuickFixMark(mark);
    APP_LOGD("ToInnerAppQuickFix end");
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
    return ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_ERROR;
}

ErrCode QuickFixDeployer::SaveAppQuickFix(const InnerAppQuickFix &innerAppQuickFix)
{
    if ((GetQuickFixDataMgr() != ERR_OK)) {
        APP_LOGE("error: quickFixDataMgr_ is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    if (!quickFixDataMgr_->SaveInnerAppQuickFix(innerAppQuickFix)) {
        APP_LOGE("bundleName: %{public}s, inner app quick fix save failed",
            innerAppQuickFix.GetAppQuickFix().bundleName.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_SAVE_APP_QUICK_FIX_FAILED;
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::MoveHqfFiles(InnerAppQuickFix &innerAppQuickFix, const std::string &targetPath)
{
    APP_LOGD("MoveHqfFiles start.");
    if (targetPath.empty() || (GetQuickFixDataMgr() != ERR_OK)) {
        APP_LOGE("MoveHqfFiles params error");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    QuickFixMark mark = innerAppQuickFix.GetQuickFixMark();
    AppQuickFix appQuickFix = innerAppQuickFix.GetAppQuickFix();
    std::string path = targetPath;
    if (path.back() != Constants::FILE_SEPARATOR_CHAR) {
        path.push_back(Constants::FILE_SEPARATOR_CHAR);
    }
    for (HqfInfo &info : appQuickFix.deployingAppqfInfo.hqfInfos) {
        if (info.hqfFilePath.empty()) {
            APP_LOGE("error hapFilePath is empty");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
        }
        std::string realPath = path + info.moduleName + Constants::QUICK_FIX_FILE_SUFFIX;
        ErrCode ret = InstalldClient::GetInstance()->MoveFile(info.hqfFilePath, realPath);
        if (ret != ERR_OK) {
            APP_LOGE("error MoveFile failed, errcode: %{public}d", ret);
            return ERR_BUNDLEMANAGER_QUICK_FIX_MOVE_PATCH_FILE_FAILED;
        }
        info.hqfFilePath = realPath;
    }
    mark.status = QuickFixStatus::DEPLOY_END;
    innerAppQuickFix.SetQuickFixMark(mark);
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    APP_LOGD("MoveHqfFiles end.");
    return ERR_OK;
}

DeployQuickFixResult QuickFixDeployer::GetDeployQuickFixResult() const
{
    return deployQuickFixResult_;
}

ErrCode QuickFixDeployer::GetQuickFixDataMgr()
{
    if (quickFixDataMgr_ == nullptr) {
        quickFixDataMgr_ = DelayedSingleton<QuickFixDataMgr>::GetInstance();
        if (quickFixDataMgr_ == nullptr) {
            APP_LOGE("error: quickFixDataMgr_ is nullptr");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::SaveToInnerBundleInfo(const InnerAppQuickFix &newInnerAppQuickFix)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("error dataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    const std::string &bundleName = newInnerAppQuickFix.GetAppQuickFix().bundleName;
    InnerBundleInfo innerBundleInfo;
    // obtain innerBundleInfo and enableGuard used to enable bundle which is under disable status
    if (!dataMgr->GetInnerBundleInfo(bundleName, innerBundleInfo)) {
        APP_LOGE("cannot obtain the innerbundleInfo from data mgr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO;
    }
    ScopeGuard enableGuard([&bundleName, &dataMgr] { dataMgr->EnableBundle(bundleName); });
    AppQuickFix appQuickFix = newInnerAppQuickFix.GetAppQuickFix();
    appQuickFix.deployedAppqfInfo = innerBundleInfo.GetAppQuickFix().deployedAppqfInfo;
    innerBundleInfo.SetAppQuickFix(appQuickFix);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    if (!dataMgr->UpdateQuickFixInnerBundleInfo(bundleName, innerBundleInfo)) {
        APP_LOGE("update quickfix innerbundleInfo failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ProcessBundleFilePaths(const std::vector<std::string> &bundleFilePaths,
    std::vector<std::string> &realFilePaths)
{
    ErrCode ret = BundleUtil::CheckFilePath(bundleFilePaths, realFilePaths);
    if (ret != ERR_OK) {
        APP_LOGE("ProcessBundleFilePaths CheckFilePath failed.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    for (const auto &path : realFilePaths) {
        if (!BundleUtil::CheckFileType(path, Constants::QUICK_FIX_FILE_SUFFIX)) {
            APP_LOGE("ProcessBundleFilePaths CheckFileType failed.");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
        }
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS