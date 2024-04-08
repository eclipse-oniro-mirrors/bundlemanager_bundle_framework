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

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_util.h"
#include "installd_client.h"
#include "event_report.h"
#include "patch_extractor.h"
#include "patch_parser.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string DEBUG_APP_IDENTIFIER = "DEBUG_LIB_ID";
const std::string COMPILE_SDK_TYPE_OPEN_HARMONY = "OpenHarmony";
}

QuickFixDeployer::QuickFixDeployer(const std::vector<std::string> &bundleFilePaths,
    bool isDebug) : patchPaths_(bundleFilePaths), isDebug_(isDebug)
{}

ErrCode QuickFixDeployer::Execute()
{
    ErrCode ret = DeployQuickFix();
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "QuickFixDeployer errcode %{public}d", ret);
    }
    return ret;
}

ErrCode QuickFixDeployer::DeployQuickFix()
{
    if (patchPaths_.empty() || (GetQuickFixDataMgr() != ERR_OK)) {
        LOG_E(BMSTag::QUICK_FIX, "DeployQuickFix wrong parms");
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
                LOG_E(BMSTag::QUICK_FIX, "RemovePatchFile failed path: %{private}s", tempPath.c_str());
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
            LOG_E(BMSTag::QUICK_FIX, "delete %{private}s failed", oldPath.c_str());
        }
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToDeployStartStatus(const std::vector<std::string> &bundleFilePaths,
    InnerAppQuickFix &newInnerAppQuickFix, InnerAppQuickFix &oldInnerAppQuickFix)
{
    LOG_I(BMSTag::QUICK_FIX, "ToDeployStartStatus start.");
    if (GetQuickFixDataMgr() != ERR_OK) {
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    std::unordered_map<std::string, AppQuickFix> infos;
    // parse and check multi app quick fix info
    ErrCode ret = ParseAndCheckAppQuickFixInfos(bundleFilePaths, infos);
    CHECK_QUICK_FIX_RESULT_RETURN_IF_FAIL(ret);

    const AppQuickFix &appQuickFix = infos.begin()->second;
    bool isExist = quickFixDataMgr_->QueryInnerAppQuickFix(appQuickFix.bundleName, oldInnerAppQuickFix);
    const QuickFixMark &mark = oldInnerAppQuickFix.GetQuickFixMark();
    if (isExist && (mark.status != QuickFixStatus::DEPLOY_START) && (mark.status != QuickFixStatus::DEPLOY_END)) {
        LOG_E(BMSTag::QUICK_FIX, "error: wrong quick fix status, now status : %{public}d", mark.status);
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATCH_STATUS;
    }
    const AppQuickFix &oldAppQuickFix = oldInnerAppQuickFix.GetAppQuickFix();
    // exist and type same need to check version code
    if (isExist && (appQuickFix.deployingAppqfInfo.type == oldAppQuickFix.deployingAppqfInfo.type)) {
        // check current app quick fix version code
        ret = CheckPatchVersionCode(appQuickFix, oldAppQuickFix);
        CHECK_QUICK_FIX_RESULT_RETURN_IF_FAIL(ret);
    }
    // check bundleName exist
    BundleInfo bundleInfo;
    ret = GetBundleInfo(appQuickFix.bundleName, bundleInfo);
    CHECK_QUICK_FIX_RESULT_RETURN_IF_FAIL(ret);

    // check resources/rawfile whether valid
    ret = CheckHqfResourceIsValid(bundleFilePaths, bundleInfo);
    CHECK_QUICK_FIX_RESULT_RETURN_IF_FAIL(ret);

    // check with installed bundle
    if (appQuickFix.deployingAppqfInfo.type == QuickFixType::PATCH) {
        ret = ProcessPatchDeployStart(bundleFilePaths, bundleInfo, infos);
    } else if (appQuickFix.deployingAppqfInfo.type == QuickFixType::HOT_RELOAD) {
        ret = ProcessHotReloadDeployStart(bundleInfo, appQuickFix);
    } else {
        ret = ERR_BUNDLEMANAGER_QUICK_FIX_UNKNOWN_QUICK_FIX_TYPE;
    }
    CHECK_QUICK_FIX_RESULT_RETURN_IF_FAIL(ret);

    // convert to InnerAppQuickFix
    ret = ToInnerAppQuickFix(infos, oldInnerAppQuickFix, newInnerAppQuickFix);
    CHECK_QUICK_FIX_RESULT_RETURN_IF_FAIL(ret);

    // save infos and update status DEPLOY_START
    ret = SaveAppQuickFix(newInnerAppQuickFix);
    CHECK_QUICK_FIX_RESULT_RETURN_IF_FAIL(ret);

    LOG_I(BMSTag::QUICK_FIX, "ToDeployStartStatus end.");
    return ERR_OK;
}

void QuickFixDeployer::ToDeployQuickFixResult(const AppQuickFix &appQuickFix)
{
    LOG_D(BMSTag::QUICK_FIX, "ToDeployQuickFixResult start.");
    deployQuickFixResult_.bundleName = appQuickFix.bundleName;
    deployQuickFixResult_.bundleVersionCode = appQuickFix.versionCode;
    deployQuickFixResult_.patchVersionCode = appQuickFix.deployingAppqfInfo.versionCode;
    deployQuickFixResult_.type = appQuickFix.deployingAppqfInfo.type;
    deployQuickFixResult_.isSoContained = HasNativeSoInBundle(appQuickFix);
    deployQuickFixResult_.moduleNames.clear();
    for (const auto &hqf : appQuickFix.deployingAppqfInfo.hqfInfos) {
        deployQuickFixResult_.moduleNames.emplace_back(hqf.moduleName);
    }
    LOG_D(BMSTag::QUICK_FIX, "ToDeployQuickFixResult end.");
}

ErrCode QuickFixDeployer::ProcessPatchDeployStart(
    const std::vector<std::string> bundleFilePaths,
    const BundleInfo &bundleInfo,
    std::unordered_map<std::string, AppQuickFix> &infos)
{
    LOG_I(BMSTag::QUICK_FIX, "ProcessPatchDeployStart start.");
    if (infos.empty()) {
        LOG_E(BMSTag::QUICK_FIX, "error: appQuickFix infos is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }
    QuickFixChecker checker;
    // check multiple cpuAbi and native library path
    ErrCode ret = checker.CheckMultiNativeSo(infos);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "ProcessPatchDeployStart check native so failed");
        return ret;
    }
    // parse signature info
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    ret = checker.CheckMultipleHqfsSignInfo(bundleFilePaths, hapVerifyRes);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "ProcessPatchDeployStart check check multiple hqfs signInfo failed");
        return ret;
    }
    if (hapVerifyRes.empty()) {
        LOG_E(BMSTag::QUICK_FIX, "error: appQuickFix hapVerifyRes is empty");
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
    }
    const auto &provisionInfo = hapVerifyRes[0].GetProvisionInfo();
    const AppQuickFix &appQuickFix = infos.begin()->second;
    // check with installed bundle, signature info, bundleName, versionCode
    ret = checker.CheckPatchWithInstalledBundle(appQuickFix, bundleInfo, provisionInfo);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "check AppQuickFixInfos with installed bundle failed, errcode : %{public}d", ret);
        return ret;
    }
    appDistributionType_ = checker.GetAppDistributionType(provisionInfo.distributionType);
    LOG_I(BMSTag::QUICK_FIX, "ProcessPatchDeployStart end.");
    return ERR_OK;
}

ErrCode QuickFixDeployer::ProcessHotReloadDeployStart(
    const BundleInfo &bundleInfo,
    const AppQuickFix &appQuickFix)
{
    LOG_I(BMSTag::QUICK_FIX, "ProcessHotReloadDeployStart start.");
    QuickFixChecker checker;
    ErrCode ret = checker.CheckHotReloadWithInstalledBundle(appQuickFix, bundleInfo);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "check AppQuickFixInfos with installed bundle failed");
        return ret;
    }
    LOG_I(BMSTag::QUICK_FIX, "ProcessHotReloadDeployStart end.");
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToDeployEndStatus(InnerAppQuickFix &newInnerAppQuickFix,
    const InnerAppQuickFix &oldInnerAppQuickFix)
{
    LOG_I(BMSTag::QUICK_FIX, "ToDeployEndStatus start.");
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
        LOG_E(BMSTag::QUICK_FIX, "error: unknown QuickFixType");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "Process Patch or HotReload DeployEnd failed, bundleName:%{public}s",
            newQuickFix.bundleName.c_str());
        return ret;
    }

    // if so files exist, library path add patch_versionCode;
    // if so files not exist, modify library path to empty.
    ProcessNativeLibraryPath(newPatchPath, newInnerAppQuickFix);

    // move hqf files to new patch path
    ret = MoveHqfFiles(newInnerAppQuickFix, newPatchPath);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "error MoveHqfFiles failed, bundleName: %{public}s", newQuickFix.bundleName.c_str());
        return ret;
    }
    ret = VerifyCodeSignatureForHqf(newInnerAppQuickFix, newPatchPath);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "verify failed bundleName: %{public}s", newQuickFix.bundleName.c_str());
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
        LOG_E(BMSTag::QUICK_FIX, "error: bundleName %{public}s update failed due to innerBundleInfo failed",
            newQuickFix.bundleName.c_str());
        return ret;
    }
    guardRemovePatchPath.Dismiss();
    LOG_I(BMSTag::QUICK_FIX, "ToDeployEndStatus end.");
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
        LOG_E(BMSTag::QUICK_FIX, "ProcessNativeLibraryPath IsExistDir(%{public}s) failed", soPath.c_str());
        return;
    }

    AppQuickFix appQuickFix = innerAppQuickFix.GetAppQuickFix();
    if (isSoExist) {
        nativeLibraryPath = Constants::PATCH_PATH +
            std::to_string(appQuickFix.deployingAppqfInfo.versionCode) + Constants::PATH_SEPARATOR + libraryPath;
    } else {
        LOG_I(BMSTag::QUICK_FIX, "So(%{public}s) is not exist and set nativeLibraryPath(%{public}s) empty",
            soPath.c_str(), nativeLibraryPath.c_str());
        nativeLibraryPath.clear();
    }
}

ErrCode QuickFixDeployer::ProcessPatchDeployEnd(const AppQuickFix &appQuickFix, std::string &patchPath)
{
    patchPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + appQuickFix.bundleName +
        Constants::PATH_SEPARATOR + Constants::PATCH_PATH + std::to_string(appQuickFix.deployingAppqfInfo.versionCode);
    if (InstalldClient::GetInstance()->CreateBundleDir(patchPath) != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "error: creat patch path failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_CREATE_PATCH_PATH_FAILED;
    }
    BundleInfo bundleInfo;
    ErrCode ret = GetBundleInfo(appQuickFix.bundleName, bundleInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    if (isDebug_ && (bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG)) {
        return ExtractQuickFixSoFile(appQuickFix, patchPath, bundleInfo);
    }
    std::string oldSoPath = Constants::HAP_COPY_PATH + Constants::PATH_SEPARATOR +
        appQuickFix.bundleName + Constants::TMP_SUFFIX + Constants::LIBS;
    ScopeGuard guardRemoveOldSoPath([oldSoPath] {InstalldClient::GetInstance()->RemoveDir(oldSoPath);});

    auto &appQfInfo = appQuickFix.deployingAppqfInfo;
    for (const auto &hqf : appQfInfo.hqfInfos) {
        // if hap has no so file then continue
        std::string tmpSoPath = oldSoPath;

        InnerBundleInfo innerBundleInfo;
        if (!FetchInnerBundleInfo(appQuickFix.bundleName, innerBundleInfo)) {
            LOG_E(BMSTag::QUICK_FIX, "Fetch bundleInfo(%{public}s) failed.", appQuickFix.bundleName.c_str());
            return false;
        }
        int32_t bundleUid = Constants::INVALID_UID;
        if (innerBundleInfo.IsEncryptedMoudle(hqf.moduleName)) {
            InnerBundleUserInfo innerBundleUserInfo;
            if (!innerBundleInfo.GetInnerBundleUserInfo(Constants::ALL_USERID, innerBundleUserInfo)) {
                LOG_E(BMSTag::QUICK_FIX, "no user info of bundle %{public}s", appQuickFix.bundleName.c_str());
                return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST;
            }
            bundleUid = innerBundleUserInfo.uid;
            if (!ExtractEncryptedSoFiles(bundleInfo, hqf.moduleName, bundleUid, tmpSoPath)) {
                LOG_W(BMSTag::QUICK_FIX, "module:%{public}s has no so file", hqf.moduleName.c_str());
                continue;
            }
        } else {
            if (!ExtractSoFiles(bundleInfo, hqf.moduleName, tmpSoPath)) {
                LOG_W(BMSTag::QUICK_FIX, "module:%{public}s has no so file", hqf.moduleName.c_str());
                continue;
            }
        }

        auto result = ProcessApplyDiffPatch(appQuickFix, hqf, tmpSoPath, patchPath, bundleUid);
        if (result != ERR_OK) {
            LOG_E(BMSTag::QUICK_FIX, "bundleName: %{public}s Process failed.", appQuickFix.bundleName.c_str());
            return result;
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
        LOG_E(BMSTag::QUICK_FIX, "error: creat hotreload path failed, errcode %{public}d", ret);
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
        LOG_E(BMSTag::QUICK_FIX, "parse AppQuickFixFiles failed, errcode %{public}d", ret);
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }

    ResetNativeSoAttrs(infos);
    QuickFixChecker checker;
    // check multiple AppQuickFix
    ret = checker.CheckAppQuickFixInfos(infos);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "check AppQuickFixInfos failed");
        return ret;
    }
    const QuickFixType &quickFixType = infos.begin()->second.deployingAppqfInfo.type;
    if (quickFixType == QuickFixType::UNKNOWN) {
        LOG_E(BMSTag::QUICK_FIX, "error unknown quick fix type");
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
        LOG_W(BMSTag::QUICK_FIX, "The number of hqfInfos is not one.");
        return;
    }

    bool isLibIsolated = IsLibIsolated(appQuickFix.bundleName, appqfInfo.hqfInfos[0].moduleName);
    if (!isLibIsolated) {
        LOG_W(BMSTag::QUICK_FIX, "Lib is not isolated.");
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
        LOG_E(BMSTag::QUICK_FIX, "Fetch bundleInfo(%{public}s) failed.", bundleName.c_str());
        return false;
    }

    return innerBundleInfo.IsLibIsolated(moduleName);
}

bool QuickFixDeployer::FetchInnerBundleInfo(
    const std::string &bundleName, InnerBundleInfo &innerBundleInfo)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMSTag::QUICK_FIX, "error dataMgr is nullptr");
        return false;
    }

    if (!dataMgr->FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
        LOG_E(BMSTag::QUICK_FIX, "Fetch bundleInfo(%{public}s) failed.", bundleName.c_str());
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
        LOG_E(BMSTag::QUICK_FIX, "error: bms is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = bms->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMSTag::QUICK_FIX, "error: dataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    // check bundleName is exists
    if (!dataMgr->GetBundleInfo(bundleName, BundleFlag::GET_BUNDLE_DEFAULT,
        bundleInfo, Constants::ANY_USERID)) {
        LOG_E(BMSTag::QUICK_FIX, "error: GetBundleInfo failed, bundleName: %{public}s not exist", bundleName.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToInnerAppQuickFix(const std::unordered_map<std::string, AppQuickFix> infos,
    const InnerAppQuickFix &oldInnerAppQuickFix, InnerAppQuickFix &newInnerAppQuickFix)
{
    LOG_D(BMSTag::QUICK_FIX, "ToInnerAppQuickFix start");
    if (infos.empty()) {
        LOG_E(BMSTag::QUICK_FIX, "error: appQuickFix is empty");
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
            LOG_E(BMSTag::QUICK_FIX, "error: appQuickFix add hqf moduleName: %{public}s failed", moduleName.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_ADD_HQF_FAILED;
        }
    }
    newInnerAppQuickFix.SetQuickFixMark(mark);
    LOG_D(BMSTag::QUICK_FIX, "ToInnerAppQuickFix end");
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
    LOG_E(BMSTag::QUICK_FIX, "CheckPatchVersionCode failed, version code should be greater than the original");
    return ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_ERROR;
}

ErrCode QuickFixDeployer::SaveAppQuickFix(const InnerAppQuickFix &innerAppQuickFix)
{
    if ((GetQuickFixDataMgr() != ERR_OK)) {
        LOG_E(BMSTag::QUICK_FIX, "error: quickFixDataMgr_ is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    if (!quickFixDataMgr_->SaveInnerAppQuickFix(innerAppQuickFix)) {
        LOG_E(BMSTag::QUICK_FIX, "bundleName: %{public}s, inner app quick fix save failed",
            innerAppQuickFix.GetAppQuickFix().bundleName.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_SAVE_APP_QUICK_FIX_FAILED;
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::MoveHqfFiles(InnerAppQuickFix &innerAppQuickFix, const std::string &targetPath)
{
    LOG_D(BMSTag::QUICK_FIX, "MoveHqfFiles start.");
    if (targetPath.empty() || (GetQuickFixDataMgr() != ERR_OK)) {
        LOG_E(BMSTag::QUICK_FIX, "MoveHqfFiles params error");
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
            LOG_E(BMSTag::QUICK_FIX, "error hapFilePath is empty");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
        }
        std::string realPath = path + info.moduleName + Constants::QUICK_FIX_FILE_SUFFIX;
        ErrCode ret = InstalldClient::GetInstance()->CopyFile(info.hqfFilePath, realPath);
        if (ret != ERR_OK) {
            LOG_E(BMSTag::QUICK_FIX, "error CopyFile failed, errcode: %{public}d", ret);
            return ERR_BUNDLEMANAGER_QUICK_FIX_MOVE_PATCH_FILE_FAILED;
        }
        info.hqfFilePath = realPath;
    }
    mark.status = QuickFixStatus::DEPLOY_END;
    innerAppQuickFix.SetQuickFixMark(mark);
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    LOG_D(BMSTag::QUICK_FIX, "MoveHqfFiles end.");
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
            LOG_E(BMSTag::QUICK_FIX, "error: quickFixDataMgr_ is nullptr");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::SaveToInnerBundleInfo(const InnerAppQuickFix &newInnerAppQuickFix)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMSTag::QUICK_FIX, "error dataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    const std::string &bundleName = newInnerAppQuickFix.GetAppQuickFix().bundleName;
    InnerBundleInfo innerBundleInfo;
    // obtain innerBundleInfo and enableGuard used to enable bundle which is under disable status
    if (!dataMgr->GetInnerBundleInfo(bundleName, innerBundleInfo)) {
        LOG_E(BMSTag::QUICK_FIX, "cannot obtain the innerbundleInfo from data mgr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO;
    }
    ScopeGuard enableGuard([&bundleName, &dataMgr] { dataMgr->EnableBundle(bundleName); });
    AppQuickFix appQuickFix = newInnerAppQuickFix.GetAppQuickFix();
    appQuickFix.deployedAppqfInfo = innerBundleInfo.GetAppQuickFix().deployedAppqfInfo;
    // add apply quick fix frequency
    innerBundleInfo.AddApplyQuickFixFrequency();
    innerBundleInfo.SetAppQuickFix(appQuickFix);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    if (!dataMgr->UpdateQuickFixInnerBundleInfo(bundleName, innerBundleInfo)) {
        LOG_E(BMSTag::QUICK_FIX, "update quickfix innerbundleInfo failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    // send quick fix data
    SendQuickFixSystemEvent(innerBundleInfo);
    return ERR_OK;
}

ErrCode QuickFixDeployer::ProcessBundleFilePaths(const std::vector<std::string> &bundleFilePaths,
    std::vector<std::string> &realFilePaths)
{
    for (const auto &path : bundleFilePaths) {
        if (path.find(Constants::RELATIVE_PATH) != std::string::npos) {
            LOG_E(BMSTag::QUICK_FIX, "ProcessBundleFilePaths path is illegal.");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
        }
        if (path.find(Constants::HAP_COPY_PATH + Constants::PATH_SEPARATOR +
            Constants::SECURITY_QUICK_FIX_PATH + Constants::PATH_SEPARATOR) != 0) {
            LOG_E(BMSTag::QUICK_FIX, "ProcessBundleFilePaths path is illegal.");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
        }
    }
    ErrCode ret = BundleUtil::CheckFilePath(bundleFilePaths, realFilePaths);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "ProcessBundleFilePaths CheckFilePath failed.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    for (const auto &path : realFilePaths) {
        if (!BundleUtil::CheckFileType(path, Constants::QUICK_FIX_FILE_SUFFIX)) {
            LOG_E(BMSTag::QUICK_FIX, "ProcessBundleFilePaths CheckFileType failed.");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
        }
    }
    return ERR_OK;
}

void QuickFixDeployer::SendQuickFixSystemEvent(const InnerBundleInfo &innerBundleInfo)
{
    EventInfo sysEventInfo;
    sysEventInfo.errCode = ERR_OK;
    sysEventInfo.bundleName = innerBundleInfo.GetBundleName();
    sysEventInfo.appDistributionType = appDistributionType_;
    for (const auto &hqfInfo : innerBundleInfo.GetAppQuickFix().deployingAppqfInfo.hqfInfos) {
        sysEventInfo.filePath.push_back(hqfInfo.hqfFilePath);
        sysEventInfo.hashValue.push_back(hqfInfo.hapSha256);
    }
    sysEventInfo.applyQuickFixFrequency = innerBundleInfo.GetApplyQuickFixFrequency();
    EventReport::SendBundleSystemEvent(BundleEventType::QUICK_FIX, sysEventInfo);
}

ErrCode QuickFixDeployer::ExtractQuickFixSoFile(
    const AppQuickFix &appQuickFix, const std::string &hqfSoPath, const BundleInfo &bundleInfo)
{
    LOG_D(BMSTag::QUICK_FIX, "start, bundleName:%{public}s", appQuickFix.bundleName.c_str());
    auto &appQfInfo = appQuickFix.deployingAppqfInfo;
    if (appQfInfo.hqfInfos.empty()) {
        LOG_E(BMSTag::QUICK_FIX, "hqfInfos is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }
    for (const auto &hqf : appQfInfo.hqfInfos) {
        auto iter = std::find_if(std::begin(bundleInfo.hapModuleInfos), std::end(bundleInfo.hapModuleInfos),
            [hqf](const HapModuleInfo &info) {
                return info.moduleName == hqf.moduleName;
            });
        if (iter == bundleInfo.hapModuleInfos.end()) {
            LOG_W(BMSTag::QUICK_FIX, "moduleName:%{public}s not exist", hqf.moduleName.c_str());
            continue;
        }

        std::string libraryPath;
        std::string cpuAbi;
        bool isLibIsolated = IsLibIsolated(appQuickFix.bundleName, hqf.moduleName);
        if (!FetchPatchNativeSoAttrs(appQuickFix.deployingAppqfInfo, hqf, isLibIsolated, libraryPath, cpuAbi)) {
            LOG_D(BMSTag::QUICK_FIX, "no so file");
            continue;
        }
        std::string soPath = hqfSoPath + Constants::PATH_SEPARATOR + libraryPath;
        ExtractParam extractParam;
        extractParam.extractFileType = ExtractFileType::SO;
        extractParam.srcPath = hqf.hqfFilePath;
        extractParam.targetPath = soPath;
        extractParam.cpuAbi = cpuAbi;
        if (InstalldClient::GetInstance()->ExtractFiles(extractParam) != ERR_OK) {
            LOG_W(BMSTag::QUICK_FIX, "moduleName: %{public}s extract so failed", hqf.moduleName.c_str());
            continue;
        }
    }
    LOG_D(BMSTag::QUICK_FIX, "end");
    return ERR_OK;
}

bool QuickFixDeployer::ExtractSoFiles(
    const BundleInfo &bundleInfo,
    const std::string &moduleName,
    std::string &tmpSoPath)
{
    auto iter = std::find_if(std::begin(bundleInfo.hapModuleInfos), std::end(bundleInfo.hapModuleInfos),
        [&moduleName](const HapModuleInfo &info) {
            return info.moduleName == moduleName;
        });
    if (iter == bundleInfo.hapModuleInfos.end()) {
        return false;
    }
    std::string cpuAbi = bundleInfo.applicationInfo.cpuAbi;
    std::string nativeLibraryPath = bundleInfo.applicationInfo.nativeLibraryPath;
    if (!iter->nativeLibraryPath.empty()) {
        cpuAbi = iter->cpuAbi;
        nativeLibraryPath = iter->nativeLibraryPath;
    }
    if (nativeLibraryPath.empty()) {
        return false;
    }

    tmpSoPath = (tmpSoPath.back() == Constants::PATH_SEPARATOR[0]) ? (tmpSoPath + moduleName) :
        (tmpSoPath + Constants::PATH_SEPARATOR + moduleName);
    ExtractParam extractParam;
    extractParam.extractFileType = ExtractFileType::SO;
    extractParam.srcPath = iter->hapPath;
    extractParam.targetPath = tmpSoPath;
    extractParam.cpuAbi = cpuAbi;
    if (InstalldClient::GetInstance()->ExtractFiles(extractParam) != ERR_OK) {
        LOG_W(BMSTag::QUICK_FIX, "bundleName: %{public}s moduleName: %{public}s extract so failed, ",
            bundleInfo.name.c_str(), moduleName.c_str());
        return false;
    }
    return true;
}

ErrCode QuickFixDeployer::ProcessApplyDiffPatch(const AppQuickFix &appQuickFix, const HqfInfo &hqf,
    const std::string &oldSoPath, const std::string &patchPath, int32_t uid)
{
    std::string libraryPath;
    std::string cpuAbi;
    bool isLibIsolated = IsLibIsolated(appQuickFix.bundleName, hqf.moduleName);
    if (!FetchPatchNativeSoAttrs(appQuickFix.deployingAppqfInfo, hqf, isLibIsolated, libraryPath, cpuAbi)) {
        return ERR_OK;
    }
    // extract diff so, diff so path
    std::string diffFilePath = Constants::HAP_COPY_PATH + Constants::PATH_SEPARATOR +
        appQuickFix.bundleName + Constants::TMP_SUFFIX;
    ScopeGuard guardRemoveDiffPath([diffFilePath] { InstalldClient::GetInstance()->RemoveDir(diffFilePath); });
    // extract diff so to targetPath
    auto ret = InstalldClient::GetInstance()->ExtractDiffFiles(hqf.hqfFilePath, diffFilePath, cpuAbi);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "error: ExtractDiffFiles failed errcode :%{public}d", ret);
        return ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED;
    }
    // apply diff patch
    std::string newSoPath = patchPath + Constants::PATH_SEPARATOR + libraryPath;
    ret = InstalldClient::GetInstance()->ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath, uid);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "ApplyDiffPatch failed, bundleName:%{public}s, errcode: %{public}d",
            appQuickFix.bundleName.c_str(), ret);
        return ERR_BUNDLEMANAGER_QUICK_FIX_APPLY_DIFF_PATCH_FAILED;
    }
    return ERR_OK;
}

bool QuickFixDeployer::ExtractEncryptedSoFiles(const BundleInfo &bundleInfo, const std::string &moduleName,
    int32_t uid, std::string &tmpSoPath)
{
    LOG_D(BMSTag::QUICK_FIX, "start to extract decoded so files to tmp path");
    auto iter = std::find_if(std::begin(bundleInfo.hapModuleInfos), std::end(bundleInfo.hapModuleInfos),
        [&moduleName](const HapModuleInfo &info) {
            return info.moduleName == moduleName;
        });
    if (iter == bundleInfo.hapModuleInfos.end()) {
        return false;
    }
    std::string cpuAbi = bundleInfo.applicationInfo.cpuAbi;
    std::string nativeLibraryPath = bundleInfo.applicationInfo.nativeLibraryPath;
    if (!iter->nativeLibraryPath.empty()) {
        cpuAbi = iter->cpuAbi;
        nativeLibraryPath = iter->nativeLibraryPath;
    }
    if (nativeLibraryPath.empty()) {
        return false;
    }
    std::string hapPath = iter->hapPath;
    std::string realSoFilesPath;
    if (iter->compressNativeLibs) {
        realSoFilesPath.append(Constants::BUNDLE_CODE_DIR).append(Constants::PATH_SEPARATOR)
            .append(bundleInfo.name).append(Constants::PATH_SEPARATOR).append(nativeLibraryPath)
            .append(Constants::PATH_SEPARATOR);
    }
    tmpSoPath = (tmpSoPath.back() == Constants::PATH_SEPARATOR[0]) ? (tmpSoPath + moduleName) :
        (tmpSoPath + Constants::PATH_SEPARATOR + moduleName + Constants::PATH_SEPARATOR);
    LOG_D(BMSTag::QUICK_FIX, "real so path is %{public}s tmpSoPath is %{public}s",
        realSoFilesPath.c_str(), tmpSoPath.c_str());
    return InstalldClient::GetInstance()->ExtractEncryptedSoFiles(hapPath, realSoFilesPath, cpuAbi, tmpSoPath, uid) ==
        ERR_OK;
}

void QuickFixDeployer::PrepareCodeSignatureParam(const AppQuickFix &appQuickFix, const HqfInfo &hqf,
    const BundleInfo &bundleInfo, const std::string &hqfSoPath, CodeSignatureParam &codeSignatureParam)
{
    std::string libraryPath;
    std::string cpuAbi;
    bool isLibIsolated = IsLibIsolated(appQuickFix.bundleName, hqf.moduleName);
    if (!FetchPatchNativeSoAttrs(appQuickFix.deployingAppqfInfo, hqf, isLibIsolated, libraryPath, cpuAbi)) {
        LOG_I(BMSTag::QUICK_FIX, "no so file");
        codeSignatureParam.targetSoPath = "";
    } else {
        std::string soPath = hqfSoPath.substr(0, hqfSoPath.rfind(Constants::PATH_SEPARATOR) + 1) + libraryPath;
        codeSignatureParam.targetSoPath = soPath;
    }
    codeSignatureParam.cpuAbi = cpuAbi;
    codeSignatureParam.modulePath = hqf.hqfFilePath;
    codeSignatureParam.isEnterpriseBundle =
        (appDistributionType_ == Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL ||
        appDistributionType_ == Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM ||
        appDistributionType_ == Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE);
    codeSignatureParam.appIdentifier = DEBUG_APP_IDENTIFIER;
    codeSignatureParam.isCompileSdkOpenHarmony =
        bundleInfo.applicationInfo.compileSdkType == COMPILE_SDK_TYPE_OPEN_HARMONY;
}

ErrCode QuickFixDeployer::VerifyCodeSignatureForHqf(
    const InnerAppQuickFix &innerAppQuickFix, const std::string &hqfSoPath)
{
    AppQuickFix appQuickFix = innerAppQuickFix.GetAppQuickFix();
    LOG_D(BMSTag::QUICK_FIX, "start, bundleName:%{public}s", appQuickFix.bundleName.c_str());
    BundleInfo bundleInfo;
    if (GetBundleInfo(appQuickFix.bundleName, bundleInfo) != ERR_OK) {
        return ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO;
    }
    if (!isDebug_ || bundleInfo.applicationInfo.appProvisionType != Constants::APP_PROVISION_TYPE_DEBUG) {
        return ERR_OK;
    }
    auto &appQfInfo = appQuickFix.deployingAppqfInfo;
    if (appQfInfo.hqfInfos.empty()) {
        LOG_E(BMSTag::QUICK_FIX, "hqfInfos is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }
    for (const auto &hqf : appQfInfo.hqfInfos) {
        auto iter = std::find_if(std::begin(bundleInfo.hapModuleInfos), std::end(bundleInfo.hapModuleInfos),
            [hqf](const HapModuleInfo &info) {
                return info.moduleName == hqf.moduleName;
            });
        if (iter == bundleInfo.hapModuleInfos.end()) {
            LOG_W(BMSTag::QUICK_FIX, "moduleName:%{public}s not exist", hqf.moduleName.c_str());
            continue;
        }

        CodeSignatureParam codeSignatureParam;
        PrepareCodeSignatureParam(appQuickFix, hqf, bundleInfo, hqfSoPath, codeSignatureParam);
        ErrCode ret = InstalldClient::GetInstance()->VerifyCodeSignatureForHap(codeSignatureParam);
        if (ret != ERR_OK) {
            LOG_E(BMSTag::QUICK_FIX, "moduleName: %{public}s verify code signature failed", hqf.moduleName.c_str());
            return ret;
        }
    }
    LOG_D(BMSTag::QUICK_FIX, "end");
    return ERR_OK;
}

ErrCode QuickFixDeployer::CheckHqfResourceIsValid(
    const std::vector<std::string> bundleFilePaths, const BundleInfo &bundleInfo)
{
    LOG_D(BMSTag::QUICK_FIX, "start, bundleName:%{public}s", bundleInfo.name.c_str());
    if (bundleInfo.applicationInfo.debug &&
        (bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG)) {
        return ERR_OK;
    }
    PatchParser patchParser;
    bool hasResourceFile = patchParser.HasResourceFile(bundleFilePaths);
    if (hasResourceFile) {
        LOG_W(BMSTag::QUICK_FIX, "bundleName:%{public}s check resource failed", bundleInfo.name.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_RELEASE_HAP_HAS_RESOURCES_FILE_FAILED;
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS