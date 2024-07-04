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
const std::string PATCH_DIR = "patch/";
}

QuickFixDeployer::QuickFixDeployer(const std::vector<std::string> &bundleFilePaths, bool isDebug,
    const std::string &targetPath) : patchPaths_(bundleFilePaths), isDebug_(isDebug), targetPath_(targetPath)
{}

ErrCode QuickFixDeployer::Execute()
{
    ErrCode ret = DeployQuickFix();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "QuickFixDeployer errcode %{public}d", ret);
    }
    return ret;
}

ErrCode QuickFixDeployer::DeployQuickFix()
{
    if (patchPaths_.empty() || (GetQuickFixDataMgr() != ERR_OK)) {
        LOG_E(BMS_TAG_DEFAULT, "DeployQuickFix wrong parms");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }

    std::vector<std::string> realFilePaths;
    ErrCode ret = ProcessBundleFilePaths(patchPaths_, realFilePaths);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "ProcessBundleFilePaths failed");
        return ret;
    }
    ScopeGuard guardRemovePath([realFilePaths] {
        for (const auto &path: realFilePaths) {
            std::string tempPath = path.substr(0, path.rfind(ServiceConstants::PATH_SEPARATOR));
            if (InstalldClient::GetInstance()->RemoveDir(tempPath) != ERR_OK) {
                LOG_E(BMS_TAG_DEFAULT, "RemovePatchFile failed path: %{private}s", tempPath.c_str());
            }
        }
    });
    // parse check multi hqf files, update status DEPLOY_START
    InnerAppQuickFix newInnerAppQuickFix;
    InnerAppQuickFix oldInnerAppQuickFix;
    if ((ret = ToDeployStartStatus(realFilePaths, newInnerAppQuickFix, oldInnerAppQuickFix)) != ERR_OK) {
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
        std::string oldPath = Constants::BUNDLE_CODE_DIR + ServiceConstants::PATH_SEPARATOR +
            appQuick.bundleName + ServiceConstants::PATH_SEPARATOR;
        if (appQuick.deployingAppqfInfo.type == QuickFixType::HOT_RELOAD) {
            oldPath += ServiceConstants::HOT_RELOAD_PATH + std::to_string(appQuick.deployingAppqfInfo.versionCode);
        } else {
            oldPath += ServiceConstants::PATCH_PATH + std::to_string(appQuick.deployingAppqfInfo.versionCode);
        }
        if (InstalldClient::GetInstance()->RemoveDir(oldPath)) {
            LOG_E(BMS_TAG_DEFAULT, "delete %{private}s failed", oldPath.c_str());
        }
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToDeployStartStatus(const std::vector<std::string> &bundleFilePaths,
    InnerAppQuickFix &newInnerAppQuickFix, InnerAppQuickFix &oldInnerAppQuickFix)
{
    LOG_I(BMS_TAG_DEFAULT, "ToDeployStartStatus start.");
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
        LOG_E(BMS_TAG_DEFAULT, "error: wrong quick fix status, now status : %{public}d", mark.status);
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

    LOG_I(BMS_TAG_DEFAULT, "ToDeployStartStatus end.");
    return ERR_OK;
}

void QuickFixDeployer::ToDeployQuickFixResult(const AppQuickFix &appQuickFix)
{
    LOG_D(BMS_TAG_DEFAULT, "ToDeployQuickFixResult start.");
    deployQuickFixResult_.bundleName = appQuickFix.bundleName;
    deployQuickFixResult_.bundleVersionCode = appQuickFix.versionCode;
    deployQuickFixResult_.patchVersionCode = appQuickFix.deployingAppqfInfo.versionCode;
    deployQuickFixResult_.type = appQuickFix.deployingAppqfInfo.type;
    deployQuickFixResult_.isSoContained = HasNativeSoInBundle(appQuickFix);
    deployQuickFixResult_.moduleNames.clear();
    for (const auto &hqf : appQuickFix.deployingAppqfInfo.hqfInfos) {
        deployQuickFixResult_.moduleNames.emplace_back(hqf.moduleName);
    }
    LOG_D(BMS_TAG_DEFAULT, "ToDeployQuickFixResult end.");
}

ErrCode QuickFixDeployer::ProcessPatchDeployStart(
    const std::vector<std::string> bundleFilePaths,
    const BundleInfo &bundleInfo,
    std::unordered_map<std::string, AppQuickFix> &infos)
{
    LOG_I(BMS_TAG_DEFAULT, "ProcessPatchDeployStart start.");
    if (infos.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "error: appQuickFix infos is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }
    QuickFixChecker checker;
    // check multiple cpuAbi and native library path
    ErrCode ret = checker.CheckMultiNativeSo(infos);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "ProcessPatchDeployStart check native so failed");
        return ret;
    }
    // parse signature info
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    ret = checker.CheckMultipleHqfsSignInfo(bundleFilePaths, hapVerifyRes);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "ProcessPatchDeployStart check check multiple hqfs signInfo failed");
        return ret;
    }
    if (hapVerifyRes.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "error: appQuickFix hapVerifyRes is empty");
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
    }
    const auto &provisionInfo = hapVerifyRes[0].GetProvisionInfo();
    const AppQuickFix &appQuickFix = infos.begin()->second;
    // check with installed bundle, signature info, bundleName, versionCode
    ret = checker.CheckPatchWithInstalledBundle(appQuickFix, bundleInfo, provisionInfo);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "check AppQuickFixInfos with installed bundle failed, errcode : %{public}d", ret);
        return ret;
    }
    appDistributionType_ = checker.GetAppDistributionType(provisionInfo.distributionType);
    LOG_I(BMS_TAG_DEFAULT, "ProcessPatchDeployStart end.");
    return ERR_OK;
}

ErrCode QuickFixDeployer::ProcessHotReloadDeployStart(
    const BundleInfo &bundleInfo,
    const AppQuickFix &appQuickFix)
{
    LOG_I(BMS_TAG_DEFAULT, "ProcessHotReloadDeployStart start.");
    QuickFixChecker checker;
    ErrCode ret = checker.CheckHotReloadWithInstalledBundle(appQuickFix, bundleInfo);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "check AppQuickFixInfos with installed bundle failed");
        return ret;
    }
    LOG_I(BMS_TAG_DEFAULT, "ProcessHotReloadDeployStart end.");
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToDeployEndStatus(InnerAppQuickFix &newInnerAppQuickFix,
    const InnerAppQuickFix &oldInnerAppQuickFix)
{
    LOG_I(BMS_TAG_DEFAULT, "ToDeployEndStatus start.");
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
        LOG_E(BMS_TAG_DEFAULT, "error: unknown QuickFixType");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "Process Patch or HotReload DeployEnd failed, bundleName:%{public}s",
            newQuickFix.bundleName.c_str());
        return ret;
    }

    // if so files exist, library path add patch_versionCode;
    // if so files not exist, modify library path to empty.
    ProcessNativeLibraryPath(newPatchPath, newInnerAppQuickFix);

    // move hqf files to new patch path
    ret = MoveHqfFiles(newInnerAppQuickFix, newPatchPath);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "error MoveHqfFiles failed, bundleName: %{public}s", newQuickFix.bundleName.c_str());
        return ret;
    }
    ret = VerifyCodeSignatureForHqf(newInnerAppQuickFix, newPatchPath);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "verify failed bundleName: %{public}s", newQuickFix.bundleName.c_str());
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
        LOG_E(BMS_TAG_DEFAULT, "error: bundleName %{public}s update failed due to innerBundleInfo failed",
            newQuickFix.bundleName.c_str());
        return ret;
    }
    guardRemovePatchPath.Dismiss();
    LOG_I(BMS_TAG_DEFAULT, "ToDeployEndStatus end.");
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

    if (appQuickFix.deployingAppqfInfo.nativeLibraryPath.empty() && !targetPath_.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "nativeLibraryPath is empty, set nativeLibraryPath to targetPath");
        appQuickFix.deployingAppqfInfo.nativeLibraryPath = PATCH_DIR + targetPath_;
    }

    innerAppQuickFix.SetAppQuickFix(appQuickFix);
}

void QuickFixDeployer::ProcessNativeLibraryPath(
    const std::string &patchPath, const InnerAppQuickFix &innerAppQuickFix, std::string &nativeLibraryPath)
{
    bool isSoExist = false;
    auto libraryPath = nativeLibraryPath;
    std::string soPath = patchPath + ServiceConstants::PATH_SEPARATOR + libraryPath;
    if (InstalldClient::GetInstance()->IsExistDir(soPath, isSoExist) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "ProcessNativeLibraryPath IsExistDir(%{public}s) failed", soPath.c_str());
        return;
    }

    AppQuickFix appQuickFix = innerAppQuickFix.GetAppQuickFix();
    if (isSoExist) {
        if (!targetPath_.empty()) {
            nativeLibraryPath = PATCH_DIR + targetPath_ + ServiceConstants::PATH_SEPARATOR + libraryPath;
        } else {
            nativeLibraryPath = ServiceConstants::PATCH_PATH
                + std::to_string(appQuickFix.deployingAppqfInfo.versionCode)
                + ServiceConstants::PATH_SEPARATOR + libraryPath;
        }
    } else {
        LOG_I(BMS_TAG_DEFAULT, "So(%{public}s) is not exist and set nativeLibraryPath(%{public}s) empty",
            soPath.c_str(), nativeLibraryPath.c_str());
        nativeLibraryPath.clear();
    }
}

ErrCode QuickFixDeployer::ProcessPatchDeployEnd(const AppQuickFix &appQuickFix, std::string &patchPath)
{
    if (!targetPath_.empty()) {
        patchPath = Constants::BUNDLE_CODE_DIR + ServiceConstants::PATH_SEPARATOR + appQuickFix.bundleName
            + ServiceConstants::PATH_SEPARATOR + PATCH_DIR + targetPath_;
    } else {
        patchPath = Constants::BUNDLE_CODE_DIR + ServiceConstants::PATH_SEPARATOR + appQuickFix.bundleName
            + ServiceConstants::PATH_SEPARATOR + ServiceConstants::PATCH_PATH
            + std::to_string(appQuickFix.deployingAppqfInfo.versionCode);
    }
    if (InstalldClient::GetInstance()->CreateBundleDir(patchPath) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "error: creat patch path failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_CREATE_PATCH_PATH_FAILED;
    }
    BundleInfo bundleInfo;
    ErrCode ret = GetBundleInfo(appQuickFix.bundleName, bundleInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    if (ExtractQuickFixResFile(appQuickFix, bundleInfo) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "error: ExtractQuickFixResFile failed");
    }
    if (isDebug_ && (bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG)) {
        return ExtractQuickFixSoFile(appQuickFix, patchPath, bundleInfo);
    }
    std::string oldSoPath = ServiceConstants::HAP_COPY_PATH + ServiceConstants::PATH_SEPARATOR +
        appQuickFix.bundleName + ServiceConstants::TMP_SUFFIX + ServiceConstants::LIBS;
    ScopeGuard guardRemoveOldSoPath([oldSoPath] {InstalldClient::GetInstance()->RemoveDir(oldSoPath);});

    ret = ExtractSoAndApplyDiff(appQuickFix, bundleInfo, patchPath);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "error: ExtractSoAndApplyDiff failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ProcessHotReloadDeployEnd(const AppQuickFix &appQuickFix, std::string &patchPath)
{
    patchPath = Constants::BUNDLE_CODE_DIR + ServiceConstants::PATH_SEPARATOR + appQuickFix.bundleName +
        ServiceConstants::PATH_SEPARATOR + ServiceConstants::HOT_RELOAD_PATH +
        std::to_string(appQuickFix.deployingAppqfInfo.versionCode);
    ErrCode ret = InstalldClient::GetInstance()->CreateBundleDir(patchPath);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "error: creat hotreload path failed, errcode %{public}d", ret);
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
        LOG_E(BMS_TAG_DEFAULT, "parse AppQuickFixFiles failed, errcode %{public}d", ret);
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }

    ResetNativeSoAttrs(infos);
    QuickFixChecker checker;
    // check multiple AppQuickFix
    ret = checker.CheckAppQuickFixInfos(infos);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "check AppQuickFixInfos failed");
        return ret;
    }
    const QuickFixType &quickFixType = infos.begin()->second.deployingAppqfInfo.type;
    if (quickFixType == QuickFixType::UNKNOWN) {
        LOG_E(BMS_TAG_DEFAULT, "error unknown quick fix type");
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
        LOG_W(BMS_TAG_DEFAULT, "The number of hqfInfos is not one.");
        return;
    }

    bool isLibIsolated = IsLibIsolated(appQuickFix.bundleName, appqfInfo.hqfInfos[0].moduleName);
    if (!isLibIsolated) {
        LOG_W(BMS_TAG_DEFAULT, "Lib is not isolated.");
        return;
    }

    appqfInfo.hqfInfos[0].cpuAbi = appqfInfo.cpuAbi;
    appqfInfo.hqfInfos[0].nativeLibraryPath =
        appqfInfo.hqfInfos[0].moduleName + ServiceConstants::PATH_SEPARATOR + appqfInfo.nativeLibraryPath;
    appqfInfo.nativeLibraryPath.clear();
}

bool QuickFixDeployer::IsLibIsolated(
    const std::string &bundleName, const std::string &moduleName)
{
    InnerBundleInfo innerBundleInfo;
    if (!FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
        LOG_E(BMS_TAG_DEFAULT, "Fetch bundleInfo(%{public}s) failed.", bundleName.c_str());
        return false;
    }

    return innerBundleInfo.IsLibIsolated(moduleName);
}

bool QuickFixDeployer::FetchInnerBundleInfo(
    const std::string &bundleName, InnerBundleInfo &innerBundleInfo)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "error dataMgr is nullptr");
        return false;
    }

    if (!dataMgr->FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
        LOG_E(BMS_TAG_DEFAULT, "Fetch bundleInfo(%{public}s) failed.", bundleName.c_str());
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
        LOG_E(BMS_TAG_DEFAULT, "error: bms is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = bms->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "error: dataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    // check bundleName is exists
    if (!dataMgr->GetBundleInfo(bundleName, BundleFlag::GET_BUNDLE_DEFAULT,
        bundleInfo, Constants::ANY_USERID)) {
        LOG_E(BMS_TAG_DEFAULT, "error: GetBundleInfo failed, bundleName: %{public}s not exist", bundleName.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ToInnerAppQuickFix(const std::unordered_map<std::string, AppQuickFix> infos,
    const InnerAppQuickFix &oldInnerAppQuickFix, InnerAppQuickFix &newInnerAppQuickFix)
{
    LOG_D(BMS_TAG_DEFAULT, "ToInnerAppQuickFix start");
    if (infos.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "error: appQuickFix is empty");
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
            LOG_E(BMS_TAG_DEFAULT, "error: appQuickFix add hqf moduleName: %{public}s failed", moduleName.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_ADD_HQF_FAILED;
        }
    }
    newInnerAppQuickFix.SetQuickFixMark(mark);
    LOG_D(BMS_TAG_DEFAULT, "ToInnerAppQuickFix end");
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
    LOG_E(BMS_TAG_DEFAULT, "CheckPatchVersionCode failed, version code should be greater than the original");
    return ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_ERROR;
}

ErrCode QuickFixDeployer::SaveAppQuickFix(const InnerAppQuickFix &innerAppQuickFix)
{
    if ((GetQuickFixDataMgr() != ERR_OK)) {
        LOG_E(BMS_TAG_DEFAULT, "error: quickFixDataMgr_ is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    if (!quickFixDataMgr_->SaveInnerAppQuickFix(innerAppQuickFix)) {
        LOG_E(BMS_TAG_DEFAULT, "bundleName: %{public}s, inner app quick fix save failed",
            innerAppQuickFix.GetAppQuickFix().bundleName.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_SAVE_APP_QUICK_FIX_FAILED;
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::MoveHqfFiles(InnerAppQuickFix &innerAppQuickFix, const std::string &targetPath)
{
    LOG_D(BMS_TAG_DEFAULT, "MoveHqfFiles start.");
    if (targetPath.empty() || (GetQuickFixDataMgr() != ERR_OK)) {
        LOG_E(BMS_TAG_DEFAULT, "MoveHqfFiles params error");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    QuickFixMark mark = innerAppQuickFix.GetQuickFixMark();
    AppQuickFix appQuickFix = innerAppQuickFix.GetAppQuickFix();
    std::string path = targetPath;
    if (path.back() != ServiceConstants::FILE_SEPARATOR_CHAR) {
        path.push_back(ServiceConstants::FILE_SEPARATOR_CHAR);
    }
    for (HqfInfo &info : appQuickFix.deployingAppqfInfo.hqfInfos) {
        if (info.hqfFilePath.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "error hapFilePath is empty");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
        }
        std::string realPath = path + info.moduleName + ServiceConstants::QUICK_FIX_FILE_SUFFIX;
        ErrCode ret = InstalldClient::GetInstance()->CopyFile(info.hqfFilePath, realPath);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "error CopyFile failed, errcode: %{public}d", ret);
            return ERR_BUNDLEMANAGER_QUICK_FIX_MOVE_PATCH_FILE_FAILED;
        }
        info.hqfFilePath = realPath;
    }
    mark.status = QuickFixStatus::DEPLOY_END;
    innerAppQuickFix.SetQuickFixMark(mark);
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    LOG_D(BMS_TAG_DEFAULT, "MoveHqfFiles end.");
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
            LOG_E(BMS_TAG_DEFAULT, "error: quickFixDataMgr_ is nullptr");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::SaveToInnerBundleInfo(const InnerAppQuickFix &newInnerAppQuickFix)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "error dataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    const std::string &bundleName = newInnerAppQuickFix.GetAppQuickFix().bundleName;
    InnerBundleInfo innerBundleInfo;
    // obtain innerBundleInfo and enableGuard used to enable bundle which is under disable status
    if (!dataMgr->GetInnerBundleInfo(bundleName, innerBundleInfo)) {
        LOG_E(BMS_TAG_DEFAULT, "cannot obtain the innerbundleInfo from data mgr");
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
        LOG_E(BMS_TAG_DEFAULT, "update quickfix innerbundleInfo failed");
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
        if (path.find(ServiceConstants::RELATIVE_PATH) != std::string::npos) {
            LOG_E(BMS_TAG_DEFAULT, "ProcessBundleFilePaths path is illegal.");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
        }
        if (path.find(ServiceConstants::HAP_COPY_PATH + ServiceConstants::PATH_SEPARATOR +
            ServiceConstants::SECURITY_QUICK_FIX_PATH + ServiceConstants::PATH_SEPARATOR) != 0) {
            LOG_E(BMS_TAG_DEFAULT, "ProcessBundleFilePaths path is illegal.");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
        }
    }
    ErrCode ret = BundleUtil::CheckFilePath(bundleFilePaths, realFilePaths);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "ProcessBundleFilePaths CheckFilePath failed.");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    for (const auto &path : realFilePaths) {
        if (!BundleUtil::CheckFileType(path, ServiceConstants::QUICK_FIX_FILE_SUFFIX)) {
            LOG_E(BMS_TAG_DEFAULT, "ProcessBundleFilePaths CheckFileType failed.");
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
    LOG_D(BMS_TAG_DEFAULT, "start, bundleName:%{public}s", appQuickFix.bundleName.c_str());
    auto &appQfInfo = appQuickFix.deployingAppqfInfo;
    if (appQfInfo.hqfInfos.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "hqfInfos is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }
    for (const auto &hqf : appQfInfo.hqfInfos) {
        auto iter = std::find_if(std::begin(bundleInfo.hapModuleInfos), std::end(bundleInfo.hapModuleInfos),
            [hqf](const HapModuleInfo &info) {
                return info.moduleName == hqf.moduleName;
            });
        if (iter == bundleInfo.hapModuleInfos.end()) {
            LOG_W(BMS_TAG_DEFAULT, "moduleName:%{public}s not exist", hqf.moduleName.c_str());
            continue;
        }

        std::string libraryPath;
        std::string cpuAbi;
        bool isLibIsolated = IsLibIsolated(appQuickFix.bundleName, hqf.moduleName);
        if (!FetchPatchNativeSoAttrs(appQuickFix.deployingAppqfInfo, hqf, isLibIsolated, libraryPath, cpuAbi)) {
            LOG_D(BMS_TAG_DEFAULT, "no so file");
            continue;
        }
        std::string soPath = hqfSoPath + ServiceConstants::PATH_SEPARATOR + libraryPath;
        ExtractParam extractParam;
        extractParam.extractFileType = ExtractFileType::SO;
        extractParam.srcPath = hqf.hqfFilePath;
        extractParam.targetPath = soPath;
        extractParam.cpuAbi = cpuAbi;
        if (InstalldClient::GetInstance()->ExtractFiles(extractParam) != ERR_OK) {
            LOG_W(BMS_TAG_DEFAULT, "moduleName: %{public}s extract so failed", hqf.moduleName.c_str());
            continue;
        }
    }
    LOG_D(BMS_TAG_DEFAULT, "end");
    return ERR_OK;
}

ErrCode QuickFixDeployer::ExtractSoAndApplyDiff(const AppQuickFix &appQuickFix, const BundleInfo &bundleInfo,
    const std::string &patchPath)
{
    auto &appQfInfo = appQuickFix.deployingAppqfInfo;
    for (const auto &hqf : appQfInfo.hqfInfos) {
        // if hap has no so file then continue
        std::string tmpSoPath = ServiceConstants::HAP_COPY_PATH + ServiceConstants::PATH_SEPARATOR +
            appQuickFix.bundleName + ServiceConstants::TMP_SUFFIX + ServiceConstants::LIBS;

        InnerBundleInfo innerBundleInfo;
        if (!FetchInnerBundleInfo(appQuickFix.bundleName, innerBundleInfo)) {
            LOG_E(BMS_TAG_DEFAULT, "Fetch bundleInfo(%{public}s) failed.", appQuickFix.bundleName.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST;
        }
        int32_t bundleUid = Constants::INVALID_UID;
        if (innerBundleInfo.IsEncryptedMoudle(hqf.moduleName)) {
            InnerBundleUserInfo innerBundleUserInfo;
            if (!innerBundleInfo.GetInnerBundleUserInfo(Constants::ALL_USERID, innerBundleUserInfo)) {
                LOG_E(BMS_TAG_DEFAULT, "no user info of bundle %{public}s", appQuickFix.bundleName.c_str());
                return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST;
            }
            bundleUid = innerBundleUserInfo.uid;
            if (!ExtractEncryptedSoFiles(bundleInfo, hqf.moduleName, bundleUid, tmpSoPath)) {
                LOG_W(BMS_TAG_DEFAULT, "module:%{public}s has no so file", hqf.moduleName.c_str());
                continue;
            }
        } else {
            if (!ExtractSoFiles(bundleInfo, hqf.moduleName, tmpSoPath)) {
                LOG_W(BMS_TAG_DEFAULT, "module:%{public}s has no so file", hqf.moduleName.c_str());
                continue;
            }
        }

        auto result = ProcessApplyDiffPatch(appQuickFix, hqf, tmpSoPath, patchPath, bundleUid);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "bundleName: %{public}s Process failed.", appQuickFix.bundleName.c_str());
            return result;
        }
    }
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
        LOG_W(BMS_TAG_DEFAULT, "nativeLibraryPath is empty");
        return false;
    }

    tmpSoPath = (tmpSoPath.back() == ServiceConstants::PATH_SEPARATOR[0]) ? (tmpSoPath + moduleName) :
        (tmpSoPath + ServiceConstants::PATH_SEPARATOR + moduleName);
    ExtractParam extractParam;
    extractParam.extractFileType = ExtractFileType::SO;
    extractParam.srcPath = iter->hapPath;
    extractParam.targetPath = tmpSoPath;
    extractParam.cpuAbi = cpuAbi;
    if (InstalldClient::GetInstance()->ExtractFiles(extractParam) != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s moduleName: %{public}s extract so failed, ",
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
    std::string diffFilePath = ServiceConstants::HAP_COPY_PATH + ServiceConstants::PATH_SEPARATOR +
        appQuickFix.bundleName + ServiceConstants::TMP_SUFFIX;
    ScopeGuard guardRemoveDiffPath([diffFilePath] { InstalldClient::GetInstance()->RemoveDir(diffFilePath); });
    // extract diff so to targetPath
    auto ret = InstalldClient::GetInstance()->ExtractDiffFiles(hqf.hqfFilePath, diffFilePath, cpuAbi);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "error: ExtractDiffFiles failed errcode :%{public}d", ret);
        return ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED;
    }
    // apply diff patch
    std::string newSoPath = patchPath + ServiceConstants::PATH_SEPARATOR + libraryPath;
    ret = InstalldClient::GetInstance()->ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath, uid);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "ApplyDiffPatch failed, bundleName:%{public}s, errcode: %{public}d",
            appQuickFix.bundleName.c_str(), ret);
        return ERR_BUNDLEMANAGER_QUICK_FIX_APPLY_DIFF_PATCH_FAILED;
    }
    return ERR_OK;
}

bool QuickFixDeployer::ExtractEncryptedSoFiles(const BundleInfo &bundleInfo, const std::string &moduleName,
    int32_t uid, std::string &tmpSoPath)
{
    LOG_D(BMS_TAG_DEFAULT, "start to extract decoded so files to tmp path");
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
        LOG_W(BMS_TAG_DEFAULT, "nativeLibraryPath is empty");
        return false;
    }
    std::string hapPath = iter->hapPath;
    std::string realSoFilesPath;
    if (iter->compressNativeLibs) {
        realSoFilesPath.append(Constants::BUNDLE_CODE_DIR).append(ServiceConstants::PATH_SEPARATOR)
            .append(bundleInfo.name).append(ServiceConstants::PATH_SEPARATOR).append(nativeLibraryPath)
            .append(ServiceConstants::PATH_SEPARATOR);
    }
    tmpSoPath = (tmpSoPath.back() == ServiceConstants::PATH_SEPARATOR[0]) ? (tmpSoPath + moduleName) :
        (tmpSoPath + ServiceConstants::PATH_SEPARATOR + moduleName + ServiceConstants::PATH_SEPARATOR);
    LOG_D(BMS_TAG_DEFAULT, "real so path is %{public}s tmpSoPath is %{public}s",
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
        LOG_I(BMS_TAG_DEFAULT, "no so file");
        codeSignatureParam.targetSoPath = "";
    } else {
        std::string soPath = hqfSoPath.substr(0, hqfSoPath.rfind(ServiceConstants::PATH_SEPARATOR) + 1) + libraryPath;
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
    LOG_D(BMS_TAG_DEFAULT, "start, bundleName:%{public}s", appQuickFix.bundleName.c_str());
    BundleInfo bundleInfo;
    if (GetBundleInfo(appQuickFix.bundleName, bundleInfo) != ERR_OK) {
        return ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO;
    }
    if (!isDebug_ || bundleInfo.applicationInfo.appProvisionType != Constants::APP_PROVISION_TYPE_DEBUG) {
        return ERR_OK;
    }
    auto &appQfInfo = appQuickFix.deployingAppqfInfo;
    if (appQfInfo.hqfInfos.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "hqfInfos is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }
    for (const auto &hqf : appQfInfo.hqfInfos) {
        auto iter = std::find_if(std::begin(bundleInfo.hapModuleInfos), std::end(bundleInfo.hapModuleInfos),
            [hqf](const HapModuleInfo &info) {
                return info.moduleName == hqf.moduleName;
            });
        if (iter == bundleInfo.hapModuleInfos.end()) {
            LOG_W(BMS_TAG_DEFAULT, "moduleName:%{public}s not exist", hqf.moduleName.c_str());
            continue;
        }

        CodeSignatureParam codeSignatureParam;
        PrepareCodeSignatureParam(appQuickFix, hqf, bundleInfo, hqfSoPath, codeSignatureParam);
        ErrCode ret = InstalldClient::GetInstance()->VerifyCodeSignatureForHap(codeSignatureParam);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "moduleName: %{public}s verify code signature failed", hqf.moduleName.c_str());
            return ret;
        }
    }
    LOG_D(BMS_TAG_DEFAULT, "end");
    return ERR_OK;
}

ErrCode QuickFixDeployer::CheckHqfResourceIsValid(
    const std::vector<std::string> bundleFilePaths, const BundleInfo &bundleInfo)
{
    LOG_D(BMS_TAG_DEFAULT, "start, bundleName:%{public}s", bundleInfo.name.c_str());
    if (bundleInfo.applicationInfo.debug &&
        (bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG)) {
        return ERR_OK;
    }
    PatchParser patchParser;
    bool hasResourceFile = patchParser.HasResourceFile(bundleFilePaths);
    if (hasResourceFile) {
        LOG_W(BMS_TAG_DEFAULT, "bundleName:%{public}s check resource failed", bundleInfo.name.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_RELEASE_HAP_HAS_RESOURCES_FILE_FAILED;
    }
    return ERR_OK;
}

ErrCode QuickFixDeployer::ExtractQuickFixResFile(const AppQuickFix &appQuickFix, const BundleInfo &bundleInfo)
{
    LOG_D(BMS_TAG_DEFAULT, "ExtractQuickFixResFile start, bundleName:%{public}s", appQuickFix.bundleName.c_str());
    auto &appQfInfo = appQuickFix.deployingAppqfInfo;
    if (appQfInfo.hqfInfos.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "hqfInfos is empty");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
    }
    for (const auto &hqf : appQfInfo.hqfInfos) {
        auto iter = std::find_if(std::begin(bundleInfo.hapModuleInfos), std::end(bundleInfo.hapModuleInfos),
            [hqf](const HapModuleInfo &info) {
                return info.moduleName == hqf.moduleName;
            });
        if (iter == bundleInfo.hapModuleInfos.end()) {
            LOG_W(BMS_TAG_DEFAULT, "moduleName:%{public}s not exist", hqf.moduleName.c_str());
            continue;
        }

        std::string targetPath = Constants::BUNDLE_CODE_DIR + ServiceConstants::PATH_SEPARATOR + appQuickFix.bundleName
            + ServiceConstants::PATH_SEPARATOR + hqf.moduleName + ServiceConstants::PATH_SEPARATOR
            + ServiceConstants::RES_FILE_PATH;
        ExtractParam extractParam;
        extractParam.extractFileType = ExtractFileType::RES_FILE;
        extractParam.srcPath = hqf.hqfFilePath;
        extractParam.targetPath = targetPath;
        if (InstalldClient::GetInstance()->ExtractFiles(extractParam) != ERR_OK) {
            LOG_W(BMS_TAG_DEFAULT, "moduleName: %{public}s extract so failed", hqf.moduleName.c_str());
            continue;
        }
    }
    LOG_D(BMS_TAG_DEFAULT, "ExtractQuickFixResFile end");
    return ERR_OK;
}
} // AppExecFwk
} // OHOS