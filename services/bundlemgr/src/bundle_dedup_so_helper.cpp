/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "bundle_dedup_so_helper.h"

#include "app_log_tag_wrapper.h"
#include "bundle_parser.h"
#include "bundle_util.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// Derive the effective bundle name from the target so path (stripping the
// +new- staging prefix) for the installd-side domain validation.
std::string GetEffectiveBundleNameFromSoPath(const std::string &targetSoPath)
{
    std::string codeDirPrefix = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR;
    if (!BundleUtil::StartWith(targetSoPath, codeDirPrefix)) {
        return std::string();
    }
    size_t nameStart = codeDirPrefix.size();
    size_t nameEnd = targetSoPath.find(ServiceConstants::PATH_SEPARATOR, nameStart);
    if (nameEnd == std::string::npos || nameEnd == nameStart) {
        return std::string();
    }
    std::string bundleName = targetSoPath.substr(nameStart, nameEnd - nameStart);
    // bundle-update staging rotate dir: +new-<bundleName>
    std::string stagingPrefix = ServiceConstants::BUNDLE_NEW_CODE_DIR;
    if (BundleUtil::StartWith(bundleName, stagingPrefix)) {
        bundleName = bundleName.substr(stagingPrefix.size());
    }
    return bundleName;
}
}  // namespace

ErrCode DedupSoHelper::MapLinkResultCode(uint32_t resultCode)
{
    switch (resultCode) {
        case SO_DEDUP_RESULT_LINKED:
        case SO_DEDUP_RESULT_ALREADY_LINKED:
            // already linked is an idempotent success
            return ERR_OK;
        case SO_DEDUP_RESULT_NO_MATCH:
            return ERR_APPEXECFWK_INSTALL_DEDUP_SO_NO_MATCH;
        case SO_DEDUP_RESULT_CONFIG_UNAVAILABLE:
            return ERR_APPEXECFWK_INSTALL_DEDUP_SO_CONFIG_UNAVAILABLE;
        case SO_DEDUP_RESULT_VERSION_MISMATCH:
            // musl already created a fallback symlink: fail closed so the rollback removes it
            return ERR_APPEXECFWK_INSTALL_DEDUP_SO_VERSION_MISMATCH;
        default:
            // SO_DEDUP_RESULT_ERROR and any unexpected value
            return ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED;
    }
}

ErrCode DedupSoHelper::ProcessDedupSoFiles(const std::string &hapPath, const InnerBundleInfo &newBundleInfo,
    const std::string &targetSoPath, const std::string &cpuAbi)
{
    // FA-model or driver-type packages keep the normal install flow
    if (!newBundleInfo.GetIsNewVersion() || newBundleInfo.HasDriverExtension()) {
        LOG_D(BMS_TAG_INSTALLER, "ignore dedupfiles.json for FA model or driver type bundle");
        return ERR_OK;
    }
    if (hapPath.empty()) {
        LOG_D(BMS_TAG_INSTALLER, "no hap path, skip dedup so link");
        return ERR_OK;
    }

    DedupSoInfoList dedupSoInfoList;
    auto result = BundleParser().ParseDedupFiles(hapPath, newBundleInfo.GetBundleName(), dedupSoInfoList);
    if (result != ERR_OK) {
        // DEBUG here: the parser already logged one ERROR for this failure
        LOG_D(BMS_TAG_INSTALLER, "parse dedupfiles.json failed, error is %{public}d", result);
        return result;
    }
    if (dedupSoInfoList.empty()) {
        LOG_D(BMS_TAG_INSTALLER, "no dedupfiles.json in the hap, skip dedup so link");
        return ERR_OK;
    }
    if (targetSoPath.empty()) {
        // the manifest is not empty, so the so is expected; an empty target
        // path (the abi derivation failed) fails closed with 8519951 instead
        // of installing a bundle whose so is missing at runtime
        LOG_E(BMS_TAG_INSTALLER,
            "bundleName: %{public}s dedup manifest is not empty but target so path is empty",
            newBundleInfo.GetBundleName().c_str());
        return ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED;
    }

    std::string bundleName = GetEffectiveBundleNameFromSoPath(targetSoPath);
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "bundleName: %{public}s invalid target so path %{private}s",
            newBundleInfo.GetBundleName().c_str(), targetSoPath.c_str());
        return ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED;
    }
    // only the entries matching the installed module's cpu abi are linked, other
    // ABIs are filtered out; the abi is the per-module derivation, never GetCpuAbi()
    std::string abiPrefix =
        std::string(ServiceConstants::LIBS) + cpuAbi + ServiceConstants::PATH_SEPARATOR;
    // matched-and-linked count, feeds only the summary log below
    size_t linkedCount = 0;
    for (const auto &dedupSoInfo : dedupSoInfoList) {
        if (!BundleUtil::StartWith(dedupSoInfo.originalPathInHap, abiPrefix)) {
            continue;
        }
        std::string libraryPath = targetSoPath + dedupSoInfo.originalPathInHap.substr(abiPrefix.length());
        uint32_t resultCode = 0;
        auto ipcResult = InstalldClient::GetInstance()->LinkDedupedSo(
            bundleName, libraryPath, dedupSoInfo.originalSha256, resultCode);
        if (ipcResult != ERR_OK) {
            // the single ERROR of the ipc failure chain (the proxy layer stays
            // at DEBUG); the fault event also rides the BUNDLE_INSTALL_EXCEPTION chain
            LOG_E(BMS_TAG_INSTALLER,
                "bundleName: %{public}s LinkDedupedSo ipc failed, libraryPath is %{private}s, error is %{public}d",
                bundleName.c_str(), libraryPath.c_str(), ipcResult);
            return ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED;
        }
        result = MapLinkResultCode(resultCode);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLER,
                "bundleName: %{public}s link so failed, libraryPath: %{private}s, "
                "resultCode: %{public}u, error is %{public}d",
                bundleName.c_str(), libraryPath.c_str(), resultCode, result);
            return result;
        }
        linkedCount++;
    }
    if (linkedCount == 0) {
        // trusted zero-match: an entry the manifest does not carry for the
        // installed module abi is a so the hap does not need, so one WARN is
        // the expected outcome, never an error
        LOG_W(BMS_TAG_INSTALLER, "bundleName: %{public}s no dedup so entry matched the module abi %{public}s, "
            "total: %{public}zu",
            newBundleInfo.GetBundleName().c_str(), cpuAbi.c_str(), dedupSoInfoList.size());
        return ERR_OK;
    }
    // one INFO per install, not a hot path: declared vs abi-matched link count
    LOG_I(BMS_TAG_INSTALLER, "dedup so link finished, total: %{public}zu, linked: %{public}zu",
        dedupSoInfoList.size(), linkedCount);
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
