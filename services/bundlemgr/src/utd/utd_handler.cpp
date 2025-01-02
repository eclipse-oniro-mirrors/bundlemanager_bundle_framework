/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "utd_handler.h"

#include <sstream>

#include "app_log_tag_wrapper.h"
#include "bundle_extractor.h"
#include "bundle_mgr_service.h"
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
#include "utd_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* UTD_PROFILE_PATH = "resources/rawfile/arkdata/utd/utd.json5";
}

void UtdHandler::InstallUtdAsync(const std::string &bundleName, const int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
    auto installUtdTask = [bundleName, userId]() {
        LOG_I(BMS_TAG_INSTALLER, "install utd,%{public}s,%{public}d", bundleName.c_str(), userId);
        std::string entryHapPath = UtdHandler::GetEntryHapPath(bundleName, userId);
        std::string utdProfile = UtdHandler::GetUtdProfileFromHap(entryHapPath);
        LOG_I(BMS_TAG_INSTALLER, "utdProfile:%{public}zu", utdProfile.size());
        UDMF::UtdClient::GetInstance().InstallCustomUtds(bundleName, utdProfile, userId);
    };
    ffrt::submit(installUtdTask);
#endif
}

void UtdHandler::UninstallUtdAsync(const std::string &bundleName, const int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
    auto uninstallUtdTask = [bundleName, userId]() {
        LOG_I(BMS_TAG_INSTALLER, "uninstall utd,%{public}s,%{public}d", bundleName.c_str(), userId);
        UDMF::UtdClient::GetInstance().UninstallCustomUtds(bundleName, userId);
    };
    ffrt::submit(uninstallUtdTask);
#endif
}

std::string UtdHandler::GetEntryHapPath(const std::string &bundleName, const int32_t userId)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_INSTALLER, "dataMgr is null");
        return Constants::EMPTY_STRING;
    }
    BundleInfo bundleInfo;
    uint32_t flags = static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE);
    flags |= static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE);
    ErrCode ret = dataMgr->GetBundleInfoV9(bundleName, static_cast<int32_t>(flags), bundleInfo, userId);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_INSTALLER, "getBundleInfo failed,%{public}s,%{public}d", bundleName.c_str(), userId);
        return Constants::EMPTY_STRING;
    }
    for (const auto &hapInfo : bundleInfo.hapModuleInfos) {
        if (hapInfo.moduleType == ModuleType::ENTRY) {
            return hapInfo.hapPath;
        }
    }
    LOG_I(BMS_TAG_INSTALLER, "no entry");
    return Constants::EMPTY_STRING;
}

std::string UtdHandler::GetUtdProfileFromHap(const std::string &hapPath)
{
    if (hapPath.empty()) {
        LOG_I(BMS_TAG_INSTALLER, "hapPath empty");
        return Constants::EMPTY_STRING;
    }
    BundleExtractor bundleExtractor(hapPath);
    if (!bundleExtractor.Init()) {
        LOG_W(BMS_TAG_INSTALLER, "extractor init failed");
        return Constants::EMPTY_STRING;
    }
    if (!bundleExtractor.HasEntry(UTD_PROFILE_PATH)) {
        LOG_I(BMS_TAG_INSTALLER, "no utd profile");
        return Constants::EMPTY_STRING;
    }
    std::ostringstream utdJsonStream;
    if (!bundleExtractor.ExtractByName(UTD_PROFILE_PATH, utdJsonStream)) {
        LOG_W(BMS_TAG_INSTALLER, "extract utd profile failed");
        return Constants::EMPTY_STRING;
    }
    return utdJsonStream.str();
}
}  // namespace AppExecFwk
}  // namespace OHOS
