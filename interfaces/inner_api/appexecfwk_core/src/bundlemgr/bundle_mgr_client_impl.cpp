/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "bundle_mgr_client_impl.h"

#include <cerrno>
#include <fstream>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service_death_recipient.h"
#include "iservice_registry.h"
#include "nlohmann/json.hpp"
#include "system_ability_definition.h"

#ifdef GLOBAL_RESMGR_ENABLE
using namespace OHOS::Global::Resource;
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* BUNDLE_MAP_CODE_PATH = "/data/storage/el1/bundle";
const char* DATA_APP_PATH = "/data/app";
#ifdef GLOBAL_RESMGR_ENABLE
constexpr const char* PROFILE_FILE_PREFIX = "$profile:";
#endif
const char* PATH_SEPARATOR = "/";
} // namespace

BundleMgrClientImpl::BundleMgrClientImpl()
{
    APP_LOGD("create bundleMgrClientImpl");
}

BundleMgrClientImpl::~BundleMgrClientImpl()
{
    APP_LOGD("destroy bundleMgrClientImpl");
    std::lock_guard<std::mutex> lock(mutex_);
    if (bundleMgr_ != nullptr && deathRecipient_ != nullptr) {
        bundleMgr_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
}

ErrCode BundleMgrClientImpl::GetNameForUid(const int uid, std::string &name)
{
    if (Connect() != ERR_OK) {
        APP_LOGE("failed to connect");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return bundleMgr_->GetNameForUid(uid, name);
}

bool BundleMgrClientImpl::GetBundleInfo(const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo,
    int32_t userId)
{
    LOG_D(BMS_TAG_QUERY, "GetBundleInfo begin");

    ErrCode result = Connect();
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_QUERY, "failed to connect");
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return bundleMgr_->GetBundleInfo(bundleName, flag, bundleInfo, userId);
}

ErrCode BundleMgrClientImpl::GetBundlePackInfo(
    const std::string &bundleName, const BundlePackFlag flag, BundlePackInfo &bundlePackInfo, int32_t userId)
{
    APP_LOGD("enter");
    ErrCode result = Connect();
    if (result != ERR_OK) {
        APP_LOGE("failed to connect");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return bundleMgr_->GetBundlePackInfo(bundleName, flag, bundlePackInfo, userId);
}

ErrCode BundleMgrClientImpl::CreateBundleDataDir(int32_t userId)
{
    APP_LOGD("enter");
    ErrCode result = Connect();
    if (result != ERR_OK) {
        APP_LOGE("failed to connect");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return bundleMgr_->CreateBundleDataDir(userId);
}

bool BundleMgrClientImpl::GetHapModuleInfo(const std::string &bundleName, const std::string &hapName,
    HapModuleInfo &hapModuleInfo)
{
    ErrCode result = Connect();
    if (result != ERR_OK) {
        APP_LOGE("failed to connect");
        return false;
    }

    AbilityInfo info;
    info.bundleName = bundleName;
    info.package = hapName;
    std::lock_guard<std::mutex> lock(mutex_);
    return bundleMgr_->GetHapModuleInfo(info, hapModuleInfo);
}

bool BundleMgrClientImpl::GetResConfigFile(const HapModuleInfo &hapModuleInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos) const
{
    bool isCompressed = !hapModuleInfo.hapPath.empty();
    std::string resourcePath = isCompressed ? hapModuleInfo.hapPath : hapModuleInfo.resourcePath;
    if (!GetResProfileByMetadata(hapModuleInfo.metadata, metadataName, resourcePath, isCompressed, profileInfos)) {
        APP_LOGE("GetResProfileByMetadata failed");
        return false;
    }
    if (profileInfos.empty()) {
        APP_LOGE("no valid file can be obtained");
        return false;
    }
    int32_t InfoSize = static_cast<int32_t>(profileInfos.size());
    APP_LOGD("The size of the profile info is : %{public}d", InfoSize);
    return true;
}

bool BundleMgrClientImpl::GetResConfigFile(const ExtensionAbilityInfo &extensionInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos) const
{
    bool isCompressed = !extensionInfo.hapPath.empty();
    std::string resourcePath = isCompressed ? extensionInfo.hapPath : extensionInfo.resourcePath;
    if (!GetResProfileByMetadata(extensionInfo.metadata, metadataName, resourcePath, isCompressed, profileInfos)) {
        APP_LOGE("GetResProfileByMetadata failed");
        return false;
    }
    if (profileInfos.empty()) {
        APP_LOGE("no valid file can be obtained");
        return false;
    }
    int32_t InfoSize = static_cast<int32_t>(profileInfos.size());
    APP_LOGD("The size of the profile info is : %{public}d", InfoSize);
    return true;
}

bool BundleMgrClientImpl::GetResConfigFile(const AbilityInfo &abilityInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos) const
{
    bool isCompressed = !abilityInfo.hapPath.empty();
    std::string resourcePath = isCompressed ? abilityInfo.hapPath : abilityInfo.resourcePath;
    if (!GetResProfileByMetadata(abilityInfo.metadata, metadataName, resourcePath, isCompressed, profileInfos)) {
        APP_LOGE("GetResProfileByMetadata failed");
        return false;
    }
    if (profileInfos.empty()) {
        APP_LOGE("no valid file can be obtained");
        return false;
    }
    return true;
}

bool BundleMgrClientImpl::GetProfileFromExtension(const ExtensionAbilityInfo &extensionInfo,
    const std::string &metadataName, std::vector<std::string> &profileInfos) const
{
    APP_LOGD("get extension config file from extension dir begin");
    bool isCompressed = !extensionInfo.hapPath.empty();
    std::string resPath = isCompressed ? extensionInfo.hapPath : extensionInfo.resourcePath;
    if (!ConvertResourcePath(extensionInfo.bundleName, resPath, isCompressed)) {
        APP_LOGE("ConvertResourcePath failed %{public}s", resPath.c_str());
        return false;
    }
    ExtensionAbilityInfo innerExtension = extensionInfo;
    if (isCompressed) {
        innerExtension.hapPath = resPath;
    } else {
        innerExtension.resourcePath = resPath;
    }
    return GetResConfigFile(innerExtension, metadataName, profileInfos);
}

bool BundleMgrClientImpl::GetProfileFromAbility(const AbilityInfo &abilityInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos) const
{
    APP_LOGD("get ability config file from ability begin");
    bool isCompressed = !abilityInfo.hapPath.empty();
    std::string resPath = isCompressed ? abilityInfo.hapPath : abilityInfo.resourcePath;
    if (!ConvertResourcePath(abilityInfo.bundleName, resPath, isCompressed)) {
        APP_LOGE("ConvertResourcePath failed %{public}s", resPath.c_str());
        return false;
    }
    AbilityInfo innerAbilityInfo = abilityInfo;
    if (isCompressed) {
        innerAbilityInfo.hapPath = resPath;
    } else {
        innerAbilityInfo.resourcePath = resPath;
    }
    return GetResConfigFile(innerAbilityInfo, metadataName, profileInfos);
}

bool BundleMgrClientImpl::GetProfileFromHap(const HapModuleInfo &hapModuleInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos) const
{
    APP_LOGD("get hap module config file from hap begin");
    bool isCompressed = !hapModuleInfo.hapPath.empty();
    std::string resPath = isCompressed ? hapModuleInfo.hapPath : hapModuleInfo.resourcePath;
    if (!ConvertResourcePath(hapModuleInfo.bundleName, resPath, isCompressed)) {
        APP_LOGE("ConvertResourcePath failed %{public}s", resPath.c_str());
        return false;
    }
    HapModuleInfo innerHapModuleInfo = hapModuleInfo;
    if (isCompressed) {
        innerHapModuleInfo.hapPath = resPath;
    } else {
        innerHapModuleInfo.resourcePath = resPath;
    }
    return GetResConfigFile(innerHapModuleInfo, metadataName, profileInfos);
}

bool BundleMgrClientImpl::ConvertResourcePath(
    const std::string &bundleName, std::string &resPath, bool isCompressed) const
{
    if (resPath.empty()) {
        APP_LOGE("res path is empty");
        return false;
    }
    if (isCompressed && (resPath.find(DATA_APP_PATH) != 0)) {
        APP_LOGD("no need to convert to sandbox path");
        return true;
    }
    std::string innerStr = std::string(Constants::BUNDLE_CODE_DIR) + std::string(PATH_SEPARATOR) + bundleName;
    if (resPath.find(innerStr) == std::string::npos) {
        APP_LOGE("res path is incorrect");
        return false;
    }
    resPath.replace(0, innerStr.length(), BUNDLE_MAP_CODE_PATH);
    return true;
}

bool BundleMgrClientImpl::GetResProfileByMetadata(const std::vector<Metadata> &metadata,
    const std::string &metadataName, const std ::string &resourcePath, bool isCompressed,
    std::vector<std::string> &profileInfos) const
{
#ifdef GLOBAL_RESMGR_ENABLE
    if (metadata.empty()) {
        APP_LOGE("GetResProfileByMetadata failed due to empty metadata");
        return false;
    }
    if (resourcePath.empty()) {
        APP_LOGE("GetResProfileByMetadata failed due to empty resourcePath");
        return false;
    }
    std::shared_ptr<ResourceManager> resMgr = InitResMgr(resourcePath);
    if (resMgr == nullptr) {
        APP_LOGE("GetResProfileByMetadata init resMgr failed");
        return false;
    }

    if (metadataName.empty()) {
        for_each(metadata.begin(), metadata.end(),
            [this, &resMgr, isCompressed, &profileInfos](const Metadata& data)->void {
            if (!GetResFromResMgr(data.resource, resMgr, isCompressed, profileInfos)) {
                APP_LOGW("GetResFromResMgr failed");
            }
        });
    } else {
        for_each(metadata.begin(), metadata.end(),
            [this, &resMgr, &metadataName, isCompressed, &profileInfos](const Metadata& data)->void {
            if ((metadataName.compare(data.name) == 0)
                && (!GetResFromResMgr(data.resource, resMgr, isCompressed, profileInfos))) {
                APP_LOGW("GetResFromResMgr failed");
            }
        });
    }

    return true;
#else
    APP_LOGW("GLOBAL_RESMGR_ENABLE is false");
    return false;
#endif
}

#ifdef GLOBAL_RESMGR_ENABLE
std::shared_ptr<ResourceManager> BundleMgrClientImpl::InitResMgr(const std::string &resourcePath) const
{
    APP_LOGD("InitResMgr begin");
    if (resourcePath.empty()) {
        APP_LOGE("InitResMgr failed due to invalid param");
        return nullptr;
    }
    std::shared_ptr<ResourceManager> resMgr(CreateResourceManager());
    if (!resMgr) {
        APP_LOGE("InitResMgr resMgr is nullptr");
        return nullptr;
    }

    std::unique_ptr<ResConfig> resConfig(CreateResConfig());
    if (!resConfig) {
        APP_LOGE("InitResMgr resConfig is nullptr");
        return nullptr;
    }
    resMgr->UpdateResConfig(*resConfig);

    APP_LOGD("resourcePath is %{private}s", resourcePath.c_str());
    if (!resourcePath.empty() && !resMgr->AddResource(resourcePath.c_str())) {
        APP_LOGE("InitResMgr AddResource failed");
        return nullptr;
    }
    return resMgr;
}

bool BundleMgrClientImpl::GetResFromResMgr(const std::string &resName, const std::shared_ptr<ResourceManager> &resMgr,
    bool isCompressed, std::vector<std::string> &profileInfos) const
{
    APP_LOGD("GetResFromResMgr begin");
    if (resName.empty()) {
        APP_LOGE("GetResFromResMgr res name is empty");
        return false;
    }

    size_t pos = resName.rfind(PROFILE_FILE_PREFIX);
    if ((pos == std::string::npos) || (pos == resName.length() - strlen(PROFILE_FILE_PREFIX))) {
        APP_LOGE("GetResFromResMgr res name %{public}s invalid", resName.c_str());
        return false;
    }
    std::string profileName = resName.substr(pos + strlen(PROFILE_FILE_PREFIX));
    // hap is compressed status, get file content.
    if (isCompressed) {
        APP_LOGD("compressed status");
        std::unique_ptr<uint8_t[]> fileContentPtr = nullptr;
        size_t len = 0;
        if (resMgr->GetProfileDataByName(profileName.c_str(), len, fileContentPtr) != SUCCESS) {
            APP_LOGE("GetProfileDataByName failed");
            return false;
        }
        if (fileContentPtr == nullptr || len == 0) {
            APP_LOGE("invalid data");
            return false;
        }
        std::string rawData(fileContentPtr.get(), fileContentPtr.get() + len);
        nlohmann::json profileJson = nlohmann::json::parse(rawData, nullptr, false);
        if (profileJson.is_discarded()) {
            APP_LOGE("bad profile file");
            return false;
        }
        profileInfos.emplace_back(profileJson.dump());
        return true;
    }
    // hap is decompressed status, get file path then read file.
    std::string resPath;
    if (resMgr->GetProfileByName(profileName.c_str(), resPath) != SUCCESS) {
        APP_LOGE("GetResFromResMgr profileName cannot be found");
        return false;
    }
    APP_LOGD("GetResFromResMgr resPath is %{private}s", resPath.c_str());
    std::string profile;
    if (!TransformFileToJsonString(resPath, profile)) {
        return false;
    }
    profileInfos.emplace_back(profile);
    return true;
}
#endif

bool BundleMgrClientImpl::IsFileExisted(const std::string &filePath) const
{
    if (filePath.empty()) {
        APP_LOGE("the file is not existed due to empty file path");
        return false;
    }

    if (access(filePath.c_str(), F_OK) != 0) {
        APP_LOGE("not access file: %{private}s errno: %{public}d", filePath.c_str(), errno);
        return false;
    }
    return true;
}

bool BundleMgrClientImpl::TransformFileToJsonString(const std::string &resPath, std::string &profile) const
{
    if (!IsFileExisted(resPath)) {
        APP_LOGE("the file is not existed");
        return false;
    }
    std::fstream in;
    char errBuf[256];
    errBuf[0] = '\0';
    in.open(resPath, std::ios_base::in | std::ios_base::binary);
    if (!in.is_open()) {
        strerror_r(errno, errBuf, sizeof(errBuf));
        APP_LOGE("file open fail due to %{public}s errno:%{public}d", errBuf, errno);
        return false;
    }
    in.seekg(0, std::ios::end);
    int64_t size = in.tellg();
    if (size <= 0) {
        APP_LOGE("file empty err %{public}d", errno);
        in.close();
        return false;
    }
    in.seekg(0, std::ios::beg);
    nlohmann::json profileJson = nlohmann::json::parse(in, nullptr, false);
    if (profileJson.is_discarded()) {
        APP_LOGE("bad profile file");
        in.close();
        return false;
    }
    profile = profileJson.dump();
    in.close();
    return true;
}

ErrCode BundleMgrClientImpl::InstallSandboxApp(const std::string &bundleName, int32_t dlpType, int32_t userId,
    int32_t &appIndex)
{
    APP_LOGD("InstallSandboxApp begin");
    if (bundleName.empty()) {
        APP_LOGE("InstallSandboxApp bundleName is empty");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    ErrCode result = Connect();
    if (result != ERR_OK) {
        APP_LOGE("failed to connect");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return bundleInstaller_->InstallSandboxApp(bundleName, dlpType, userId, appIndex);
}

ErrCode BundleMgrClientImpl::UninstallSandboxApp(const std::string &bundleName, int32_t appIndex, int32_t userId)
{
    APP_LOGD("UninstallSandboxApp begin");
    if (bundleName.empty() || appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX) {
        APP_LOGE("UninstallSandboxApp params are invalid");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    ErrCode result = Connect();
    if (result != ERR_OK) {
        APP_LOGE("failed to connect");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return bundleInstaller_->UninstallSandboxApp(bundleName, appIndex, userId);
}

ErrCode BundleMgrClientImpl::GetSandboxBundleInfo(
    const std::string &bundleName, int32_t appIndex, int32_t userId, BundleInfo &info)
{
    APP_LOGD("GetSandboxBundleInfo begin");
    if (bundleName.empty() || appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX) {
        APP_LOGE("UninstallSandboxApp params are invalid");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }

    ErrCode result = Connect();
    if (result != ERR_OK) {
        APP_LOGE("failed to connect");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return bundleMgr_->GetSandboxBundleInfo(bundleName, appIndex, userId, info);
}

ErrCode BundleMgrClientImpl::GetSandboxAbilityInfo(const Want &want, int32_t appIndex, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo)
{
    APP_LOGD("GetSandboxAbilityInfo begin");
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("GetSandboxAbilityInfo params are invalid");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    ErrCode result = Connect();
    if (result != ERR_OK) {
        APP_LOGE("failed to connect");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return bundleMgr_->GetSandboxAbilityInfo(want, appIndex, flags, userId, abilityInfo);
}

ErrCode BundleMgrClientImpl::GetSandboxExtAbilityInfos(const Want &want, int32_t appIndex, int32_t flags,
    int32_t userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    APP_LOGD("GetSandboxExtensionAbilityInfos begin");
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("GetSandboxExtensionAbilityInfos params are invalid");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    ErrCode result = Connect();
    if (result != ERR_OK) {
        APP_LOGE("failed to connect");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return bundleMgr_->GetSandboxExtAbilityInfos(want, appIndex, flags, userId, extensionInfos);
}

ErrCode BundleMgrClientImpl::GetSandboxHapModuleInfo(const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId,
    HapModuleInfo &hapModuleInfo)
{
    APP_LOGD("GetSandboxHapModuleInfo begin");
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("GetSandboxHapModuleInfo params are invalid");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    ErrCode result = Connect();
    if (result != ERR_OK) {
        APP_LOGE("failed to connect");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return bundleMgr_->GetSandboxHapModuleInfo(abilityInfo, appIndex, userId, hapModuleInfo);
}

ErrCode BundleMgrClientImpl::Connect()
{
    APP_LOGD("connect begin");
    std::lock_guard<std::mutex> lock(mutex_);
    if (bundleMgr_ == nullptr) {
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityManager == nullptr) {
            APP_LOGE("failed to get system ability manager");
            return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
        }

        sptr<IRemoteObject> remoteObject_ = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (remoteObject_ == nullptr || (bundleMgr_ = iface_cast<IBundleMgr>(remoteObject_)) == nullptr) {
            APP_LOGE("failed to get bundle mgr service remote object");
            return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
        }
        std::weak_ptr<BundleMgrClientImpl> weakPtr = shared_from_this();
        auto deathCallback = [weakPtr](const wptr<IRemoteObject>& object) {
            auto sharedPtr = weakPtr.lock();
            if (sharedPtr != nullptr) {
                sharedPtr->OnDeath();
            }
        };
        deathRecipient_ = new (std::nothrow) BundleMgrServiceDeathRecipient(deathCallback);
        bundleMgr_->AsObject()->AddDeathRecipient(deathRecipient_);
    }

    if (bundleInstaller_ == nullptr) {
        bundleInstaller_ = bundleMgr_->GetBundleInstaller();
        if ((bundleInstaller_ == nullptr) || (bundleInstaller_->AsObject() == nullptr)) {
            APP_LOGE("failed to get bundle installer proxy");
            return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
        }
    }
    APP_LOGD("connect end");
    return ERR_OK;
}

void BundleMgrClientImpl::OnDeath()
{
    APP_LOGD("BundleManagerService dead");
    std::lock_guard<std::mutex> lock(mutex_);
    bundleMgr_ = nullptr;
    bundleInstaller_ = nullptr;
}
}  // namespace AppExecFwk
}  // namespace OHOS