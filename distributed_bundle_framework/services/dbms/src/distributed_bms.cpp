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

#include "distributed_bms.h"

#include <fstream>
#include <vector>

#include "account_manager_helper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "distributed_bms_proxy.h"
#include "distributed_data_storage.h"
#include "event_report.h"
#include "iservice_registry.h"
#include "if_system_ability_manager.h"
#include "locale_config.h"
#include "locale_info.h"
#include "image_compress.h"
#include "image_packer.h"
#include "image_source.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const uint8_t DECODE_VALUE_ONE = 1;
    const uint8_t DECODE_VALUE_TWO = 2;
    const uint8_t DECODE_VALUE_THREE = 3;
    const unsigned char DECODE_VALUE_CHAR_THREE = 3;
    const uint8_t DECODE_VALUE_FOUR = 4;
    const uint8_t DECODE_VALUE_SIX = 6;
    const unsigned char DECODE_VALUE_CHAR_FIFTEEN = 15;
    const unsigned char DECODE_VALUE_CHAR_SIXTY_THREE = 63;
    const std::vector<char> DECODE_TABLE = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };
    const std::string POSTFIX = "_Compress.";

    DBMSEventInfo GetEventInfo(
        const std::vector<ElementName> &elements, const std::string &localeInfo, int32_t resultCode)
    {
        DBMSEventInfo eventInfo;
        if (elements.empty()) {
            return eventInfo;
        }

        eventInfo.deviceID = elements[0].GetDeviceID();
        eventInfo.localeInfo = localeInfo;
        for (auto element : elements) {
            if (eventInfo.bundleName.empty()) {
                eventInfo.bundleName.append(element.GetBundleName());
            } else {
                eventInfo.bundleName.append(";").append(element.GetBundleName());
            }

            if (eventInfo.abilityName.empty()) {
                eventInfo.abilityName.append(element.GetAbilityName());
            } else {
                eventInfo.abilityName.append(";").append(element.GetAbilityName());
            }
        }

        eventInfo.resultCode = resultCode;
        return eventInfo;
    }

    DBMSEventInfo GetEventInfo(
        const ElementName &element, const std::string &localeInfo, int32_t resultCode)
    {
        DBMSEventInfo eventInfo;
        eventInfo.bundleName = element.GetBundleName();
        eventInfo.abilityName = element.GetAbilityName();
        eventInfo.deviceID = element.GetDeviceID();
        eventInfo.localeInfo = localeInfo;
        eventInfo.resultCode = resultCode;
        return eventInfo;
    }
}
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<DistributedBms>::GetInstance().get());

DistributedBms::DistributedBms() : SystemAbility(DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, true)
{
    APP_LOGI("DistributedBms :%{public}s call", __func__);
}

DistributedBms::~DistributedBms()
{
    APP_LOGI("DistributedBms: DBundleMgrService");
}

void DistributedBms::OnStart()
{
    APP_LOGI("DistributedBms: OnStart");
    Init();
    bool res = Publish(this);
    if (!res) {
        APP_LOGE("DistributedBms: OnStart failed");
    }
    APP_LOGI("DistributedBms: OnStart end");
}

void DistributedBms::OnStop()
{
    APP_LOGI("DistributedBms: OnStop");
    if (distributedSub_ != nullptr) {
        EventFwk::CommonEventManager::UnSubscribeCommonEvent(distributedSub_);
    }
}

void DistributedBms::Init()
{
    APP_LOGI("DistributedBms: Init");
    DistributedDataStorage::GetInstance();
    if (distributedSub_ == nullptr) {
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
        EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
        distributedSub_ = std::make_shared<DistributedMonitor>(subscribeInfo);
        EventFwk::CommonEventManager::SubscribeCommonEvent(distributedSub_);
    }
    int32_t userId = AccountManagerHelper::GetCurrentActiveUserId();
    if (userId == Constants::INVALID_USERID) {
        APP_LOGW("get user id failed");
        return;
    }
    DistributedDataStorage::GetInstance()->UpdateDistributedData(userId);
}

OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> DistributedBms::GetBundleMgr()
{
    if (bundleMgr_ == nullptr) {
        std::lock_guard<std::mutex> lock(bundleMgrMutex_);
        if (bundleMgr_ == nullptr) {
            auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
            if (systemAbilityManager == nullptr) {
                APP_LOGE("GetBundleMgr GetSystemAbilityManager is null");
                return nullptr;
            }
            auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
            if (bundleMgrSa == nullptr) {
                APP_LOGE("GetBundleMgr GetSystemAbility is null");
                return nullptr;
            }
            bundleMgr_ = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
        }
    }
    return bundleMgr_;
}

static OHOS::sptr<OHOS::AppExecFwk::IDistributedBms> GetDistributedBundleMgr(const std::string &deviceId)
{
    auto samgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> remoteObject;
    if (deviceId.empty()) {
        APP_LOGW("GetDistributedBundleMgr deviceId is empty");
        return nullptr;
    } else {
        APP_LOGI("GetDistributedBundleMgr get remote d-bms");
        remoteObject = samgr->CheckSystemAbility(OHOS::DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, deviceId);
    }
    return OHOS::iface_cast<IDistributedBms>(remoteObject);
}

int32_t DistributedBms::GetRemoteAbilityInfo(
    const OHOS::AppExecFwk::ElementName &elementName, RemoteAbilityInfo &remoteAbilityInfo)
{
    return GetRemoteAbilityInfo(elementName, "", remoteAbilityInfo);
}

int32_t DistributedBms::GetRemoteAbilityInfo(const OHOS::AppExecFwk::ElementName &elementName,
    const std::string &localeInfo, RemoteAbilityInfo &remoteAbilityInfo)
{
    auto iDistBundleMgr = GetDistributedBundleMgr(elementName.GetDeviceID());
    int32_t resultCode = OHOS::NO_ERROR;
    if (!iDistBundleMgr) {
        APP_LOGE("GetDistributedBundle object failed");
        resultCode = ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY;
    } else {
        APP_LOGD("GetDistributedBundleMgr get remote d-bms");
        resultCode = iDistBundleMgr->GetAbilityInfo(elementName, localeInfo, remoteAbilityInfo);
    }

    EventReport::SendSystemEvent(
        DBMSEventType::GET_REMOTE_ABILITY_INFO, GetEventInfo(elementName, localeInfo, resultCode));
    return resultCode;
}

int32_t DistributedBms::GetRemoteAbilityInfos(
    const std::vector<ElementName> &elementNames, std::vector<RemoteAbilityInfo> &remoteAbilityInfos)
{
    return GetRemoteAbilityInfos(elementNames, "", remoteAbilityInfos);
}

int32_t DistributedBms::GetRemoteAbilityInfos(const std::vector<ElementName> &elementNames,
    const std::string &localeInfo, std::vector<RemoteAbilityInfo> &remoteAbilityInfos)
{
    auto iDistBundleMgr = GetDistributedBundleMgr(elementNames[0].GetDeviceID());
    int32_t resultCode = OHOS::NO_ERROR;
    if (!iDistBundleMgr) {
        APP_LOGE("GetDistributedBundle object failed");
        resultCode = ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY;
    } else {
        APP_LOGD("GetDistributedBundleMgr get remote d-bms");
        resultCode = iDistBundleMgr->GetAbilityInfos(elementNames, localeInfo, remoteAbilityInfos);
    }

    EventReport::SendSystemEvent(
        DBMSEventType::GET_REMOTE_ABILITY_INFOS, GetEventInfo(elementNames, localeInfo, resultCode));
    return resultCode;
}

int32_t DistributedBms::GetAbilityInfo(
    const OHOS::AppExecFwk::ElementName &elementName, RemoteAbilityInfo &remoteAbilityInfo)
{
    return GetAbilityInfo(elementName, "", remoteAbilityInfo);
}

int32_t DistributedBms::GetAbilityInfo(const OHOS::AppExecFwk::ElementName &elementName,
    const std::string &localeInfo, RemoteAbilityInfo &remoteAbilityInfo)
{
    APP_LOGI("DistributedBms GetAbilityInfo bundleName:%{public}s , abilityName:%{public}s, localeInfo:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str(), localeInfo.c_str());
    auto iBundleMgr = GetBundleMgr();
    if (!iBundleMgr) {
        APP_LOGE("DistributedBms GetBundleMgr failed");
        return ERR_APPEXECFWK_FAILED_SERVICE_DIED;
    }
    int userId = AccountManagerHelper::GetCurrentActiveUserId();
    if (userId == Constants::INVALID_USERID) {
        APP_LOGE("GetCurrentUserId failed");
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    BundleInfo bundleInfo;
    if (!iBundleMgr->GetBundleInfo(elementName.GetBundleName(), 1, bundleInfo, userId)) {
        APP_LOGE("DistributedBms GetBundleInfo failed");
        return ERR_APPEXECFWK_FAILED_GET_BUNDLE_INFO;
    }
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager = nullptr;
    resourceManager = GetResourceManager(bundleInfo, localeInfo);
    if (resourceManager == nullptr) {
        APP_LOGE("DistributedBms InitResourceManager failed");
        return ERR_APPEXECFWK_FAILED_GET_RESOURCEMANAGER;
    }

    AbilityInfo abilityInfo;
    OHOS::AAFwk::Want want;
    want.SetElement(elementName);
    if (!iBundleMgr->QueryAbilityInfo(want, GET_ABILITY_INFO_WITH_APPLICATION, userId, abilityInfo)) {
        APP_LOGE("DistributedBms QueryAbilityInfo failed");
        return ERR_APPEXECFWK_FAILED_GET_ABILITY_INFO;
    }
    remoteAbilityInfo.elementName = elementName;
    int32_t labelError = GetAbilityLabel(resourceManager, abilityInfo, remoteAbilityInfo);
    if (labelError != OHOS::NO_ERROR) {
        return labelError;
    }
    if (!abilityInfo.hapPath.empty()) {
        return GetAbilityIconByContent(resourceManager, abilityInfo, localeInfo, remoteAbilityInfo);
    }
    
    return GetAbilityIconByFile(resourceManager, abilityInfo, localeInfo, remoteAbilityInfo);
}

int32_t DistributedBms::GetAbilityLabel(std::shared_ptr<Global::Resource::ResourceManager> &resourceManager,
    const AbilityInfo &abilityInfo, RemoteAbilityInfo &remoteAbilityInfo)
{
    OHOS::Global::Resource::RState errval =
        resourceManager->GetStringById(static_cast<uint32_t>(abilityInfo.labelId), remoteAbilityInfo.label);
    if (errval != OHOS::Global::Resource::RState::SUCCESS) {
        APP_LOGE("DistributedBms GetStringById failed");
        return ERR_APPEXECFWK_FAILED_GET_RESOURCEMANAGER;
    }
    APP_LOGD("DistributedBms GetAbilityInfo label:%{public}s", remoteAbilityInfo.label.c_str());
    return OHOS::NO_ERROR;
}

int32_t DistributedBms::Base64WithoutCompress(std::unique_ptr<uint8_t[]> &imageContent, size_t imageContentSize,
    RemoteAbilityInfo &remoteAbilityInfo)
{
    std::string imageType;
    std::unique_ptr<ImageCompress> imageCompress = std::make_unique<ImageCompress>();
    if (!imageCompress->GetImageTypeString(imageContent, imageContentSize, imageType)) {
        return ERR_APPEXECFWK_INPUT_WRONG_TYPE_FILE;
    }
    if (!GetMediaBase64(imageContent, static_cast<int64_t>(imageContentSize), imageType, remoteAbilityInfo.icon)) {
        APP_LOGE("DistributedBms GetMediaBase64 failed");
        return ERR_APPEXECFWK_ENCODE_BASE64_FILE_FAILED;
    }
    return OHOS::NO_ERROR;
}

int32_t DistributedBms::GetAbilityIconByContent(
    const std::shared_ptr<Global::Resource::ResourceManager> &resourceManager,
    const AbilityInfo &abilityInfo, const std::string &localeInfo, RemoteAbilityInfo &remoteAbilityInfo)
{
    std::unique_ptr<uint8_t[]> imageContent;
    size_t imageContentSize = 0;
    OHOS::Global::Resource::RState imageContentErrval =
        resourceManager->GetMediaDataById(static_cast<uint32_t>(abilityInfo.iconId), imageContentSize, imageContent);
    if (imageContentErrval != OHOS::Global::Resource::RState::SUCCESS) {
        return ERR_APPEXECFWK_FAILED_GET_RESOURCEMANAGER;
    }
    APP_LOGD("imageContentSize is %{public}d", static_cast<int32_t>(imageContentSize));
    std::unique_ptr<ImageCompress> imageCompress = std::make_unique<ImageCompress>();
    if (imageCompress->IsImageNeedCompressBySize(imageContentSize)) {
        std::unique_ptr<uint8_t[]> compressData;
        int64_t compressSize = 0;
        std::string imageType;
        if (!imageCompress->CompressImageByContent(imageContent, imageContentSize,
            compressData, compressSize, imageType)) {
            return Base64WithoutCompress(imageContent, imageContentSize, remoteAbilityInfo);
        }
        if (!GetMediaBase64(compressData, compressSize, imageType, remoteAbilityInfo.icon)) {
            APP_LOGE("DistributedBms GetMediaBase64 failed");
            return ERR_APPEXECFWK_ENCODE_BASE64_FILE_FAILED;
        }
    } else {
        return Base64WithoutCompress(imageContent, imageContentSize, remoteAbilityInfo);
    }
    return OHOS::NO_ERROR;
}

int32_t DistributedBms::GetAbilityIconByFile(const std::shared_ptr<Global::Resource::ResourceManager> &resourceManager,
    const AbilityInfo &abilityInfo, const std::string &localeInfo, RemoteAbilityInfo &remoteAbilityInfo)
{
    std::string iconPath;
    OHOS::Global::Resource::RState iconPathErrval =
        resourceManager->GetMediaById(static_cast<uint32_t>(abilityInfo.iconId), iconPath);
    if (iconPathErrval != OHOS::Global::Resource::RState::SUCCESS) {
        APP_LOGE("DistributedBms GetStringById  iconPath failed");
        return ERR_APPEXECFWK_FAILED_GET_RESOURCEMANAGER;
    }
    std::unique_ptr<ImageCompress> imageCompress = std::make_unique<ImageCompress>();
    std::unique_ptr<uint8_t[]> imageContent;
    int64_t imageContentSize = 0;
    if (!imageCompress->GetImageFileInfo(iconPath, imageContent, imageContentSize)) {
        APP_LOGE("GetImageFileInfo failed!");
        return ERR_APPEXECFWK_FAILED_GET_RESOURCEMANAGER;
    }
    if (imageCompress->IsImageNeedCompressBySize(imageContentSize)) {
        std::unique_ptr<uint8_t[]> compressData;
        int64_t compressSize = 0;
        std::string imageType;
        if (!imageCompress->CompressImageByContent(imageContent, imageContentSize,
            compressData, compressSize, imageType)) {
            return Base64WithoutCompress(imageContent, imageContentSize, remoteAbilityInfo);
        }
        if (!GetMediaBase64(compressData, compressSize, imageType, remoteAbilityInfo.icon)) {
            APP_LOGE("DistributedBms GetMediaBase64 failed");
            return ERR_APPEXECFWK_ENCODE_BASE64_FILE_FAILED;
        }
    } else {
        return Base64WithoutCompress(imageContent, imageContentSize, remoteAbilityInfo);
    }
    return OHOS::NO_ERROR;
}

int32_t DistributedBms::GetAbilityInfos(
    const std::vector<ElementName> &elementNames, std::vector<RemoteAbilityInfo> &remoteAbilityInfos)
{
    APP_LOGD("DistributedBms GetAbilityInfos");
    return GetAbilityInfos(elementNames, "", remoteAbilityInfos);
}

int32_t DistributedBms::GetAbilityInfos(const std::vector<ElementName> &elementNames,
    const std::string &localeInfo, std::vector<RemoteAbilityInfo> &remoteAbilityInfos)
{
    APP_LOGD("DistributedBms GetAbilityInfos");
    for (auto elementName : elementNames) {
        RemoteAbilityInfo remoteAbilityInfo;
        int32_t result = GetAbilityInfo(elementName, localeInfo, remoteAbilityInfo);
        if (result) {
            APP_LOGE("get AbilityInfo:%{public}s, %{public}s, %{public}s failed", elementName.GetBundleName().c_str(),
                elementName.GetModuleName().c_str(), elementName.GetAbilityName().c_str());
            return result;
        }
        remoteAbilityInfos.push_back(remoteAbilityInfo);
    }
    return OHOS::NO_ERROR;
}

bool DistributedBms::GetMediaBase64(std::unique_ptr<uint8_t[]> &data, int64_t fileLength,
    std::string &imageType, std::string &value)
{
    std::unique_ptr<char[]> base64Data = EncodeBase64(data, fileLength);
    value = "data:" + imageType + ";base64," + base64Data.get();
    return true;
}

bool DistributedBms::GetDistributedBundleInfo(const std::string &networkId, const std::string &bundleName,
    DistributedBundleInfo &distributedBundleInfo)
{
    return DistributedDataStorage::GetInstance()->GetStorageDistributeInfo(
        networkId, bundleName, distributedBundleInfo);
}

std::shared_ptr<Global::Resource::ResourceManager> DistributedBms::GetResourceManager(
    const AppExecFwk::BundleInfo &bundleInfo, const std::string &localeInfo)
{
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    for (const HapModuleInfo &hapModuleInfo : bundleInfo.hapModuleInfos) {
        std::string moduleResPath = hapModuleInfo.hapPath.empty() ? hapModuleInfo.resourcePath : hapModuleInfo.hapPath;
        if (!moduleResPath.empty()) {
            if (!resourceManager->AddResource(moduleResPath.c_str())) {
                APP_LOGE("DistributedBms::InitResourceManager AddResource failed");
            }
        }
    }
    APP_LOGD("DistributedBms::InitResourceManager locale:%{public}s", localeInfo.c_str());
    std::map<std::string, std::string> configs;
    OHOS::Global::I18n::LocaleInfo locale(localeInfo, configs);
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    resConfig->SetLocaleInfo(locale.GetLanguage().c_str(), locale.GetScript().c_str(), locale.GetRegion().c_str());
    resourceManager->UpdateResConfig(*resConfig);
    if (resConfig->GetLocaleInfo() != nullptr) {
        APP_LOGD("DistributedBms::InitResourceManager language: %{public}s, script: %{public}s, region: %{public}s,",
            resConfig->GetLocaleInfo()->getLanguage(),
            resConfig->GetLocaleInfo()->getScript(),
            resConfig->GetLocaleInfo()->getCountry());
    } else {
        APP_LOGW("DistributedBms::InitResourceManager language: GetLocaleInfo is null.");
    }

    return resourceManager;
}

std::unique_ptr<char[]> DistributedBms::EncodeBase64(std::unique_ptr<uint8_t[]> &data, int srcLen)
{
    int len = (srcLen / DECODE_VALUE_THREE) * DECODE_VALUE_FOUR; // Split 3 bytes to 4 parts, each containing 6 bits.
    int outLen = ((srcLen % DECODE_VALUE_THREE) != 0) ? (len + DECODE_VALUE_FOUR) : len;
    const uint8_t *srcData = data.get();
    std::unique_ptr<char[]>  result = std::make_unique<char[]>(outLen + DECODE_VALUE_ONE);
    char *dstData = result.get();
    int j = 0;
    int i = 0;
    for (; i < srcLen - DECODE_VALUE_THREE; i += DECODE_VALUE_THREE) {
        unsigned char byte1 = srcData[i];
        unsigned char byte2 = srcData[i + DECODE_VALUE_ONE];
        unsigned char byte3 = srcData[i + DECODE_VALUE_TWO];
        dstData[j++] = DECODE_TABLE[byte1 >> DECODE_VALUE_TWO];
        dstData[j++] =
            DECODE_TABLE[(static_cast<uint8_t>(byte1 & DECODE_VALUE_CHAR_THREE) << DECODE_VALUE_FOUR)
             | (byte2 >> DECODE_VALUE_FOUR)];
        dstData[j++] =
            DECODE_TABLE[(static_cast<uint8_t>(byte2 & DECODE_VALUE_CHAR_FIFTEEN)
                << DECODE_VALUE_TWO) | (byte3 >> DECODE_VALUE_SIX)];
        dstData[j++] = DECODE_TABLE[byte3 & DECODE_VALUE_CHAR_SIXTY_THREE];
    }
    if (srcLen % DECODE_VALUE_THREE == DECODE_VALUE_ONE) {
        unsigned char byte1 = srcData[i];
        dstData[j++] = DECODE_TABLE[byte1 >> DECODE_VALUE_TWO];
        dstData[j++] = DECODE_TABLE[static_cast<uint8_t>(byte1 & DECODE_VALUE_CHAR_THREE) << DECODE_VALUE_FOUR];
        dstData[j++] = '=';
        dstData[j++] = '=';
    } else {
        unsigned char byte1 = srcData[i];
        unsigned char byte2 = srcData[i + DECODE_VALUE_ONE];
        dstData[j++] = DECODE_TABLE[byte1 >> DECODE_VALUE_TWO];
        dstData[j++] =
            DECODE_TABLE[(static_cast<uint8_t>(byte1 & DECODE_VALUE_CHAR_THREE) << DECODE_VALUE_FOUR)
             | (byte2 >> DECODE_VALUE_FOUR)];
        dstData[j++] = DECODE_TABLE[static_cast<uint8_t>(byte2 & DECODE_VALUE_CHAR_FIFTEEN)
                                    << DECODE_VALUE_TWO];
        dstData[j++] = '=';
    }
    dstData[outLen] = '\0';

    return result;
}
}
}