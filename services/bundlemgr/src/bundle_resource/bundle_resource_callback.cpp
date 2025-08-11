/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundle_resource_callback.h"

#include <fstream>

#include "account_helper.h"
#include "bundle_constants.h"
#include "bundle_parser.h"
#include "bundle_resource_constants.h"
#include "bundle_resource_manager.h"
#ifdef GLOBAL_RESMGR_ENABLE
#include "resource_manager.h"
#endif
namespace OHOS {
namespace AppExecFwk {
bool BundleResourceCallback::OnUserIdSwitched(const int32_t oldUserId, const int32_t userId, const uint32_t type)
{
    APP_LOGI("start, oldUserId:%{public}d to newUserId:%{public}d no need to process", oldUserId, userId);
    return true;
}

bool BundleResourceCallback::OnSystemColorModeChanged(const std::string &colorMode, const uint32_t type)
{
    APP_LOGI("start, colorMode: %{public}s", colorMode.c_str());
    if (colorMode == BundleSystemState::GetInstance().GetSystemColorMode()) {
        APP_LOGD("colorMode: %{public}s no change", colorMode.c_str());
        return true;
    }
    APP_LOGI("end, colorMode: %{public}s", colorMode.c_str());
    return true;
}

bool BundleResourceCallback::OnSystemLanguageChange(const std::string &language, const uint32_t type)
{
    APP_LOGI("start, language %{public}s", language.c_str());
    if (language == BundleSystemState::GetInstance().GetSystemLanguage()) {
        APP_LOGD("current language is %{public}s no change", language.c_str());
        return true;
    }
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if (currentUserId <= 0) {
        currentUserId = Constants::START_USERID;
    }
    SetConfigInFile(language, "", -1, -1, type, currentUserId);
    BundleSystemState::GetInstance().SetSystemLanguage(language);
    // need delete all and reload all
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager is nullptr");
        return false;
    }

    if (!manager->AddAllResourceInfo(currentUserId, type)) {
        APP_LOGE("AddAllResourceInfo currentUserId %{public}d failed", currentUserId);
        return false;
    }
    DeleteConfigInFile(currentUserId, type);
    APP_LOGI("end, language %{public}s", language.c_str());
    return true;
}

bool BundleResourceCallback::OnApplicationThemeChanged(const std::string &theme,
    const int32_t themeId, const int32_t themeIcon, const uint32_t type)
{
    APP_LOGI("start, theme:%{public}s, themeId:%{public}d", theme.c_str(), themeId);
    if (theme.empty()) {
        APP_LOGW("theme is empty, no need to change");
        return false;
    }

    nlohmann::json jsonObject = nlohmann::json::parse(theme, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("failed parse theme %{public}s", theme.c_str());
        return false;
    }
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    int32_t updateIcons = 0;
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, "icons", updateIcons,
        JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    if (updateIcons == 0) {
        APP_LOGI("icons no need to change, return");
        return false;
    }
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if (currentUserId <= 0) {
        currentUserId = Constants::START_USERID;
    }
    SetConfigInFile("", theme, themeId, themeIcon, type, currentUserId);
#ifdef GLOBAL_RESMGR_ENABLE
    if (!SetThemeParamForThemeChanged(themeId, themeIcon)) {
        APP_LOGE("set theme param failed, themeId %{public}d themeIcon %{public}d", themeId, themeIcon);
    }
#endif

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager is nullptr");
        return false;
    }

    if (!manager->AddAllResourceInfo(currentUserId, type)) {
        APP_LOGE("AddAllResourceInfo currentUserId %{public}d failed", currentUserId);
        return false;
    }
    DeleteConfigInFile(currentUserId, type);
    APP_LOGI("end, theme:%{public}s", theme.c_str());
    return true;
}

bool BundleResourceCallback::OnOverlayStatusChanged(
    const std::string &bundleName,
    bool isEnabled,
    int32_t userId)
{
    APP_LOGI("start, bundleName:%{public}s, isEnabled:%{public}d, userId:%{public}d",
        bundleName.c_str(), isEnabled, userId);
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if ((currentUserId > 0) && (userId != currentUserId)) {
        APP_LOGW("userId:%{public}d current:%{public}d not same", currentUserId, userId);
        return false;
    }
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager is nullptr");
        return false;
    }
    std::string targetBundleName = bundleName;
    manager->GetTargetBundleName(bundleName, targetBundleName);
    APP_LOGI("bundleName:%{public}s, targetBundleName:%{public}s overlay changed", bundleName.c_str(),
        targetBundleName.c_str());
    if (!manager->AddResourceInfoByBundleNameWhenUpdate(targetBundleName, userId)) {
        APP_LOGE("add resource failed %{public}s", targetBundleName.c_str());
        return false;
    }
    APP_LOGI("end, targetBundleName:%{public}s, isEnabled:%{public}d, userId:%{public}d",
        targetBundleName.c_str(), isEnabled, userId);
    return true;
}

bool BundleResourceCallback::SetThemeParamForThemeChanged(const int32_t themeId, const int32_t themeIcon)
{
    if (themeId <= 0) {
        return false;
    }
#ifdef GLOBAL_RESMGR_ENABLE
    auto resourcePtr = std::shared_ptr<Global::Resource::ResourceManager>(Global::Resource::CreateResourceManager());
    if (resourcePtr == nullptr) {
        APP_LOGE("resource is nullptr, themeId %{public}d themeIcon %{public}d", themeId, themeIcon);
        return false;
    }
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if (currentUserId <= 0) {
        APP_LOGW("currentUserId get failed");
        currentUserId = Constants::START_USERID;
    }
    resourcePtr->userId = currentUserId;
    APP_LOGI("start set themeId %{public}d userId %{public}d themeIcon %{public}d",
        themeId, currentUserId, themeIcon);
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    if (resConfig == nullptr) {
        APP_LOGE("resConfig is nullptr, themeId %{public}d themeIcon %{public}d", themeId, themeIcon);
        return false;
    }
    resConfig->SetThemeId(themeId);
    resConfig->SetThemeIcon(themeIcon > 0 ? true : false);
    Global::Resource::RState ret = resourcePtr->UpdateResConfig(*resConfig); // no need to process ret
    if (ret != Global::Resource::RState::SUCCESS) {
        APP_LOGW("UpdateResConfig ret %{public}d, themeId %{public}d, themeIcon %{public}d",
            static_cast<int32_t>(ret), themeId, themeIcon);
    }
    APP_LOGI("end set themeId %{public}d themeIcon %{public}d", themeId, themeIcon);
#endif
    return true;
}

void BundleResourceCallback::SetUserId(const int32_t userId)
{
    std::string path = std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH) +
        std::string(BundleResourceConstants::USER_FILE_NAME);
    nlohmann::json jsonBuf;
    if (!BundleParser::ReadFileIntoJson(path, jsonBuf)) {
        APP_LOGW("read user file failed, errno %{public}d", errno);
    }
    std::ofstream out(path, std::ios::out);
    if (!out.is_open()) {
        APP_LOGE("open user file failed, errno:%{public}d", errno);
        return;
    }
    jsonBuf[BundleResourceConstants::USER] = userId;
    out << jsonBuf.dump();
    out.close();
}

void BundleResourceCallback::DeleteConfigInFile(const int32_t userId, const uint32_t type)
{
    std::string path = std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH) +
        std::string(BundleResourceConstants::USER_FILE_NAME);
    nlohmann::json jsonBuf;
    if (!BundleParser::ReadFileIntoJson(path, jsonBuf)) {
        APP_LOGW("read user file failed, errno %{public}d", errno);
        return;
    }
    std::string key;
    if (type == static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE)) {
        key = std::string(BundleResourceConstants::LANGUAGE) +
            std::string(BundleResourceConstants::UNDER_LINE) + std::to_string(userId);
    } else if (type == static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE)) {
        key = std::string(BundleResourceConstants::THEME) +
            std::string(BundleResourceConstants::UNDER_LINE) + std::to_string(userId);
    } else {
        return;
    }
    auto it = jsonBuf.find(key);
    if (it == jsonBuf.end()) {
        return;
    }
    jsonBuf.erase(it);
    std::ofstream out(path, std::ios::out);
    if (!out.is_open()) {
        APP_LOGE("open user file failed, errno:%{public}d", errno);
        return;
    }
    out << jsonBuf.dump();
    out.close();
    APP_LOGI("-u %{public}d -t %{public}d delete config success.", userId, type);
}

void BundleResourceCallback::SetConfigInFile(const std::string &language, const std::string &theme,
    const int32_t id, const int32_t themeIcon, const uint32_t type, const int32_t userId)
{
    std::string path = std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH) +
        std::string(BundleResourceConstants::USER_FILE_NAME);
    nlohmann::json jsonBuf;
    std::lock_guard<std::mutex> lock(userFileMutex_);
    if (!BundleParser::ReadFileIntoJson(path, jsonBuf)) {
        APP_LOGW("read user file failed, errno %{public}d", errno);
    }
    FILE *out = fopen(path.c_str(), "w");
    if (out == nullptr) {
        APP_LOGE("fopen %{public}s failed", path.c_str());
        return;
    }
    nlohmann::json config;
    if (type == static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE)) {
        config[BundleResourceConstants::LANGUAGE] = language;
        config[BundleResourceConstants::USER] = userId;
        config[BundleResourceConstants::TYPE] = type;
        std::string key = std::string(BundleResourceConstants::LANGUAGE) +
            std::string(BundleResourceConstants::UNDER_LINE) + std::to_string(userId);
        jsonBuf[key] = config;
    } else if (type == static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE)) {
        config[BundleResourceConstants::THEME] = theme;
        config[BundleResourceConstants::THEME_ID] = id;
        config[BundleResourceConstants::THEME_ICON] = themeIcon;
        config[BundleResourceConstants::USER] = userId;
        config[BundleResourceConstants::TYPE] = type;
        std::string key = std::string(BundleResourceConstants::THEME) +
            std::string(BundleResourceConstants::UNDER_LINE) + std::to_string(userId);
        jsonBuf[key] = config;
    } else {
        (void)fclose(out);
        return;
    }

    if (fputs(jsonBuf.dump().c_str(), out) == EOF) {
        APP_LOGE("fputs %{public}s failed", path.c_str());
        (void)fclose(out);
        return;
    }
    (void)fsync(fileno(out));
    (void)fclose(out);
    APP_LOGI("-u %{public}d -t %{public}d save config success.", userId, type);
}
} // AppExecFwk
} // OHOS
