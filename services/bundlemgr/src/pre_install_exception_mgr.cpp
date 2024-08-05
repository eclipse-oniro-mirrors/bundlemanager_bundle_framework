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

#include "pre_install_exception_mgr.h"

#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* PREINSTALL_EXCEPTION = "PreInstallExceptionMgr";
constexpr const char* EXCEPTION_PATHS = "ExceptionPaths";
constexpr const char* EXCEPTION_BUNDLENAMES = "ExceptionBundleNames";
}
PreInstallExceptionMgr::PreInstallExceptionMgr()
{}

PreInstallExceptionMgr::~PreInstallExceptionMgr()
{
    APP_LOGD("PreInstallExceptionMgr instance is destroyed");
}

bool PreInstallExceptionMgr::GetAllPreInstallExceptionInfo(
    std::set<std::string> &exceptionPaths, std::set<std::string> &exceptionBundleNames)
{
    std::lock_guard<std::mutex> lock(preInstallExceptionMutex_);
    if (!hasInit_) {
        APP_LOGI("LoadPreInstallExceptionInfosFromDb");
        if (!LoadPreInstallExceptionInfosFromDb()) {
            APP_LOGE("Load PreInstall Exception Infos FromDb error");
            return false;
        }
    }

    exceptionPaths = exceptionPaths_;
    exceptionBundleNames = exceptionBundleNames_;
    return !exceptionPaths_.empty() || !exceptionBundleNames_.empty();
}

bool PreInstallExceptionMgr::LoadPreInstallExceptionInfosFromDb()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        APP_LOGE("bmsPara is nullptr");
        return false;
    }

    std::string preInstallExceptionStr;
    bmsPara->GetBmsParam(PREINSTALL_EXCEPTION, preInstallExceptionStr);
    if (preInstallExceptionStr.empty()) {
        APP_LOGI("preInstallExceptionStr is empty");
        return false;
    }

    nlohmann::json jsonObject = nlohmann::json::parse(preInstallExceptionStr, nullptr, false);
    if (jsonObject.is_discarded() || !jsonObject.is_object()) {
        APP_LOGE("jsonObject is invalid");
        return false;
    }

    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::set<std::string>>(jsonObject,
        jsonObjectEnd,
        EXCEPTION_PATHS,
        exceptionPaths_,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::set<std::string>>(jsonObject,
        jsonObjectEnd,
        EXCEPTION_BUNDLENAMES,
        exceptionBundleNames_,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    if (parseResult != ERR_OK) {
        APP_LOGE("from_json error code : %{public}d", parseResult);
        exceptionPaths_.clear();
        exceptionBundleNames_.clear();
        return false;
    }
    APP_LOGI("Successfully loaded pre-install exception information");
    
    hasInit_ = true;
    return true;
}

void PreInstallExceptionMgr::SavePreInstallExceptionInfosToDb()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        APP_LOGE("bmsPara is nullptr");
        return;
    }

    nlohmann::json jsonObject;
    jsonObject[EXCEPTION_PATHS] = exceptionPaths_;
    jsonObject[EXCEPTION_BUNDLENAMES] = exceptionBundleNames_;
    bmsPara->SaveBmsParam(PREINSTALL_EXCEPTION, jsonObject.dump());
}

void PreInstallExceptionMgr::DeletePreInstallExceptionInfosFromDb()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        APP_LOGE("bmsPara is nullptr");
        return;
    }

    nlohmann::json jsonObject;
    if (!exceptionPaths_.empty()) {
        jsonObject[EXCEPTION_PATHS] = exceptionPaths_;
    }

    if (!exceptionBundleNames_.empty()) {
        jsonObject[EXCEPTION_BUNDLENAMES] = exceptionBundleNames_;
    }

    if (jsonObject.empty()) {
        APP_LOGI("Exception information is empty, Deleting pre-install exception information from database");
        bmsPara->DeleteBmsParam(PREINSTALL_EXCEPTION);
    } else {
        APP_LOGI("Updating pre-install exception information in database");
        bmsPara->SaveBmsParam(PREINSTALL_EXCEPTION, jsonObject.dump());
    }
}

void PreInstallExceptionMgr::SavePreInstallExceptionPath(
    const std::string &bundleDir)
{
    std::lock_guard<std::mutex> lock(preInstallExceptionMutex_);
    if (bundleDir.empty()) {
        APP_LOGE("bundleDir is empty");
        return;
    }

    if (exceptionPaths_.find(bundleDir) != exceptionPaths_.end()) {
        APP_LOGE("bundleDir %{public}s saved", bundleDir.c_str());
        return;
    }

    exceptionPaths_.insert(bundleDir);
    SavePreInstallExceptionInfosToDb();
    APP_LOGI("Pre-install exception infos saved to database successfully");
}

void PreInstallExceptionMgr::DeletePreInstallExceptionPath(const std::string &bundleDir)
{
    std::lock_guard<std::mutex> lock(preInstallExceptionMutex_);
    if (bundleDir.empty()) {
        APP_LOGE("bundleDir is empty");
        return;
    }

    if (exceptionPaths_.find(bundleDir) == exceptionPaths_.end()) {
        APP_LOGE("bundleDir %{public}s deleted", bundleDir.c_str());
        return;
    }

    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        APP_LOGE("bmsPara is nullptr");
        return;
    }

    exceptionPaths_.erase(bundleDir);
    DeletePreInstallExceptionInfosFromDb();
    APP_LOGI("Pre-install exception infos deleted from database successfully for bundleDir %{public}s",
             bundleDir.c_str());
}

void PreInstallExceptionMgr::SavePreInstallExceptionBundleName(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(preInstallExceptionMutex_);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return;
    }

    if (exceptionBundleNames_.find(bundleName) != exceptionBundleNames_.end()) {
        APP_LOGE("bundleName %{public}s saved", bundleName.c_str());
        return;
    }

    exceptionBundleNames_.insert(bundleName);
    SavePreInstallExceptionInfosToDb();
    APP_LOGI("Pre-install exception infos saved to database successfully for bundleName %{public}s",
             bundleName.c_str());
}

void PreInstallExceptionMgr::DeletePreInstallExceptionBundleName(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(preInstallExceptionMutex_);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return;
    }

    if (exceptionBundleNames_.find(bundleName) == exceptionBundleNames_.end()) {
        APP_LOGE("bundleName %{public}s deleted", bundleName.c_str());
        return;
    }

    exceptionBundleNames_.erase(bundleName);
    DeletePreInstallExceptionInfosFromDb();
    APP_LOGI("Pre-install exception infos deleted from database successfully for bundleName %{public}s",
             bundleName.c_str());
}

void PreInstallExceptionMgr::ClearAll()
{
    std::lock_guard<std::mutex> lock(preInstallExceptionMutex_);
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        APP_LOGE("bmsPara is nullptr");
        return;
    }

    bmsPara->DeleteBmsParam(PREINSTALL_EXCEPTION);
    exceptionPaths_.clear();
    exceptionBundleNames_.clear();
    hasInit_ = false;
    APP_LOGI("Pre-install exception information cleared successfully");
}
}  // namespace AppExecFwk
}  // namespace OHOS