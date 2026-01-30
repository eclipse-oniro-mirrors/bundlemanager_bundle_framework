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

#include "idle_param_util.h"

#include <cstdlib>
#include <fstream>
#include <sstream>

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* LOCAL_CFG_PATH = "/system/etc/SwitchOffList/";
constexpr const char* CLOUD_CFG_PATH =
    "/data/service/el1/public/update/param_service/install/system/etc/SwitchOffList/";
constexpr const char* VERSION_FILE_NAME = "version.txt";
constexpr const char* SWITCH_OFF_LIST = "switch_off_list";
constexpr const char* RELABEL_FEATURE_OFF = "relabel_feature_off";
// the number of digits extracted from the fixed format string "x.x.x.x"
constexpr int32_t VERSION_LEN = 4;
}

bool IdleParamUtil::IsRelabelFeatureDisabled()
{
    std::string higherVersionPath = GetHigherVersionPath();
    if (higherVersionPath.empty()) {
        APP_LOGE("higherVersionPath is empty");
        return false;
    }
    std::string filePath = higherVersionPath + SWITCH_OFF_LIST;
    std::ifstream inputFile(filePath);
    if (!inputFile.is_open()) {
        APP_LOGE("Can not open file: %{public}s", filePath.c_str());
        return false;
    }
    std::string line;
    while (std::getline(inputFile, line)) {
        Trim(line);
        if (line == RELABEL_FEATURE_OFF) {
            APP_LOGI("off switch found");
            return true;
        }
    }
    APP_LOGI("off switch not found");
    return false;
}

std::string IdleParamUtil::GetHigherVersionPath()
{
    std::string localVersionFile = std::string(LOCAL_CFG_PATH) + VERSION_FILE_NAME;
    std::string cloudVersionFile = std::string(CLOUD_CFG_PATH) + VERSION_FILE_NAME;
    std::vector<int32_t> localVersionNums = GetVersionNums(localVersionFile);
    std::vector<int32_t> cloudVersionNums = GetVersionNums(cloudVersionFile);
    return CompareVersion(localVersionNums, cloudVersionNums);
}

std::vector<int32_t> IdleParamUtil::GetVersionNums(const std::string& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open()) {
        APP_LOGD("version file %{public}s is not open", filePath.c_str());
        return {};
    }
    std::string line;
    // version info is expected to be in the first line.
    std::getline(file, line);
    if (line.empty()) {
        APP_LOGE("version file %{public}s is empty", filePath.c_str());
        return {};
    }
    // expect to divide the string into two parts by '='
    std::vector<std::string> versionStr = SplitString(line, '=');
    const size_t expectedSize = 2;
    if (versionStr.size() != expectedSize) {
        APP_LOGE("version invalid %{public}s in %{public}s", line.c_str(), filePath.c_str());
        return {};
    }
    // index 1 indicates string representing the version number.
    Trim(versionStr[1]);
    if (versionStr[1].empty()) {
        APP_LOGE("version value is empty in %{public}s", filePath.c_str());
        return {};
    }
    std::vector<std::string> versionParts = SplitString(versionStr[1], '.');
    if (versionParts.size() != VERSION_LEN) {
        APP_LOGE("version invalid %{public}s in %{public}s", line.c_str(), filePath.c_str());
        return {};
    }
    std::vector<int32_t> versionNums;
    for (const auto& part : versionParts) {
        if (!IsNumber(part)) {
            APP_LOGE("not a number: %{public}s in %{public}s", part.c_str(), filePath.c_str());
            return {};
        }
        versionNums.push_back(atoi(part.c_str()));
    }
    return versionNums;
}

std::string IdleParamUtil::CompareVersion(
    const std::vector<int32_t> &localVersion, const std::vector<int32_t> &cloudVersion)
{
    if (localVersion.empty() && cloudVersion.empty()) {
        APP_LOGE("Get version nums failed");
        return "";
    }
    if (cloudVersion.empty()) {
        return LOCAL_CFG_PATH;
    }
    if (localVersion.empty()) {
        return CLOUD_CFG_PATH;
    }
    if (localVersion.size() != VERSION_LEN || cloudVersion.size() != VERSION_LEN) {
        APP_LOGD("version num is not valid.");
        return "";
    }
    for (auto i = 0; i < VERSION_LEN; i++) {
        if (localVersion[i] != cloudVersion[i]) {
            return (localVersion[i] > cloudVersion[i]) ? LOCAL_CFG_PATH : CLOUD_CFG_PATH;
        }
    }
    return LOCAL_CFG_PATH;
}

std::vector<std::string> IdleParamUtil::SplitString(const std::string& str, char pattern)
{
    std::stringstream iss(str);
    std::vector<std::string> result;
    std::string token;
    while (getline(iss, token, pattern)) {
        result.emplace_back(token);
    }
    return result;
}

void IdleParamUtil::Trim(std::string& inputStr)
{
    if (inputStr.empty()) {
        return;
    }
    inputStr.erase(inputStr.begin(), std::find_if(inputStr.begin(), inputStr.end(),
        [](unsigned char ch) { return !std::isspace(static_cast<unsigned char>(ch)); }));
    inputStr.erase(std::find_if(inputStr.rbegin(), inputStr.rend(),
        [](unsigned char ch) { return !std::isspace(static_cast<unsigned char>(ch)); }).base(), inputStr.end());
}

bool IdleParamUtil::IsNumber(const std::string &str)
{
    if (str.empty()) {
        return false;
    }
    for (char c : str) {
        if (!std::isdigit(c)) {
            return false;
        }
    }
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
