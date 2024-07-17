/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "base_extractor.h"

#include <cerrno>
#include <dirent.h>
#include <fstream>
#include <limits>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* MODULE_PROFILE_NAME = "module.json";
}

BaseExtractor::BaseExtractor(const std::string &source) : sourceFile_(source), zipFile_(source)
{
    APP_LOGD("BaseExtractor instance is created");
}

BaseExtractor::~BaseExtractor()
{
    APP_LOGD("BaseExtractor instance is destroyed");
}

bool BaseExtractor::Init()
{
    if (!zipFile_.Open()) {
        APP_LOGE("open zip file failed, errno:%{public}d", errno);
        return false;
    }
    ZipEntry zipEntry;
    isNewVersion_ = zipFile_.GetEntry(MODULE_PROFILE_NAME, zipEntry);
    initial_ = true;
    return true;
}

bool BaseExtractor::HasEntry(const std::string &fileName) const
{
    if (!initial_) {
        APP_LOGE("extractor is not initial");
        return false;
    }

    return zipFile_.HasEntry(fileName);
}

bool BaseExtractor::IsDirExist(const std::string &dir) const
{
    if (!initial_) {
        APP_LOGE("extractor is not initial");
        return false;
    }
    if (dir.empty()) {
        APP_LOGE("param dir empty");
        return false;
    }
    return zipFile_.IsDirExist(dir);
}

bool BaseExtractor::ExtractByName(const std::string &fileName, std::ostream &dest) const
{
    if (!initial_) {
        APP_LOGE("extractor is not initial");
        return false;
    }
    if (!zipFile_.ExtractFile(fileName, dest)) {
        APP_LOGE("extractor is not ExtractFile");
        return false;
    }
    return true;
}

bool BaseExtractor::ExtractFile(const std::string &fileName, const std::string &targetPath) const
{
    APP_LOGD("begin to extract %{public}s file into %{private}s targetPath", fileName.c_str(), targetPath.c_str());
    std::ofstream fileStream;
    fileStream.open(targetPath, std::ios_base::out | std::ios_base::binary);
    if (!fileStream.is_open()) {
        APP_LOGE("fail to open %{private}s file to write, errno:%{public}d", targetPath.c_str(), errno);
        return false;
    }
    if ((!ExtractByName(fileName, fileStream)) || (!fileStream.good())) {
        APP_LOGE("fail to extract %{public}s zip file into stream", fileName.c_str());
        fileStream.clear();
        fileStream.close();
        if (remove(targetPath.c_str()) != 0) {
            APP_LOGE("fail to remove %{private}s file which writes stream error, errno:%{public}d",
                targetPath.c_str(), errno);
        }
        return false;
    }
    fileStream.clear();
    fileStream.close();
    return true;
}

bool BaseExtractor::GetZipFileNames(std::vector<std::string> &fileNames) const
{
    auto &entryMap = zipFile_.GetAllEntries();
    auto entryFilter = [&fileNames](const auto &entry) {
        auto position = entry.first.rfind(ServiceConstants::QUICK_FIX_FILE_SUFFIX);
        bool isHqfFile = false;
        if (position != std::string::npos) {
            std::string suffixStr = entry.first.substr(position);
            isHqfFile = suffixStr == ServiceConstants::QUICK_FIX_FILE_SUFFIX;
        }
        if ((entry.first.find(ServiceConstants::RELATIVE_PATH) == std::string::npos) && !isHqfFile) {
            fileNames.emplace_back(entry.first);
        }
    };
    for_each(entryMap.begin(), entryMap.end(), entryFilter);
    return true;
}

bool BaseExtractor::IsStageBasedModel(std::string abilityName)
{
    auto &entryMap = zipFile_.GetAllEntries();
    std::vector<std::string> splitStrs;
    OHOS::SplitStr(abilityName, "", splitStrs);
    std::string name = splitStrs.empty() ? abilityName : splitStrs.back();
    std::string entry = "assets/js/" + name + "/" + name + ".js";
    bool isStageBasedModel = entryMap.find(entry) != entryMap.end();
    APP_LOGI("name:%{public}s isStageBasedModel:%{public}d", abilityName.c_str(), isStageBasedModel);
    return isStageBasedModel;
}

bool BaseExtractor::IsNewVersion() const
{
    return isNewVersion_;
}

bool BaseExtractor::GetFileInfo(const std::string &fileName, uint32_t &offset, uint32_t &length) const
{
    if (!initial_) {
        APP_LOGE("extractor is not initial");
        return false;
    }
    ZipPos tmpOffset = 0;
    if (!zipFile_.GetDataOffsetRelative(fileName, tmpOffset, length)) {
        APP_LOGE("GetDataOffsetRelative failed");
        return false;
    }
    if (tmpOffset > std::numeric_limits<uint32_t>::max()) {
        APP_LOGE("offset too large");
        return false;
    }
    offset = static_cast<uint32_t>(tmpOffset);
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
