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

#include "quick_fix/patch_parser.h"

#include <sstream>

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "patch_extractor.h"
#include "patch_profile.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string RESOURCES_RAW_FILE = "resources/rawfile/";
} // namespace

ErrCode PatchParser::ParsePatchInfo(const std::string &pathName, AppQuickFix &appQuickFix) const
{
    LOG_D(BMS_TAG_DEFAULT, "Parse patch.json from %{private}s", pathName.c_str());
    if (pathName.empty()) {
        return ERR_APPEXECFWK_PARSE_NO_PROFILE;
    }
    PatchExtractor patchExtractor(pathName);
    if (!patchExtractor.Init()) {
        LOG_E(BMS_TAG_DEFAULT, "patch extractor init failed");
        return ERR_APPEXECFWK_PARSE_UNEXPECTED;
    }
    
    std::ostringstream outStreamForHatchInfo;
    if (!patchExtractor.ExtractPatchProfile(outStreamForHatchInfo)) {
        LOG_E(BMS_TAG_DEFAULT, "extract patch.json failed");
        return ERR_APPEXECFWK_PARSE_NO_PROFILE;
    }
    LOG_D(BMS_TAG_DEFAULT, "extract patch complete");

    PatchProfile patchProfile;
    ErrCode ret = patchProfile.TransformTo(outStreamForHatchInfo, patchExtractor, appQuickFix);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "transform stream to appQuickFix failed %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode PatchParser::ParsePatchInfo(const std::vector<std::string> &filePaths,
    std::unordered_map<std::string, AppQuickFix> &appQuickFixes) const
{
    LOG_D(BMS_TAG_DEFAULT, "Parse quick fix files start.");
    if (filePaths.empty()) {
        return ERR_APPEXECFWK_PARSE_NO_PROFILE;
    }
    for (size_t index = 0; index < filePaths.size(); ++index) {
        AppQuickFix appQuickFix;
        ErrCode result = ParsePatchInfo(filePaths[index], appQuickFix);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "quick fix parse failed %{public}d", result);
            return result;
        }
        appQuickFixes.emplace(filePaths[index], appQuickFix);
    }
    LOG_D(BMS_TAG_DEFAULT, "Parse quick fix files end.");
    return ERR_OK;
}

bool PatchParser::HasResourceFile(const std::string &filePath) const
{
    LOG_D(BMS_TAG_DEFAULT, "check filePath has resource file start");
    if (filePath.empty()) {
        return false;
    }
    PatchExtractor patchExtractor(filePath);
    if (!patchExtractor.Init()) {
        LOG_E(BMS_TAG_DEFAULT, "patch extractor init failed");
        return false;
    }

    return patchExtractor.IsDirExist(RESOURCES_RAW_FILE);
}

bool PatchParser::HasResourceFile(const std::vector<std::string> &filePaths) const
{
    LOG_D(BMS_TAG_DEFAULT, "check filePaths has resource file start");
    for (size_t index = 0; index < filePaths.size(); ++index) {
        if (HasResourceFile(filePaths[index])) {
            return true;
        }
    }
    LOG_D(BMS_TAG_DEFAULT, "does not exist resource rawfile");
    return false;
}
} // namespace AppExecFwk
} // namespace OHOS