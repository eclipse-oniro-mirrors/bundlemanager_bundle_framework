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

#include "app_log_wrapper.h"
#include "patch_extractor.h"
#include "patch_profile.h"

namespace OHOS {
namespace AppExecFwk {
ErrCode PatchParser::ParsePatchInfo(const std::string &pathName, AppQuickFix &appQuickFix) const
{
    APP_LOGD("Parse patch.json from %{private}s", pathName.c_str());
    if (pathName.empty()) {
        return ERR_APPEXECFWK_PARSE_NO_PROFILE;
    }
    PatchExtractor patchExtractor(pathName);
    if (!patchExtractor.Init()) {
        APP_LOGE("patch extractor init failed");
        return ERR_APPEXECFWK_PARSE_UNEXPECTED;
    }
    
    std::ostringstream outStreamForHatchInfo;
    if (!patchExtractor.ExtractPatchProfile(outStreamForHatchInfo)) {
        APP_LOGE("extract patch.json failed");
        return ERR_APPEXECFWK_PARSE_NO_PROFILE;
    }
    APP_LOGD("extract patch complete");

    PatchProfile patchProfile;
    ErrCode ret = patchProfile.TransformTo(outStreamForHatchInfo, patchExtractor, appQuickFix);
    if (ret != ERR_OK) {
        APP_LOGE("transform stream to appQuickFix failed %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode PatchParser::ParsePatchInfo(const std::vector<std::string> &filePaths,
    std::unordered_map<std::string, AppQuickFix> &appQuickFixes) const
{
    APP_LOGD("Parse quick fix files start.");
    if (filePaths.empty()) {
        return ERR_APPEXECFWK_PARSE_NO_PROFILE;
    }
    for (size_t index = 0; index < filePaths.size(); ++index) {
        AppQuickFix appQuickFix;
        ErrCode result = ParsePatchInfo(filePaths[index], appQuickFix);
        if (result != ERR_OK) {
            APP_LOGE("quick fix parse failed %{public}d", result);
            return result;
        }
        appQuickFixes.emplace(filePaths[index], appQuickFix);
    }
    APP_LOGD("Parse quick fix files end.");
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS