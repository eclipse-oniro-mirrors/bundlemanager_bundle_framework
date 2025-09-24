/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "param_validator.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr uint16_t MAX_FILE_TYPE_VECTOR_SIZE = 1024;
constexpr uint16_t MAX_FILE_TYPE_SIZE = 512;
}

ErrCode ParamValidator::ValidateAbilityFileTypes(const std::string &moduleName, const std::string &abilityName,
    const std::vector<std::string> &fileTypes)
{
    if (moduleName.empty()) {
        APP_LOGE_NOFUNC("moduleName empty");
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    if (abilityName.empty()) {
        APP_LOGE_NOFUNC("abilityName empty");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    if (fileTypes.empty()) {
        return ERR_OK;
    }
    if (fileTypes.size() > MAX_FILE_TYPE_VECTOR_SIZE) {
        APP_LOGE_NOFUNC("fileTypes size exceed max limit");
        return ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF;
    }
    for (const std::string &fileType : fileTypes) {
        if (fileType.empty()) {
            APP_LOGE_NOFUNC("fileType empty");
            return ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF;
        }
        if (fileType.size() > MAX_FILE_TYPE_SIZE) {
            APP_LOGE_NOFUNC("fileType size exceed max limit");
            return ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF;
        }
        if (fileType == Constants::TYPE_WILDCARD || fileType == Constants::GENERAL_OBJECT) {
            APP_LOGE_NOFUNC("not allowed fileType:%{public}s", fileType.c_str());
            return ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF;
        }
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
