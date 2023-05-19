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

#include "appexecfwk_errors.h"
#include "bms_extension.h"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
class BmsExtensionProfile {
public:
    /**
     * @brief Parse bms extension file, then save in BmsExtension info.
     * @param jsonPath Indicates the bms-extension.json File.
     * @param bmsExtension Indicates the obtained BmsExtension object.
     * @return Returns ERR_OK if the json file successfully parsed; returns ErrCode otherwise.
     */
    ErrCode ParseBmsExtension(const std::string &jsonPath, BmsExtension &bmsExtension) const;
private:
    bool ReadFileIntoJson(const std::string &filePath, nlohmann::json &jsonBuf) const;
    ErrCode TransformTo(const nlohmann::json &jsonObject, BmsExtension &bmsExtension) const;
};
}  // namespace AppExecFwk
}  // namespace OHOS