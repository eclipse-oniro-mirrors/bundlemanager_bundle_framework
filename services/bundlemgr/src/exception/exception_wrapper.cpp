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

#include <cstdint>
#include <string>

#include "app_log_wrapper.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Safely dump json object to string with exception handling.
 * @param jsonObject The json object to dump.
 * @param result Output parameter for the dumped string.
 * @param indent The indent for output, -1 means no indent.
 * @return Returns true if dump succeeds, false otherwise.
 */
extern "C" __attribute__((visibility("default")))
bool BundleMgrSafeDump(const nlohmann::json& jsonObject, std::string& result, int32_t indent)
{
    try {
        result = jsonObject.dump(indent);
        return true;
    } catch (const nlohmann::json::exception& e) {
        APP_LOGE_NOFUNC("json dump failed, err:%{public}s", e.what());
        return false;
    }
}
} // namespace AppExecFwk
} // namespace OHOS
