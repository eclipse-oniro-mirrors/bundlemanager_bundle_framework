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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_PARAM_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_PARAM_H

#include "rdb_data_manager.h"

namespace OHOS {
namespace AppExecFwk {
class BmsParam {
public:
    BmsParam();
    ~BmsParam();

    /**
     * @brief Get bms param.
     * @param key Indicates the key.
     * @param value Indicates the value.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetBmsParam(const std::string &key, std::string &value);
    /**
     * @brief Save the bms param.
     * @param paramKeyInfo Indicates the bms param key.
     * @param paramValueInfo Indicates the bms param value.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool SaveBmsParam(const std::string &paramKeyInfo, const std::string &paramValueInfo);

private:
    std::shared_ptr<RdbDataManager> rdbDataManager_ = nullptr;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_PARAM_H