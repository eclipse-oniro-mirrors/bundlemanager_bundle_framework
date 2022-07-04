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

#ifndef FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_IDEFAULT_APP_DB
#define FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_IDEFAULT_APP_DB

#include <map>

#include "bundle_constants.h"
#include "default_app_data.h"
#include "element.h"
#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class IDefaultAppDb {
public:
    IDefaultAppDb() = default;
    virtual ~IDefaultAppDb() = default;
    virtual bool GetDefaultApplicationInfos(int32_t userId, std::map<std::string, Element>& infos) = 0;
    virtual bool GetDefaultApplicationInfo(int32_t userId, const std::string& type, Element& element) = 0;
    virtual bool SetDefaultApplicationInfos(int32_t userId, const std::map<std::string, Element>& infos) = 0;
    virtual bool SetDefaultApplicationInfo(int32_t userId, const std::string& type, const Element& element) = 0;
    virtual bool DeleteDefaultApplicationInfos(int32_t userId) = 0;
    virtual bool DeleteDefaultApplicationInfo(int32_t userId, const std::string& type) = 0;
    virtual void RegisterDeathListener() = 0;
    virtual void UnRegisterDeathListener() = 0;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_IDEFAULT_APP_DB
