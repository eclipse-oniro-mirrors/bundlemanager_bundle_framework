/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ROUTER_DATA_STORAGE_INTERFACE_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ROUTER_DATA_STORAGE_INTERFACE_H

#include <map>
#include <vector>

#include "hap_module_info.h"

namespace OHOS {
namespace AppExecFwk {
class IRouterDataStorage {
public:
    IRouterDataStorage() = default;
    virtual ~IRouterDataStorage() = default;
    virtual bool UpdateRouterInfo(
        const std::string &bundleName, const std::map<std::string, std::string> &routerInfoMap) = 0;
    virtual bool GetRouterInfo(const std::string &bundleName, const std::string &moduleName,
        std::vector<RouterItem> &routerInfos) = 0;
    virtual void GetAllBundleNames(std::set<std::string> &bundleNames);
    virtual bool DeleteRouterInfo(const std::string &bundleName) = 0;
    virtual bool DeleteRouterInfo(const std::string &bundleName, const std::string &moduleName) = 0;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ROUTER_DATA_STORAGE_INTERFACE_H