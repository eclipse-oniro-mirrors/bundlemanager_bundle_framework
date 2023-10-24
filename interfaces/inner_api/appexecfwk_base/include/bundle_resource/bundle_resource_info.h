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

#ifndef FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_RESOURCE_INFO_H
#define FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_RESOURCE_INFO_H

#include <string>

namespace OHOS {
namespace AppExecFwk {
enum class ResourceFlag {
    // Used to obtain the all resource info
    GET_RESOURCE_INFO_ALL = 0x00000001,
    // Used to obtained the label resource info
    GET_RESOURCE_INFO_WITH_LABEL = 0x00000002,
    //Used to obtained the icon resource info
    GET_RESOURCE_INFO_WITH_ICON = 0x00000004,
    //Used to obtain the resource info sorted by label
    GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL = 0x00000008
};

struct BundleResourceInfo {
    std::string bundleName;
    std::string label;
    std::string icon;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_RESOURCE_INFO_H
