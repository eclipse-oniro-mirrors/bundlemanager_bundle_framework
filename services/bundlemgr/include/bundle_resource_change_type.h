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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORY_SERVICES_BUNDLE_RESOURCE_CHANGE_TYPE_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORY_SERVICES_BUNDLE_RESOURCE_CHANGE_TYPE_H

namespace OHOS {
namespace AppExecFwk {
enum class BundleResourceChangeType {
    // for langue changed
    SYSTEM_LANGUE_CHANGE = 0x00000001,
    // for system theme changed
    SYSTEM_THEME_CHANGE = 0x00000010,
    // for color mode changed
    SYSTEM_COLOR_MODE_CHANGE = 0x00000020,
    // for user changed
    SYSTEM_USER_ID_CHANGE = 0x00000030,
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORY_SERVICES_BUNDLE_RESOURCE_CHANGE_TYPE_H