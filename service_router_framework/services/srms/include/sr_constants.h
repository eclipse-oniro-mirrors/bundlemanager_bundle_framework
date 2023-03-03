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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SR_INCLUDE_CONSTANTS_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SR_INCLUDE_CONSTANTS_H

#include <string>

namespace OHOS {
namespace AppExecFwk {
namespace SrConstants {
const std::string METADATA_SUPPORT_PURPOSE_KEY = "ohos.extension.supportpurpose";
const std::string MUTIL_SPLIT_KEY = "|";
const std::string FORM_PURPOSE_CARD_SPLIT_KEY = ":";
const int32_t FORM_PURPOSE_CARD_SPLIT_SIZE = 2;
const std::string METADATA_SERVICE_TYPE_KEY = "ohos.extension.servicetype";
} // namespace SrConstants
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SR_INCLUDE_CONSTANTS_H
