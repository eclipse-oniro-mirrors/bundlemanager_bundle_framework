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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_EL5_FILEKEY_CALLBACK_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_EL5_FILEKEY_CALLBACK_H

#include "el5_filekey_callback_stub.h"

namespace OHOS {
namespace AppExecFwk {
class El5FilekeyCallback : public Security::AccessToken::El5FilekeyCallbackStub {
public:
    El5FilekeyCallback() = default;

    ~El5FilekeyCallback() = default;

    void OnRegenerateAppKey(std::vector<Security::AccessToken::AppKeyInfo> &infos) override;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_CALLBACK_H