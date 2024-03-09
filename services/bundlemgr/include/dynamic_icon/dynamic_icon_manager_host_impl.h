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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_DYNAMIC_ICON_MANAGER_HOST_IMPL_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_DYNAMIC_ICON_MANAGER_HOST_IMPL_H

#include "dynamic_icon_manager_host.h"

namespace OHOS {
namespace AppExecFwk {
class DynamicIconManagerHostImpl : public DynamicIconManagerHost {
public:
    DynamicIconManagerHostImpl();
    virtual ~DynamicIconManagerHostImpl();

    ErrCode EnableDynamicIcon(const std::string &bundleName,
        const std::string &dynamicIconKey, const std::string &filePath) override;
    ErrCode DisableDynamicIcon(const std::string &bundleName) override;
    ErrCode GetDynamicIcon(const std::string &bundleName, std::string &dynamicIconKey) override;
    ErrCode CreateFd(const std::string &fileName, int32_t &fd, std::string &path) override;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_DYNAMIC_ICON_MANAGER_HOST_IMPL_H
