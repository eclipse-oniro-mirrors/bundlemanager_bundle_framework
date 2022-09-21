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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DEFAULT_APP_HOST_IMPL_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DEFAULT_APP_HOST_IMPL_H

#include "default_app_host.h"
#include "default_app_mgr.h"

namespace OHOS {
namespace AppExecFwk {
class DefaultAppHostImpl : public DefaultAppHost {
public:
    virtual ErrCode IsDefaultApplication(const std::string& type, bool& isDefaultApp) override;
    virtual ErrCode GetDefaultApplication(int32_t userId, const std::string& type, BundleInfo& bundleInfo) override;
    virtual ErrCode SetDefaultApplication(int32_t userId, const std::string& type, const Want& want) override;
    virtual ErrCode ResetDefaultApplication(int32_t userId, const std::string& type) override;
};
}
}
#endif
