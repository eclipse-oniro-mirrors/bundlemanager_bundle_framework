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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_DEFAULT_APP_INTERFACE_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_DEFAULT_APP_INTERFACE_H

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "iremote_broker.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
class IDefaultApp : public IRemoteBroker {
public:
    using Want = OHOS::AAFwk::Want;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.DefaultApp");
    
    virtual ErrCode IsDefaultApplication(const std::string& type, bool& isDefaultApp)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode GetDefaultApplication(int32_t userId, const std::string& type, BundleInfo& bundleInfo)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode SetDefaultApplication(int32_t userId, const std::string& type, const Want& want)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode ResetDefaultApplication(int32_t userId, const std::string& type)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
};
}
}
#endif
