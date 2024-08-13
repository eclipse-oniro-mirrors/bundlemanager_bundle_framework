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

#ifndef BMS_SERVICES_INCLUDE_ECOLOGICALRULEMANAGERSERVICE_INTERFACE_H
#define BMS_SERVICES_INCLUDE_ECOLOGICALRULEMANAGERSERVICE_INTERFACE_H

#include <string>
#include "iremote_broker.h"
#include "bms_ecological_rule_mgr_service_param.h"
#include "want.h"
#include "ability_info.h"

namespace OHOS {
namespace AppExecFwk {
class IBmsEcologicalRuleMgrService : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.cloud.ecologicalrulemgrservice.IBmsEcologicalRuleMgrService");

    using Want = OHOS::AAFwk::Want;

    using AbilityInfo = OHOS::AppExecFwk::AbilityInfo;

    virtual int32_t QueryFreeInstallExperience(const Want &want, const BmsCallerInfo &callerInfo,
        BmsExperienceRule &rule) = 0;

    enum {
        QUERY_FREE_INSTALL_EXPERIENCE_CMD = 0
    };

    enum ErrCode : int8_t {
        ERR_BASE = (-99),
        ERR_FAILED = (-1),
        ERR_PERMISSION_DENIED = (-2),
        ERR_OK = 0,
    };
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // BMS_SERVICES_INCLUDE_ECOLOGICALRULEMANAGERSERVICE_INTERFACE_H