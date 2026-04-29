/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_SKILL_SKILL_MANAGER_HOST_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_SKILL_SKILL_MANAGER_HOST_H

#include "bundle_skill/skill_manager_interface.h"
#include "bundle_skill/skill_manager_proxy.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class BundleSkillManagerHost : public IRemoteStub<IBundleSkillManager> {
public:
    BundleSkillManagerHost() = default;
    virtual ~BundleSkillManagerHost() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    ErrCode HandleGetSkillInfoForSelf(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetSkillInfosForSelf(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetSkillInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetSkillInfos(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetAllSkillInfos(MessageParcel &data, MessageParcel &reply);

    DISALLOW_COPY_AND_MOVE(BundleSkillManagerHost);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_SKILL_SKILL_MANAGER_HOST_H
