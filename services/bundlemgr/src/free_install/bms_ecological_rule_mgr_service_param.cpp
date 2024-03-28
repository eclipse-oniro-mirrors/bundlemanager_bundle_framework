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

#include "bms_ecological_rule_mgr_service_param.h"

#include <string>
#include <vector>
#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
#define TAG "ERMS_PARAM"

BmsExperienceRule *BmsExperienceRule::Unmarshalling(Parcel &in)
{
    auto *rule = new (std::nothrow) BmsExperienceRule();
    if (rule == nullptr) {
        return nullptr;
    }

    if (!in.ReadBool(rule->isAllow)) {
        delete rule;
        return nullptr;
    }

    if (!in.ReadString(rule->sceneCode)) {
        delete rule;
        return nullptr;
    }

    rule->replaceWant = in.ReadParcelable<Want>();

    return rule;
}

bool BmsExperienceRule::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(isAllow)) {
        LOG_E(BMSTag::FREE_INSTALL, "write isAllow failed");
        return false;
    }

    if (!parcel.WriteString(sceneCode)) {
        LOG_E(BMSTag::FREE_INSTALL, "write sceneCode failed");
        return false;
    }
    if (!parcel.WriteParcelable(replaceWant)) {
        LOG_E(BMSTag::FREE_INSTALL, "write replaceWant failed");
        return false;
    }

    return true;
}

bool BmsCallerInfo::ReadFromParcel(Parcel &parcel)
{
    LOG_I(BMSTag::FREE_INSTALL, "read from parcel");
    return true;
}

BmsCallerInfo *BmsCallerInfo::Unmarshalling(Parcel &in)
{
    auto *info = new (std::nothrow) BmsCallerInfo();
    if (info == nullptr) {
        LOG_E(BMSTag::FREE_INSTALL, "new callerInfo failed, return nullptr");
        return nullptr;
    }

    info->packageName = in.ReadString();
    LOG_I(BMSTag::FREE_INSTALL, "read packageName result: %{public}s", info->packageName.c_str());

    if (!in.ReadInt32(info->uid)) {
        LOG_E(BMSTag::FREE_INSTALL, "read uid failed");
        delete info;
        return nullptr;
    }

    if (!in.ReadInt32(info->pid)) {
        LOG_E(BMSTag::FREE_INSTALL, "read pid failed");
        delete info;
        return nullptr;
    }

    if (!in.ReadInt32(info->callerAppType)) {
        LOG_E(BMSTag::FREE_INSTALL, "read callerAppType failed");
        delete info;
        return nullptr;
    }

    if (!in.ReadInt32(info->targetAppType)) {
        LOG_E(BMSTag::FREE_INSTALL, "read targetAppType failed");
        delete info;
        return nullptr;
    }

    return info;
}

bool BmsCallerInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(packageName)) {
        LOG_E(BMSTag::FREE_INSTALL, "write packageName failed");
        return false;
    }

    if (!parcel.WriteInt32(uid)) {
        LOG_E(BMSTag::FREE_INSTALL, "write uid failed");
        return false;
    }

    if (!parcel.WriteInt32(pid)) {
        LOG_E(BMSTag::FREE_INSTALL, "write pid failed");
        return false;
    }

    if (!parcel.WriteInt32(callerAppType)) {
        LOG_E(BMSTag::FREE_INSTALL, "write callerAppType failed");
        return false;
    }

    if (!parcel.WriteInt32(targetAppType)) {
        LOG_E(BMSTag::FREE_INSTALL, "write targetAppType failed");
        return false;
    }
    return true;
}

std::string BmsCallerInfo::ToString() const
{
    std::string str = "BmsCallerInfo{packageName:" + packageName + ",uid:" + std::to_string(uid) +
        ",pid:" + std::to_string(pid) + ",callerAppType:" + std::to_string(callerAppType) +
        ",targetAppType:" + std::to_string(targetAppType) + "}";
    return str;
}
} // namespace AppExecFwk
} // namespace OHOS
