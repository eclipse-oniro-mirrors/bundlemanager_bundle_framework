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

#include "bundle_skill/skill_manager_host.h"

#include "app_log_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {

int32_t BundleSkillManagerHost::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    APP_LOGD("skill manager host onReceived message, the message code is %{public}u", code);
    std::u16string descriptor = BundleSkillManagerHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        APP_LOGE("descriptor mismatch");
        return OBJECT_NULL;
    }

    ErrCode errCode = ERR_OK;
    switch (code) {
        case static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO_FOR_SELF):
            errCode = HandleGetSkillInfoForSelf(data, reply);
            break;
        case static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFOS_FOR_SELF):
            errCode = HandleGetSkillInfosForSelf(data, reply);
            break;
        case static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO):
            errCode = HandleGetSkillInfo(data, reply);
            break;
        case static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFOS):
            errCode = HandleGetSkillInfos(data, reply);
            break;
        case static_cast<uint32_t>(SkillManagerInterfaceCode::GET_ALL_SKILL_INFOS):
            errCode = HandleGetAllSkillInfos(data, reply);
            break;
        default:
            APP_LOGW("skill manager host receives unknown code, code = %{public}u", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    APP_LOGD("skill manager host finish to process message, errCode: %{public}d", errCode);
    return (errCode == ERR_OK) ? NO_ERROR : UNKNOWN_ERROR;
}

ErrCode BundleSkillManagerHost::HandleGetSkillInfoForSelf(MessageParcel &data, MessageParcel &reply)
{
    std::string moduleName = data.ReadString();
    std::string skillName = data.ReadString();
    int32_t userId = data.ReadInt32();
    uint32_t flags = data.ReadUint32();
    SkillInfo skillInfo;
    ErrCode ret = GetSkillInfoForSelf(moduleName, skillName, userId, flags, skillInfo);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&skillInfo)) {
            APP_LOGE("write skillInfo failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleSkillManagerHost::HandleGetSkillInfosForSelf(MessageParcel &data, MessageParcel &reply)
{
    uint32_t flags = data.ReadUint32();
    int32_t userId = data.ReadInt32();
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = GetSkillInfosForSelf(flags, userId, skillInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        int32_t infoSize = static_cast<int32_t>(skillInfos.size());
        if (!reply.WriteInt32(infoSize)) {
            APP_LOGE("write infoSize failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        for (int32_t i = 0; i < infoSize; ++i) {
            if (!reply.WriteParcelable(&skillInfos[i])) {
                APP_LOGE("write skillInfo failed");
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
        }
    }
    return ERR_OK;
}

ErrCode BundleSkillManagerHost::HandleGetSkillInfo(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::string skillName = data.ReadString();
    uint32_t flags = data.ReadUint32();
    int32_t userId = data.ReadInt32();
    SkillInfo skillInfo;
    ErrCode ret = GetSkillInfo(bundleName, moduleName, skillName, flags, userId, skillInfo);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&skillInfo)) {
            APP_LOGE("write skillInfo failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleSkillManagerHost::HandleGetSkillInfos(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    uint32_t flags = data.ReadUint32();
    int32_t userId = data.ReadInt32();
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = GetSkillInfos(bundleName, flags, userId, skillInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        int32_t infoSize = static_cast<int32_t>(skillInfos.size());
        if (!reply.WriteInt32(infoSize)) {
            APP_LOGE("write infoSize failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        for (int32_t i = 0; i < infoSize; ++i) {
            if (!reply.WriteParcelable(&skillInfos[i])) {
                APP_LOGE("write skillInfo failed");
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
        }
    }
    return ERR_OK;
}

ErrCode BundleSkillManagerHost::HandleGetAllSkillInfos(MessageParcel &data, MessageParcel &reply)
{
    uint32_t flags = data.ReadUint32();
    int32_t userId = data.ReadInt32();
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = GetAllSkillInfos(flags, userId, skillInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        int32_t infoSize = static_cast<int32_t>(skillInfos.size());
        if (!reply.WriteInt32(infoSize)) {
            APP_LOGE("write infoSize failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        for (int32_t i = 0; i < infoSize; ++i) {
            if (!reply.WriteParcelable(&skillInfos[i])) {
                APP_LOGE("write skillInfo failed");
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
        }
    }
    return ERR_OK;
}

} // namespace AppExecFwk
} // namespace OHOS
