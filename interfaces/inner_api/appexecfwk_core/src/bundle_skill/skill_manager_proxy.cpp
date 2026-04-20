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

#include "bundle_skill/skill_manager_proxy.h"

#include "app_log_wrapper.h"
#include "ipc_types.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {

BundleSkillManagerProxy::BundleSkillManagerProxy(const sptr<IRemoteObject>& object)
    : IRemoteProxy<IBundleSkillManager>(object)
{}

ErrCode BundleSkillManagerProxy::GetSkillInfoForSelf(const std::string &moduleName,
    const std::string &skillName, int32_t userId, uint32_t flags, SkillInfo &skillInfo)
{
    APP_LOGD("start, moduleName:%{public}s, skillName:%{public}s, flags:%{public}u",
        moduleName.c_str(), skillName.c_str(), flags);
    if (moduleName.empty() || skillName.empty()) {
        APP_LOGE("moduleName or skillName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to write moduleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(skillName)) {
        APP_LOGE("fail to write skillName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to write userId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(flags)) {
        APP_LOGE("fail to write flags");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(SkillManagerInterfaceCode::GET_SKILL_INFO_FOR_SELF, data, reply)) {
        APP_LOGE("SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err: %{public}d", ret);
        return ret;
    }
    std::unique_ptr<SkillInfo> info(reply.ReadParcelable<SkillInfo>());
    if (info == nullptr) {
        APP_LOGE("ReadParcelable failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    skillInfo = *info;
    return ERR_OK;
}

bool BundleSkillManagerProxy::SendRequest(SkillManagerInterfaceCode code,
    MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail send transact cmd due to remote object");
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error %{public}d in transact cmd", result);
        return false;
    }
    return true;
}

ErrCode BundleSkillManagerProxy::GetSkillInfosForSelf(uint32_t flags, int32_t userId,
    std::vector<SkillInfo> &skillInfos)
{
    APP_LOGD("start, flags:%{public}u", flags);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(flags)) {
        APP_LOGE("fail to write flags");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to write userId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendRequest(SkillManagerInterfaceCode::GET_SKILL_INFOS_FOR_SELF, data, reply)) {
        APP_LOGE("SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err: %{public}d", ret);
        return ret;
    }
    int32_t infoSize = reply.ReadInt32();
    for (int32_t i = 0; i < infoSize; ++i) {
        std::unique_ptr<SkillInfo> info(reply.ReadParcelable<SkillInfo>());
        if (info == nullptr) {
            APP_LOGE("ReadParcelable failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        skillInfos.emplace_back(*info);
    }
    return ERR_OK;
}

ErrCode BundleSkillManagerProxy::GetSkillInfo(const std::string &bundleName,
    const std::string &moduleName, const std::string &skillName,
    uint32_t flags, int32_t userId, SkillInfo &skillInfo)
{
    APP_LOGD("start, bundleName:%{public}s, moduleName:%{public}s, flags:%{public}u",
        bundleName.c_str(), moduleName.c_str(), flags);
    if (bundleName.empty() || moduleName.empty() || skillName.empty()) {
        APP_LOGE("bundleName or moduleName or skillName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to write moduleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(skillName)) {
        APP_LOGE("fail to write skillName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(flags)) {
        APP_LOGE("fail to write flags");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to write userId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendRequest(SkillManagerInterfaceCode::GET_SKILL_INFO, data, reply)) {
        APP_LOGE("SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err: %{public}d", ret);
        return ret;
    }
    std::unique_ptr<SkillInfo> info(reply.ReadParcelable<SkillInfo>());
    if (info == nullptr) {
        APP_LOGE("ReadParcelable failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    skillInfo = *info;
    return ERR_OK;
}

ErrCode BundleSkillManagerProxy::GetSkillInfos(const std::string &bundleName, uint32_t flags,
    int32_t userId, std::vector<SkillInfo> &skillInfos)
{
    APP_LOGD("start, bundleName:%{public}s, flags:%{public}u", bundleName.c_str(), flags);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(flags)) {
        APP_LOGE("fail to write flags");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to write userId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendRequest(SkillManagerInterfaceCode::GET_SKILL_INFOS, data, reply)) {
        APP_LOGE("SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err: %{public}d", ret);
        return ret;
    }
    int32_t infoSize = reply.ReadInt32();
    for (int32_t i = 0; i < infoSize; ++i) {
        std::unique_ptr<SkillInfo> info(reply.ReadParcelable<SkillInfo>());
        if (info == nullptr) {
            APP_LOGE("ReadParcelable failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        skillInfos.emplace_back(*info);
    }
    return ERR_OK;
}

ErrCode BundleSkillManagerProxy::GetAllSkillInfos(uint32_t flags, int32_t userId,
    std::vector<SkillInfo> &skillInfos)
{
    APP_LOGD("start, flags:%{public}u, userId:%{public}d", flags, userId);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(flags)) {
        APP_LOGE("fail to write flags");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to write userId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendRequest(SkillManagerInterfaceCode::GET_ALL_SKILL_INFOS, data, reply)) {
        APP_LOGE("SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err: %{public}d", ret);
        return ret;
    }
    int32_t infoSize = reply.ReadInt32();
    for (int32_t i = 0; i < infoSize; ++i) {
        std::unique_ptr<SkillInfo> info(reply.ReadParcelable<SkillInfo>());
        if (info == nullptr) {
            APP_LOGE("ReadParcelable failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        skillInfos.emplace_back(*info);
    }
    return ERR_OK;
}

} // namespace AppExecFwk
} // namespace OHOS
