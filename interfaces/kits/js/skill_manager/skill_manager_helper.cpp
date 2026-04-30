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

#include "skill_manager_helper.h"

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {

sptr<IBundleSkillManager> SkillManagerHelper::skillManager_ = nullptr;
std::mutex SkillManagerHelper::skillManagerMutex_;
sptr<IRemoteObject::DeathRecipient> SkillManagerHelper::deathRecipient_(
    sptr<SkillManagerDeathRecipient>::MakeSptr());

void SkillManagerHelper::SkillManagerDeathRecipient::OnRemoteDied(
    [[maybe_unused]] const wptr<IRemoteObject>& remote)
{
    APP_LOGI("BundleManagerService dead");
    std::lock_guard<std::mutex> lock(skillManagerMutex_);
    skillManager_ = nullptr;
}

sptr<IBundleSkillManager> SkillManagerHelper::GetSkillManager()
{
    std::lock_guard<std::mutex> lock(skillManagerMutex_);
    if (skillManager_ == nullptr) {
        auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityManager == nullptr) {
            APP_LOGE("systemAbilityManager is null");
            return nullptr;
        }
        auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (bundleMgrSa == nullptr) {
            APP_LOGE("bundleMgrSa is null");
            return nullptr;
        }
        auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
        if (bundleMgr == nullptr) {
            APP_LOGE("iface_cast failed");
            return nullptr;
        }
        bundleMgr->AsObject()->AddDeathRecipient(deathRecipient_);
        skillManager_ = bundleMgr->GetSkillManagerProxy();
    }
    return skillManager_;
}

ErrCode SkillManagerHelper::InnerGetSkillInfoForSelf(const std::string &moduleName,
    const std::string &skillName, uint32_t flags, SkillInfo &skillInfo)
{
    APP_LOGD("start");
    auto skillManagerProxy = SkillManagerHelper::GetSkillManager();
    if (skillManagerProxy == nullptr) {
        APP_LOGE("skillManagerProxy is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = skillManagerProxy->GetSkillInfoForSelf(moduleName, skillName, flags, skillInfo);
    if (ret != ERR_OK) {
        APP_LOGE("failed, moduleName is %{public}s, errCode: %{public}d", moduleName.c_str(), ret);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode SkillManagerHelper::InnerGetSkillInfosForSelf(uint32_t flags,
    std::vector<SkillInfo> &skillInfos)
{
    APP_LOGD("start");
    auto skillManagerProxy = SkillManagerHelper::GetSkillManager();
    if (skillManagerProxy == nullptr) {
        APP_LOGE("skillManagerProxy is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = skillManagerProxy->GetSkillInfosForSelf(flags, skillInfos);
    if (ret != ERR_OK) {
        APP_LOGE("failed, errCode: %{public}d", ret);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode SkillManagerHelper::InnerGetSkillInfo(const std::string &bundleName, const std::string &moduleName,
    const std::string &skillName, uint32_t flags, int32_t userId, SkillInfo &skillInfo)
{
    APP_LOGD("start");
    auto skillManagerProxy = SkillManagerHelper::GetSkillManager();
    if (skillManagerProxy == nullptr) {
        APP_LOGE("skillManagerProxy is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = skillManagerProxy->GetSkillInfo(bundleName, moduleName, skillName, flags, userId, skillInfo);
    if (ret != ERR_OK) {
        APP_LOGE("failed, bundleName is %{public}s, errCode: %{public}d", bundleName.c_str(), ret);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode SkillManagerHelper::InnerGetSkillInfos(const std::string &bundleName, uint32_t flags, int32_t userId,
    std::vector<SkillInfo> &skillInfos)
{
    APP_LOGD("start");
    auto skillManagerProxy = SkillManagerHelper::GetSkillManager();
    if (skillManagerProxy == nullptr) {
        APP_LOGE("skillManagerProxy is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = skillManagerProxy->GetSkillInfos(bundleName, flags, userId, skillInfos);
    if (ret != ERR_OK) {
        APP_LOGE("failed, bundleName is %{public}s, errCode: %{public}d", bundleName.c_str(), ret);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode SkillManagerHelper::InnerGetAllSkillInfos(uint32_t flags, int32_t userId,
    std::vector<SkillInfo> &skillInfos)
{
    APP_LOGD("start");
    auto skillManagerProxy = SkillManagerHelper::GetSkillManager();
    if (skillManagerProxy == nullptr) {
        APP_LOGE("skillManagerProxy is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = skillManagerProxy->GetAllSkillInfos(flags, userId, skillInfos);
    if (ret != ERR_OK) {
        APP_LOGE("failed, errCode: %{public}d", ret);
    }
    return CommonFunc::ConvertErrCode(ret);
}

} // namespace AppExecFwk
} // namespace OHOS
