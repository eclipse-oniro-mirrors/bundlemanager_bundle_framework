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

#include "default_app_mgr.h"

#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#ifdef BMS_RDB_ENABLE
#include "default_app_rdb.h"
#else
#include "default_app_db.h"
#endif
#include "ipc_skeleton.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr int32_t INITIAL_USER_ID = -1;
    constexpr int32_t TYPE_PART_COUNT = 2;
    constexpr int32_t INDEX_ZERO = 0;
    constexpr int32_t INDEX_ONE = 1;
    const std::string SPLIT = "/";
    const std::string ACTION_VIEW_DATA = "ohos.want.action.viewData";
    const std::string ENTITY_BROWSER = "entity.system.browsable";
    const std::string HTTP = "http";
    const std::string HTTPS = "https";
    const std::string WILDCARD = "*";
    const std::string IMAGE_TYPE = "image/*";
    const std::string AUDIO_TYPE = "audio/*";
    const std::string VIDEO_TYPE = "video/*";
    const std::string PDF_TYPE = "application/pdf";
    const std::string DOC_TYPE = "application/msword";
    const std::string DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    const std::string XLS_TYPE = "application/vnd.ms-excel";
    const std::string XLSX_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    const std::string PPT_TYPE = "application/vnd.ms-powerpoint";
    const std::string PPTX_TYPE = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    const std::string BROWSER = "BROWSER";
    const std::string IMAGE = "IMAGE";
    const std::string AUDIO = "AUDIO";
    const std::string VIDEO = "VIDEO";
    const std::string PDF = "PDF";
    const std::string WORD = "WORD";
    const std::string EXCEL = "EXCEL";
    const std::string PPT = "PPT";
}

std::set<std::string> DefaultAppMgr::supportAppTypes = {BROWSER, IMAGE, AUDIO, VIDEO, PDF, WORD, EXCEL, PPT};

DefaultAppMgr& DefaultAppMgr::GetInstance()
{
    static DefaultAppMgr defaultAppMgr;
    return defaultAppMgr;
}

DefaultAppMgr::DefaultAppMgr()
{
    APP_LOGD("create DefaultAppMgr.");
    Init();
}

DefaultAppMgr::~DefaultAppMgr()
{
    APP_LOGD("destroy DefaultAppMgr.");
    defaultAppDb_->UnRegisterDeathListener();
}

void DefaultAppMgr::Init()
{
#ifdef BMS_RDB_ENABLE
    defaultAppDb_ = std::make_shared<DefaultAppRdb>();
#else
    defaultAppDb_ = std::make_shared<DefaultAppDb>();
#endif
    defaultAppDb_->RegisterDeathListener();
}

ErrCode DefaultAppMgr::IsDefaultApplication(int32_t userId, const std::string& type, bool& isDefaultApp) const
{
    if (VerifyUserIdAndType(userId, type) != ERR_OK) {
        APP_LOGW("VerifyUserIdAndType failed.");
        isDefaultApp = false;
        return ERR_OK;
    }
    Element element;
    bool ret = defaultAppDb_->GetDefaultApplicationInfo(userId, type, element);
    if (!ret) {
        APP_LOGW("GetDefaultApplicationInfo failed.");
        isDefaultApp = false;
        return ERR_OK;
    }
    ret = IsElementValid(userId, type, element);
    if (!ret) {
        APP_LOGW("Element is invalid.");
        isDefaultApp = false;
        return ERR_OK;
    }
    // get bundle name via calling uid
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGW("get BundleDataMgr failed.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string callingBundleName;
    ret = dataMgr->GetBundleNameForUid(IPCSkeleton::GetCallingUid(), callingBundleName);
    if (!ret) {
        APP_LOGW("GetBundleNameForUid failed.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    APP_LOGD("callingBundleName : %{public}s", callingBundleName.c_str());
    isDefaultApp = element.bundleName == callingBundleName;
    return ERR_OK;
}

ErrCode DefaultAppMgr::GetDefaultApplication(int32_t userId, const std::string& type, BundleInfo& bundleInfo) const
{
    ErrCode errCode = VerifyUserIdAndType(userId, type);
    if (errCode != ERR_OK) {
        APP_LOGW("VerifyUserIdAndType failed.");
        return errCode;
    }
    if (!BundlePermissionMgr::VerifySystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_DEFAULT_APPLICATION)) {
        APP_LOGW("verify permission ohos.permission.GET_DEFAULT_APPLICATION failed.");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    if (IsAppType(type)) {
        return GetBundleInfoByAppType(userId, type, bundleInfo);
    } else if (IsFileType(type)) {
        return GetBundleInfoByFileType(userId, type, bundleInfo);
    } else {
        APP_LOGW("invalid type, not app type or file type.");
        return ERR_BUNDLE_MANAGER_INVALID_TYPE;
    }
}

ErrCode DefaultAppMgr::SetDefaultApplication(int32_t userId, const std::string& type, const Element& element) const
{
    ErrCode errCode = VerifyUserIdAndType(userId, type);
    if (errCode != ERR_OK) {
        APP_LOGW("VerifyUserIdAndType failed.");
        return errCode;
    }
    if (!BundlePermissionMgr::VerifySystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_SET_DEFAULT_APPLICATION)) {
        APP_LOGW("verify permission ohos.permission.SET_DEFAULT_APPLICATION failed.");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    // clear default app
    bool ret = IsElementEmpty(element);
    if (ret) {
        APP_LOGD("clear default app.");
        ret = defaultAppDb_->DeleteDefaultApplicationInfo(userId, type);
        if (!ret) {
            APP_LOGW("DeleteDefaultApplicationInfo failed.");
            return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
        }
        APP_LOGD("SetDefaultApplication success.");
        return ERR_OK;
    }
    ret = IsElementValid(userId, type, element);
    if (!ret) {
        APP_LOGW("Element is invalid.");
        return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
    }
    ret = defaultAppDb_->SetDefaultApplicationInfo(userId, type, element);
    if (!ret) {
        APP_LOGW("SetDefaultApplicationInfo failed.");
        return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
    }
    APP_LOGD("SetDefaultApplication success.");
    return ERR_OK;
}

ErrCode DefaultAppMgr::ResetDefaultApplication(int32_t userId, const std::string& type) const
{
    ErrCode errCode = VerifyUserIdAndType(userId, type);
    if (errCode != ERR_OK) {
        APP_LOGW("VerifyUserIdAndType failed.");
        return errCode;
    }
    if (!BundlePermissionMgr::VerifySystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_SET_DEFAULT_APPLICATION)) {
        APP_LOGW("verify permission ohos.permission.SET_DEFAULT_APPLICATION failed.");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    Element element;
    bool ret = defaultAppDb_->GetDefaultApplicationInfo(INITIAL_USER_ID, type, element);
    if (!ret) {
        APP_LOGD("directly delete default info.");
        if (defaultAppDb_->DeleteDefaultApplicationInfo(userId, type)) {
            return ERR_OK;
        }
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ret = IsElementValid(userId, type, element);
    if (!ret) {
        APP_LOGW("Element is invalid.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ret = defaultAppDb_->SetDefaultApplicationInfo(userId, type, element);
    if (!ret) {
        APP_LOGW("SetDefaultApplicationInfo failed.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    APP_LOGD("ResetDefaultApplication success.");
    return ERR_OK;
}

void DefaultAppMgr::HandleUninstallBundle(int32_t userId, const std::string& bundleName) const
{
    APP_LOGD("begin to HandleUninstallBundle.");
    std::map<std::string, Element> infos;
    bool ret = defaultAppDb_->GetDefaultApplicationInfos(userId, infos);
    if (!ret) {
        APP_LOGW("GetDefaultApplicationInfos failed.");
        return;
    }
    for (auto item = infos.begin(); item != infos.end();) {
        if (item->second.bundleName == bundleName) {
            item = infos.erase(item);
        } else {
            item++;
        }
    }
    defaultAppDb_->SetDefaultApplicationInfos(userId, infos);
}

void DefaultAppMgr::HandleCreateUser(int32_t userId) const
{
    APP_LOGD("begin to HandleCreateUser.");
    std::map<std::string, Element> infos;
    bool ret = defaultAppDb_->GetDefaultApplicationInfos(INITIAL_USER_ID, infos);
    if (!ret) {
        APP_LOGW("GetDefaultApplicationInfos failed.");
        return;
    }
    defaultAppDb_->SetDefaultApplicationInfos(userId, infos);
}

void DefaultAppMgr::HandleRemoveUser(int32_t userId) const
{
    APP_LOGD("begin to HandleRemoveUser.");
    defaultAppDb_->DeleteDefaultApplicationInfos(userId);
}

ErrCode DefaultAppMgr::GetBundleInfoByAppType(int32_t userId, const std::string& type, BundleInfo& bundleInfo) const
{
    Element element;
    bool ret = defaultAppDb_->GetDefaultApplicationInfo(userId, type, element);
    if (!ret) {
        APP_LOGW("GetDefaultApplicationInfo failed.");
        return ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
    }
    ret = GetBundleInfo(userId, type, element, bundleInfo);
    if (!ret) {
        APP_LOGW("GetBundleInfo failed.");
        return ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
    }
    APP_LOGD("GetBundleInfoByAppType success.");
    return ERR_OK;
}

ErrCode DefaultAppMgr::GetBundleInfoByFileType(int32_t userId, const std::string& type, BundleInfo& bundleInfo) const
{
    std::map<std::string, Element> infos;
    bool ret = defaultAppDb_->GetDefaultApplicationInfos(userId, infos);
    if (!ret) {
        APP_LOGW("GetDefaultApplicationInfos failed.");
        return ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
    }
    std::map<std::string, Element> defaultAppTypeInfos;
    std::map<std::string, Element> defaultFileTypeInfos;
    for (const auto& item : infos) {
        if (IsAppType(item.first)) {
            defaultAppTypeInfos.emplace(item.first, item.second);
        }
        if (IsFileType(item.first)) {
            defaultFileTypeInfos.emplace(item.first, item.second);
        }
    }
    // match default app type
    for (const auto& item : defaultAppTypeInfos) {
        if (GetBundleInfo(userId, type, item.second, bundleInfo)) {
            APP_LOGD("match default app type success.");
            return ERR_OK;
        }
    }
    // match default file type
    for (const auto& item : defaultFileTypeInfos) {
        if (item.first == type && GetBundleInfo(userId, type, item.second, bundleInfo)) {
            APP_LOGD("match default file type success.");
            return ERR_OK;
        }
    }
    APP_LOGW("GetBundleInfoByFileType failed.");
    return ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
}

bool DefaultAppMgr::GetBundleInfo(int32_t userId, const std::string& type, const Element& element,
    BundleInfo& bundleInfo) const
{
    APP_LOGD("begin to GetBundleInfo.");
    bool ret = VerifyElementFormat(element);
    if (!ret) {
        APP_LOGW("VerifyElementFormat failed.");
        return false;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGW("get BundleDataMgr failed.");
        return false;
    }
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    std::vector<Skill> skills;
    // verify if element exists
    ret = dataMgr->QueryInfoAndSkillsByElement(userId, element, abilityInfo, extensionInfo, skills);
    if (!ret) {
        APP_LOGW("GetBundleInfo, QueryInfoAndSkillsByElement failed.");
        return false;
    }
    // match type and skills
    ret = IsMatch(type, skills);
    if (!ret) {
        APP_LOGW("GetBundleInfo, type and skills not match.");
        return false;
    }
    ret = dataMgr->GetBundleInfo(element.bundleName, GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!ret) {
        APP_LOGW("GetBundleInfo failed.");
        return false;
    }
    bool isAbility = !element.abilityName.empty();
    if (isAbility) {
        bundleInfo.abilityInfos.emplace_back(abilityInfo);
    } else {
        bundleInfo.extensionInfos.emplace_back(extensionInfo);
    }
    APP_LOGD("GetBundleInfo success.");
    return true;
}

bool DefaultAppMgr::IsMatch(const std::string& type, const std::vector<Skill>& skills) const
{
    if (IsAppType(type)) {
        return MatchAppType(type, skills);
    } else if (IsFileType(type)) {
        return MatchFileType(type, skills);
    } else {
        APP_LOGW("invalid type.");
        return false;
    }
}

bool DefaultAppMgr::MatchAppType(const std::string& type, const std::vector<Skill>& skills) const
{
    APP_LOGW("begin to match app type, type : %{public}s.", type.c_str());
    if (type == BROWSER) {
        return IsBrowserSkillsValid(skills);
    } else if (type == IMAGE) {
        return IsImageSkillsValid(skills);
    } else if (type == AUDIO) {
        return IsAudioSkillsValid(skills);
    } else if (type == VIDEO) {
        return IsVideoSkillsValid(skills);
    } else if (type == PDF) {
        return IsPdfSkillsValid(skills);
    } else if (type == WORD) {
        return IsWordSkillsValid(skills);
    } else if (type == EXCEL) {
        return IsExcelSkillsValid(skills);
    } else if (type == PPT) {
        return IsPptSkillsValid(skills);
    } else {
        return false;
    }
}

bool DefaultAppMgr::IsBrowserSkillsValid(const std::vector<Skill>& skills) const
{
    APP_LOGD("begin to verify browser skills.");
    for (const Skill& skill : skills) {
        auto item = std::find(skill.actions.cbegin(), skill.actions.cend(), ACTION_VIEW_DATA);
        if (item == skill.actions.cend()) {
            continue;
        }
        item = std::find(skill.entities.cbegin(), skill.entities.cend(), ENTITY_BROWSER);
        if (item == skill.entities.cend()) {
            continue;
        }
        for (const SkillUri& skillUri : skill.uris) {
            if (skillUri.scheme == HTTP || skillUri.scheme == HTTPS) {
                APP_LOGD("browser skills is valid.");
                return true;
            }
        }
    }
    APP_LOGW("browser skills is invalid.");
    return false;
}

bool DefaultAppMgr::IsImageSkillsValid(const std::vector<Skill>& skills) const
{
    APP_LOGD("begin to verify image skills.");
    for (const Skill& skill : skills) {
        auto item = std::find(skill.actions.cbegin(), skill.actions.cend(), ACTION_VIEW_DATA);
        if (item == skill.actions.cend()) {
            continue;
        }
        for (const SkillUri& skillUri : skill.uris) {
            if (skill.MatchType(IMAGE_TYPE, skillUri.type)) {
                APP_LOGD("image skills is valid.");
                return true;
            }
        }
    }
    APP_LOGW("image skills is invalid.");
    return false;
}

bool DefaultAppMgr::IsAudioSkillsValid(const std::vector<Skill>& skills) const
{
    APP_LOGD("begin to verify audio skills.");
    for (const Skill& skill : skills) {
        auto item = std::find(skill.actions.cbegin(), skill.actions.cend(), ACTION_VIEW_DATA);
        if (item == skill.actions.cend()) {
            continue;
        }
        for (const SkillUri& skillUri : skill.uris) {
            if (skill.MatchType(AUDIO_TYPE, skillUri.type)) {
                APP_LOGD("audio skills is valid.");
                return true;
            }
        }
    }
    APP_LOGW("audio skills is invalid.");
    return false;
}

bool DefaultAppMgr::IsVideoSkillsValid(const std::vector<Skill>& skills) const
{
    APP_LOGD("begin to verify video skills.");
    for (const Skill& skill : skills) {
        auto item = std::find(skill.actions.cbegin(), skill.actions.cend(), ACTION_VIEW_DATA);
        if (item == skill.actions.cend()) {
            continue;
        }
        for (const SkillUri& skillUri : skill.uris) {
            if (skill.MatchType(VIDEO_TYPE, skillUri.type)) {
                APP_LOGD("video skills is valid.");
                return true;
            }
        }
    }
    APP_LOGW("video skills is invalid.");
    return false;
}

bool DefaultAppMgr::IsPdfSkillsValid(const std::vector<Skill>& skills) const
{
    APP_LOGD("begin to verify pdf skills.");
    for (const Skill& skill : skills) {
        auto item = std::find(skill.actions.cbegin(), skill.actions.cend(), ACTION_VIEW_DATA);
        if (item == skill.actions.cend()) {
            continue;
        }
        for (const SkillUri& skillUri : skill.uris) {
            if (skillUri.type == PDF_TYPE) {
                APP_LOGD("pdf skills is valid.");
                return true;
            }
        }
    }
    APP_LOGW("pdf skills is invalid.");
    return false;
}

bool DefaultAppMgr::IsWordSkillsValid(const std::vector<Skill>& skills) const
{
    APP_LOGD("begin to verify word skills.");
    for (const Skill& skill : skills) {
        auto item = std::find(skill.actions.cbegin(), skill.actions.cend(), ACTION_VIEW_DATA);
        if (item == skill.actions.cend()) {
            continue;
        }
        for (const SkillUri& skillUri : skill.uris) {
            if (skillUri.type == DOC_TYPE || skillUri.type == DOCX_TYPE) {
                APP_LOGD("word skills is valid.");
                return true;
            }
        }
    }
    APP_LOGW("word skills is invalid.");
    return false;
}

bool DefaultAppMgr::IsExcelSkillsValid(const std::vector<Skill>& skills) const
{
    APP_LOGD("begin to verify excel skills.");
    for (const Skill& skill : skills) {
        auto item = std::find(skill.actions.cbegin(), skill.actions.cend(), ACTION_VIEW_DATA);
        if (item == skill.actions.cend()) {
            continue;
        }
        for (const SkillUri& skillUri : skill.uris) {
            if (skillUri.type == XLS_TYPE || skillUri.type == XLSX_TYPE) {
                APP_LOGD("excel skills is valid.");
                return true;
            }
        }
    }
    APP_LOGW("excel skills is invalid.");
    return false;
}

bool DefaultAppMgr::IsPptSkillsValid(const std::vector<Skill>& skills) const
{
    APP_LOGD("begin to verify ppt skills.");
    for (const Skill& skill : skills) {
        auto item = std::find(skill.actions.cbegin(), skill.actions.cend(), ACTION_VIEW_DATA);
        if (item == skill.actions.cend()) {
            continue;
        }
        for (const SkillUri& skillUri : skill.uris) {
            if (skillUri.type == PPT_TYPE || skillUri.type == PPTX_TYPE) {
                APP_LOGD("ppt skills is valid.");
                return true;
            }
        }
    }
    APP_LOGW("ppt skills is invalid.");
    return false;
}

bool DefaultAppMgr::MatchFileType(const std::string& type, const std::vector<Skill>& skills) const
{
    APP_LOGW("begin to match file type, type : %{public}s.", type.c_str());
    for (const Skill& skill : skills) {
        auto item = std::find(skill.actions.cbegin(), skill.actions.cend(), ACTION_VIEW_DATA);
        if (item == skill.actions.cend()) {
            continue;
        }
        for (const SkillUri& skillUri : skill.uris) {
            if (skill.MatchType(type, skillUri.type)) {
                APP_LOGW("match file type success.");
                return true;
            }
        }
    }
    APP_LOGW("match file type failed.");
    return false;
}

bool DefaultAppMgr::IsTypeValid(const std::string& type) const
{
    return IsAppType(type) || IsFileType(type);
}

bool DefaultAppMgr::IsAppType(const std::string& type) const
{
    if (type.empty()) {
        return false;
    }
    return supportAppTypes.find(type) != supportAppTypes.end();
}

bool DefaultAppMgr::IsFileType(const std::string& type) const
{
    // valid fileType format : type/subType
    if (type.empty() || type.find(WILDCARD) != type.npos) {
        APP_LOGW("file type not allow contains *.");
        return false;
    }
    std::vector<std::string> vector;
    SplitStr(type, SPLIT, vector, false, false);
    if (vector.size() == TYPE_PART_COUNT && !vector[INDEX_ZERO].empty() && !vector[INDEX_ONE].empty()) {
        return true;
    }
    APP_LOGW("file type format invalid.");
    return false;
}

bool DefaultAppMgr::IsUserIdExist(int32_t userId) const
{
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGW("get BundleDataMgr failed.");
        return false;
    }
    return dataMgr->HasUserId(userId);
}

ErrCode DefaultAppMgr::VerifyUserIdAndType(int32_t userId, const std::string& type) const
{
    bool ret = IsUserIdExist(userId);
    if (!ret) {
        APP_LOGW("userId %{public}d doesn't exist.", userId);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    ret = IsTypeValid(type);
    if (!ret) {
        APP_LOGW("invalid type %{public}s, not app type or file type.", type.c_str());
        return ERR_BUNDLE_MANAGER_INVALID_TYPE;
    }
    return ERR_OK;
}

bool DefaultAppMgr::IsElementEmpty(const Element& element) const
{
    return element.bundleName.empty() && element.moduleName.empty()
        && element.abilityName.empty() && element.extensionName.empty();
}

bool DefaultAppMgr::VerifyElementFormat(const Element& element)
{
    const std::string& bundleName = element.bundleName;
    const std::string& moduleName = element.moduleName;
    const std::string& abilityName = element.abilityName;
    const std::string& extensionName = element.extensionName;
    if (bundleName.empty()) {
        APP_LOGW("bundleName empty, bad Element format.");
        return false;
    }
    if (moduleName.empty()) {
        APP_LOGW("moduleName empty, bad Element format.");
        return false;
    }
    if (abilityName.empty() && extensionName.empty()) {
        APP_LOGW("abilityName and extensionName both empty, bad Element format.");
        return false;
    }
    if (!abilityName.empty() && !extensionName.empty()) {
        APP_LOGW("abilityName and extensionName both non-empty, bad Element format.");
        return false;
    }
    return true;
}

bool DefaultAppMgr::IsElementValid(int32_t userId, const std::string& type, const Element& element) const
{
    bool ret = VerifyElementFormat(element);
    if (!ret) {
        APP_LOGW("VerifyElementFormat failed.");
        return false;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGW("get BundleDataMgr failed.");
        return false;
    }
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    std::vector<Skill> skills;
    // verify if element exists
    ret = dataMgr->QueryInfoAndSkillsByElement(userId, element, abilityInfo, extensionInfo, skills);
    if (!ret) {
        APP_LOGW("QueryInfoAndSkillsByElement failed.");
        return false;
    }
    // match type and skills
    ret = IsMatch(type, skills);
    if (!ret) {
        APP_LOGW("type and skills not match.");
        return false;
    }
    APP_LOGD("Element is valid.");
    return true;
}
}
}