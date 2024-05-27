/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "app_log_tag_wrapper.h"
#include "bms_extension_client.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "default_app_rdb.h"
#include "ipc_skeleton.h"
#include "mime_type_mgr.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

namespace {
constexpr int32_t INITIAL_USER_ID = -1;
constexpr int32_t TYPE_PART_COUNT = 2;
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
const std::string SPLIT = "/";
const std::string EMAIL_ACTION = "ohos.want.action.sendToData";
const std::string EMAIL_SCHEME = "mailto";
const std::string ENTITY_BROWSER = "entity.system.browsable";
const std::string HTTP = "http";
const std::string HTTPS = "https";
const std::string HTTP_SCHEME = "http://";
const std::string HTTPS_SCHEME = "https://";
const std::string WILDCARD = "*";
const std::string BROWSER = "BROWSER";
const std::string IMAGE = "IMAGE";
const std::string AUDIO = "AUDIO";
const std::string VIDEO = "VIDEO";
const std::string PDF = "PDF";
const std::string WORD = "WORD";
const std::string EXCEL = "EXCEL";
const std::string PPT = "PPT";
const std::string EMAIL = "EMAIL";
constexpr const char* ACTION_VIEW_DATA = "ohos.want.action.viewData";
const std::map<std::string, std::set<std::string>> APP_TYPES = {
    {IMAGE, {"image/*"}},
    {AUDIO, {"audio/*"}},
    {VIDEO, {"video/*"}},
    {PDF, {"application/pdf"}},
    {WORD, {"application/msword",
        "application/vnd.ms-word.document",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template"}},
    {EXCEL, {"application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template"}},
    {PPT, {"application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.presentationml.template"}},
};
const std::set<std::string> supportAppTypes = {BROWSER, IMAGE, AUDIO, VIDEO, PDF, WORD, EXCEL, PPT, EMAIL};
}

DefaultAppMgr& DefaultAppMgr::GetInstance()
{
    static DefaultAppMgr defaultAppMgr;
    return defaultAppMgr;
}

DefaultAppMgr::DefaultAppMgr()
{
    LOG_D(BMS_TAG_DEFAULT_APP, "create DefaultAppMgr.");
    Init();
}

DefaultAppMgr::~DefaultAppMgr()
{
    LOG_D(BMS_TAG_DEFAULT_APP, "destroy DefaultAppMgr.");
    defaultAppDb_->UnRegisterDeathListener();
}

void DefaultAppMgr::Init()
{
    defaultAppDb_ = std::make_shared<DefaultAppRdb>();
    defaultAppDb_->RegisterDeathListener();
}

ErrCode DefaultAppMgr::IsDefaultApplication(int32_t userId, const std::string& type, bool& isDefaultApp) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::string mimeType = type;
    ConvertTypeBySuffix(mimeType);
    if (VerifyUserIdAndType(userId, mimeType) != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT_APP, "VerifyUserIdAndType failed.");
        isDefaultApp = false;
        return ERR_OK;
    }
    Element element;
    bool ret = defaultAppDb_->GetDefaultApplicationInfo(userId, mimeType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "GetDefaultApplicationInfo failed.");
        isDefaultApp = false;
        return ERR_OK;
    }
    ret = IsElementValid(userId, mimeType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "Element is invalid.");
        isDefaultApp = false;
        return ERR_OK;
    }
    // get bundle name via calling uid
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT_APP, "get BundleDataMgr failed.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string callingBundleName;
    ret = dataMgr->GetBundleNameForUid(IPCSkeleton::GetCallingUid(), callingBundleName);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "GetBundleNameForUid failed.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    LOG_D(BMS_TAG_DEFAULT_APP, "callingBundleName : %{public}s", callingBundleName.c_str());
    isDefaultApp = element.bundleName == callingBundleName;
    return ERR_OK;
}

ErrCode DefaultAppMgr::GetDefaultApplication(
    int32_t userId, const std::string& type, BundleInfo& bundleInfo, bool backup) const
{
    LOG_D(BMS_TAG_DEFAULT_APP, "begin, backup(bool) : %{public}d", backup);
    std::lock_guard<std::mutex> lock(mutex_);
    std::string mimeType = type;
    ConvertTypeBySuffix(mimeType);

    ErrCode errCode = VerifyUserIdAndType(userId, mimeType);
    if (errCode != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT_APP, "VerifyUserIdAndType failed.");
        return errCode;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_DEFAULT_APP, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_DEFAULT_APPLICATION)) {
        LOG_W(BMS_TAG_DEFAULT_APP, "verify permission ohos.permission.GET_DEFAULT_APPLICATION failed.");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    if (IsAppType(mimeType)) {
        return GetBundleInfoByAppType(userId, mimeType, bundleInfo, backup);
    } else if (IsFileType(mimeType)) {
        return GetBundleInfoByFileType(userId, mimeType, bundleInfo, backup);
    } else {
        LOG_W(BMS_TAG_DEFAULT_APP, "invalid type, not app type or file type.");
        return ERR_BUNDLE_MANAGER_INVALID_TYPE;
    }
}

ErrCode DefaultAppMgr::SetDefaultApplication(int32_t userId, const std::string& type, const Element& element) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::string mimeType = type;
    ConvertTypeBySuffix(mimeType);

    ErrCode errCode = VerifyUserIdAndType(userId, mimeType);
    if (errCode != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT_APP, "VerifyUserIdAndType failed.");
        return errCode;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_DEFAULT_APP, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_SET_DEFAULT_APPLICATION)) {
        LOG_W(BMS_TAG_DEFAULT_APP, "verify permission ohos.permission.SET_DEFAULT_APPLICATION failed.");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    // clear default app
    bool ret = IsElementEmpty(element);
    if (ret) {
        LOG_D(BMS_TAG_DEFAULT_APP, "clear default app.");
        ret = defaultAppDb_->DeleteDefaultApplicationInfo(userId, mimeType);
        if (!ret) {
            LOG_W(BMS_TAG_DEFAULT_APP, "DeleteDefaultApplicationInfo failed.");
            return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
        }
        LOG_D(BMS_TAG_DEFAULT_APP, "SetDefaultApplication success.");
        return ERR_OK;
    }
    ret = IsElementValid(userId, mimeType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "Element is invalid.");
        return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
    }
    ret = defaultAppDb_->SetDefaultApplicationInfo(userId, mimeType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "SetDefaultApplicationInfo failed.");
        return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
    }
    LOG_D(BMS_TAG_DEFAULT_APP, "SetDefaultApplication success.");
    return ERR_OK;
}

ErrCode DefaultAppMgr::ResetDefaultApplication(int32_t userId, const std::string& type) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::string mimeType = type;
    ConvertTypeBySuffix(mimeType);

    ErrCode errCode = VerifyUserIdAndType(userId, mimeType);
    if (errCode != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT_APP, "VerifyUserIdAndType failed.");
        return errCode;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_DEFAULT_APP, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_SET_DEFAULT_APPLICATION)) {
        LOG_W(BMS_TAG_DEFAULT_APP, "verify permission ohos.permission.SET_DEFAULT_APPLICATION failed.");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    Element element;
    bool ret = defaultAppDb_->GetDefaultApplicationInfo(INITIAL_USER_ID, mimeType, element);
    if (!ret) {
        LOG_D(BMS_TAG_DEFAULT_APP, "directly delete default info.");
        if (defaultAppDb_->DeleteDefaultApplicationInfo(userId, mimeType)) {
            return ERR_OK;
        }
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ret = IsElementValid(userId, mimeType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "Element is invalid.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ret = defaultAppDb_->SetDefaultApplicationInfo(userId, mimeType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "SetDefaultApplicationInfo failed.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    LOG_D(BMS_TAG_DEFAULT_APP, "ResetDefaultApplication success.");
    return ERR_OK;
}

void DefaultAppMgr::HandleUninstallBundle(int32_t userId, const std::string& bundleName) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    LOG_D(BMS_TAG_DEFAULT_APP, "begin");
    std::map<std::string, Element> currentInfos;
    bool ret = defaultAppDb_->GetDefaultApplicationInfos(userId, currentInfos);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "GetDefaultApplicationInfos failed");
        return;
    }
    // if type exist in default_app.json, use it
    std::map<std::string, Element> newInfos;
    for (const auto& item : currentInfos) {
        if (item.second.bundleName == bundleName) {
            Element element;
            if (defaultAppDb_->GetDefaultApplicationInfo(INITIAL_USER_ID, item.first, element)) {
                LOG_D(BMS_TAG_DEFAULT_APP, "set default application to preset, type : %{public}s", item.first.c_str());
                newInfos.emplace(item.first, element);
            } else {
                LOG_D(BMS_TAG_DEFAULT_APP, "erase uninstalled application type:%{public}s", item.first.c_str());
            }
        } else {
            newInfos.emplace(item.first, item.second);
        }
    }
    defaultAppDb_->SetDefaultApplicationInfos(userId, newInfos);
}

void DefaultAppMgr::HandleCreateUser(int32_t userId) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    LOG_D(BMS_TAG_DEFAULT_APP, "begin");
    std::map<std::string, Element> infos;
    bool ret = defaultAppDb_->GetDefaultApplicationInfos(INITIAL_USER_ID, infos);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "GetDefaultApplicationInfos failed");
        return;
    }
    defaultAppDb_->SetDefaultApplicationInfos(userId, infos);
}

void DefaultAppMgr::HandleRemoveUser(int32_t userId) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    LOG_D(BMS_TAG_DEFAULT_APP, "begin");
    defaultAppDb_->DeleteDefaultApplicationInfos(userId);
}

bool DefaultAppMgr::IsBrowserWant(const Want& want) const
{
    bool matchAction = want.GetAction() == ACTION_VIEW_DATA;
    if (!matchAction) {
        LOG_D(BMS_TAG_DEFAULT_APP, "Action does not match, not browser want");
        return false;
    }
    std::string uri = want.GetUriString();
    bool matchUri = uri.rfind(HTTP_SCHEME, 0) == 0 || uri.rfind(HTTPS_SCHEME, 0) == 0;
    if (!matchUri) {
        LOG_D(BMS_TAG_DEFAULT_APP, "Uri does not match, not browser want");
        return false;
    }
    LOG_D(BMS_TAG_DEFAULT_APP, "is browser want");
    return true;
}

bool DefaultAppMgr::IsEmailWant(const Want& want) const
{
    bool matchAction = want.GetAction() == EMAIL_ACTION;
    if (!matchAction) {
        LOG_D(BMS_TAG_DEFAULT_APP, "Action does not match, not email want");
        return false;
    }
    std::string uri = want.GetUriString();
    bool matchUri = uri.rfind(EMAIL_SCHEME, 0) == 0;
    if (!matchUri) {
        LOG_D(BMS_TAG_DEFAULT_APP, "Uri does not match, not email want");
        return false;
    }
    LOG_D(BMS_TAG_DEFAULT_APP, "is email want");
    return true;
}

std::string DefaultAppMgr::GetType(const Want& want) const
{
    if (IsBrowserWant(want)) {
        return BROWSER;
    }
    if (IsEmailWant(want)) {
        return EMAIL;
    }
    if (want.GetAction() == ACTION_VIEW_DATA) {
        std::string type = want.GetType();
        if (!type.empty()) {
            return type;
        }
        std::string uri = want.GetUriString();
        if (uri.empty()) {
            LOG_E(BMS_TAG_DEFAULT_APP, "uri is empty");
            return Constants::EMPTY_STRING;
        }
        std::string convertType;
        if (MimeTypeMgr::GetMimeTypeByUri(uri, convertType)) {
            LOG_D(BMS_TAG_DEFAULT_APP, "get type by uri success, convertType : %{public}s", convertType.c_str());
            return convertType;
        }
        return Constants::EMPTY_STRING;
    }
    return Constants::EMPTY_STRING;
}

bool DefaultAppMgr::GetDefaultApplication(const Want& want, const int32_t userId,
    std::vector<AbilityInfo>& abilityInfos, std::vector<ExtensionAbilityInfo>& extensionInfos, bool backup) const
{
    LOG_D(BMS_TAG_DEFAULT_APP, "begin, backup(bool) : %{public}d", backup);
    std::string type = GetType(want);
    LOG_I(BMS_TAG_DEFAULT_APP, "type : %{public}s", type.c_str());
    if (type.empty()) {
        LOG_E(BMS_TAG_DEFAULT_APP, "GetType failed");
        return false;
    }
    BundleInfo bundleInfo;
    ErrCode ret = GetDefaultApplication(userId, type, bundleInfo, backup);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT_APP, "GetDefaultApplication failed");
        return false;
    }

    std::string bundleName = want.GetElement().GetBundleName();
    if (!bundleName.empty() && bundleName != bundleInfo.name) {
        LOG_D(BMS_TAG_DEFAULT_APP, "request bundleName : %{public}s, default bundleName : %{public}s",
            bundleName.c_str(), bundleInfo.name.c_str());
        return false;
    }

    if (bundleInfo.abilityInfos.size() == 1) {
        abilityInfos = bundleInfo.abilityInfos;
        LOG_D(BMS_TAG_DEFAULT_APP, "find default ability");
        return true;
    } else if (bundleInfo.extensionInfos.size() == 1) {
        extensionInfos = bundleInfo.extensionInfos;
        LOG_D(BMS_TAG_DEFAULT_APP, "find default extension");
        return true;
    } else {
        LOG_E(BMS_TAG_DEFAULT_APP, "invalid bundleInfo");
        return false;
    }
}

ErrCode DefaultAppMgr::GetBundleInfoByAppType(
    int32_t userId, const std::string& type, BundleInfo& bundleInfo, bool backup) const
{
    int32_t key = backup ? Constants::BACKUP_DEFAULT_APP_KEY : userId;
    Element element;
    bool ret = defaultAppDb_->GetDefaultApplicationInfo(key, type, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "GetDefaultApplicationInfo failed.");
        return ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
    }
    ret = GetBundleInfo(userId, type, element, bundleInfo);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "GetBundleInfo failed.");
        return ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
    }
    LOG_D(BMS_TAG_DEFAULT_APP, "GetBundleInfoByAppType success.");
    return ERR_OK;
}

ErrCode DefaultAppMgr::GetBundleInfoByFileType(
    int32_t userId, const std::string& type, BundleInfo& bundleInfo, bool backup) const
{
    int32_t key = backup ? Constants::BACKUP_DEFAULT_APP_KEY : userId;
    std::map<std::string, Element> infos;
    bool ret = defaultAppDb_->GetDefaultApplicationInfos(key, infos);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "GetDefaultApplicationInfos failed.");
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
        const auto iter = APP_TYPES.find(item.first);
        if (iter == APP_TYPES.end()) {
            continue;
        }
        Skill skill;
        for (const auto& mimeType : iter->second) {
            if (skill.MatchType(type, mimeType) && GetBundleInfo(userId, type, item.second, bundleInfo)) {
                LOG_D(BMS_TAG_DEFAULT_APP, "match default app type success");
                return ERR_OK;
            }
        }
    }
    // match default file type
    for (const auto& item : defaultFileTypeInfos) {
        if (item.first == type && GetBundleInfo(userId, type, item.second, bundleInfo)) {
            LOG_D(BMS_TAG_DEFAULT_APP, "match default file type success.");
            return ERR_OK;
        }
    }
    LOG_W(BMS_TAG_DEFAULT_APP, "GetBundleInfoByFileType failed.");
    return ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
}

bool DefaultAppMgr::GetBundleInfo(int32_t userId, const std::string& type, const Element& element,
    BundleInfo& bundleInfo) const
{
    LOG_D(BMS_TAG_DEFAULT_APP, "begin to GetBundleInfo.");
    bool ret = VerifyElementFormat(element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "VerifyElementFormat failed.");
        return false;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT_APP, "get BundleDataMgr failed.");
        return false;
    }
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    std::vector<Skill> skills;
    // verify if element exists
    ret = dataMgr->QueryInfoAndSkillsByElement(userId, element, abilityInfo, extensionInfo, skills);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "GetBundleInfo, QueryInfoAndSkillsByElement failed.");
        return GetBrokerBundleInfo(element, bundleInfo);
    }
    // match type and skills
    ret = IsMatch(type, skills);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "GetBundleInfo, type and skills not match.");
        return false;
    }
    ret = dataMgr->GetBundleInfo(element.bundleName, GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "GetBundleInfo failed.");
        return false;
    }
    bool isAbility = !element.abilityName.empty();
    if (isAbility) {
        bundleInfo.abilityInfos.emplace_back(abilityInfo);
    } else {
        bundleInfo.extensionInfos.emplace_back(extensionInfo);
    }
    LOG_D(BMS_TAG_DEFAULT_APP, "GetBundleInfo success.");
    return true;
}

bool DefaultAppMgr::MatchActionAndType(
    const std::string& action, const std::string& type, const std::vector<Skill>& skills) const
{
    LOG_D(BMS_TAG_DEFAULT_APP, "begin, action : %{public}s, type : %{public}s", action.c_str(), type.c_str());
    for (const Skill& skill : skills) {
        auto item = std::find(skill.actions.cbegin(), skill.actions.cend(), action);
        if (item == skill.actions.cend()) {
            continue;
        }
        for (const SkillUri& skillUri : skill.uris) {
            if (skill.MatchType(type, skillUri.type)) {
                return true;
            }
        }
    }
    LOG_W(BMS_TAG_DEFAULT_APP, "MatchActionAndType failed");
    return false;
}

bool DefaultAppMgr::IsMatch(const std::string& type, const std::vector<Skill>& skills) const
{
    if (IsAppType(type)) {
        return MatchAppType(type, skills);
    } else if (IsFileType(type)) {
        return MatchFileType(type, skills);
    } else {
        LOG_W(BMS_TAG_DEFAULT_APP, "invalid type.");
        return false;
    }
}

bool DefaultAppMgr::MatchAppType(const std::string& type, const std::vector<Skill>& skills) const
{
    LOG_W(BMS_TAG_DEFAULT_APP, "begin to match app type, type : %{public}s.", type.c_str());
    if (type == BROWSER) {
        return IsBrowserSkillsValid(skills);
    }
    if (type == EMAIL) {
        return IsEmailSkillsValid(skills);
    }
    auto item = APP_TYPES.find(type);
    if (item == APP_TYPES.end()) {
        LOG_E(BMS_TAG_DEFAULT_APP, "invalid app type : %{public}s.", type.c_str());
        return false;
    }
    for (const std::string& mimeType : item->second) {
        if (MatchActionAndType(ACTION_VIEW_DATA, mimeType, skills)) {
            return true;
        }
    }
    return false;
}

bool DefaultAppMgr::IsBrowserSkillsValid(const std::vector<Skill>& skills) const
{
    LOG_D(BMS_TAG_DEFAULT_APP, "begin to verify browser skills.");
    Want httpWant;
    httpWant.SetAction(ACTION_VIEW_DATA);
    httpWant.AddEntity(ENTITY_BROWSER);
    httpWant.SetUri(HTTP);

    Want httpsWant;
    httpsWant.SetAction(ACTION_VIEW_DATA);
    httpsWant.AddEntity(ENTITY_BROWSER);
    httpsWant.SetUri(HTTPS);
    for (const Skill& skill : skills) {
        if (skill.Match(httpsWant) || skill.Match(httpWant)) {
            LOG_D(BMS_TAG_DEFAULT_APP, "browser skills is valid");
            return true;
        }
    }
    LOG_W(BMS_TAG_DEFAULT_APP, "browser skills is invalid.");
    return false;
}

bool DefaultAppMgr::IsEmailSkillsValid(const std::vector<Skill>& skills) const
{
    LOG_D(BMS_TAG_DEFAULT_APP, "begin to verify email skills");
    Want want;
    want.SetAction(EMAIL_ACTION);
    want.SetUri(EMAIL_SCHEME);

    for (const Skill& skill : skills) {
        if (skill.Match(want)) {
            LOG_D(BMS_TAG_DEFAULT_APP, "email skills valid");
            return true;
        }
    }
    LOG_W(BMS_TAG_DEFAULT_APP, "email skills invalid");
    return false;
}

bool DefaultAppMgr::MatchFileType(const std::string& type, const std::vector<Skill>& skills) const
{
    LOG_D(BMS_TAG_DEFAULT_APP, "type : %{public}s", type.c_str());
    if (MatchActionAndType(ACTION_VIEW_DATA, type, skills)) {
        return true;
    }
    LOG_E(BMS_TAG_DEFAULT_APP, "MatchFileType failed");
    return false;
}

bool DefaultAppMgr::IsTypeValid(const std::string& type) const
{
    return IsAppType(type) || IsFileType(type);
}

bool DefaultAppMgr::IsAppType(const std::string& type) const
{
    if (type.empty()) {
        LOG_E(BMS_TAG_DEFAULT_APP, "type is empty");
        return false;
    }
    return supportAppTypes.find(type) != supportAppTypes.end();
}

bool DefaultAppMgr::IsFileType(const std::string& type) const
{
    // valid fileType format : type/subType
    if (type.empty() || type.find(WILDCARD) != type.npos) {
        LOG_W(BMS_TAG_DEFAULT_APP, "file type not allow contains *.");
        return false;
    }
    std::vector<std::string> vector;
    SplitStr(type, SPLIT, vector, false, false);
    if (vector.size() == TYPE_PART_COUNT && !vector[INDEX_ZERO].empty() && !vector[INDEX_ONE].empty()) {
        return true;
    }
    LOG_W(BMS_TAG_DEFAULT_APP, "file type format invalid.");
    return false;
}

bool DefaultAppMgr::IsUserIdExist(int32_t userId) const
{
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT_APP, "get BundleDataMgr failed.");
        return false;
    }
    return dataMgr->HasUserId(userId);
}

ErrCode DefaultAppMgr::VerifyUserIdAndType(int32_t userId, const std::string& type) const
{
    bool ret = IsUserIdExist(userId);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "userId %{public}d doesn't exist.", userId);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    ret = IsTypeValid(type);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "invalid type %{public}s, not app type or file type.", type.c_str());
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
        LOG_W(BMS_TAG_DEFAULT_APP, "bundleName empty, bad Element format.");
        return false;
    }
    if (moduleName.empty()) {
        LOG_W(BMS_TAG_DEFAULT_APP, "moduleName empty, bad Element format.");
        return false;
    }
    if (abilityName.empty() && extensionName.empty()) {
        LOG_W(BMS_TAG_DEFAULT_APP, "abilityName and extensionName both empty, bad Element format.");
        return false;
    }
    if (!abilityName.empty() && !extensionName.empty()) {
        LOG_W(BMS_TAG_DEFAULT_APP, "abilityName and extensionName both non-empty, bad Element format.");
        return false;
    }
    return true;
}

bool DefaultAppMgr::IsElementValid(int32_t userId, const std::string& type, const Element& element) const
{
    bool ret = VerifyElementFormat(element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "VerifyElementFormat failed.");
        return false;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT_APP, "get BundleDataMgr failed.");
        return false;
    }
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    std::vector<Skill> skills;
    // verify if element exists
    ret = dataMgr->QueryInfoAndSkillsByElement(userId, element, abilityInfo, extensionInfo, skills);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "QueryInfoAndSkillsByElement failed.");
        BundleInfo bundleInfo;
        return GetBrokerBundleInfo(element, bundleInfo);
    }
    // match type and skills
    ret = IsMatch(type, skills);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "type and skills not match.");
        return false;
    }
    LOG_D(BMS_TAG_DEFAULT_APP, "Element is valid.");
    return true;
}

void DefaultAppMgr::ConvertTypeBySuffix(std::string& suffix) const
{
    if (suffix.empty() || suffix.find('.') != 0) {
        LOG_D(BMS_TAG_DEFAULT_APP, "default app type is not suffix form");
        return;
    }

    std::string type;
    bool ret = MimeTypeMgr::GetMimeTypeByUri(suffix, type);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT_APP, "uri suffix %{public}s has no corresponding mime type", suffix.c_str());
        return;
    }
    LOG_D(BMS_TAG_DEFAULT_APP, "corresponding mime type is %{public}s", type.c_str());
    suffix = type;
    return;
}

bool DefaultAppMgr::GetBrokerBundleInfo(const Element& element, BundleInfo& bundleInfo) const
{
    if (element.bundleName.empty() || element.abilityName.empty()) {
        LOG_W(BMS_TAG_DEFAULT_APP, "invalid param, get broker bundleInfo failed");
        return false;
    }
    if (!DelayedSingleton<BundleMgrService>::GetInstance()->IsBrokerServiceStarted()) {
        LOG_W(BMS_TAG_DEFAULT_APP, "broker not started, get broker bundleInfo failed");
        return false;
    }
    Want want;
    ElementName elementName("", element.bundleName, element.abilityName, element.moduleName);
    want.SetElement(elementName);
    AbilityInfo abilityInfo;
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ErrCode ret = bmsExtensionClient->QueryAbilityInfo(want, 0, Constants::START_USERID, abilityInfo, true);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT_APP, "query abilityInfo from broker failed");
        return false;
    }
    bundleInfo.name = abilityInfo.bundleName;
    bundleInfo.abilityInfos.emplace_back(abilityInfo);
    LOG_I(BMS_TAG_DEFAULT_APP, "get broker bundleInfo success");
    return true;
}
}
}