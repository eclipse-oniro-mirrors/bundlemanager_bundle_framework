/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "default_app_rdb.h"
#include "ipc_skeleton.h"
#include "mime_type_mgr.h"
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
#include "type_descriptor.h"
#include "utd_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

namespace {
constexpr int32_t INITIAL_USER_ID = -1;
constexpr int32_t TYPE_PART_COUNT = 2;
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr size_t TYPE_MAX_SIZE = 200;
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
    LOG_D(BMS_TAG_DEFAULT, "create DefaultAppMgr");
    Init();
}

DefaultAppMgr::~DefaultAppMgr()
{
    LOG_D(BMS_TAG_DEFAULT, "destroy DefaultAppMgr");
    defaultAppDb_->UnRegisterDeathListener();
}

void DefaultAppMgr::Init()
{
    defaultAppDb_ = std::make_shared<DefaultAppRdb>();
    defaultAppDb_->RegisterDeathListener();
}

ErrCode DefaultAppMgr::IsDefaultApplication(int32_t userId, const std::string& type, bool& isDefaultApp) const
{
    LOG_I(BMS_TAG_DEFAULT, "IsDefaultApplication begin, userId : %{public}d, type : %{public}s", userId, type.c_str());
    if (type.size() > TYPE_MAX_SIZE) {
        LOG_W(BMS_TAG_DEFAULT, "type size too large");
        isDefaultApp = false;
        return ERR_OK;
    }

    if (!IsUserIdExist(userId)) {
        LOG_W(BMS_TAG_DEFAULT, "userId not exist");
        isDefaultApp = false;
        return ERR_OK;
    }

    std::string normalizedType = Normalize(type);
    LOG_I(BMS_TAG_DEFAULT, "normalizedType : %{public}s", normalizedType.c_str());
    if (normalizedType.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "normalizedType empty");
        isDefaultApp = false;
        return ERR_OK;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    Element element;
    bool ret = defaultAppDb_->GetDefaultApplicationInfo(userId, normalizedType, element);
    if (!ret) {
        LOG_I(BMS_TAG_DEFAULT, "GetDefaultApplicationInfo failed");
        isDefaultApp = false;
        return ERR_OK;
    }
    ret = IsElementValid(userId, normalizedType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "invalid element");
        isDefaultApp = false;
        return ERR_OK;
    }
    // get bundle name via calling uid
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT, "dataMgr is null");
        isDefaultApp = false;
        return ERR_OK;
    }
    std::string callingBundleName;
    ret = dataMgr->GetBundleNameForUid(IPCSkeleton::GetCallingUid(), callingBundleName);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "GetBundleNameForUid failed");
        isDefaultApp = false;
        return ERR_OK;
    }
    LOG_I(BMS_TAG_DEFAULT, "callingBundleName : %{public}s", callingBundleName.c_str());
    isDefaultApp = element.bundleName == callingBundleName;
    return ERR_OK;
}

ErrCode DefaultAppMgr::GetDefaultApplication(
    int32_t userId, const std::string& type, BundleInfo& bundleInfo, bool backup) const
{
    LOG_I(BMS_TAG_DEFAULT, "GetDefaultApplication begin, userId : %{public}d, \
        type : %{public}s, backup(bool) : %{public}d", userId, type.c_str(), backup);

    ErrCode ret = VerifyPermission(Constants::PERMISSION_GET_DEFAULT_APPLICATION);
    if (ret != ERR_OK) {
        return ret;
    }

    if (!IsUserIdExist(userId)) {
        LOG_W(BMS_TAG_DEFAULT, "userId not exist");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::string normalizedType = Normalize(type);
    LOG_I(BMS_TAG_DEFAULT, "normalizedType : %{public}s", normalizedType.c_str());
    if (normalizedType.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "normalizedType empty");
        return ERR_BUNDLE_MANAGER_INVALID_TYPE;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (IsAppType(normalizedType)) {
        return GetBundleInfoByAppType(userId, normalizedType, bundleInfo, backup);
    }
    return GetBundleInfoByUtd(userId, normalizedType, bundleInfo, backup);
}

ErrCode DefaultAppMgr::SetDefaultApplication(
    int32_t userId, const std::string& type, const Element& element) const
{
    LOG_I(BMS_TAG_DEFAULT,
        "SetDefaultApplication begin, userId : %{public}d, type : %{public}s", userId, type.c_str());

    ErrCode permissionRet = VerifyPermission(Constants::PERMISSION_SET_DEFAULT_APPLICATION);
    if (permissionRet != ERR_OK) {
        return permissionRet;
    }

    if (!IsUserIdExist(userId)) {
        LOG_W(BMS_TAG_DEFAULT, "userId not exist");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::string normalizedType = Normalize(type);
    LOG_I(BMS_TAG_DEFAULT, "normalizedType : %{public}s", normalizedType.c_str());
    if (normalizedType.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "normalizedType empty");
        return ERR_BUNDLE_MANAGER_INVALID_TYPE;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    // clear default app
    bool ret = IsElementEmpty(element);
    if (ret) {
        LOG_I(BMS_TAG_DEFAULT, "clear default app");
        ret = defaultAppDb_->DeleteDefaultApplicationInfo(userId, normalizedType);
        if (!ret) {
            LOG_W(BMS_TAG_DEFAULT, "DeleteDefaultApplicationInfo failed");
            return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
        }
        LOG_D(BMS_TAG_DEFAULT, "SetDefaultApplication success");
        return ERR_OK;
    }
    // set default app
    ret = IsElementValid(userId, normalizedType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "invalid element");
        return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
    }
    ret = defaultAppDb_->SetDefaultApplicationInfo(userId, normalizedType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "SetDefaultApplicationInfo failed");
        return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
    }
    LOG_D(BMS_TAG_DEFAULT, "SetDefaultApplication success");
    return ERR_OK;
}

ErrCode DefaultAppMgr::ResetDefaultApplication(int32_t userId, const std::string& type) const
{
    LOG_I(BMS_TAG_DEFAULT,
        "ResetDefaultApplication begin, userId : %{public}d, type : %{public}s", userId, type.c_str());

    ErrCode permissionRet = VerifyPermission(Constants::PERMISSION_SET_DEFAULT_APPLICATION);
    if (permissionRet != ERR_OK) {
        return permissionRet;
    }

    if (!IsUserIdExist(userId)) {
        LOG_W(BMS_TAG_DEFAULT, "userId not exist");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::string normalizedType = Normalize(type);
    LOG_I(BMS_TAG_DEFAULT, "normalizedType : %{public}s", normalizedType.c_str());
    if (normalizedType.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "normalizedType empty");
        return ERR_BUNDLE_MANAGER_INVALID_TYPE;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    Element element;
    bool ret = defaultAppDb_->GetDefaultApplicationInfo(INITIAL_USER_ID, normalizedType, element);
    if (!ret) {
        LOG_I(BMS_TAG_DEFAULT, "directly delete default info");
        if (defaultAppDb_->DeleteDefaultApplicationInfo(userId, normalizedType)) {
            return ERR_OK;
        }
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ret = IsElementValid(userId, normalizedType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "invalid element");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ret = defaultAppDb_->SetDefaultApplicationInfo(userId, normalizedType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "SetDefaultApplicationInfo failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    LOG_I(BMS_TAG_DEFAULT, "ResetDefaultApplication success");
    return ERR_OK;
}

void DefaultAppMgr::HandleUninstallBundle(int32_t userId, const std::string& bundleName) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    LOG_D(BMS_TAG_DEFAULT, "begin");
    std::map<std::string, Element> currentInfos;
    bool ret = defaultAppDb_->GetDefaultApplicationInfos(userId, currentInfos);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "GetDefaultApplicationInfos failed");
        return;
    }
    // if type exist in default_app.json, use it
    std::map<std::string, Element> newInfos;
    for (const auto& item : currentInfos) {
        if (item.second.bundleName == bundleName) {
            Element element;
            if (defaultAppDb_->GetDefaultApplicationInfo(INITIAL_USER_ID, item.first, element)) {
                LOG_I(BMS_TAG_DEFAULT, "set default application to preset, type : %{public}s", item.first.c_str());
                newInfos.emplace(item.first, element);
            } else {
                LOG_D(BMS_TAG_DEFAULT, "erase uninstalled application type:%{public}s", item.first.c_str());
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
    LOG_D(BMS_TAG_DEFAULT, "begin");
    std::map<std::string, Element> infos;
    bool ret = defaultAppDb_->GetDefaultApplicationInfos(INITIAL_USER_ID, infos);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "GetDefaultApplicationInfos failed");
        return;
    }
    defaultAppDb_->SetDefaultApplicationInfos(userId, infos);
}

void DefaultAppMgr::HandleRemoveUser(int32_t userId) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    LOG_D(BMS_TAG_DEFAULT, "begin");
    defaultAppDb_->DeleteDefaultApplicationInfos(userId);
}

bool DefaultAppMgr::IsBrowserWant(const Want& want) const
{
    bool matchAction = want.GetAction() == ACTION_VIEW_DATA;
    if (!matchAction) {
        LOG_D(BMS_TAG_DEFAULT, "Action does not match, not browser want");
        return false;
    }
    std::string uri = want.GetUriString();
    bool matchUri = uri.rfind(HTTP_SCHEME, 0) == 0 || uri.rfind(HTTPS_SCHEME, 0) == 0;
    if (!matchUri) {
        LOG_D(BMS_TAG_DEFAULT, "Uri does not match, not browser want");
        return false;
    }
    LOG_D(BMS_TAG_DEFAULT, "is browser want");
    return true;
}

bool DefaultAppMgr::IsEmailWant(const Want& want) const
{
    bool matchAction = want.GetAction() == EMAIL_ACTION;
    if (!matchAction) {
        LOG_D(BMS_TAG_DEFAULT, "Action does not match, not email want");
        return false;
    }
    std::string uri = want.GetUriString();
    bool matchUri = uri.rfind(EMAIL_SCHEME, 0) == 0;
    if (!matchUri) {
        LOG_D(BMS_TAG_DEFAULT, "Uri does not match, not email want");
        return false;
    }
    LOG_D(BMS_TAG_DEFAULT, "is email want");
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
    if (want.GetAction() != ACTION_VIEW_DATA) {
        return Constants::EMPTY_STRING;
    }
    return GetUtdByWant(want);
}

bool DefaultAppMgr::GetDefaultApplication(const Want& want, const int32_t userId,
    std::vector<AbilityInfo>& abilityInfos, std::vector<ExtensionAbilityInfo>& extensionInfos, bool backup) const
{
    LOG_D(BMS_TAG_DEFAULT, "begin, backup(bool) : %{public}d", backup);
    std::string normalizedType = GetType(want);
    LOG_I(BMS_TAG_DEFAULT, "normalizedType from want : %{public}s", normalizedType.c_str());
    if (normalizedType.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "normalizedType empty");
        return false;
    }
    BundleInfo bundleInfo;
    ErrCode ret = GetDefaultApplication(userId, normalizedType, bundleInfo, backup);
    if (ret != ERR_OK) {
        LOG_I(BMS_TAG_DEFAULT, "GetDefaultApplication failed");
        return false;
    }

    std::string bundleName = want.GetElement().GetBundleName();
    if (!bundleName.empty() && bundleName != bundleInfo.name) {
        LOG_I(BMS_TAG_DEFAULT, "request bundleName : %{public}s, default bundleName : %{public}s not same",
            bundleName.c_str(), bundleInfo.name.c_str());
        return false;
    }

    if (bundleInfo.abilityInfos.size() == 1) {
        abilityInfos = bundleInfo.abilityInfos;
        LOG_I(BMS_TAG_DEFAULT, "find default ability");
        return true;
    } else if (bundleInfo.extensionInfos.size() == 1) {
        extensionInfos = bundleInfo.extensionInfos;
        LOG_I(BMS_TAG_DEFAULT, "find default extension");
        return true;
    } else {
        LOG_E(BMS_TAG_DEFAULT, "invalid bundleInfo");
        return false;
    }
}

ErrCode DefaultAppMgr::GetBundleInfoByAppType(
    int32_t userId, const std::string& appType, BundleInfo& bundleInfo, bool backup) const
{
    int32_t key = backup ? ServiceConstants::BACKUP_DEFAULT_APP_KEY : userId;
    Element element;
    bool ret = defaultAppDb_->GetDefaultApplicationInfo(key, appType, element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "GetDefaultApplicationInfo failed");
        return ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
    }
    ret = GetBundleInfo(userId, appType, element, bundleInfo);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "GetBundleInfo failed");
        return ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
    }
    LOG_I(BMS_TAG_DEFAULT, "get bundleInfo by appType success");
    return ERR_OK;
}

ErrCode DefaultAppMgr::GetBundleInfoByUtd(
    int32_t userId, const std::string& utd, BundleInfo& bundleInfo, bool backup) const
{
    int32_t key = backup ? ServiceConstants::BACKUP_DEFAULT_APP_KEY : userId;
    std::map<std::string, Element> infos;
    bool ret = defaultAppDb_->GetDefaultApplicationInfos(key, infos);
    if (!ret) {
        LOG_I(BMS_TAG_DEFAULT, "GetDefaultApplicationInfos failed");
        return ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
    }
    std::map<std::string, Element> defaultAppTypeInfos;
    std::map<std::string, Element> defaultUtdInfos;
    for (const auto& item : infos) {
        if (IsAppType(item.first)) {
            defaultAppTypeInfos.emplace(item.first, item.second);
        } else {
            defaultUtdInfos.emplace(item.first, item.second);
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
            if (skill.MatchType(utd, mimeType) && GetBundleInfo(userId, utd, item.second, bundleInfo)) {
                LOG_I(BMS_TAG_DEFAULT, "match default app type success");
                return ERR_OK;
            }
        }
    }
    // match default utd
    for (const auto& item : defaultUtdInfos) {
        if (item.first == utd && GetBundleInfo(userId, utd, item.second, bundleInfo)) {
            LOG_I(BMS_TAG_DEFAULT, "match default utd success");
            return ERR_OK;
        }
    }
    LOG_W(BMS_TAG_DEFAULT, "get bundleInfo by utd failed");
    return ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
}

bool DefaultAppMgr::GetBundleInfo(int32_t userId, const std::string& type, const Element& element,
    BundleInfo& bundleInfo) const
{
    LOG_D(BMS_TAG_DEFAULT, "begin to GetBundleInfo");
    bool ret = VerifyElementFormat(element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "invalid element format");
        return false;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT, "dataMgr is null");
        return false;
    }
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    std::vector<Skill> skills;
    // verify if element exists
    ret = dataMgr->QueryInfoAndSkillsByElement(userId, element, abilityInfo, extensionInfo, skills);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "GetBundleInfo, QueryInfoAndSkillsByElement failed");
        return GetBrokerBundleInfo(element, bundleInfo);
    }
    // match type and skills
    ret = IsMatch(type, skills);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "GetBundleInfo, type and skills not match");
        return false;
    }
    ret = dataMgr->GetBundleInfo(element.bundleName, GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "GetBundleInfo failed");
        return false;
    }
    bool isAbility = !element.abilityName.empty();
    if (isAbility) {
        bundleInfo.abilityInfos.emplace_back(abilityInfo);
    } else {
        bundleInfo.extensionInfos.emplace_back(extensionInfo);
    }
    LOG_D(BMS_TAG_DEFAULT, "GetBundleInfo success");
    return true;
}

bool DefaultAppMgr::MatchActionAndType(
    const std::string& action, const std::string& type, const std::vector<Skill>& skills) const
{
    LOG_D(BMS_TAG_DEFAULT, "begin, action : %{public}s, type : %{public}s", action.c_str(), type.c_str());
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
    LOG_W(BMS_TAG_DEFAULT, "MatchActionAndType failed");
    return false;
}

bool DefaultAppMgr::IsMatch(const std::string& type, const std::vector<Skill>& skills) const
{
    if (IsAppType(type)) {
        return MatchAppType(type, skills);
    }
    return MatchUtd(type, skills);
}

bool DefaultAppMgr::MatchAppType(const std::string& type, const std::vector<Skill>& skills) const
{
    LOG_D(BMS_TAG_DEFAULT, "begin to match app type, type : %{public}s", type.c_str());
    if (type == BROWSER) {
        return IsBrowserSkillsValid(skills);
    }
    if (type == EMAIL) {
        return IsEmailSkillsValid(skills);
    }
    auto item = APP_TYPES.find(type);
    if (item == APP_TYPES.end()) {
        LOG_E(BMS_TAG_DEFAULT, "invalid app type : %{public}s", type.c_str());
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
    LOG_D(BMS_TAG_DEFAULT, "begin to verify browser skills");
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
            LOG_D(BMS_TAG_DEFAULT, "browser skills is valid");
            return true;
        }
    }
    LOG_W(BMS_TAG_DEFAULT, "browser skills is invalid");
    return false;
}

bool DefaultAppMgr::IsEmailSkillsValid(const std::vector<Skill>& skills) const
{
    LOG_D(BMS_TAG_DEFAULT, "begin to verify email skills");
    Want want;
    want.SetAction(EMAIL_ACTION);
    want.SetUri(EMAIL_SCHEME);

    for (const Skill& skill : skills) {
        if (skill.Match(want)) {
            LOG_D(BMS_TAG_DEFAULT, "email skills valid");
            return true;
        }
    }
    LOG_W(BMS_TAG_DEFAULT, "email skills invalid");
    return false;
}

bool DefaultAppMgr::MatchUtd(const std::string& utd, const std::vector<Skill>& skills) const
{
    LOG_D(BMS_TAG_DEFAULT, "utd : %{public}s", utd.c_str());
    if (MatchActionAndType(ACTION_VIEW_DATA, utd, skills)) {
        return true;
    }
    LOG_E(BMS_TAG_DEFAULT, "match utd failed");
    return false;
}

bool DefaultAppMgr::IsUserIdExist(int32_t userId) const
{
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT, "get BundleDataMgr failed");
        return false;
    }
    return dataMgr->HasUserId(userId);
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
        LOG_W(BMS_TAG_DEFAULT, "bundleName empty, bad Element format");
        return false;
    }
    if (moduleName.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "moduleName empty, bad Element format");
        return false;
    }
    if (abilityName.empty() && extensionName.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "abilityName and extensionName both empty, bad Element format");
        return false;
    }
    if (!abilityName.empty() && !extensionName.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "abilityName and extensionName both non-empty, bad Element format");
        return false;
    }
    return true;
}

bool DefaultAppMgr::IsElementValid(int32_t userId, const std::string& type, const Element& element) const
{
    bool ret = VerifyElementFormat(element);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "VerifyElementFormat failed");
        return false;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT, "dataMgr is null");
        return false;
    }
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    std::vector<Skill> skills;
    // verify if element exists
    ret = dataMgr->QueryInfoAndSkillsByElement(userId, element, abilityInfo, extensionInfo, skills);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "QueryInfoAndSkillsByElement failed");
        BundleInfo bundleInfo;
        return GetBrokerBundleInfo(element, bundleInfo);
    }
    // match type and skills
    ret = IsMatch(type, skills);
    if (!ret) {
        LOG_W(BMS_TAG_DEFAULT, "type and skills not match");
        return false;
    }
    LOG_D(BMS_TAG_DEFAULT, "Element is valid");
    return true;
}

bool DefaultAppMgr::GetBrokerBundleInfo(const Element& element, BundleInfo& bundleInfo) const
{
    if (element.bundleName.empty() || element.abilityName.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "invalid param, get broker bundleInfo failed");
        return false;
    }
    if (!DelayedSingleton<BundleMgrService>::GetInstance()->IsBrokerServiceStarted()) {
        LOG_W(BMS_TAG_DEFAULT, "broker not started, get broker bundleInfo failed");
        return false;
    }
    Want want;
    ElementName elementName("", element.bundleName, element.abilityName, element.moduleName);
    want.SetElement(elementName);
    AbilityInfo abilityInfo;
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ErrCode ret = bmsExtensionClient->QueryAbilityInfo(want, 0, Constants::START_USERID, abilityInfo, true);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "query abilityInfo from broker failed");
        return false;
    }
    bundleInfo.name = abilityInfo.bundleName;
    bundleInfo.abilityInfos.emplace_back(abilityInfo);
    LOG_I(BMS_TAG_DEFAULT, "get broker bundleInfo success");
    return true;
}

ErrCode DefaultAppMgr::VerifyPermission(const std::string& permissionName) const
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_W(BMS_TAG_DEFAULT, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(permissionName)) {
        LOG_W(BMS_TAG_DEFAULT, "verify permission %{public}s failed", permissionName.c_str());
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return ERR_OK;
}

std::string DefaultAppMgr::GetUtdByWant(const AAFwk::Want& want) const
{
    // get from type
    std::string type = want.GetType();
    if (!type.empty()) {
        if (BundleUtil::IsUtd(type)) {
            return type;
        }
        return BundleUtil::GetUtdByMimeType(type);
    }
    // get from uri
    std::string uri = want.GetUriString();
    if (uri.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "uri is empty");
        return Constants::EMPTY_STRING;
    }
    std::string utd;
    if (!MimeTypeMgr::GetUtdByUri(uri, utd)) {
        LOG_W(BMS_TAG_DEFAULT, "get utd by uri failed");
        return Constants::EMPTY_STRING;
    }
    return utd;
}

std::string DefaultAppMgr::Normalize(const std::string& param)
{
    if (IsAppType(param)) {
        return param;
    }
    if (BundleUtil::IsUtd(param)) {
        if (BundleUtil::IsSpecificUtd(param)) {
            return param;
        }
        return Constants::EMPTY_STRING;
    }
    if (IsSpecificMimeType(param)) {
        return BundleUtil::GetUtdByMimeType(param);
    }
    std::string utd;
    if (!MimeTypeMgr::GetUtdByUri(param, utd)) {
        LOG_W(BMS_TAG_DEFAULT, "get utd by uri failed");
        return Constants::EMPTY_STRING;
    }
    return utd;
}

bool DefaultAppMgr::IsAppType(const std::string& param)
{
    return supportAppTypes.find(param) != supportAppTypes.end();
}

bool DefaultAppMgr::IsSpecificMimeType(const std::string& param)
{
    // valid mimeType format : type/subType
    if (param.find(WILDCARD) != param.npos) {
        LOG_W(BMS_TAG_DEFAULT, "specific mimeType not allow contains *");
        return false;
    }
    std::vector<std::string> vector;
    SplitStr(param, SPLIT, vector, false, false);
    if (vector.size() == TYPE_PART_COUNT && !vector[INDEX_ZERO].empty() && !vector[INDEX_ONE].empty()) {
        return true;
    }
    LOG_W(BMS_TAG_DEFAULT, "not specific mimeType");
    return false;
}
}
}