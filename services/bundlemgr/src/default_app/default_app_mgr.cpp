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
const std::set<std::string> supportAppTypes = {BROWSER, IMAGE, AUDIO, VIDEO, PDF, WORD, EXCEL, PPT};
}

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
    defaultAppDb_ = std::make_shared<DefaultAppRdb>();
    defaultAppDb_->RegisterDeathListener();
}

ErrCode DefaultAppMgr::IsDefaultApplication(int32_t userId, const std::string& type, bool& isDefaultApp) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::string mimeType = type;
    ConvertTypeBySuffix(mimeType);
    if (VerifyUserIdAndType(userId, mimeType) != ERR_OK) {
        APP_LOGW("VerifyUserIdAndType failed.");
        isDefaultApp = false;
        return ERR_OK;
    }
    Element element;
    bool ret = defaultAppDb_->GetDefaultApplicationInfo(userId, mimeType, element);
    if (!ret) {
        APP_LOGW("GetDefaultApplicationInfo failed.");
        isDefaultApp = false;
        return ERR_OK;
    }
    ret = IsElementValid(userId, mimeType, element);
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
    std::lock_guard<std::mutex> lock(mutex_);
    std::string mimeType = type;
    ConvertTypeBySuffix(mimeType);

    ErrCode errCode = VerifyUserIdAndType(userId, mimeType);
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

    if (IsAppType(mimeType)) {
        return GetBundleInfoByAppType(userId, mimeType, bundleInfo);
    } else if (IsFileType(mimeType)) {
        return GetBundleInfoByFileType(userId, mimeType, bundleInfo);
    } else {
        APP_LOGW("invalid type, not app type or file type.");
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
        ret = defaultAppDb_->DeleteDefaultApplicationInfo(userId, mimeType);
        if (!ret) {
            APP_LOGW("DeleteDefaultApplicationInfo failed.");
            return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
        }
        APP_LOGD("SetDefaultApplication success.");
        return ERR_OK;
    }
    ret = IsElementValid(userId, mimeType, element);
    if (!ret) {
        APP_LOGW("Element is invalid.");
        return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
    }
    ret = defaultAppDb_->SetDefaultApplicationInfo(userId, mimeType, element);
    if (!ret) {
        APP_LOGW("SetDefaultApplicationInfo failed.");
        return ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH;
    }
    APP_LOGD("SetDefaultApplication success.");
    return ERR_OK;
}

ErrCode DefaultAppMgr::ResetDefaultApplication(int32_t userId, const std::string& type) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::string mimeType = type;
    ConvertTypeBySuffix(mimeType);

    ErrCode errCode = VerifyUserIdAndType(userId, mimeType);
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
    bool ret = defaultAppDb_->GetDefaultApplicationInfo(INITIAL_USER_ID, mimeType, element);
    if (!ret) {
        APP_LOGD("directly delete default info.");
        if (defaultAppDb_->DeleteDefaultApplicationInfo(userId, mimeType)) {
            return ERR_OK;
        }
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ret = IsElementValid(userId, mimeType, element);
    if (!ret) {
        APP_LOGW("Element is invalid.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ret = defaultAppDb_->SetDefaultApplicationInfo(userId, mimeType, element);
    if (!ret) {
        APP_LOGW("SetDefaultApplicationInfo failed.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    APP_LOGD("ResetDefaultApplication success.");
    return ERR_OK;
}

void DefaultAppMgr::HandleUninstallBundle(int32_t userId, const std::string& bundleName) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    APP_LOGD("begin");
    std::map<std::string, Element> currentInfos;
    bool ret = defaultAppDb_->GetDefaultApplicationInfos(userId, currentInfos);
    if (!ret) {
        APP_LOGW("GetDefaultApplicationInfos failed");
        return;
    }
    // if type exist in default_app.json, use it
    std::map<std::string, Element> newInfos;
    for (const auto& item : currentInfos) {
        if (item.second.bundleName == bundleName) {
            Element element;
            if (defaultAppDb_->GetDefaultApplicationInfo(INITIAL_USER_ID, item.first, element)) {
                APP_LOGD("set default application to preset, type : %{public}s", item.first.c_str());
                newInfos.emplace(item.first, element);
            } else {
                APP_LOGD("erase uninstalled default application, type : %{public}s", item.first.c_str());
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
    APP_LOGD("begin");
    std::map<std::string, Element> infos;
    bool ret = defaultAppDb_->GetDefaultApplicationInfos(INITIAL_USER_ID, infos);
    if (!ret) {
        APP_LOGW("GetDefaultApplicationInfos failed");
        return;
    }
    defaultAppDb_->SetDefaultApplicationInfos(userId, infos);
}

void DefaultAppMgr::HandleRemoveUser(int32_t userId) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    APP_LOGD("begin");
    defaultAppDb_->DeleteDefaultApplicationInfos(userId);
}

bool DefaultAppMgr::IsBrowserWant(const Want& want) const
{
    bool matchAction = want.GetAction() == Constants::ACTION_VIEW_DATA;
    if (!matchAction) {
        APP_LOGD("Action does not match, not browser want");
        return false;
    }
    std::string uri = want.GetUriString();
    bool matchUri = uri.rfind(HTTP_SCHEME, 0) == 0 || uri.rfind(HTTPS_SCHEME, 0) == 0;
    if (!matchUri) {
        APP_LOGD("Uri does not match, not browser want");
        return false;
    }
    APP_LOGD("is browser want");
    return true;
}

std::string DefaultAppMgr::GetType(const Want& want) const
{
    if (IsBrowserWant(want)) {
        return BROWSER;
    }
    if (want.GetAction() == Constants::ACTION_VIEW_DATA) {
        std::string type = want.GetType();
        if (!type.empty()) {
            return type;
        }
        std::string uri = want.GetUriString();
        if (uri.empty()) {
            return Constants::EMPTY_STRING;
        }
        std::string convertType;
        if (MimeTypeMgr::GetMimeTypeByUri(uri, convertType)) {
            APP_LOGD("get type by uri success, convertType : %{public}s", convertType.c_str());
            return convertType;
        }
        return Constants::EMPTY_STRING;
    }
    return Constants::EMPTY_STRING;
}

bool DefaultAppMgr::GetDefaultApplication(const Want& want, const int32_t userId,
    std::vector<AbilityInfo>& abilityInfos, std::vector<ExtensionAbilityInfo>& extensionInfos) const
{
    APP_LOGD("begin");
    std::string type = GetType(want);
    APP_LOGD("type : %{public}s", type.c_str());
    if (type.empty()) {
        APP_LOGE("GetType failed");
        return false;
    }
    BundleInfo bundleInfo;
    ErrCode ret = GetDefaultApplication(userId, type, bundleInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetDefaultApplication failed");
        return false;
    }

    std::string bundleName = want.GetElement().GetBundleName();
    if (!bundleName.empty() && bundleName != bundleInfo.name) {
        APP_LOGD("request bundleName : %{public}s, default bundleName : %{public}s",
            bundleName.c_str(), bundleInfo.name.c_str());
        return false;
    }

    if (bundleInfo.abilityInfos.size() == 1) {
        abilityInfos = bundleInfo.abilityInfos;
        APP_LOGD("find default ability");
        return true;
    } else if (bundleInfo.extensionInfos.size() == 1) {
        extensionInfos = bundleInfo.extensionInfos;
        APP_LOGD("find default extension");
        return true;
    } else {
        APP_LOGE("invalid bundleInfo");
        return false;
    }
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
        const auto iter = APP_TYPES.find(item.first);
        if (iter == APP_TYPES.end()) {
            continue;
        }
        Skill skill;
        for (const auto& mimeType : iter->second) {
            if (skill.MatchType(type, mimeType) && GetBundleInfo(userId, type, item.second, bundleInfo)) {
                APP_LOGD("match default app type success");
                return ERR_OK;
            }
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

bool DefaultAppMgr::MatchActionAndType(
    const std::string& action, const std::string& type, const std::vector<Skill>& skills) const
{
    APP_LOGD("begin, action : %{public}s, type : %{public}s", action.c_str(), type.c_str());
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
    APP_LOGW("MatchActionAndType failed");
    return false;
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
    }
    auto item = APP_TYPES.find(type);
    if (item == APP_TYPES.end()) {
        APP_LOGE("invalid app type : %{public}s.", type.c_str());
        return false;
    }
    for (const std::string& mimeType : item->second) {
        if (MatchActionAndType(Constants::ACTION_VIEW_DATA, mimeType, skills)) {
            return true;
        }
    }
    return false;
}

bool DefaultAppMgr::IsBrowserSkillsValid(const std::vector<Skill>& skills) const
{
    APP_LOGD("begin to verify browser skills.");
    Want httpWant;
    httpWant.SetAction(Constants::ACTION_VIEW_DATA);
    httpWant.AddEntity(ENTITY_BROWSER);
    httpWant.SetUri(HTTP);

    Want httpsWant;
    httpsWant.SetAction(Constants::ACTION_VIEW_DATA);
    httpsWant.AddEntity(ENTITY_BROWSER);
    httpsWant.SetUri(HTTPS);
    for (const Skill& skill : skills) {
        if (skill.Match(httpsWant) || skill.Match(httpWant)) {
            APP_LOGD("browser skills is valid");
            return true;
        }
    }
    APP_LOGW("browser skills is invalid.");
    return false;
}

bool DefaultAppMgr::MatchFileType(const std::string& type, const std::vector<Skill>& skills) const
{
    APP_LOGD("type : %{public}s", type.c_str());
    if (MatchActionAndType(Constants::ACTION_VIEW_DATA, type, skills)) {
        return true;
    }
    APP_LOGE("MatchFileType failed");
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

void DefaultAppMgr::ConvertTypeBySuffix(std::string& suffix) const
{
    if (suffix.empty() || suffix.find('.') != 0) {
        APP_LOGD("default app type is not suffix form");
        return;
    }

    std::string type;
    bool ret = MimeTypeMgr::GetMimeTypeByUri(suffix, type);
    if (!ret) {
        APP_LOGW("uri suffix %{public}s has no corresponding mime type", suffix.c_str());
        return;
    }
    APP_LOGD("corresponding mime type is %{public}s", type.c_str());
    suffix = type;
    return;
}
}
}