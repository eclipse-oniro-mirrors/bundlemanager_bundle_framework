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
constexpr int8_t INITIAL_USER_ID = -1;
constexpr int8_t TYPE_PART_COUNT = 2;
constexpr int8_t INDEX_ZERO = 0;
constexpr int8_t INDEX_ONE = 1;
constexpr uint16_t TYPE_MAX_SIZE = 200;
constexpr const char* SPLIT = "/";
constexpr const char* SCHEME_SIGN = "://";
constexpr const char* EMAIL_ACTION = "ohos.want.action.sendToData";
constexpr const char* EMAIL_SCHEME = "mailto";
constexpr const char* ENTITY_BROWSER = "entity.system.browsable";
constexpr const char* HTTP = "http";
constexpr const char* HTTPS = "https";
constexpr const char* HTTP_SCHEME = "http://";
constexpr const char* HTTPS_SCHEME = "https://";
constexpr const char* FILE_SCHEME = "file://";
constexpr const char* CONTENT_SCHEME = "content://";
constexpr const char* WILDCARD = "*";
constexpr const char* BROWSER = "BROWSER";
constexpr const char* IMAGE = "IMAGE";
constexpr const char* AUDIO = "AUDIO";
constexpr const char* VIDEO = "VIDEO";
constexpr const char* PDF = "PDF";
constexpr const char* WORD = "WORD";
constexpr const char* EXCEL = "EXCEL";
constexpr const char* PPT = "PPT";
constexpr const char* EMAIL = "EMAIL";
constexpr const char* APP_TYPES_KEY[] = {
    IMAGE, AUDIO, VIDEO, PDF, WORD, EXCEL, PPT
};
const std::set<std::string> APP_TYPES_VALUE[] = {
    {"general.image"},
    {"general.audio"},
    {"general.video"},
    {"com.adobe.pdf"},
    {"com.microsoft.word.doc",
        "com.microsoft.word.dot",
        "org.openxmlformats.wordprocessingml.document",
        "org.openxmlformats.wordprocessingml.template",
        "org.openxmlformats.wordprocessingml.document.macroenabled",
        "org.openxmlformats.wordprocessingml.template.macroenabled"},
    {"com.microsoft.excel.xls",
        "com.microsoft.excel.xlt",
        "com.microsoft.excel.dif",
        "org.openxmlformats.spreadsheetml.sheet",
        "org.openxmlformats.spreadsheetml.template",
        "org.openxmlformats.spreadsheetml.template.macroenabled",
        "org.openxmlformats.spreadsheetml.addin.macroenabled",
        "org.openxmlformats.spreadsheetml.binary.macroenabled",
        "org.openxmlformats.spreadsheetml.sheet.macroenabled"},
    {"com.microsoft.powerpoint.ppt",
        "com.microsoft.powerpoint.pps",
        "com.microsoft.powerpoint.pot",
        "org.openxmlformats.presentationml.presentation",
        "org.openxmlformats.presentationml.template",
        "org.openxmlformats.presentationml.slideshow",
        "org.openxmlformats.presentationml.addin.macroenabled",
        "org.openxmlformats.presentationml.presentation.macroenabled",
        "org.openxmlformats.presentationml.slideshow.macroenabled",
        "org.openxmlformats.presentationml.template.macroenabled"}
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
    LOG_I(BMS_TAG_DEFAULT, "IsDefault,userId:%{public}d,type:%{private}s", userId, type.c_str());
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

    std::vector<std::string> normalizedTypeVector = Normalize(type);
    LOG_I(BMS_TAG_DEFAULT, "normalized:%{public}s", BundleUtil::ToString(normalizedTypeVector).c_str());
    if (normalizedTypeVector.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "normalizedTypeVector empty");
        isDefaultApp = false;
        return ERR_OK;
    }

    for (const std::string& normalizedType : normalizedTypeVector) {
        (void)IsDefaultApplicationInternal(userId, normalizedType, isDefaultApp);
        if (isDefaultApp) {
            return ERR_OK;
        }
    }
    return ERR_OK;
}

ErrCode DefaultAppMgr::IsDefaultApplicationInternal(
    int32_t userId, const std::string& normalizedType, bool& isDefaultApp) const
{
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
    LOG_I(BMS_TAG_DEFAULT, "callingBundleName:%{public}s", callingBundleName.c_str());
    isDefaultApp = element.bundleName == callingBundleName;
    return ERR_OK;
}

ErrCode DefaultAppMgr::GetDefaultApplication(
    int32_t userId, const std::string& type, BundleInfo& bundleInfo, bool backup) const
{
    LOG_I(BMS_TAG_DEFAULT, "GetDefault,userId:%{public}d,type:%{private}s,backup(bool):%{public}d",
        userId, type.c_str(), backup);

    ErrCode ret = VerifyPermission(Constants::PERMISSION_GET_DEFAULT_APPLICATION);
    if (ret != ERR_OK) {
        return ret;
    }

    if (!IsUserIdExist(userId)) {
        LOG_W(BMS_TAG_DEFAULT, "userId not exist");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::vector<std::string> normalizedTypeVector = Normalize(type);
    LOG_I(BMS_TAG_DEFAULT, "normalized:%{public}s", BundleUtil::ToString(normalizedTypeVector).c_str());
    if (normalizedTypeVector.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "normalizedTypeVector empty");
        return ERR_BUNDLE_MANAGER_INVALID_TYPE;
    }

    for (const std::string& normalizedType : normalizedTypeVector) {
        ret = GetDefaultApplicationInternal(userId, normalizedType, bundleInfo, backup);
        if (ret == ERR_OK) {
            return ret;
        }
    }
    return ret;
}

ErrCode DefaultAppMgr::GetDefaultApplicationInternal(
    int32_t userId, const std::string& normalizedType, BundleInfo& bundleInfo, bool backup) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (IsAppType(normalizedType)) {
        return GetBundleInfoByAppType(userId, normalizedType, bundleInfo, backup);
    }
    return GetBundleInfoByUtd(userId, normalizedType, bundleInfo, backup);
}

ErrCode DefaultAppMgr::SetDefaultApplication(
    int32_t userId, const std::string& type, const Element& element) const
{
    LOG_I(BMS_TAG_DEFAULT, "SetDefault,userId:%{public}d,type:%{private}s", userId, type.c_str());

    ErrCode ret = VerifyPermission(Constants::PERMISSION_SET_DEFAULT_APPLICATION);
    if (ret != ERR_OK) {
        return ret;
    }

    if (!IsUserIdExist(userId)) {
        LOG_W(BMS_TAG_DEFAULT, "userId not exist");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::vector<std::string> normalizedTypeVector = Normalize(type);
    LOG_I(BMS_TAG_DEFAULT, "normalized:%{public}s", BundleUtil::ToString(normalizedTypeVector).c_str());
    if (normalizedTypeVector.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "normalizedTypeVector empty");
        return ERR_BUNDLE_MANAGER_INVALID_TYPE;
    }
    std::unordered_map<std::string, std::pair<bool, Element>> originStateMap;
    GetDefaultInfo(userId, normalizedTypeVector, originStateMap);
    bool isAnySet = false;
    std::unordered_map<std::string, ErrCode> setResultMap;
    for (const std::string& normalizedType : normalizedTypeVector) {
        ret = SetDefaultApplicationInternal(userId, normalizedType, element);
        setResultMap.try_emplace(normalizedType, ret);
        if (ret == ERR_OK) {
            isAnySet = true;
        }
    }
    if (!isAnySet) {
        return ret;
    }
    // set any success, clear failed records
    for (const auto& item : setResultMap) {
        if (item.second != ERR_OK) {
            LOG_I(BMS_TAG_DEFAULT, "clear record,normalizedType:%{public}s", item.first.c_str());
            Element element;
            (void)SetDefaultApplicationInternal(userId, item.first, element);
        }
    }
    SendDefaultAppChangeEventIfNeeded(userId, normalizedTypeVector, originStateMap);
    return ERR_OK;
}

ErrCode DefaultAppMgr::SetDefaultApplicationInternal(
    int32_t userId, const std::string& normalizedType, const Element& element) const
{
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
    LOG_I(BMS_TAG_DEFAULT, "ResetDefault,userId:%{public}d,type:%{private}s", userId, type.c_str());
    ErrCode ret = VerifyPermission(Constants::PERMISSION_SET_DEFAULT_APPLICATION);
    if (ret != ERR_OK) {
        return ret;
    }

    if (!IsUserIdExist(userId)) {
        LOG_W(BMS_TAG_DEFAULT, "userId not exist");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::vector<std::string> normalizedTypeVector = Normalize(type);
    LOG_I(BMS_TAG_DEFAULT, "normalized:%{public}s", BundleUtil::ToString(normalizedTypeVector).c_str());
    if (normalizedTypeVector.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "normalizedTypeVector empty");
        return ERR_BUNDLE_MANAGER_INVALID_TYPE;
    }

    std::unordered_map<std::string, std::pair<bool, Element>> originStateMap;
    GetDefaultInfo(userId, normalizedTypeVector, originStateMap);
    bool isAnySet = false;
    for (const std::string& normalizedType : normalizedTypeVector) {
        ret = ResetDefaultApplicationInternal(userId, normalizedType);
        if (ret == ERR_OK) {
            isAnySet = true;
        }
    }

    SendDefaultAppChangeEventIfNeeded(userId, normalizedTypeVector, originStateMap);
    return isAnySet ? ERR_OK : ret;
}

ErrCode DefaultAppMgr::ResetDefaultApplicationInternal(int32_t userId, const std::string& normalizedType) const
{
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
    LOG_D(BMS_TAG_DEFAULT, "ResetDefaultApplication success");
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
    std::vector<std::string> changedTypeVec;
    for (const auto& item : currentInfos) {
        if (item.second.bundleName != bundleName) {
            newInfos.emplace(item.first, item.second);
            continue;
        }
        Element element;
        if (defaultAppDb_->GetDefaultApplicationInfo(INITIAL_USER_ID, item.first, element)) {
            LOG_I(BMS_TAG_DEFAULT, "set default application to preset, type : %{public}s", item.first.c_str());
            newInfos.emplace(item.first, element);
        } else {
            LOG_D(BMS_TAG_DEFAULT, "erase uninstalled application type:%{public}s", item.first.c_str());
        }
        changedTypeVec.emplace_back(item.first);
    }
    defaultAppDb_->SetDefaultApplicationInfos(userId, newInfos);
    (void)SendDefaultAppChangeEvent(userId, changedTypeVec);
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
    bool matchAction = want.GetAction() == ServiceConstants::ACTION_VIEW_DATA;
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

std::string DefaultAppMgr::GetTypeFromWant(const Want& want) const
{
    if (IsBrowserWant(want)) {
        return BROWSER;
    }
    if (IsEmailWant(want)) {
        return EMAIL;
    }
    if (want.GetAction() != ServiceConstants::ACTION_VIEW_DATA) {
        return Constants::EMPTY_STRING;
    }
    std::string uri = Skill::GetOptParamUri(want.GetUriString());
    bool containsScheme = uri.find(SCHEME_SIGN) != std::string::npos;
    bool isLocalScheme = uri.rfind(FILE_SCHEME, 0) == 0 || uri.rfind(CONTENT_SCHEME, 0) == 0;
    if (containsScheme && !isLocalScheme) {
        LOG_D(BMS_TAG_DEFAULT, "not local scheme");
        return Constants::EMPTY_STRING;
    }
    // get from type
    std::string type = want.GetType();
    if (!type.empty()) {
        return type;
    }
    // get from uri
    std::string suffix;
    (void)MimeTypeMgr::GetUriSuffix(uri, suffix);
    return suffix;
}

bool DefaultAppMgr::GetDefaultApplication(const Want& want, const int32_t userId,
    std::vector<AbilityInfo>& abilityInfos, std::vector<ExtensionAbilityInfo>& extensionInfos, bool backup) const
{
    std::string type = GetTypeFromWant(want);
    LOG_I(BMS_TAG_DEFAULT, "backup(bool):%{public}d, type(want):%{private}s", backup, type.c_str());
    if (type.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "type empty");
        return false;
    }
    BundleInfo bundleInfo;
    ErrCode ret = GetDefaultApplication(userId, type, bundleInfo, backup);
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
    size_t len = sizeof(APP_TYPES_KEY) / sizeof(APP_TYPES_KEY[0]);
    for (const auto& item : defaultAppTypeInfos) {
        size_t i = 0;
        for (i = 0; i < len; i++) {
            if (APP_TYPES_KEY[i] == item.first) break;
        }
        if (i == len) continue;
        Skill skill;
        for (const auto& utdId : APP_TYPES_VALUE[i]) {
            if (skill.MatchType(utd, utdId) && GetBundleInfo(userId, utd, item.second, bundleInfo)) {
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
    size_t i = 0;
    size_t len = sizeof(APP_TYPES_KEY) / sizeof(APP_TYPES_KEY[0]);
    for (i = 0; i < len; i++) {
        if (APP_TYPES_KEY[i] == type) break;
    }
    if (i == len) {
        LOG_E(BMS_TAG_DEFAULT, "invalid app type : %{public}s", type.c_str());
        return false;
    }
    for (const std::string& utdId : APP_TYPES_VALUE[i]) {
        if (MatchActionAndType(ServiceConstants::ACTION_VIEW_DATA, utdId, skills)) {
            return true;
        }
    }
    return false;
}

bool DefaultAppMgr::IsBrowserSkillsValid(const std::vector<Skill>& skills) const
{
    LOG_D(BMS_TAG_DEFAULT, "begin to verify browser skills");
    Want httpWant;
    httpWant.SetAction(ServiceConstants::ACTION_VIEW_DATA);
    httpWant.AddEntity(ENTITY_BROWSER);
    httpWant.SetUri(HTTP);

    Want httpsWant;
    httpsWant.SetAction(ServiceConstants::ACTION_VIEW_DATA);
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
    if (MatchActionAndType(ServiceConstants::ACTION_VIEW_DATA, utd, skills)) {
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

std::vector<std::string> DefaultAppMgr::Normalize(const std::string& param)
{
    if (IsAppType(param)) {
        return {param};
    }
    if (BundleUtil::IsUtd(param)) {
        if (BundleUtil::IsSpecificUtd(param)) {
            return {param};
        }
        return {};
    }
    if (IsSpecificMimeType(param)) {
        return BundleUtil::GetUtdVectorByMimeType(param);
    }
    std::vector<std::string> utdVector;
    if (!MimeTypeMgr::GetUtdVectorByUri(param, utdVector)) {
        LOG_W(BMS_TAG_DEFAULT, "GetUtdVectorByUri failed");
        return {};
    }
    return utdVector;
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

void DefaultAppMgr::GetDefaultInfo(const int32_t userId, const std::vector<std::string>& normalizedTypeVec,
    std::unordered_map<std::string, std::pair<bool, Element>>& defaultInfo) const
{
    for (const std::string& normalizedType : normalizedTypeVec) {
        Element element;
        bool ret = defaultAppDb_->GetDefaultApplicationInfo(userId, normalizedType, element);
        defaultInfo[normalizedType] = std::make_pair(ret, element);
    }
}

bool DefaultAppMgr::SendDefaultAppChangeEventIfNeeded(
    const int32_t userId, const std::vector<std::string>& normalizedTypeVec,
    const std::unordered_map<std::string, std::pair<bool, Element>>& originStateMap) const
{
    std::unordered_map<std::string, std::pair<bool, Element>> currentStateMap;
    GetDefaultInfo(userId, normalizedTypeVec, currentStateMap);
    std::vector<std::string> changedTypeVec;
    for (const auto& originState : originStateMap) {
        auto currentState = currentStateMap.find(originState.first);
        if (currentState == currentStateMap.end()) {
            LOG_W(BMS_TAG_DEFAULT, "currentStateMap not contains type: %{public}s", originState.first.c_str());
            continue;
        }
        if (ShouldSendEvent(originState.second.first, originState.second.second, currentState->second.first,
            currentState->second.second)) {
            changedTypeVec.emplace_back(originState.first);
        }
    }
    return SendDefaultAppChangeEvent(userId, changedTypeVec);
}

bool DefaultAppMgr::ShouldSendEvent(
    bool originalResult, const Element& originalElement, bool currentResult, const Element& currentElement) const
{
    if (originalResult && currentResult) {
        return !(originalElement == currentElement);
    }
    return originalResult || currentResult;
}

bool DefaultAppMgr::SendDefaultAppChangeEvent(const int32_t userId, const std::vector<std::string>& typeVec) const
{
    if (typeVec.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "typeVec is empty");
        return false;
    }
    std::vector<std::string> utdIdVec;
    for (const auto& type : typeVec) {
        if (!IsAppType(type)) {
            utdIdVec.emplace_back(type);
            continue;
        }

        size_t i = 0;
        size_t len = sizeof(APP_TYPES_KEY) / sizeof(APP_TYPES_KEY[0]);
        for (i = 0; i < len; i++) {
            if (APP_TYPES_KEY[i] == type) break;
        }
        if (i == len) {
            LOG_W(BMS_TAG_DEFAULT, "APP_TYPES_KEY not contains type: %{public}s", type.c_str());
            continue;
        }
        for (const std::string& utdId : APP_TYPES_VALUE[i]) {
            utdIdVec.emplace_back(utdId);
        }
    }
    if (utdIdVec.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "utdIdVec is empty");
        return false;
    }
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyDefaultAppChanged(userId, utdIdVec);
    LOG_I(BMS_TAG_DEFAULT, "Send default app change event success");
    return true;
}
}
}