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

#include "hidump_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int8_t MIN_ARGS_SIZE = 1;
constexpr int8_t MAX_ARGS_SIZE = 2;
constexpr int8_t FIRST_PARAM = 0;
constexpr int8_t SECOND_PARAM = 1;
constexpr const char* ARGS_HELP = "-h";
constexpr const char* ARGS_ABILITY = "-ability";
constexpr const char* ARGS_ABILITY_LIST = "-ability-list";
constexpr const char* ARGS_BUNDLE = "-bundle";
constexpr const char* ARGS_BUNDLE_LIST = "-bundle-list";
constexpr const char* ARGS_DEVICEID = "-device";
constexpr const char* ILLEGAL_INFOMATION = "The arguments are illegal and you can enter '-h' for help.\n";
constexpr const char* NO_INFOMATION = "no such infomation\n";

const std::unordered_map<std::string, HidumpFlag> ARGS_MAP = {
    { ARGS_HELP, HidumpFlag::GET_HELP },
    { ARGS_ABILITY, HidumpFlag::GET_ABILITY },
    { ARGS_ABILITY_LIST, HidumpFlag::GET_ABILITY_LIST },
    { ARGS_BUNDLE, HidumpFlag::GET_BUNDLE },
    { ARGS_BUNDLE_LIST, HidumpFlag::GET_BUNDLE_LIST },
    { ARGS_DEVICEID, HidumpFlag::GET_DEVICEID },
};
}

HidumpHelper::HidumpHelper(const std::weak_ptr<BundleDataMgr> &dataMgr)
    : dataMgr_(dataMgr) {}

bool HidumpHelper::Dump(const std::vector<std::string>& args, std::string &result)
{
    result.clear();
    ErrCode errCode = ERR_OK;
    int32_t argsSize = static_cast<int32_t>(args.size());
    switch (argsSize) {
        case MIN_ARGS_SIZE: {
            errCode = ProcessOneParam(args[FIRST_PARAM], result);
            break;
        }
        case MAX_ARGS_SIZE: {
            errCode = ProcessTwoParam(args[FIRST_PARAM], args[SECOND_PARAM], result);
            break;
        }
        default: {
            errCode = ERR_APPEXECFWK_HIDUMP_INVALID_ARGS;
            break;
        }
    }

    bool ret = false;
    switch (errCode) {
        case ERR_OK: {
            ret = true;
            break;
        }
        case ERR_APPEXECFWK_HIDUMP_INVALID_ARGS: {
            ShowIllealInfomation(result);
            ret = true;
            break;
        }
        case ERR_APPEXECFWK_HIDUMP_UNKONW: {
            result.append(NO_INFOMATION);
            ret = true;
            break;
        }
        case ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR: {
            ret = false;
            break;
        }
        default: {
            break;
        }
    }

    return ret;
}

ErrCode HidumpHelper::ProcessOneParam(const std::string& args, std::string &result)
{
    HidumpParam hidumpParam;
    auto operatorIter = ARGS_MAP.find(args);
    if (operatorIter != ARGS_MAP.end()) {
        hidumpParam.hidumpFlag = operatorIter->second;
    }

    if (hidumpParam.hidumpFlag == HidumpFlag::GET_HELP) {
        ShowHelp(result);
        return ERR_OK;
    }

    return ProcessDump(hidumpParam, result);
}

ErrCode HidumpHelper::ProcessTwoParam(
    const std::string& firstParam, const std::string& secondParam, std::string &result)
{
    HidumpParam hidumpParam;
    hidumpParam.args = secondParam;
    auto operatorIter = ARGS_MAP.find(firstParam);
    if (operatorIter != ARGS_MAP.end()) {
        hidumpParam.hidumpFlag = operatorIter->second;
    }

    switch (hidumpParam.hidumpFlag) {
        case HidumpFlag::GET_ABILITY: {
            hidumpParam.hidumpFlag = HidumpFlag::GET_ABILITY_BY_NAME;
            break;
        }
        case HidumpFlag::GET_BUNDLE: {
            hidumpParam.hidumpFlag = HidumpFlag::GET_BUNDLE_BY_NAME;
            break;
        }
        default: {
            break;
        }
    }

    return ProcessDump(hidumpParam, result);
}

ErrCode HidumpHelper::ProcessDump(const HidumpParam& hidumpParam, std::string &result)
{
    result.clear();
    ErrCode errCode = ERR_APPEXECFWK_HIDUMP_ERROR;
    switch (hidumpParam.hidumpFlag) {
        case HidumpFlag::GET_ABILITY: {
            errCode = GetAllAbilityInfo(result);
            break;
        }
        case HidumpFlag::GET_ABILITY_LIST: {
            errCode = GetAllAbilityNameList(result);
            break;
        }
        case HidumpFlag::GET_ABILITY_BY_NAME: {
            errCode = GetAbilityInfoByName(hidumpParam.args, result);
            break;
        }
        case HidumpFlag::GET_BUNDLE: {
            errCode = GetAllBundleInfo(result);
            break;
        }
        case HidumpFlag::GET_BUNDLE_LIST: {
            errCode = GetAllBundleNameList(result);
            break;
        }
        case HidumpFlag::GET_BUNDLE_BY_NAME: {
            errCode = GetBundleInfoByName(hidumpParam.args, result);
            break;
        }
        case HidumpFlag::GET_DEVICEID: {
            errCode = GetAllDeviced(result);
            break;
        }
        default: {
            errCode = ERR_APPEXECFWK_HIDUMP_INVALID_ARGS;
            break;
        }
    }

    return errCode;
}

ErrCode HidumpHelper::GetAllAbilityInfo(std::string &result)
{
    auto shareDataMgr = dataMgr_.lock();
    if (shareDataMgr == nullptr) {
        return ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR;
    }

    std::vector<BundleInfo> bundleInfos;
    if (!shareDataMgr->GetBundleInfos(static_cast<int32_t>(
        BundleFlag::GET_BUNDLE_WITH_ABILITIES |
        BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO |
        BundleFlag::GET_BUNDLE_WITH_HASH_VALUE),
        bundleInfos, Constants::ANY_USERID)) {
        APP_LOGE("get bundleInfos failed");
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }

    for (auto &bundleInfo : bundleInfos) {
        for (auto &abilityInfo :  bundleInfo.abilityInfos) {
            result.append(abilityInfo.name);
            result.append(":\n");
            nlohmann::json jsonObject = abilityInfo;
            std::string ability;
            try {
                ability = jsonObject.dump(Constants::DUMP_INDENT);
            } catch (const nlohmann::json::type_error &e) {
                APP_LOGE("json dump failed: %{public}s", e.what());
                return ERR_APPEXECFWK_HIDUMP_ERROR;
            }
            result.append(ability);
            result.append("\n");
        }
    }

    APP_LOGD("get all ability info success");
    return ERR_OK;
}

ErrCode HidumpHelper::GetAllAbilityNameList(std::string &result)
{
    auto shareDataMgr = dataMgr_.lock();
    if (shareDataMgr == nullptr) {
        return ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR;
    }

    std::vector<BundleInfo> bundleInfos;
    if (!shareDataMgr->GetBundleInfos(static_cast<int32_t>(
        BundleFlag::GET_BUNDLE_WITH_ABILITIES |
        BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO |
        BundleFlag::GET_BUNDLE_WITH_HASH_VALUE),
        bundleInfos, Constants::ANY_USERID)) {
        APP_LOGE("get bundleInfos failed");
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }

    for (const auto &bundleInfo : bundleInfos) {
        for (auto abilityInfo :  bundleInfo.abilityInfos) {
            result.append(abilityInfo.name);
            result.append("\n");
        }
    }

    APP_LOGD("get all ability list info success");
    return ERR_OK;
}

ErrCode HidumpHelper::GetAbilityInfoByName(const std::string &name, std::string &result)
{
    auto shareDataMgr = dataMgr_.lock();
    if (shareDataMgr == nullptr) {
        return ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR;
    }

    std::vector<BundleInfo> bundleInfos;
    if (!shareDataMgr->GetBundleInfos(static_cast<int32_t>(
        BundleFlag::GET_BUNDLE_WITH_ABILITIES |
        BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO |
        BundleFlag::GET_BUNDLE_WITH_HASH_VALUE),
        bundleInfos, Constants::ANY_USERID)) {
        APP_LOGE("get bundleInfos failed");
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }

    nlohmann::json jsonObject;
    for (const auto &bundleInfo : bundleInfos) {
        for (auto abilityInfo :  bundleInfo.abilityInfos) {
            if (abilityInfo.name == name) {
                jsonObject[abilityInfo.bundleName][abilityInfo.moduleName] = abilityInfo;
            }
        }
    }

    if (jsonObject.is_discarded() || jsonObject.empty()) {
        APP_LOGE("get ability by abilityName failed");
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }
    std::string abilities;
    try {
        abilities = jsonObject.dump(Constants::DUMP_INDENT);
    } catch (const nlohmann::json::type_error &e) {
        APP_LOGE("json dump failed: %{public}s", e.what());
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }
    result.append(abilities);
    result.append("\n");
    return ERR_OK;
}

ErrCode HidumpHelper::GetAllBundleInfo(std::string &result)
{
    auto shareDataMgr = dataMgr_.lock();
    if (shareDataMgr == nullptr) {
        return ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR;
    }

    std::vector<BundleInfo> bundleInfos;
    if (!shareDataMgr->GetBundleInfos(static_cast<int32_t>(
        BundleFlag::GET_BUNDLE_WITH_ABILITIES |
        BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO |
        BundleFlag::GET_BUNDLE_WITH_HASH_VALUE),
        bundleInfos, Constants::ANY_USERID)) {
        APP_LOGE("get bundleInfos failed");
        return ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR;
    }

    for (auto &info : bundleInfos) {
        result.append(info.name);
        result.append(":\n");
        nlohmann::json jsonObject = info;
        jsonObject["hapModuleInfos"] = info.hapModuleInfos;
        std::string hapModules;
        try {
            hapModules = jsonObject.dump(Constants::DUMP_INDENT);
        } catch (const nlohmann::json::type_error &e) {
            APP_LOGE("json dump failed: %{public}s", e.what());
            return ERR_APPEXECFWK_HIDUMP_ERROR;
        }
        result.append(hapModules);
        result.append("\n");
    }
    APP_LOGD("get all bundle info success");
    return ERR_OK;
}

ErrCode HidumpHelper::GetAllBundleNameList(std::string &result)
{
    auto shareDataMgr = dataMgr_.lock();
    if (shareDataMgr == nullptr) {
        APP_LOGE("shareDataMgr is nullptr");
        return ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR;
    }

    std::vector<std::string> bundleNames;
    if (!shareDataMgr->GetBundleList(bundleNames, Constants::ANY_USERID)) {
        APP_LOGE("get bundle list failed");
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }

    for (auto &name : bundleNames) {
        result.append(name);
        result.append("\n");
    }

    return ERR_OK;
}

ErrCode HidumpHelper::GetBundleInfoByName(const std::string &name, std::string &result)
{
    APP_LOGD("hidump bundle info begin");
    auto shareDataMgr = dataMgr_.lock();
    if (shareDataMgr == nullptr) {
        return ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR;
    }

    BundleInfo bundleInfo;
    if (!shareDataMgr->GetBundleInfo(name,
        BundleFlag::GET_BUNDLE_WITH_ABILITIES |
        BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION |
        BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO |
        BundleFlag::GET_BUNDLE_WITH_HASH_VALUE, bundleInfo, Constants::ANY_USERID)) {
        APP_LOGE("get bundleInfo(%{public}s) failed", name.c_str());
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }

    result.append(name);
    result.append(":\n");
    nlohmann::json jsonObject = bundleInfo;
    jsonObject["hapModuleInfos"] = bundleInfo.hapModuleInfos;
    std::string hapModules;
    try {
        hapModules = jsonObject.dump(Constants::DUMP_INDENT);
    } catch (const nlohmann::json::type_error &e) {
        APP_LOGE("json dump failed: %{public}s", e.what());
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }
    result.append(hapModules);
    result.append("\n");
    APP_LOGD("get %{public}s bundle info success", name.c_str());
    return ERR_OK;
}

ErrCode HidumpHelper::GetAllDeviced(std::string &result)
{
    result = "This command is deprecated. Please use `hidumper -s 4802 -a -getTrustlist` instead.";
    return ERR_OK;
}

void HidumpHelper::ShowHelp(std::string &result)
{
    result.append("Usage:dump  <command> [options]\n")
    .append("Description:\n")
    .append("-ability          ")
    .append("dump all ability infomation in the system\n")
    .append("-ability    [abilityName]\n")
    .append("                  dump ability list information of the specified name in the system\n")
    .append("-ability-list     ")
    .append("dump list of all ability names in the system\n")
    .append("-bundle           ")
    .append("dump all bundle infomation in the system\n")
    .append("-bundle     [bundleName]\n")
    .append("                  dump bundle list information of the specified name in the system\n")
    .append("-bundle-list      ")
    .append("dump list of all bundle names in the system\n")
    .append("-device           ")
    .append("dump the list of devices involved in the ability infomation in the system\n");
}

void HidumpHelper::ShowIllealInfomation(std::string &result)
{
    result.append(ILLEGAL_INFOMATION);
}
}  // namespace AppExecFwk
}  // namespace OHOS
