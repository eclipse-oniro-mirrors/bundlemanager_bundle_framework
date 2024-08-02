/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "bundle_parser.h"

#include <fstream>
#include <sstream>

#include "bundle_profile.h"
#include "default_permission_profile.h"
#include "module_profile.h"
#include "pre_bundle_profile.h"
#include "rpcid_decode/syscap_tool.h"
#include "securec.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BUNDLE_PACKFILE_NAME = "pack.info";
constexpr const char* SYSCAP_NAME = "rpcid.sc";
static const char* ROUTER_MAP = "routerMap";
static const char* ROUTER_MAP_DATA = "data";
static const char* ROUTER_ITEM_KEY_CUSTOM_DATA = "customData";
static const uint16_t DATA_MAX_LENGTH = 4096;
const char* NO_DISABLING_CONFIG_KEY = "residentProcessInExtremeMemory";
const char* NO_DISABLING_KEY_BUNDLE_NAME = "bundleName";

bool ParseStr(const char *buf, const int itemLen, int totalLen, std::vector<std::string> &sysCaps)
{
    APP_LOGD("Parse rpcid output start, itemLen:%{public}d  totalLen:%{public}d", itemLen, totalLen);
    if (buf == nullptr || itemLen <= 0 || totalLen <= 0) {
        APP_LOGE("param invalid");
        return false;
    }

    int index = 0;
    while (index + itemLen <= totalLen) {
        char item[itemLen];
        if (strncpy_s(item, sizeof(item), buf + index, itemLen) != 0) {
            APP_LOGE("Parse rpcid failed due to strncpy_s error");
            return false;
        }

        sysCaps.emplace_back((std::string)item, 0, itemLen);
        index += itemLen;
    }

    return true;
}
} // namespace

bool BundleParser::ReadFileIntoJson(const std::string &filePath, nlohmann::json &jsonBuf)
{
    if (access(filePath.c_str(), F_OK) != 0) {
        APP_LOGD("access file %{public}s failed, error: %{public}s", filePath.c_str(), strerror(errno));
        return false;
    }

    std::fstream in;
    char errBuf[256];
    errBuf[0] = '\0';
    in.open(filePath, std::ios_base::in);
    if (!in.is_open()) {
        strerror_r(errno, errBuf, sizeof(errBuf));
        APP_LOGE("file open failed due to %{public}s, errno:%{public}d", errBuf, errno);
        return false;
    }

    in.seekg(0, std::ios::end);
    int64_t size = in.tellg();
    if (size <= 0) {
        APP_LOGE("file empty, errno:%{public}d", errno);
        in.close();
        return false;
    }

    in.seekg(0, std::ios::beg);
    jsonBuf = nlohmann::json::parse(in, nullptr, false);
    in.close();
    if (jsonBuf.is_discarded()) {
        APP_LOGE("bad profile file");
        return false;
    }

    return true;
}

ErrCode BundleParser::Parse(
    const std::string &pathName,
    InnerBundleInfo &innerBundleInfo) const
{
    APP_LOGD("parse from %{private}s", pathName.c_str());
    BundleExtractor bundleExtractor(pathName);
    if (!bundleExtractor.Init()) {
        APP_LOGE("bundle extractor init failed");
        return ERR_APPEXECFWK_PARSE_UNEXPECTED;
    }

    // to extract config.json
    std::ostringstream outStream;
    if (!bundleExtractor.ExtractProfile(outStream)) {
        APP_LOGE("extract profile file failed");
        return ERR_APPEXECFWK_PARSE_NO_PROFILE;
    }

    if (bundleExtractor.IsNewVersion()) {
        APP_LOGD("module.json transform to InnerBundleInfo");
        innerBundleInfo.SetIsNewVersion(true);
        ModuleProfile moduleProfile;
        return moduleProfile.TransformTo(
            outStream, bundleExtractor, innerBundleInfo);
    }
    APP_LOGD("config.json transform to InnerBundleInfo");
    innerBundleInfo.SetIsNewVersion(false);
    BundleProfile bundleProfile;
    ErrCode ret = bundleProfile.TransformTo(
        outStream, bundleExtractor, innerBundleInfo);
    if (ret != ERR_OK) {
        APP_LOGE("transform stream to innerBundleInfo failed %{public}d", ret);
        return ret;
    }
    auto& abilityInfos = innerBundleInfo.FetchAbilityInfos();
    for (auto& info : abilityInfos) {
        info.second.isStageBasedModel = bundleExtractor.IsStageBasedModel(info.second.name);
        auto iter = innerBundleInfo.FetchInnerModuleInfos().find(info.second.package);
        if (iter != innerBundleInfo.FetchInnerModuleInfos().end()) {
            iter->second.isStageBasedModel = info.second.isStageBasedModel;
        }
    }

    return ERR_OK;
}

ErrCode BundleParser::ParsePackInfo(const std::string &pathName, BundlePackInfo &bundlePackInfo) const
{
    APP_LOGD("parse from %{private}s", pathName.c_str());
    BundleExtractor bundleExtractor(pathName);
    if (!bundleExtractor.Init()) {
        APP_LOGE("bundle extractor init failed");
        return ERR_APPEXECFWK_PARSE_UNEXPECTED;
    }

    // to extract pack.info
    if (!bundleExtractor.HasEntry(BUNDLE_PACKFILE_NAME)) {
        APP_LOGW("cannot find pack.info in the hap file");
        return ERR_OK;
    }
    std::ostringstream outStreamForPackInfo;
    if (!bundleExtractor.ExtractPackFile(outStreamForPackInfo)) {
        APP_LOGE("extract profile file failed");
        return ERR_APPEXECFWK_PARSE_NO_PROFILE;
    }
    BundleProfile bundleProfile;
    ErrCode ret = bundleProfile.TransformTo(outStreamForPackInfo, bundlePackInfo);
    if (ret != ERR_OK) {
        APP_LOGE("transform stream to bundlePackinfo failed %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode BundleParser::ParseSysCap(const std::string &pathName, std::vector<std::string> &sysCaps) const
{
    APP_LOGD("Parse sysCaps from %{private}s", pathName.c_str());
    BundleExtractor bundleExtractor(pathName);
    if (!bundleExtractor.Init()) {
        APP_LOGE("Bundle extractor init failed");
        return ERR_APPEXECFWK_PARSE_UNEXPECTED;
    }

    if (!bundleExtractor.HasEntry(SYSCAP_NAME)) {
        APP_LOGD("Rpcid.sc is not exist, and do not need verification sysCaps");
        return ERR_OK;
    }

    std::stringstream rpcidStream;
    if (!bundleExtractor.ExtractByName(SYSCAP_NAME, rpcidStream)) {
        APP_LOGE("Extract rpcid file failed");
        return ERR_APPEXECFWK_PARSE_RPCID_FAILED;
    }

    int32_t rpcidLen = rpcidStream.tellp();
    if (rpcidLen < 0) {
        return ERR_APPEXECFWK_PARSE_UNEXPECTED;
    }
    char rpcidBuf[rpcidLen];
    rpcidStream.read(rpcidBuf, rpcidLen);
    uint32_t outLen;
    char *outBuffer;
    int result = RPCIDStreamDecodeToBuffer(rpcidBuf, rpcidLen, &outBuffer, &outLen);
    if (result != 0) {
        APP_LOGE("Decode syscaps failed");
        return ERR_APPEXECFWK_PARSE_RPCID_FAILED;
    }

    if (!ParseStr(outBuffer, SINGLE_SYSCAP_LENGTH, outLen, sysCaps)) {
        APP_LOGE("Parse syscaps str failed");
        free(outBuffer);
        return ERR_APPEXECFWK_PARSE_RPCID_FAILED;
    }

    APP_LOGD("Parse sysCaps str success");
    free(outBuffer);
    return ERR_OK;
}

ErrCode BundleParser::ParsePreInstallConfig(
    const std::string &configFile, std::set<PreScanInfo> &scanInfos) const
{
    APP_LOGD("Parse preInstallConfig from %{public}s", configFile.c_str());
    nlohmann::json jsonBuf;
    if (!ReadFileIntoJson(configFile, jsonBuf)) {
        APP_LOGE_NOFUNC("Parse file %{public}s failed", configFile.c_str());
        return ERR_APPEXECFWK_PARSE_FILE_FAILED;
    }

    PreBundleProfile preBundleProfile;
    return preBundleProfile.TransformTo(jsonBuf, scanInfos);
}

ErrCode BundleParser::ParsePreUnInstallConfig(
    const std::string &configFile,
    std::set<std::string> &uninstallList) const
{
    APP_LOGD("Parse PreUnInstallConfig from %{public}s", configFile.c_str());
    nlohmann::json jsonBuf;
    if (!ReadFileIntoJson(configFile, jsonBuf)) {
        APP_LOGE_NOFUNC("Parse file %{public}s failed", configFile.c_str());
        return ERR_APPEXECFWK_PARSE_FILE_FAILED;
    }

    PreBundleProfile preBundleProfile;
    return preBundleProfile.TransformTo(jsonBuf, uninstallList);
}

ErrCode BundleParser::ParsePreInstallAbilityConfig(
    const std::string &configFile, std::set<PreBundleConfigInfo> &preBundleConfigInfos) const
{
    APP_LOGD("Parse PreInstallAbilityConfig from %{public}s", configFile.c_str());
    nlohmann::json jsonBuf;
    if (!ReadFileIntoJson(configFile, jsonBuf)) {
        APP_LOGE("Parse file %{public}s failed", configFile.c_str());
        return ERR_APPEXECFWK_PARSE_FILE_FAILED;
    }

    PreBundleProfile preBundleProfile;
    return preBundleProfile.TransformTo(jsonBuf, preBundleConfigInfos);
}

ErrCode BundleParser::ParseDefaultPermission(
    const std::string &permissionFile, std::set<DefaultPermission> &defaultPermissions) const
{
    APP_LOGD("Parse DefaultPermission from %{private}s", permissionFile.c_str());
    nlohmann::json jsonBuf;
    if (!ReadFileIntoJson(permissionFile, jsonBuf)) {
        APP_LOGE_NOFUNC("Parse file %{public}s failed", permissionFile.c_str());
        return ERR_APPEXECFWK_PARSE_FILE_FAILED;
    }

    DefaultPermissionProfile profile;
    return profile.TransformTo(jsonBuf, defaultPermissions);
}

ErrCode BundleParser::ParseExtTypeConfig(
    const std::string &configFile, std::set<std::string> &extensionTypeList) const
{
    nlohmann::json jsonBuf;
    if (!ReadFileIntoJson(configFile, jsonBuf)) {
        APP_LOGE_NOFUNC("Parse file %{public}s failed", configFile.c_str());
        return ERR_APPEXECFWK_PARSE_FILE_FAILED;
    }

    PreBundleProfile preBundleProfile;
    return preBundleProfile.TransformJsonToExtensionTypeList(jsonBuf, extensionTypeList);
}

bool BundleParser::CheckRouterData(nlohmann::json data) const
{
    if (data.find(ROUTER_MAP_DATA) == data.end()) {
        APP_LOGW("data is not existed");
        return false;
    }
    if (!data.at(ROUTER_MAP_DATA).is_object()) {
        APP_LOGW("data is not a json object");
        return false;
    }
    for (nlohmann::json::iterator kt = data.at(ROUTER_MAP_DATA).begin(); kt != data.at(ROUTER_MAP_DATA).end(); ++kt) {
        // check every value is string
        if (!kt.value().is_string()) {
            APP_LOGW("Error: Value in data object for key %{public}s must be a string", kt.key().c_str());
            return false;
        }
    }
    return true;
}

ErrCode BundleParser::ParseRouterArray(
    const std::string &jsonString, std::vector<RouterItem> &routerArray) const
{
    if (jsonString.empty()) {
        APP_LOGE("jsonString is empty");
        return ERR_APPEXECFWK_PARSE_NO_PROFILE;
    }
    APP_LOGD("Parse RouterItem from %{private}s", jsonString.c_str());
    nlohmann::json jsonBuf = nlohmann::json::parse(jsonString, nullptr, false);
    if (jsonBuf.is_discarded()) {
        APP_LOGE("json file %{private}s discarded", jsonString.c_str());
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }
    if (jsonBuf.find(ROUTER_MAP) == jsonBuf.end()) {
        APP_LOGE("routerMap no exist");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }
    nlohmann::json routerJson = jsonBuf.at(ROUTER_MAP);
    if (!routerJson.is_array()) {
        APP_LOGE("json under routerMap is not a json array");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }

    for (const auto &object : routerJson) {
        if (!object.is_object()) {
            return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        }
        RouterItem routerItem;
        if (object.count(ROUTER_MAP_DATA) > 0 && !CheckRouterData(object)) {
            APP_LOGW("check data type failed");
            continue;
        }
        from_json(object, routerItem);
        if (object.find(ROUTER_ITEM_KEY_CUSTOM_DATA) != object.end()) {
            if (object[ROUTER_ITEM_KEY_CUSTOM_DATA].dump().size() <= DATA_MAX_LENGTH) {
                routerItem.customData = object[ROUTER_ITEM_KEY_CUSTOM_DATA].dump();
            } else {
                APP_LOGE("customData in routerMap profile is too long");
            }
        }
        routerArray.emplace_back(routerItem);
    }
    return ERR_OK;
}

ErrCode BundleParser::ParseNoDisablingList(const std::string &configPath, std::vector<std::string> &noDisablingList)
{
    nlohmann::json object;
    if (!ReadFileIntoJson(configPath, object)) {
        APP_LOGI("Parse file %{public}s failed", configPath.c_str());
        return ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL;
    }
    if (!object.contains(NO_DISABLING_CONFIG_KEY) || !object.at(NO_DISABLING_CONFIG_KEY).is_array()) {
        APP_LOGE("no disabling config not existed");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }
    for (auto &item : object.at(NO_DISABLING_CONFIG_KEY).items()) {
        const nlohmann::json& jsonObject = item.value();
        if (jsonObject.contains(NO_DISABLING_KEY_BUNDLE_NAME) &&
            jsonObject.at(NO_DISABLING_KEY_BUNDLE_NAME).is_string()) {
            std::string bundleName = jsonObject.at(NO_DISABLING_KEY_BUNDLE_NAME).get<std::string>();
            noDisablingList.emplace_back(bundleName);
        }
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
