/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <fstream>
#include <sstream>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bms_extension_profile.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t BUFFER_SIZE = 256;
static const std::string BMS_EXTENSION_PROFILE = "bms-extensions";
static const std::string BMS_EXTENSION_PROFILE_BUNDLE_MGR = "bundle-mgr";
static const std::string BUNDLE_MGR_KEY_EXTENSION_NAME = "extension-name";
static const std::string BUNDLE_MGR_KEY_LIB_PATH = "libpath";
static const std::string BUNDLE_MGR_KEY_LIB64_PATH = "lib64path";
}

ErrCode BmsExtensionProfile::ParseBmsExtension(
    const std::string &jsonPath, BmsExtension &bmsExtension) const
{
    APP_LOGD("Parse BmsExtension from %{private}s", jsonPath.c_str());
    nlohmann::json jsonBuf;
    if (!ReadFileIntoJson(jsonPath, jsonBuf)) {
        APP_LOGE("Parse failed %{public}s", jsonPath.c_str());
        return ERR_APPEXECFWK_PARSE_FILE_FAILED;
    }
    return TransformTo(jsonBuf, bmsExtension);
}

bool BmsExtensionProfile::ReadFileIntoJson(const std::string &filePath, nlohmann::json &jsonBuf) const
{
    if (access(filePath.c_str(), F_OK) != 0) {
        APP_LOGE("access failed %{public}s errno:%{public}d", filePath.c_str(), errno);
        return false;
    }

    std::fstream in;
    char errBuf[BUFFER_SIZE];
    errBuf[0] = '\0';
    in.open(filePath, std::ios_base::in);
    if (!in.is_open()) {
        strerror_r(errno, errBuf, sizeof(errBuf));
        APP_LOGE("open failed %{public}s errno :%{public}d", errBuf, errno);
        return false;
    }

    in.seekg(0, std::ios::end);
    int64_t size = in.tellg();
    if (size <= 0) {
        APP_LOGE("file is empty %{public}d", errno);
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

ErrCode BmsExtensionProfile::TransformTo(const nlohmann::json &jsonObject,
    BmsExtension &bmsExtension) const
{
    APP_LOGD("transform bms-extension.json stream to BmsExtension");
    if (jsonObject.is_discarded()) {
        APP_LOGE("profile format error");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }
    if (jsonObject.find(BMS_EXTENSION_PROFILE) == jsonObject.end()) {
        APP_LOGE("bms-extensions no exist");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }
    nlohmann::json bmsExtensionJson = jsonObject.at(BMS_EXTENSION_PROFILE);
    if (!bmsExtensionJson.is_object()) {
        APP_LOGE("bms-extension.json file lacks of invalid bms-extensions property");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }
    if (bmsExtensionJson.find(BMS_EXTENSION_PROFILE_BUNDLE_MGR) == bmsExtensionJson.end()) {
        APP_LOGE("bundle-mgr no exist");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }
    nlohmann::json bundleMgrJson = bmsExtensionJson.at(BMS_EXTENSION_PROFILE_BUNDLE_MGR);
    if (!bundleMgrJson.is_object()) {
        APP_LOGE("bms-extension.json file lacks of invalid bundle-mgr property");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }
    const auto &jsonObjectEnd = bundleMgrJson.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(bundleMgrJson, jsonObjectEnd, BUNDLE_MGR_KEY_EXTENSION_NAME,
        bmsExtension.bmsExtensionBundleMgr.extensionName, JsonType::STRING, true, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(bundleMgrJson, jsonObjectEnd, BUNDLE_MGR_KEY_LIB_PATH,
        bmsExtension.bmsExtensionBundleMgr.libPath, JsonType::STRING, true, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(bundleMgrJson, jsonObjectEnd, BUNDLE_MGR_KEY_LIB64_PATH,
        bmsExtension.bmsExtensionBundleMgr.lib64Path, JsonType::STRING, true, parseResult, ArrayType::NOT_ARRAY);
    return parseResult;
}
}  // namespace AppExecFwk
}  // namespace OHOS

