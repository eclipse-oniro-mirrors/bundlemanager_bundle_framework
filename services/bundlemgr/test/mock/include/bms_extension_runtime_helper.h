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

#ifndef BMS_EXTENSION_RUNTIME_HELPER_H
#define BMS_EXTENSION_RUNTIME_HELPER_H

#include <fstream>
#include <string>
#include <unistd.h>

#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *BMS_EXTENSION_RUNTIME_PATH = "/system/etc/app/bms-extensions.json";
constexpr const char *BMS_EXTENSION_JSON_ROOT = "bms-extensions";
constexpr const char *BMS_EXTENSION_JSON_BUNDLE_MGR = "bundle-mgr";
constexpr const char *BMS_EXTENSION_JSON_LIB_PATH = "libpath";
constexpr const char *BMS_EXTENSION_JSON_LIB64_PATH = "lib64path";

inline bool HasLibFile(const nlohmann::json &node, const char *key)
{
    if (!node.contains(key) || !node.at(key).is_string()) {
        return false;
    }
    const std::string path = node.at(key).get<std::string>();
    return !path.empty() && access(path.c_str(), F_OK) == 0;
}

inline bool ParseExtensionRoot(nlohmann::json &root)
{
    std::ifstream file(BMS_EXTENSION_RUNTIME_PATH);
    if (!file.is_open()) {
        return false;
    }
    root = nlohmann::json::parse(file, nullptr, false);
    return !root.is_discarded() && root.contains(BMS_EXTENSION_JSON_ROOT) &&
        root.at(BMS_EXTENSION_JSON_ROOT).is_object();
}

inline bool LoadBundleMgrNode(nlohmann::json &bundleMgr)
{
    nlohmann::json root;
    if (!ParseExtensionRoot(root)) {
        return false;
    }
    const auto &ext = root.at(BMS_EXTENSION_JSON_ROOT);
    if (!ext.contains(BMS_EXTENSION_JSON_BUNDLE_MGR) || !ext.at(BMS_EXTENSION_JSON_BUNDLE_MGR).is_object()) {
        return false;
    }
    bundleMgr = ext.at(BMS_EXTENSION_JSON_BUNDLE_MGR);
    return true;
}
}  // namespace

/**
 * Runtime check for BMS extension capability.
 * Compile-time USE_EXTENSION_DATA only means arm64; config/so may still be absent.
 */
inline bool IsBmsExtensionRuntimeReady()
{
    if (access(BMS_EXTENSION_RUNTIME_PATH, F_OK) != 0) {
        return false;
    }
    nlohmann::json bundleMgr;
    if (!LoadBundleMgrNode(bundleMgr)) {
        return false;
    }
    return HasLibFile(bundleMgr, BMS_EXTENSION_JSON_LIB64_PATH) ||
        HasLibFile(bundleMgr, BMS_EXTENSION_JSON_LIB_PATH);
}
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // BMS_EXTENSION_RUNTIME_HELPER_H
