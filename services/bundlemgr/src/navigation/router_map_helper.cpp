/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "router_map_helper.h"
#include "regex.h"
#include "app_log_wrapper.h"
#include "router_item_compare.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* ALNUM_PATTERN = "^[a-zA-Z0-9]*$";
const char* NUM_PATTERN = "^[0-9]+$";
}

void RouterMapHelper::MergeRouter(BundleInfo &info, const std::vector<RouterItem> &pluginRouterInfos)
{
    if (info.hapModuleInfos.empty()) {
        APP_LOGW("hapModuleInfos in bundleInfo is empty");
        return;
    }
    std::vector<RouterItem> routerArrayList;
    std::set<std::string> moduleNameSet;
    std::set<std::string> nameSet;
    for (const auto &hapModuleInfo : info.hapModuleInfos) {
        if (hapModuleInfo.moduleType == ModuleType::ENTRY || hapModuleInfo.moduleType == ModuleType::FEATURE) {
            moduleNameSet.insert(hapModuleInfo.name);
        }
        for (const auto &routerItem : hapModuleInfo.routerArray) {
            routerArrayList.emplace_back(routerItem);
            nameSet.insert(routerItem.name);
        }
    }
    for (const auto &info : pluginRouterInfos) {
        if (nameSet.find(info.name) != nameSet.end()) {
            continue;
        }
        routerArrayList.emplace_back(info);
    }
    if (routerArrayList.empty()) {
        return;
    }
    MergeRouter(routerArrayList, info.routerArray, moduleNameSet);
}

std::string RouterMapHelper::ExtractVersionFromOhmurl(const std::string &ohmurl)
{
    size_t lastAmpersandPos = ohmurl.rfind('&');
    std::string versionString;
    if (lastAmpersandPos == std::string::npos) {
        APP_LOGI_NOFUNC("No ampersand found in the input ohmurl");
        return versionString;
    }
    // "+1" for start intercepting after the "&" character
    versionString =  ohmurl.substr(lastAmpersandPos + 1);
    return versionString;
}

void RouterMapHelper::MergeRouter(const std::vector<RouterItem>& routerArrayList,
    std::vector<RouterItem>& routerArray, const std::set<std::string>& moduleNameSet)
{
    std::map<RouterItem, std::string, RouterItemCompare> routerMap((RouterItemCompare(moduleNameSet)));

    for (const auto& item : routerArrayList) {
        routerMap.emplace(item, item.name);
    }

    std::vector<RouterItem> routerArraySorted;

    routerArraySorted.reserve(routerMap.size());
    for (const auto& pair : routerMap) {
        routerArraySorted.push_back(pair.first);
    }
    routerArray.clear();
    for (size_t i = 0; i < routerArraySorted.size(); i++) {
        if ((i == 0) || (routerArraySorted[i].name != routerArray[routerArray.size() - 1].name)) {
            routerArray.emplace_back(routerArraySorted[i]);
        }
    }
}

bool RouterMapHelper::IsRegexMatch(const std::string& str, const char* pattern)
{
    regex_t regex;
    if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) != 0) {
        APP_LOGE("regex compilation failed");
        return false;
    }
    int32_t ret = regexec(&regex, str.c_str(), 0, NULL, 0);
    if (ret == 0) {
        regfree(&regex);
        return true;
    }
    APP_LOGE("failed to perform a match");
    regfree(&regex);
    return false;
}

int32_t RouterMapHelper::CompareIdentifiers(const std::string& a, const std::string& b)
{
    bool aAlnum = IsRegexMatch(a, ALNUM_PATTERN);
    bool bAlnum = IsRegexMatch(b, ALNUM_PATTERN);
    if (!aAlnum || !bAlnum) {
        return 1;
    }
    
    bool anum = IsRegexMatch(a, NUM_PATTERN);
    bool bnum = IsRegexMatch(b, NUM_PATTERN);
    if (anum && bnum) {
        auto diff = atoi(a.c_str()) - atoi(b.c_str());
        if (diff) {
            return diff > 0 ? 1 : -1;
        }
        return 0;
    }

    if (anum && !bnum) {
        return -1;
    }
    if (bnum && !anum) {
        return 1;
    }
    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    return 0;
}

int32_t RouterMapHelper::CompareMain(const SemVer &semVer1, const SemVer &semVer2)
{
    auto res = CompareIdentifiers(semVer1.major, semVer2.major);
    if (res) {
        return res;
    }
    res = CompareIdentifiers(semVer1.minor, semVer2.minor);
    if (res) {
        return res;
    }
    return CompareIdentifiers(semVer1.patch, semVer2.patch);
}

int32_t RouterMapHelper::ComparePre(const SemVer &semVer1, const SemVer &semVer2)
{
    // NOT having a prerelease is > having one
    if (!semVer1.prerelease.empty() && semVer2.prerelease.empty()) {
        return -1;
    } else if (semVer1.prerelease.empty() && !semVer2.prerelease.empty()) {
        return 1;
    } else if (semVer1.prerelease.empty() && semVer2.prerelease.empty()) {
        return 0;
    }
    size_t i = 0;
    do {
        if ((i >= semVer1.prerelease.size()) && (i >= semVer2.prerelease.size())) {
            return 0;
        } else if (i >= semVer2.prerelease.size()) {
            return 1;
        } else if (i >= semVer1.prerelease.size()) {
            return -1;
        }
        std::string a = semVer1.prerelease[i];
        std::string b = semVer2.prerelease[i];
        if (a == b || !CompareIdentifiers(a, b)) {
            continue;
        }
        return CompareIdentifiers(a, b);
    } while (++i);
    return 0;
}

int32_t RouterMapHelper::Compare(const std::string &version1, const std::string &version2)
{
    SemVer semver1(version1);
    SemVer semver2(version2);
    return Compare(semver1, semver2);
}

int32_t RouterMapHelper::Compare(const SemVer &semVer1, const SemVer &semVer2)
{
    if (semVer1.raw == semVer2.raw) {
        return 0;
    }
    auto res = CompareMain(semVer1, semVer2);
    return res ? res : ComparePre(semVer1, semVer2);
}
} // namespace AppExecFwk
} // namespace OHOS