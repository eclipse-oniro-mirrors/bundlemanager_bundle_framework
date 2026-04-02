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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_XML_UTIL_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_XML_UTIL_H

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "libxml/parser.h"

namespace OHOS {
namespace AppExecFwk {
class XmlUtil {
public:
    static std::string GetWhiteListPathByDisplayName(const std::string &displayName);
    static std::string GetDisplayManagerConfigPath();
    static bool IsValidNode(const xmlNode& currNode);
    static uint64_t ParseStrToUll(const std::string &contentStr);
    static void ParseDisplaysMap(const xmlNodePtr &currNode, std::unordered_map<std::string, uint64_t> &displaysMap);
    static bool GetDisplaysMapFromConfigXml(std::unordered_map<std::string, uint64_t> &displaysMap);
    static bool PatchReadWhiteListXml(std::unordered_map<uint64_t, std::vector<std::string>> &logicalIdWhiteListMap);
    static void ParseAllowedNodeConfig(const xmlNodePtr &rootPtr, std::vector<std::string> &bundleNames);
private:
    static std::recursive_mutex configXmlMutex_;
    static std::recursive_mutex whiteListXmlMutex_;
};
} // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_XML_UTIL_H