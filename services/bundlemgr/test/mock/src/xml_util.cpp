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

#include "xml_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
}

std::string XmlUtil::GetWhiteListPathByDisplayName(const std::string& displayName)
{
    return "";
}

std::string XmlUtil::GetDisplayManagerConfigPath()
{
    return "";
}

bool XmlUtil::IsValidNode(const xmlNode& currNode)
{
    return true;
}

uint64_t XmlUtil::ParseStrToUll(const std::string& contentStr)
{
    return 0;
}

void XmlUtil::ParseDisplaysMap(const xmlNodePtr& currNode, std::unordered_map<std::string, uint64_t> &displaysMap)
{
}

bool XmlUtil::GetDisplaysMapFromConfigXml(std::unordered_map<std::string, uint64_t> &displaysMap)
{
    return true;
}

bool XmlUtil::PatchReadWhiteListXml(std::unordered_map<uint64_t, std::vector<std::string>> &logicalIdWhiteListMap)
{
    std::vector<std::string> bundleNames = {"com.test.test"};
    logicalIdWhiteListMap.emplace(1, bundleNames);
    return true;
}

void XmlUtil::ParseAllowedNodeConfig(const xmlNodePtr &rootPtr, std::vector<std::string> &bundleNames)
{
}
}  // namespace AppExecFwk
}  // namespace OHOS