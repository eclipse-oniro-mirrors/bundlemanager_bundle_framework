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

#include <charconv>
#include <libxml/globals.h>
#include <libxml/xmlstring.h>

#include "app_log_wrapper.h"
#include "bundle_service_constants.h"
#ifdef CONFIG_POLOCY_ENABLE
#include "config_policy_utils.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
#ifdef CONFIG_POLOCY_ENABLE
const char* DISPLAY_MANAGER_CONFIG_PATH = "/etc/window/resources/display_manager_config.xml";
const char* APPLIST_WHITELIST_DIR = "/etc/user_center/";
#endif
const char* DISPLAY_MANAGER_CONFIG_PATH_DEFAULT = "/sys_prod/etc/window/resources/display_manager_config.xml";
const char* APPLIST_WHITELIST_DIR_DEFAULT = "/sys_prod/etc/user_center/";
}

std::recursive_mutex XmlUtil::configXmlMutex_;
std::recursive_mutex XmlUtil::whiteListXmlMutex_;

std::string XmlUtil::GetWhiteListPathByDisplayName(const std::string& displayName)
{
    std::string displayNameDefaultPath = std::string(APPLIST_WHITELIST_DIR_DEFAULT) + "applist"
        + std::string(ServiceConstants::UNDER_LINE) + displayName + std::string(ServiceConstants::XML_FILE_SUFFIX);
#ifdef CONFIG_POLOCY_ENABLE
    std::string displayNamePath = std::string(APPLIST_WHITELIST_DIR) + "applist"
        + std::string(ServiceConstants::UNDER_LINE) + displayName + std::string(ServiceConstants::XML_FILE_SUFFIX);
    char buf[MAX_PATH_LEN] = { 0 };
    char *configPath = GetOneCfgFile(displayNamePath.c_str(), buf, MAX_PATH_LEN);
    if (configPath == nullptr || configPath[0] == '\0') {
        APP_LOGE("XmlUtil GetOneCfgFile failed");
        return displayNameDefaultPath;
    }
    if (strlen(configPath) > MAX_PATH_LEN) {
        APP_LOGE("length exceeds");
        return displayNameDefaultPath;
    }
    return configPath;
#else
    return displayNameDefaultPath;
#endif
}

std::string XmlUtil::GetDisplayManagerConfigPath()
{
#ifdef CONFIG_POLOCY_ENABLE
    char buf[MAX_PATH_LEN] = { 0 };
    char *configPath = GetOneCfgFile(DISPLAY_MANAGER_CONFIG_PATH, buf, MAX_PATH_LEN);
    if (configPath == nullptr || configPath[0] == '\0') {
        APP_LOGE("XmlUtil GetOneCfgFile failed");
        return DISPLAY_MANAGER_CONFIG_PATH_DEFAULT;
    }
    if (strlen(configPath) > MAX_PATH_LEN) {
        APP_LOGE("length exceeds");
        return DISPLAY_MANAGER_CONFIG_PATH_DEFAULT;
    }
    return configPath;
#else
    return DISPLAY_MANAGER_CONFIG_PATH_DEFAULT;
#endif
}

bool XmlUtil::IsValidNode(const xmlNode& currNode)
{
    if (currNode.name == nullptr || currNode.type == XML_COMMENT_NODE) {
        return false;
    }
    return true;
}

uint64_t XmlUtil::ParseStrToUll(const std::string& contentStr)
{
    if (contentStr.empty()) {
        APP_LOGE("Invalid value: %{public}s", contentStr.c_str());
        return 0;
    }
    uint64_t num;
    auto result = std::from_chars(contentStr.data(), contentStr.data() + contentStr.size(), num);
    if (result.ptr != contentStr.data() + contentStr.size()) {
        APP_LOGE("Invalid value with trailing chars: %{public}s", contentStr.c_str());
        return 0;
    }
    if (result.ec == std::errc::invalid_argument) {
        APP_LOGE("Invalid value: %{public}s", contentStr.c_str());
        return 0;
    } else if (result.ec == std::errc::result_out_of_range) {
        APP_LOGE("Value out of range: %{public}s", contentStr.c_str());
        return 0;
    }
    return num;
}

void XmlUtil::ParseDisplaysMap(const xmlNodePtr& currNode, std::unordered_map<std::string, uint64_t> &displaysMap)
{
    APP_LOGI("start parse displays config");
    for (xmlNodePtr displayNode = currNode->xmlChildrenNode; displayNode != nullptr; displayNode = displayNode->next) {
        if (!IsValidNode(*displayNode) ||
            xmlStrcmp(displayNode->name, reinterpret_cast<const xmlChar*>("display")) != 0) {
            continue;
        }
        std::string name;
        uint64_t logicalId;
        for (xmlNodePtr fileNode = displayNode->xmlChildrenNode; fileNode != nullptr; fileNode = fileNode->next) {
            if (!IsValidNode(*fileNode)) {
                APP_LOGE("invalid node!");
                continue;
            }
            std::string nodeName = reinterpret_cast<const char*>(fileNode->name);
            xmlChar* content = xmlNodeGetContent(fileNode);
            std::string contentStr;
            if (content) {
                contentStr = reinterpret_cast<const char*>(content);
                xmlFree(content);
                content = nullptr;
            }
            if (nodeName == "logicalId") {
                logicalId = static_cast<uint64_t>(ParseStrToUll(contentStr));
            } else if (nodeName == "name") {
                name = contentStr;
            }
        }
        displaysMap[name] = logicalId;
    }
}

bool XmlUtil::GetDisplaysMapFromConfigXml(std::unordered_map<std::string, uint64_t> &displaysMap)
{
    auto configFilePath = GetDisplayManagerConfigPath();
    xmlDocPtr docPtr = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lock(configXmlMutex_);
        docPtr = xmlReadFile(configFilePath.c_str(), nullptr, XML_PARSE_NOBLANKS);
    }
    if (docPtr == nullptr) {
        APP_LOGE("load xml error!");
        return false;
    }
    xmlNodePtr rootPtr = xmlDocGetRootElement(docPtr);
    if (rootPtr == nullptr || rootPtr->name == nullptr ||
        xmlStrcmp(rootPtr->name, reinterpret_cast<const xmlChar*>("Configs")) != 0) {
        APP_LOGE("get root element failed!");
        xmlFreeDoc(docPtr);
        return false;
    }
    for (xmlNodePtr curNodePtr = rootPtr->xmlChildrenNode; curNodePtr != nullptr; curNodePtr = curNodePtr->next) {
        if (!IsValidNode(*curNodePtr)) {
            APP_LOGE("invalid node!");
            continue;
        }
        if (xmlStrcmp(curNodePtr->name, reinterpret_cast<const xmlChar*>("displays")) == 0) {
            APP_LOGI("find displays keyword, reading the nested content of XML");
            ParseDisplaysMap(curNodePtr, displaysMap);
        }
    }
    xmlFreeDoc(docPtr);
    return true;
}

bool XmlUtil::PatchReadWhiteListXml(std::unordered_map<uint64_t, std::vector<std::string>> &logicalIdWhiteListMap)
{
    std::unordered_map<std::string, uint64_t> displaysMap;
    if (!GetDisplaysMapFromConfigXml(displaysMap) || displaysMap.empty()) {
        APP_LOGE("displaysMap is empty!");
        return false;
    }
    bool isWhiteListExist = false;
    for (const auto &[displayName, logicalId] : displaysMap) {
        auto whiteListFilePath = GetWhiteListPathByDisplayName(displayName);
        xmlDocPtr docPtr = nullptr;
        {
            std::lock_guard<std::recursive_mutex> lock(whiteListXmlMutex_);
            docPtr = xmlReadFile(whiteListFilePath.c_str(), nullptr, XML_PARSE_NOBLANKS);
        }
        std::vector<std::string> bundleNames;
        if (docPtr == nullptr) {
            const xmlError *err = xmlGetLastError();
            if (err != NULL && err->domain == XML_FROM_PARSER && err->code == XML_ERR_DOCUMENT_EMPTY) {
                APP_LOGI("xml file is empty");
                logicalIdWhiteListMap.emplace(logicalId, bundleNames);
                isWhiteListExist = true;
                continue;
            }
            APP_LOGE("load xml error");
            continue;
        }
        xmlNodePtr rootPtr = xmlDocGetRootElement(docPtr);
        if (rootPtr == nullptr || rootPtr->name == nullptr ||
                xmlStrcmp(rootPtr->name, reinterpret_cast<const xmlChar*>("AppList")) != 0) {
            APP_LOGE("xml format error!");
            xmlFreeDoc(docPtr);
            continue;
        }
        ParseAllowedNodeConfig(rootPtr, bundleNames);
        logicalIdWhiteListMap.emplace(logicalId, bundleNames);
        xmlFreeDoc(docPtr);
        isWhiteListExist = true;
    }
    return isWhiteListExist;
}

void XmlUtil::ParseAllowedNodeConfig(const xmlNodePtr &rootPtr, std::vector<std::string> &bundleNames)
{
    for (xmlNodePtr curNodePtr = rootPtr->xmlChildrenNode; curNodePtr != nullptr; curNodePtr = curNodePtr->next) {
        if (!IsValidNode(*curNodePtr)) {
            APP_LOGE("invalid node!");
            continue;
        }
        std::string nodeName = reinterpret_cast<const char*>(curNodePtr->name);
        if (nodeName == "allowed") {
            xmlChar* attrValue = xmlGetProp(curNodePtr, reinterpret_cast<const xmlChar*>("name"));
            if (attrValue != nullptr) {
                std::string bundleName = reinterpret_cast<const char*>(attrValue);
                bundleNames.emplace_back(bundleName);
                xmlFree(attrValue);
                attrValue = nullptr;
            }
        }
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS