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

#include <cstdio>
#include <cstring>
#include <fstream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <libxml/globals.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>

#include "bundle_service_constants.h"
#include "bundle_util.h"
#ifdef CONFIG_POLOCY_ENABLE
#include "config_policy_utils.h"
#endif
#include "file_ex.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
namespace {
char g_cfgErrorName[] { "\0" };
const char* DISPLAY_MANAGER_CONFIG_PATH_DEFAULT = "/sys_prod/etc/window/resources/display_manager_config.xml";
const char* APPLIST_WHITELIST_DIR_DEFAULT = "/sys_prod/etc/user_center/";
}
}  // namespace

class BundleUtilTest : public testing::Test {
public:
    void SetUp() override
    {
        tempFile = "/data/local/tmp/orphan_nodes_info";
        std::ofstream file(tempFile);
        file << "10 20";
        file.close();
    }
    void TearDown() override
    {
        std::remove(tempFile.c_str());
    }
    bool MakeTestDisPlayManagerConfigFile(const std::string &path);
    bool MakeTestWhiteListConfigFile(const std::string &path);
    std::string tempFile;
};

bool BundleUtilTest::MakeTestDisPlayManagerConfigFile(const std::string &path)
{
    xmlDocPtr doc = xmlNewDoc(BAD_CAST("1.0"));
    xmlNodePtr root_node = xmlNewNode(nullptr, BAD_CAST("Configs"));
    xmlDocSetRootElement(doc, root_node);
    xmlNodePtr displays_node = xmlNewChild(root_node, nullptr, BAD_CAST("displays"), nullptr);
    xmlNewChild(root_node, nullptr, BAD_CAST("errorNode"), nullptr);
    xmlNodePtr errorNode = xmlNewChild(root_node, nullptr, BAD_CAST("errorNode"), nullptr);
    errorNode->type = XML_COMMENT_NODE;
    xmlNodePtr display_node = xmlNewChild(displays_node, nullptr, BAD_CAST("display"), nullptr);
    xmlNewChild(display_node, nullptr, BAD_CAST("physicalId"), BAD_CAST("1"));
    xmlNewChild(display_node, nullptr, BAD_CAST("logicalId"), BAD_CAST("1"));
    xmlNewChild(display_node, nullptr, BAD_CAST("name"), BAD_CAST("testName"));
    auto ret = xmlSaveFormatFileEnc(path.c_str(), doc, "UTF-8", 1);
    xmlFreeDoc(doc);
    if (ret == -1) {
        return false;
    } else {
        return true;
    }
}

bool BundleUtilTest::MakeTestWhiteListConfigFile(const std::string &path)
{
    xmlDocPtr doc = xmlNewDoc(BAD_CAST("1.0"));
    xmlNodePtr root_node = xmlNewNode(nullptr, BAD_CAST("AppList"));
    xmlDocSetRootElement(doc, root_node);
    xmlNodePtr allowedNode = xmlNewChild(root_node, nullptr, BAD_CAST("allowed"), nullptr);
    xmlNewProp(allowedNode, BAD_CAST("name"), BAD_CAST("com.test.test"));
    auto ret = xmlSaveFormatFileEnc(path.c_str(), doc, "UTF-8", 1);
    xmlFreeDoc(doc);
    if (ret == -1) {
        return false;
    } else {
        return true;
    }
}

/**
 * @tc.number: GetOrphanNodes_FileNotExists
 * @tc.name: test the GetOrphanNodes_FileNotExists.
 * @tc.desc: test the GetOrphanNodes_FileNotExists.
 */
HWTEST_F(BundleUtilTest, GetOrphanNodes_FileNotExists, TestSize.Level2)
{
    std::vector<int64_t> numbers;
    EXPECT_FALSE(BundleUtil::GetOrphanNodes("/notexist/file", numbers));
}

/**
 * @tc.number: GetOrphanNodes_FileEmpty
 * @tc.name: test the GetOrphanNodes_FileEmpty.
 * @tc.desc: test the GetOrphanNodes_FileEmpty.
 */
HWTEST_F(BundleUtilTest, GetOrphanNodes_FileEmpty, TestSize.Level2)
{
    std::ofstream file(tempFile);
    file.close();
    std::vector<int64_t> numbers;
    EXPECT_FALSE(BundleUtil::GetOrphanNodes(tempFile, numbers));
}

/**
 * @tc.number: GetOrphanNodes_FileTooBig
 * @tc.name: test the GetOrphanNodes_FileTooBig.
 * @tc.desc: test the GetOrphanNodes_FileTooBig.
 */
HWTEST_F(BundleUtilTest, GetOrphanNodes_FileTooBig, TestSize.Level2)
{
    std::ofstream file(tempFile);
    for (int i = 0; i < (1024 * 1024 + 1); ++i) {
        file << "1 ";
    }
    file.close();
    std::vector<int64_t> numbers;
    EXPECT_FALSE(BundleUtil::GetOrphanNodes(tempFile, numbers));
}

/**
 * @tc.number: GetOrphanNodes_FileDataInsufficient
 * @tc.name: test the GetOrphanNodes_FileDataInsufficient.
 * @tc.desc: test the GetOrphanNodes_FileDataInsufficient.
 */
HWTEST_F(BundleUtilTest, GetOrphanNodes_FileDataInsufficient, TestSize.Level2)
{
    std::ofstream file(tempFile);
    file << "10";
    file.close();
    std::vector<int64_t> numbers;
    EXPECT_FALSE(BundleUtil::GetOrphanNodes(tempFile, numbers));
}

/**
 * @tc.number: GetOrphanNodes_FileDataValid
 * @tc.name: test the GetOrphanNodes_FileDataValid.
 * @tc.desc: test the GetOrphanNodes_FileDataValid.
 */
HWTEST_F(BundleUtilTest, GetOrphanNodes_FileDataValid, TestSize.Level2)
{
    std::ofstream file(tempFile);
    file << "10 20";
    file.close();
    std::vector<int64_t> numbers;
    EXPECT_TRUE(BundleUtil::GetOrphanNodes(tempFile, numbers));
    EXPECT_EQ(numbers.size(), 2);
    EXPECT_EQ(numbers[0], 10);
    EXPECT_EQ(numbers[1], 20);
}

/**
 * @tc.number: GetWhiteListPathByDisplayNameTest
 * @tc.name: test the GetWhiteListPathByDisplayName.
 * @tc.desc: test the GetWhiteListPathByDisplayName.
 */
HWTEST_F(BundleUtilTest, GetWhiteListPathByDisplayNameTest, TestSize.Level2)
{
    std::string displayName = "displayName";
    std::string displayNameDefaultPath = std::string(APPLIST_WHITELIST_DIR_DEFAULT) + "applist"
        + std::string(ServiceConstants::UNDER_LINE) + displayName + std::string(ServiceConstants::XML_FILE_SUFFIX);
#ifdef CONFIG_POLOCY_ENABLE
    testing::NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(nullptr));
    auto path = BundleUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, displayNameDefaultPath);

    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgErrorName));
    path = BundleUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, displayNameDefaultPath);

    std::string overLengthStr(257, 'c');
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(overLengthStr.data()));
    path = BundleUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, displayNameDefaultPath);

    std::string ansStr = "abc";
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(ansStr.data()));
    path = BundleUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, ansStr);
#else
    auto path = BundleUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, displayNameDefaultPath);
#endif
}

/**
 * @tc.number: GetDisPlayManagerConfigPathTest
 * @tc.name: test the GetDisPlayManagerConfigPath.
 * @tc.desc: test the GetDisPlayManagerConfigPath.
 */
HWTEST_F(BundleUtilTest, GetDisPlayManagerConfigPathTest, TestSize.Level2)
{
#ifdef CONFIG_POLOCY_ENABLE
    testing::NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(nullptr));
    auto path = BundleUtil::GetDisPlayManagerConfigPath();
    EXPECT_EQ(path, DISPLAY_MANAGER_CONFIG_PATH_DEFAULT);

    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgErrorName));
    path = BundleUtil::GetDisPlayManagerConfigPath();
    EXPECT_EQ(path, DISPLAY_MANAGER_CONFIG_PATH_DEFAULT);

    std::string overLengthStr(257, 'c');
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(overLengthStr.data()));
    path = BundleUtil::GetDisPlayManagerConfigPath();
    EXPECT_EQ(path, DISPLAY_MANAGER_CONFIG_PATH_DEFAULT);

    std::string ansStr = "abc";
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(ansStr.data()));
    path = BundleUtil::GetDisPlayManagerConfigPath();
    EXPECT_EQ(path, ansStr);
#else
    auto path = BundleUtil::GetDisPlayManagerConfigPath();
    EXPECT_EQ(path, DISPLAY_MANAGER_CONFIG_PATH_DEFAULT);
#endif
}

/**
 * @tc.number: GetDisplaysMapFromConfigXmlTest
 * @tc.name: test the GetDisplaysMapFromConfigXml.
 * @tc.desc: test the GetDisplaysMapFromConfigXml.
 */
HWTEST_F(BundleUtilTest, GetDisplaysMapFromConfigXmlTest, TestSize.Level2)
{
#ifdef CONFIG_POLOCY_ENABLE
    std::unordered_map<std::string, uint64_t> displaysMap;
    testing::NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgErrorName));
    auto res = BundleUtil::GetDisplaysMapFromConfigXml(displaysMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(displaysMap.empty());

    std::string errorNamePath = "/data/test/ErrorName.xml";
    xmlDocPtr doc = xmlNewDoc(BAD_CAST("1.0"));
    xmlNodePtr root_node = xmlNewNode(nullptr, BAD_CAST("ErrorName"));
    xmlDocSetRootElement(doc, root_node);
    auto ret = xmlSaveFormatFileEnc(errorNamePath.c_str(), doc, "UTF-8", 1);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(errorNamePath.data()));
    res = BundleUtil::GetDisplaysMapFromConfigXml(displaysMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(displaysMap.empty());
    BundleUtil::DeleteDir(errorNamePath);

    std::string path = "/data/test/display_manager_config.xml";
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(path.data()));
    EXPECT_TRUE(MakeTestDisPlayManagerConfigFile(path));
    res = BundleUtil::GetDisplaysMapFromConfigXml(displaysMap);
    EXPECT_TRUE(res);
    EXPECT_FALSE(displaysMap.empty());
    BundleUtil::DeleteDir(path);
#else
    std::unordered_map<std::string, uint64_t> displaysMap;
    auto res = BundleUtil::GetDisplaysMapFromConfigXml(displaysMap);
    EXPECT_TRUE(res);
#endif
}

/**
 * @tc.number: PatchReadWhiteListXmlTest
 * @tc.name: test the PatchReadWhiteListXml.
 * @tc.desc: test the PatchReadWhiteListXml.
 */
HWTEST_F(BundleUtilTest, PatchReadWhiteListXmlTest, TestSize.Level2)
{
#ifdef CONFIG_POLOCY_ENABLE
    std::unordered_map<uint64_t, std::vector<std::string>> logicalIdWhiteListMap;
    testing::NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgErrorName));
    auto res = BundleUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(logicalIdWhiteListMap.empty());

    std::string emptyConfigsPath = "/data/test/EmptyConfigs.xml";
    xmlDocPtr doc = xmlNewDoc(BAD_CAST("1.0"));
    xmlNodePtr root_node = xmlNewNode(nullptr, BAD_CAST("Configs"));
    xmlDocSetRootElement(doc, root_node);
    auto ret = xmlSaveFormatFileEnc(emptyConfigsPath.c_str(), doc, "UTF-8", 1);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(emptyConfigsPath.data()));
    res = BundleUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(logicalIdWhiteListMap.empty());
    BundleUtil::DeleteDir(emptyConfigsPath);

    std::string displayConfigsPath = "/data/test/display_manager_config.xml";
    std::string whiteListPath = "/data/test/applist_testName.xml";
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile)
        .WillOnce(testing::Return(displayConfigsPath.data()))
        .WillOnce(testing::Return(whiteListPath.data()));
    EXPECT_TRUE(MakeTestDisPlayManagerConfigFile(displayConfigsPath));

    std::ofstream emptyFile(whiteListPath);
    emptyFile.close();
    res = BundleUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_TRUE(res);
    EXPECT_FALSE(logicalIdWhiteListMap.empty());
    BundleUtil::DeleteDir(whiteListPath);
    logicalIdWhiteListMap.clear();

    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile)
        .WillOnce(testing::Return(displayConfigsPath.data()))
        .WillOnce(testing::Return(whiteListPath.data()));
    doc = xmlNewDoc(BAD_CAST("1.0"));
    root_node = xmlNewNode(nullptr, BAD_CAST("ErrorName"));
    xmlDocSetRootElement(doc, root_node);
    ret = xmlSaveFormatFileEnc(whiteListPath.c_str(), doc, "UTF-8", 1);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
    res = BundleUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(logicalIdWhiteListMap.empty());
    BundleUtil::DeleteDir(whiteListPath);

    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile)
        .WillOnce(testing::Return(displayConfigsPath.data()))
        .WillOnce(testing::Return(whiteListPath.data()));
    EXPECT_TRUE(MakeTestWhiteListConfigFile(whiteListPath));
    res = BundleUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_TRUE(res);
    EXPECT_FALSE(logicalIdWhiteListMap.empty());
    BundleUtil::DeleteDir(displayConfigsPath);
    BundleUtil::DeleteDir(whiteListPath);
#else
    std::unordered_map<uint64_t, std::vector<std::string>> logicalIdWhiteListMap;
    auto res = BundleUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_FALSE(res);
#endif
}

/**
 * @tc.number: ParseStrToUllTest
 * @tc.name: test the ParseStrToUll.
 * @tc.desc: test the ParseStrToUll.
 */
HWTEST_F(BundleUtilTest, ParseStrToUllTest, TestSize.Level1)
{
    std::string input = "12345";
    uint64_t result = BundleUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 12345u);

    input = "abc123";
    result = BundleUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 0u);

    input = "123abc";
    result = BundleUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 0u);

    input = "";
    result = BundleUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 0u);

    input = "18446744073709551615";
    result = BundleUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 18446744073709551615ULL);

    input = "18446744073709551616";
    result = BundleUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 0u);

    input = " 123 ";
    result = BundleUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 0u);
}

/**
 * @tc.number: IsValidNode
 * @tc.name: test the IsValidNode.
 * @tc.desc: test the IsValidNode.
 */
HWTEST_F(BundleUtilTest, IsValidNodeTest, TestSize.Level2)
{
    xmlNode emptyNode;
    auto result = BundleUtil::IsValidNode(emptyNode);
    ASSERT_EQ(false, result);

    const xmlChar xmlStringText[] = { 't', 'e', 'x', 't', 0 };
    xmlNode node;
    node.name = xmlStringText;
    node.type = XML_TEXT_NODE;
    result = BundleUtil::IsValidNode(node);
    ASSERT_EQ(true, result);

    node.type = XML_COMMENT_NODE;
    result = BundleUtil::IsValidNode(node);
    ASSERT_EQ(false, result);
}

/**
 * @tc.number: ParseDisplaysMapTest
 * @tc.name: test the ParseDisplaysMapTest.
 * @tc.desc: test the ParseDisplaysMapTest.
 */
HWTEST_F(BundleUtilTest, ParseDisplaysMapTest, TestSize.Level2)
{
    xmlNodePtr displaysNode = xmlNewNode(nullptr, BAD_CAST("displays"));
    xmlNodePtr displayNode = xmlNewChild(displaysNode, nullptr, BAD_CAST("display"), nullptr);
    xmlNewChild(displayNode, nullptr, BAD_CAST("logicalId"), BAD_CAST("201"));
    xmlNewChild(displayNode, nullptr, BAD_CAST("name"), BAD_CAST(""));
    xmlNewChild(displayNode, nullptr, BAD_CAST("dpi"), BAD_CAST("300"));
    xmlNodePtr errorNode = xmlNewChild(displayNode, nullptr, BAD_CAST("errorNode"), BAD_CAST(""));
    errorNode->type = XML_COMMENT_NODE;
    xmlNodePtr emptyContentNode = xmlNewChild(displayNode, nullptr, BAD_CAST("emptyContentNode"), BAD_CAST(""));
    emptyContentNode->type = XML_ENTITY_NODE;
    xmlNodePtr errorDisplayNode = xmlNewChild(displaysNode, nullptr, BAD_CAST("display"), nullptr);
    errorDisplayNode->type = XML_COMMENT_NODE;

    std::unordered_map<std::string, uint64_t> displaysMap;
    BundleUtil::ParseDisplaysMap(displaysNode, displaysMap);
    ASSERT_EQ(displaysMap.size(), 1);
    xmlFree(displaysNode);
}

/**
 * @tc.number: ParseAllowedNodeConfigTest
 * @tc.name: test the ParseAllowedNodeConfigTest.
 * @tc.desc: test the ParseAllowedNodeConfigTest.
 */
HWTEST_F(BundleUtilTest, ParseAllowedNodeConfigTest, TestSize.Level2)
{
    xmlNodePtr appListNode = xmlNewNode(nullptr, BAD_CAST("AppList"));
    xmlNodePtr allowedNode = xmlNewChild(appListNode, nullptr, BAD_CAST("allowed"), nullptr);
    xmlNewProp(allowedNode, BAD_CAST("name"), BAD_CAST("testName"));
    xmlNewChild(appListNode, nullptr, BAD_CAST("allowed"), nullptr);
    xmlNewChild(appListNode, nullptr, BAD_CAST("otherNode"), nullptr);
    xmlNodePtr errorNode = xmlNewChild(appListNode, nullptr, BAD_CAST("errorNode"), BAD_CAST(""));
    errorNode->type = XML_COMMENT_NODE;

    std::vector<std::string> bundleNames;
    BundleUtil::ParseAllowedNodeConfig(appListNode, bundleNames);
    ASSERT_EQ(bundleNames.size(), 1);
    xmlFree(appListNode);
}

/**
 * @tc.number: CheckOrphanNOdeUseRateIsSufficient_Normal
 * @tc.name: test the CheckOrphanNOdeUseRateIsSufficient_Normal.
 * @tc.desc: test the CheckOrphanNOdeUseRateIsSufficient_Normal.
 */
HWTEST_F(BundleUtilTest, CheckOrphanNOdeUseRateIsSufficient_Normal, TestSize.Level2)
{
    EXPECT_TRUE(BundleUtil::CheckOrphanNodeUseRateIsSufficient());
}
} // OHOS