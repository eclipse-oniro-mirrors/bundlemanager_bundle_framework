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
#include "elf.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
namespace {
char g_cfgErrorName[] { "\0" };
const char* DISPLAY_MANAGER_CONFIG_PATH_DEFAULT = "/sys_prod/etc/window/resources/display_manager_config.xml";
const char* APPLIST_WHITELIST_DIR_DEFAULT = "/sys_prod/etc/user_center/";
const std::string TEST_FILE_PATH = "/data/local/tmp/test_elf_file";
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
        std::remove(TEST_FILE_PATH.c_str());
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
    ConfigPolicyUtilsMock cfgPolicyUtils;
    cfgPolicyUtils.whiteListConfigPath = nullptr;
    auto path = BundleUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, displayNameDefaultPath);

    cfgPolicyUtils.whiteListConfigPath = g_cfgErrorName;
    path = BundleUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, displayNameDefaultPath);

    std::string overLengthStr(257, 'c');
    cfgPolicyUtils.whiteListConfigPath = overLengthStr.data();
    path = BundleUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, displayNameDefaultPath);

    std::string ansStr = "abc";
    cfgPolicyUtils.whiteListConfigPath = ansStr.data();
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
    ConfigPolicyUtilsMock cfgPolicyUtils;
    cfgPolicyUtils.displayManagerConfigPath = nullptr;
    auto path = BundleUtil::GetDisPlayManagerConfigPath();
    EXPECT_EQ(path, DISPLAY_MANAGER_CONFIG_PATH_DEFAULT);

    cfgPolicyUtils.displayManagerConfigPath = g_cfgErrorName;
    path = BundleUtil::GetDisPlayManagerConfigPath();
    EXPECT_EQ(path, DISPLAY_MANAGER_CONFIG_PATH_DEFAULT);

    std::string overLengthStr(257, 'c');
    cfgPolicyUtils.displayManagerConfigPath = overLengthStr.data();
    path = BundleUtil::GetDisPlayManagerConfigPath();
    EXPECT_EQ(path, DISPLAY_MANAGER_CONFIG_PATH_DEFAULT);

    std::string ansStr = "abc";
    cfgPolicyUtils.displayManagerConfigPath = ansStr.data();
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
    std::string errorNamePath = "/data/test/ErrorName.xml";
    ConfigPolicyUtilsMock cfgPolicyUtils;
    cfgPolicyUtils.displayManagerConfigPath = errorNamePath.data();
    std::unordered_map<std::string, uint64_t> displaysMap;
    auto res = BundleUtil::GetDisplaysMapFromConfigXml(displaysMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(displaysMap.empty());

    xmlDocPtr doc = xmlNewDoc(BAD_CAST("1.0"));
    xmlNodePtr root_node = xmlNewNode(nullptr, BAD_CAST("ErrorName"));
    xmlDocSetRootElement(doc, root_node);
    auto ret = xmlSaveFormatFileEnc(errorNamePath.c_str(), doc, "UTF-8", 1);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
    res = BundleUtil::GetDisplaysMapFromConfigXml(displaysMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(displaysMap.empty());
    BundleUtil::DeleteDir(errorNamePath);

    std::string path = "/data/test/display_manager_config.xml";
    cfgPolicyUtils.displayManagerConfigPath = path.data();
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
 * @tc.number: PatchReadWhiteListXmlTest_0001
 * @tc.name: test the PatchReadWhiteListXml.
 * @tc.desc: test the PatchReadWhiteListXml.
 */
HWTEST_F(BundleUtilTest, PatchReadWhiteListXmlTest_0001, TestSize.Level2)
{
#ifdef CONFIG_POLOCY_ENABLE
    std::unordered_map<uint64_t, std::vector<std::string>> logicalIdWhiteListMap;
    ConfigPolicyUtilsMock cfgPolicyUtils;
    std::string emptyConfigsPath = "/data/test/EmptyConfigs.xml";
    cfgPolicyUtils.whiteListConfigPath = emptyConfigsPath.data();
    auto res = BundleUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(logicalIdWhiteListMap.empty());

    xmlDocPtr doc = xmlNewDoc(BAD_CAST("1.0"));
    xmlNodePtr root_node = xmlNewNode(nullptr, BAD_CAST("Configs"));
    xmlDocSetRootElement(doc, root_node);
    auto ret = xmlSaveFormatFileEnc(emptyConfigsPath.c_str(), doc, "UTF-8", 1);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
    res = BundleUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(logicalIdWhiteListMap.empty());
    BundleUtil::DeleteDir(emptyConfigsPath);
#else
    std::unordered_map<uint64_t, std::vector<std::string>> logicalIdWhiteListMap;
    auto res = BundleUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_FALSE(res);
#endif
}

/**
 * @tc.number: PatchReadWhiteListXmlTest_0002
 * @tc.name: test the PatchReadWhiteListXml.
 * @tc.desc: test the PatchReadWhiteListXml.
 */
HWTEST_F(BundleUtilTest, PatchReadWhiteListXmlTest_0002, TestSize.Level2)
{
#ifdef CONFIG_POLOCY_ENABLE
    std::unordered_map<uint64_t, std::vector<std::string>> logicalIdWhiteListMap;
    ConfigPolicyUtilsMock cfgPolicyUtils;

    std::string displayConfigsPath = "/data/test/display_manager_config.xml";
    std::string whiteListPath = "/data/test/applist_testName.xml";
    cfgPolicyUtils.displayManagerConfigPath = displayConfigsPath.data();
    cfgPolicyUtils.whiteListConfigPath = whiteListPath.data();
    EXPECT_TRUE(MakeTestDisPlayManagerConfigFile(displayConfigsPath));
    std::ofstream emptyFile(whiteListPath);
    emptyFile.close();
    auto res = BundleUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_TRUE(res);
    EXPECT_FALSE(logicalIdWhiteListMap.empty());
    BundleUtil::DeleteDir(whiteListPath);
    logicalIdWhiteListMap.clear();

    xmlDocPtr doc = xmlNewDoc(BAD_CAST("1.0"));
    xmlNodePtr root_node = xmlNewNode(nullptr, BAD_CAST("ErrorName"));
    xmlDocSetRootElement(doc, root_node);
    auto ret = xmlSaveFormatFileEnc(whiteListPath.c_str(), doc, "UTF-8", 1);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
    res = BundleUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(logicalIdWhiteListMap.empty());
    BundleUtil::DeleteDir(whiteListPath);

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
    xmlFreeNode(displaysNode);
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
    xmlFreeNode(appListNode);
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

/**
 * @tc.number: IsExecutableBinaryFile_001
 * @tc.name: test IsExecutableBinaryFile with empty file
 * @tc.desc: 1. file is empty
 *           2. return false
 */
HWTEST_F(BundleUtilTest, IsExecutableBinaryFile_001, TestSize.Level2)
{
    std::ofstream file(TEST_FILE_PATH);
    file.close();
    EXPECT_FALSE(BundleUtil::IsExecutableBinaryFile(TEST_FILE_PATH));
}

/**
 * @tc.number: IsExecutableBinaryFile_002
 * @tc.name: test IsExecutableBinaryFile with non-ELF file
 * @tc.desc: 1. file content is not ELF format
 *           2. return false
 */
HWTEST_F(BundleUtilTest, IsExecutableBinaryFile_002, TestSize.Level2)
{
    std::ofstream file(TEST_FILE_PATH, std::ios::binary);
    const char *data = "Not an ELF file content";
    file.write(data, strlen(data));
    file.close();
    EXPECT_FALSE(BundleUtil::IsExecutableBinaryFile(TEST_FILE_PATH));
}

/**
 * @tc.number: IsExecutableBinaryFile_003
 * @tc.name: test IsExecutableBinaryFile with invalid ELF class
 * @tc.desc: 1. ELF magic is correct but class is invalid
 *           2. return false
 */
HWTEST_F(BundleUtilTest, IsExecutableBinaryFile_003, TestSize.Level2)
{
    std::ofstream file(TEST_FILE_PATH, std::ios::binary);
    unsigned char data[EI_NIDENT] = {0};
    data[EI_MAG0] = ELFMAG0;
    data[EI_MAG1] = ELFMAG1;
    data[EI_MAG2] = ELFMAG2;
    data[EI_MAG3] = ELFMAG3;
    data[EI_CLASS] = 0;
    file.write(reinterpret_cast<char*>(data), sizeof(data));
    file.close();
    EXPECT_FALSE(BundleUtil::IsExecutableBinaryFile(TEST_FILE_PATH));
}

/**
 * @tc.number: IsExecutableBinaryFile_004
 * @tc.name: test IsExecutableBinaryFile with ELF64 shared library
 * @tc.desc: 1. ELF64 file with ET_DYN type and e_entry=0
 *           2. return false (not executable)
 */
HWTEST_F(BundleUtilTest, IsExecutableBinaryFile_004, TestSize.Level2)
{
    std::ofstream file(TEST_FILE_PATH, std::ios::binary);
    Elf64_Ehdr ehdr = {};
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_type = ET_DYN;
    ehdr.e_entry = 0;
    file.write(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    file.close();
    EXPECT_FALSE(BundleUtil::IsExecutableBinaryFile(TEST_FILE_PATH));
}

/**
 * @tc.number: IsExecutableBinaryFile_005
 * @tc.name: test IsExecutableBinaryFile with ELF64 executable
 * @tc.desc: 1. ELF64 file with ET_EXEC type
 *           2. return true
 */
HWTEST_F(BundleUtilTest, IsExecutableBinaryFile_005, TestSize.Level2)
{
    std::ofstream file(TEST_FILE_PATH, std::ios::binary);
    Elf64_Ehdr ehdr = {};
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_type = ET_EXEC;
    ehdr.e_entry = 0x1000;
    file.write(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    file.close();
    EXPECT_TRUE(BundleUtil::IsExecutableBinaryFile(TEST_FILE_PATH));
}

/**
 * @tc.number: IsExecutableBinaryFile_006
 * @tc.name: test IsExecutableBinaryFile with ELF64 PIE executable
 * @tc.desc: 1. ELF64 file with ET_DYN type and e_entry!=0
 *           2. return true
 */
HWTEST_F(BundleUtilTest, IsExecutableBinaryFile_006, TestSize.Level2)
{
    std::ofstream file(TEST_FILE_PATH, std::ios::binary);
    Elf64_Ehdr ehdr = {};
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_type = ET_DYN;
    ehdr.e_entry = 0x1000;
    file.write(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    file.close();
    EXPECT_TRUE(BundleUtil::IsExecutableBinaryFile(TEST_FILE_PATH));
}

/**
 * @tc.number: IsExecutableBinaryFile_007
 * @tc.name: test IsExecutableBinaryFile with ELF32 executable
 * @tc.desc: 1. ELF32 file with ET_EXEC type
 *           2. return true
 */
HWTEST_F(BundleUtilTest, IsExecutableBinaryFile_007, TestSize.Level2)
{
    std::ofstream file(TEST_FILE_PATH, std::ios::binary);
    Elf32_Ehdr ehdr = {};
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS32;
    ehdr.e_type = ET_EXEC;
    ehdr.e_entry = 0x1000;
    file.write(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    file.close();
    EXPECT_TRUE(BundleUtil::IsExecutableBinaryFile(TEST_FILE_PATH));
}

/**
 * @tc.number: IsExecutableBinaryFile_008
 * @tc.name: test IsExecutableBinaryFile with ELF32 PIE executable
 * @tc.desc: 1. ELF32 file with ET_DYN type and e_entry!=0
 *           2. return true
 */
HWTEST_F(BundleUtilTest, IsExecutableBinaryFile_008, TestSize.Level2)
{
    std::ofstream file(TEST_FILE_PATH, std::ios::binary);
    Elf32_Ehdr ehdr = {};
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS32;
    ehdr.e_type = ET_DYN;
    ehdr.e_entry = 0x1000;
    file.write(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    file.close();
    EXPECT_TRUE(BundleUtil::IsExecutableBinaryFile(TEST_FILE_PATH));
}
} // OHOS