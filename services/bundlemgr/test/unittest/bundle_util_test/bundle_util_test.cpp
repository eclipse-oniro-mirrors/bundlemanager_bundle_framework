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
#define private public
#include "histogram_util.h"
#undef private
#include "xml_util.h"

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

static const unsigned char TEST_ZIP_DATA[] = {
    0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x5b, 0xb0, 0x5c, 0xfd, 0x04,
    0xc6, 0x54, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x66, 0x69,
    0x6c, 0x65, 0x31, 0x2e, 0x68, 0x61, 0x70, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x68,
    0x61, 0x70, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x50, 0x4b, 0x03, 0x04, 0x14, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x76, 0x5b, 0xb0, 0x5c, 0x28, 0x55, 0x9d, 0x77, 0x13, 0x00, 0x00, 0x00,
    0x13, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x66, 0x69, 0x6c, 0x65, 0x32, 0x2e, 0x68, 0x73,
    0x70, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x68, 0x73, 0x70, 0x20, 0x63, 0x6f, 0x6e,
    0x74, 0x65, 0x6e, 0x74, 0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x5b,
    0xb0, 0x5c, 0xdf, 0xa9, 0x7d, 0x76, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x09, 0x00,
    0x00, 0x00, 0x66, 0x69, 0x6c, 0x65, 0x33, 0x2e, 0x74, 0x78, 0x74, 0x74, 0x68, 0x69, 0x73, 0x20,
    0x69, 0x73, 0x20, 0x74, 0x78, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x50, 0x4b,
    0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x5b, 0xb0, 0x5c, 0xcb, 0xef, 0xd8, 0x07,
    0x11, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x70, 0x61, 0x63, 0x6b,
    0x2e, 0x69, 0x6e, 0x66, 0x6f, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x70, 0x61, 0x63,
    0x6b, 0x20, 0x69, 0x6e, 0x66, 0x6f, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x76, 0x5b, 0xb0, 0x5c, 0xfd, 0x04, 0xc6, 0x54, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00,
    0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x66, 0x69, 0x6c, 0x65, 0x31, 0x2e, 0x68, 0x61, 0x70, 0x50, 0x4b, 0x01,
    0x02, 0x14, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x5b, 0xb0, 0x5c, 0x28, 0x55, 0x9d,
    0x77, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x3a, 0x00, 0x00, 0x00, 0x66, 0x69, 0x6c, 0x65, 0x32,
    0x2e, 0x68, 0x73, 0x70, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x76, 0x5b, 0xb0, 0x5c, 0xdf, 0xa9, 0x7d, 0x76, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x74, 0x00,
    0x00, 0x00, 0x66, 0x69, 0x6c, 0x65, 0x33, 0x2e, 0x74, 0x78, 0x74, 0x50, 0x4b, 0x01, 0x02, 0x14,
    0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x5b, 0xb0, 0x5c, 0xcb, 0xef, 0xd8, 0x07, 0x11,
    0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x80, 0x01, 0xae, 0x00, 0x00, 0x00, 0x70, 0x61, 0x63, 0x6b, 0x2e, 0x69, 0x6e,
    0x66, 0x6f, 0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0xdc, 0x00,
    0x00, 0x00, 0xe6, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const size_t TEST_ZIP_DATA_LEN = sizeof(TEST_ZIP_DATA);

static const unsigned char TEST_EMPTY_ZIP_DATA[] = {
    0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const size_t TEST_EMPTY_ZIP_DATA_LEN = sizeof(TEST_EMPTY_ZIP_DATA);

static const unsigned char TEST_SUBDIR_ZIP_DATA[] = {
    0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x5b, 0xb0, 0x5c, 0xfd, 0x04,
    0xc6, 0x54, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x75,
    0x62, 0x64, 0x69, 0x72, 0x2f, 0x66, 0x69, 0x6c, 0x65, 0x31, 0x2e, 0x68, 0x61, 0x70, 0x74, 0x68,
    0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x68, 0x61, 0x70, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
    0x74, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x5b, 0xb0,
    0x5c, 0xfd, 0x04, 0xc6, 0x54, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x73,
    0x75, 0x62, 0x64, 0x69, 0x72, 0x2f, 0x66, 0x69, 0x6c, 0x65, 0x31, 0x2e, 0x68, 0x61, 0x70, 0x50,
    0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x41,
    0x00, 0x00, 0x00, 0x00, 0x00,
};
static const size_t TEST_SUBDIR_ZIP_DATA_LEN = sizeof(TEST_SUBDIR_ZIP_DATA);

static bool WriteEmbeddedFile(const std::string &path, const unsigned char *data, size_t len)
{
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) {
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    return ofs.good();
}

static const std::string TEST_APP_FILE_PATH = "/data/local/tmp/test_valid.app";
static const std::string TEST_ZIP_FILE_PATH = "/data/local/tmp/test_util.zip";
static const std::string TEST_OUT_DIR_PATH = "/data/local/tmp/test_util_out";

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
    auto path = XmlUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, displayNameDefaultPath);

    cfgPolicyUtils.whiteListConfigPath = g_cfgErrorName;
    path = XmlUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, displayNameDefaultPath);

    std::string overLengthStr(257, 'c');
    cfgPolicyUtils.whiteListConfigPath = overLengthStr.data();
    path = XmlUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, displayNameDefaultPath);

    std::string ansStr = "abc";
    cfgPolicyUtils.whiteListConfigPath = ansStr.data();
    path = XmlUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, ansStr);
#else
    auto path = XmlUtil::GetWhiteListPathByDisplayName(displayName);
    EXPECT_EQ(path, displayNameDefaultPath);
#endif
}

/**
 * @tc.number: GetDisplayManagerConfigPathTest
 * @tc.name: test the GetDisplayManagerConfigPath.
 * @tc.desc: test the GetDisplayManagerConfigPath.
 */
HWTEST_F(BundleUtilTest, GetDisplayManagerConfigPathTest, TestSize.Level2)
{
#ifdef CONFIG_POLOCY_ENABLE
    ConfigPolicyUtilsMock cfgPolicyUtils;
    cfgPolicyUtils.displayManagerConfigPath = nullptr;
    auto path = XmlUtil::GetDisplayManagerConfigPath();
    EXPECT_EQ(path, DISPLAY_MANAGER_CONFIG_PATH_DEFAULT);

    cfgPolicyUtils.displayManagerConfigPath = g_cfgErrorName;
    path = XmlUtil::GetDisplayManagerConfigPath();
    EXPECT_EQ(path, DISPLAY_MANAGER_CONFIG_PATH_DEFAULT);

    std::string overLengthStr(257, 'c');
    cfgPolicyUtils.displayManagerConfigPath = overLengthStr.data();
    path = XmlUtil::GetDisplayManagerConfigPath();
    EXPECT_EQ(path, DISPLAY_MANAGER_CONFIG_PATH_DEFAULT);

    std::string ansStr = "abc";
    cfgPolicyUtils.displayManagerConfigPath = ansStr.data();
    path = XmlUtil::GetDisplayManagerConfigPath();
    EXPECT_EQ(path, ansStr);
#else
    auto path = XmlUtil::GetDisplayManagerConfigPath();
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
    auto res = XmlUtil::GetDisplaysMapFromConfigXml(displaysMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(displaysMap.empty());

    xmlDocPtr doc = xmlNewDoc(BAD_CAST("1.0"));
    xmlNodePtr root_node = xmlNewNode(nullptr, BAD_CAST("ErrorName"));
    xmlDocSetRootElement(doc, root_node);
    auto ret = xmlSaveFormatFileEnc(errorNamePath.c_str(), doc, "UTF-8", 1);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
    res = XmlUtil::GetDisplaysMapFromConfigXml(displaysMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(displaysMap.empty());
    BundleUtil::DeleteDir(errorNamePath);

    std::string path = "/data/test/display_manager_config.xml";
    cfgPolicyUtils.displayManagerConfigPath = path.data();
    EXPECT_TRUE(MakeTestDisPlayManagerConfigFile(path));
    res = XmlUtil::GetDisplaysMapFromConfigXml(displaysMap);
    EXPECT_TRUE(res);
    EXPECT_FALSE(displaysMap.empty());
    BundleUtil::DeleteDir(path);
#else
    std::unordered_map<std::string, uint64_t> displaysMap;
    auto res = XmlUtil::GetDisplaysMapFromConfigXml(displaysMap);
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
    auto res = XmlUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(logicalIdWhiteListMap.empty());

    xmlDocPtr doc = xmlNewDoc(BAD_CAST("1.0"));
    xmlNodePtr root_node = xmlNewNode(nullptr, BAD_CAST("Configs"));
    xmlDocSetRootElement(doc, root_node);
    auto ret = xmlSaveFormatFileEnc(emptyConfigsPath.c_str(), doc, "UTF-8", 1);
    xmlFreeDoc(doc);
    EXPECT_TRUE(ret);
    res = XmlUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(logicalIdWhiteListMap.empty());
    BundleUtil::DeleteDir(emptyConfigsPath);
#else
    std::unordered_map<uint64_t, std::vector<std::string>> logicalIdWhiteListMap;
    auto res = XmlUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
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
    auto res = XmlUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
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
    res = XmlUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_FALSE(res);
    EXPECT_TRUE(logicalIdWhiteListMap.empty());
    BundleUtil::DeleteDir(whiteListPath);

    EXPECT_TRUE(MakeTestWhiteListConfigFile(whiteListPath));
    res = XmlUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    EXPECT_TRUE(res);
    EXPECT_FALSE(logicalIdWhiteListMap.empty());
    BundleUtil::DeleteDir(displayConfigsPath);
    BundleUtil::DeleteDir(whiteListPath);
#else
    std::unordered_map<uint64_t, std::vector<std::string>> logicalIdWhiteListMap;
    auto res = XmlUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
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
    uint64_t result = XmlUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 12345u);

    input = "abc123";
    result = XmlUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 0u);

    input = "123abc";
    result = XmlUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 0u);

    input = "";
    result = XmlUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 0u);

    input = "18446744073709551615";
    result = XmlUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 18446744073709551615ULL);

    input = "18446744073709551616";
    result = XmlUtil::ParseStrToUll(input);
    EXPECT_EQ(result, 0u);

    input = " 123 ";
    result = XmlUtil::ParseStrToUll(input);
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
    auto result = XmlUtil::IsValidNode(emptyNode);
    ASSERT_EQ(false, result);

    const xmlChar xmlStringText[] = { 't', 'e', 'x', 't', 0 };
    xmlNode node;
    node.name = xmlStringText;
    node.type = XML_TEXT_NODE;
    result = XmlUtil::IsValidNode(node);
    ASSERT_EQ(true, result);

    node.type = XML_COMMENT_NODE;
    result = XmlUtil::IsValidNode(node);
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
    XmlUtil::ParseDisplaysMap(displaysNode, displaysMap);
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
    XmlUtil::ParseAllowedNodeConfig(appListNode, bundleNames);
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

/**
 * @tc.number: CheckAppFilePath_001
 * @tc.name: test CheckAppFilePath with empty path
 * @tc.desc: 1. path is empty
 *           2. return ERR_APPEXECFWK_INSTALL_FILE_PATH_EMPTY
 */
HWTEST_F(BundleUtilTest, CheckAppFilePath_001, TestSize.Level2)
{
    std::string realPath;
    auto ret = BundleUtil::CheckAppFilePath("", realPath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_EMPTY);
}

/**
 * @tc.number: CheckAppFilePath_002
 * @tc.name: test CheckAppFilePath with too long path
 * @tc.desc: 1. path length exceeds PATH_MAX_SIZE
 *           2. return ERR_APPEXECFWK_INSTALL_INVALID_FILE_NAME_SIZE
 */
HWTEST_F(BundleUtilTest, CheckAppFilePath_002, TestSize.Level2)
{
    std::string longPath(ServiceConstants::PATH_MAX_SIZE + 1, 'a');
    longPath += ".app";
    std::string realPath;
    auto ret = BundleUtil::CheckAppFilePath(longPath, realPath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INVALID_FILE_NAME_SIZE);
}

/**
 * @tc.number: CheckAppFilePath_003
 * @tc.name: test CheckAppFilePath with non-app file
 * @tc.desc: 1. file suffix is not .app
 *           2. return ERR_APPEXECFWK_INSTALL_INVALID_HAP_NAME
 */
HWTEST_F(BundleUtilTest, CheckAppFilePath_003, TestSize.Level2)
{
    std::string realPath;
    auto ret = BundleUtil::CheckAppFilePath("/data/local/tmp/test.hap", realPath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INVALID_HAP_NAME);
}

/**
 * @tc.number: CheckAppFilePath_004
 * @tc.name: test CheckAppFilePath with invalid real path
 * @tc.desc: 1. file does not exist
 *           2. return ERR_APPEXECFWK_INSTALL_FILE_PATH_IS_NOT_REAL
 */
HWTEST_F(BundleUtilTest, CheckAppFilePath_004, TestSize.Level2)
{
    std::string realPath;
    auto ret = BundleUtil::CheckAppFilePath("/data/local/tmp/not_exist_file.app", realPath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_IS_NOT_REAL);
}

/**
 * @tc.number: CheckAppFilePath_005
 * @tc.name: test CheckAppFilePath with valid app file
 * @tc.desc: 1. file exists and is valid .app
 *           2. return ERR_OK and real path
 */
HWTEST_F(BundleUtilTest, CheckAppFilePath_005, TestSize.Level2)
{
    EXPECT_TRUE(WriteEmbeddedFile(TEST_APP_FILE_PATH, TEST_ZIP_DATA, TEST_ZIP_DATA_LEN));
    std::string realPath;
    auto ret = BundleUtil::CheckAppFilePath(TEST_APP_FILE_PATH, realPath);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(realPath.empty());
    std::remove(TEST_APP_FILE_PATH.c_str());
}

/**
 * @tc.number: DecompressToFile_001
 * @tc.name: test DecompressToFile with mkdir failure
 * @tc.desc: 1. output directory parent does not exist
 *           2. return false
 */
HWTEST_F(BundleUtilTest, DecompressToFile_001, TestSize.Level2)
{
    EXPECT_TRUE(WriteEmbeddedFile(TEST_ZIP_FILE_PATH, TEST_ZIP_DATA, TEST_ZIP_DATA_LEN));
    std::vector<std::string> filePaths;
    bool ret = BundleUtil::DecompressToFile(TEST_ZIP_FILE_PATH, "/nonexistent_dir_12345/output", filePaths);
    EXPECT_FALSE(ret);
    std::remove(TEST_ZIP_FILE_PATH.c_str());
}

/**
 * @tc.number: DecompressToFile_002
 * @tc.name: test DecompressToFile with invalid zip file
 * @tc.desc: 1. zip file is not a valid zip
 *           2. return false
 */
HWTEST_F(BundleUtilTest, DecompressToFile_002, TestSize.Level2)
{
    const std::string invalidZip = "/data/local/tmp/test_invalid.zip";
    std::ofstream ofs(invalidZip);
    ofs << "this is not a zip file";
    ofs.close();

    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
    std::vector<std::string> filePaths;
    bool ret = BundleUtil::DecompressToFile(invalidZip, TEST_OUT_DIR_PATH, filePaths);
    EXPECT_FALSE(ret);
    std::remove(invalidZip.c_str());
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
}

/**
 * @tc.number: DecompressToFile_003
 * @tc.name: test DecompressToFile with empty zip
 * @tc.desc: 1. zip file has no entries
 *           2. return true and empty filePaths
 */
HWTEST_F(BundleUtilTest, DecompressToFile_003, TestSize.Level2)
{
    const std::string emptyZipPath = "/data/local/tmp/test_empty.zip";
    EXPECT_TRUE(WriteEmbeddedFile(emptyZipPath, TEST_EMPTY_ZIP_DATA, TEST_EMPTY_ZIP_DATA_LEN));
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
    std::vector<std::string> filePaths;
    bool ret = BundleUtil::DecompressToFile(emptyZipPath, TEST_OUT_DIR_PATH, filePaths);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(filePaths.empty());
    std::remove(emptyZipPath.c_str());
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
}

/**
 * @tc.number: DecompressToFile_004
 * @tc.name: test DecompressToFile with valid zip and no filter
 * @tc.desc: 1. zip contains hap, hsp, txt, pack.info
 *           2. return true and collect all files except pack.info
 */
HWTEST_F(BundleUtilTest, DecompressToFile_004, TestSize.Level2)
{
    EXPECT_TRUE(WriteEmbeddedFile(TEST_ZIP_FILE_PATH, TEST_ZIP_DATA, TEST_ZIP_DATA_LEN));
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
    std::vector<std::string> filePaths;
    bool ret = BundleUtil::DecompressToFile(TEST_ZIP_FILE_PATH, TEST_OUT_DIR_PATH, filePaths);
    EXPECT_TRUE(ret);
    EXPECT_EQ(filePaths.size(), 3);
    std::remove(TEST_ZIP_FILE_PATH.c_str());
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
}

/**
 * @tc.number: DecompressToFile_005
 * @tc.name: test DecompressToFile with valid zip and filter suffixes
 * @tc.desc: 1. zip contains hap, hsp, txt
 *           2. filter by .hap and .hsp
 *           3. return true and only collect matching files
 */
HWTEST_F(BundleUtilTest, DecompressToFile_005, TestSize.Level2)
{
    EXPECT_TRUE(WriteEmbeddedFile(TEST_ZIP_FILE_PATH, TEST_ZIP_DATA, TEST_ZIP_DATA_LEN));
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
    std::vector<std::string> filePaths;
    std::vector<std::string> filters = { ".hap", ".hsp" };
    bool ret = BundleUtil::DecompressToFile(TEST_ZIP_FILE_PATH, TEST_OUT_DIR_PATH, filePaths, filters);
    EXPECT_TRUE(ret);
    EXPECT_EQ(filePaths.size(), 2);
    std::remove(TEST_ZIP_FILE_PATH.c_str());
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
}

/**
 * @tc.number: DecompressToFile_006
 * @tc.name: test DecompressToFile with zip containing subdir path
 * @tc.desc: 1. zip entry contains subdir/file.hap
 *           2. fopen fails because subdir does not exist
 *           3. return false
 */
HWTEST_F(BundleUtilTest, DecompressToFile_006, TestSize.Level2)
{
    const std::string subdirZipPath = "/data/local/tmp/test_subdir.zip";
    EXPECT_TRUE(WriteEmbeddedFile(subdirZipPath, TEST_SUBDIR_ZIP_DATA, TEST_SUBDIR_ZIP_DATA_LEN));
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
    std::vector<std::string> filePaths;
    bool ret = BundleUtil::DecompressToFile(subdirZipPath, TEST_OUT_DIR_PATH, filePaths);
    EXPECT_FALSE(ret);
    std::remove(subdirZipPath.c_str());
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
}

/**
 * @tc.number: DecompressToFile_007
 * @tc.name: test DecompressToFile with illegal path in zip
 * @tc.desc: 1. zip entry contains ../test.hap
 *           2. IsValidFileName should return false
 *           3. return false
 */
HWTEST_F(BundleUtilTest, DecompressToFile_007, TestSize.Level2)
{
    const std::string illegalPathZip = "/data/local/tmp/test_illegal_path.zip";
    static const unsigned char illegalPathZipData[] = {
        // Local file header (30 bytes)
        0x50, 0x4b, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00,
        0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
        // Filename: ../test.hap (11 bytes)
        0x2e, 0x2e, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x68, 0x61, 0x70,
        // Data: hello (5 bytes)
        0x68, 0x65, 0x6c, 0x6c, 0x6f,
        // Central directory header (46 bytes)
        0x50, 0x4b, 0x01, 0x02, 0x14, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Filename: ../test.hap (11 bytes)
        0x2e, 0x2e, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x68, 0x61, 0x70,
        // End of central directory (22 bytes)
        0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x39, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    EXPECT_TRUE(WriteEmbeddedFile(illegalPathZip, illegalPathZipData, sizeof(illegalPathZipData)));
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
    std::vector<std::string> filePaths;
    bool ret = BundleUtil::DecompressToFile(illegalPathZip, TEST_OUT_DIR_PATH, filePaths);
    EXPECT_FALSE(ret);
    std::remove(illegalPathZip.c_str());
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
}

/**
 * @tc.number: DecompressToFile_008
 * @tc.name: test DecompressToFile with corrupted zip global info
 * @tc.desc: 1. zip file has valid signatures but no valid central directory
 *           2. return false
 */
HWTEST_F(BundleUtilTest, DecompressToFile_008, TestSize.Level2)
{
    const std::string badGlobalZip = "/data/local/tmp/test_bad_global.zip";
    static const unsigned char badGlobalZipData[] = {
        // Local file header
        0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00,
        0x00, 0x00, 0x61, 0x2e, 0x68, 0x61, 0x70, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
        // EOCD: 1 entry, cd_size=0, cd_offset=0
        0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    EXPECT_TRUE(WriteEmbeddedFile(badGlobalZip, badGlobalZipData, sizeof(badGlobalZipData)));
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
    std::vector<std::string> filePaths;
    bool ret = BundleUtil::DecompressToFile(badGlobalZip, TEST_OUT_DIR_PATH, filePaths);
    EXPECT_FALSE(ret);
    std::remove(badGlobalZip.c_str());
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
}

/**
 * @tc.number: DecompressToFile_009
 * @tc.name: test DecompressToFile with zip triggering unzGoToNextFile failure
 * @tc.desc: 1. zip file claims 2 entries but only has 1 central directory entry
 *           2. unzGoToNextFile should fail, return false
 */
HWTEST_F(BundleUtilTest, DecompressToFile_009, TestSize.Level2)
{
    const std::string badNextZip = "/data/local/tmp/test_bad_next.zip";
    static const unsigned char badNextZipData[] = {
        // Local file header (40 bytes total)
        0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00,
        0x00, 0x00, 0x61, 0x2e, 0x68, 0x61, 0x70, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
        // Central directory entry 1 (51 bytes)
        0x50, 0x4b, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x61, 0x2e, 0x68, 0x61, 0x70,
        // EOCD: claims 2 entries, cd_size=51 (0x33), cd_offset=40 (0x28)
        0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00,
        0x33, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    EXPECT_TRUE(WriteEmbeddedFile(badNextZip, badNextZipData, sizeof(badNextZipData)));
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
    std::vector<std::string> filePaths;
    bool ret = BundleUtil::DecompressToFile(badNextZip, TEST_OUT_DIR_PATH, filePaths);
    EXPECT_FALSE(ret);
    std::remove(badNextZip.c_str());
    BundleUtil::DeleteDir(TEST_OUT_DIR_PATH);
}

/**
 * @tc.number: HistogramUtilTest_0010
 * @tc.name: test HistogramUtil::ConvertErrorCodeToHistogramEnumeration
 * @tc.desc: 1. test common error code
 *           2. test error code need to be converted
 */
HWTEST_F(BundleUtilTest, HistogramUtilTest_0010, TestSize.Level2)
{
    int32_t errorCode = static_cast<int32_t>(CommonErrorType::OPERATION_FAILED);
    HistogramUtil::ConvertErrorCodeToHistogramEnumeration(errorCode);
    EXPECT_EQ(errorCode, static_cast<int32_t>(CommonErrorType::OPERATION_FAILED));
    errorCode = 801;
    HistogramUtil::ConvertErrorCodeToHistogramEnumeration(errorCode);
    EXPECT_EQ(errorCode, static_cast<int32_t>(CommonErrorType::UNSUPPORTED_FEATURE_ERRCODE));
    errorCode = -1;
    HistogramUtil::ConvertErrorCodeToHistogramEnumeration(errorCode);
    EXPECT_EQ(errorCode, static_cast<int32_t>(CommonErrorType::OPERATION_FAILED));
}
} // OHOS