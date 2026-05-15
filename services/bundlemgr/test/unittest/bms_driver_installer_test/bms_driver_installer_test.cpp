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

#define private public
#include <gtest/gtest.h>
#include "driver/driver_installer.h"
#include "inner_bundle_info.h"
#include "extension_ability_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class BmsDriverInstallerTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

// === CreateDriverSoDestinedDir ===

TEST_F(BmsDriverInstallerTest, CreateDriverSoDestinedDir_EmptyBundleName)
{
    DriverInstaller installer;
    std::string result = installer.CreateDriverSoDestinedDir("", "module", "file", "/dest", false);
    EXPECT_TRUE(result.empty());
}

TEST_F(BmsDriverInstallerTest, CreateDriverSoDestinedDir_EmptyModuleName)
{
    DriverInstaller installer;
    std::string result = installer.CreateDriverSoDestinedDir("bundle", "", "file", "/dest", false);
    EXPECT_TRUE(result.empty());
}

TEST_F(BmsDriverInstallerTest, CreateDriverSoDestinedDir_EmptyFileName)
{
    DriverInstaller installer;
    std::string result = installer.CreateDriverSoDestinedDir("bundle", "module", "", "/dest", false);
    EXPECT_TRUE(result.empty());
}

TEST_F(BmsDriverInstallerTest, CreateDriverSoDestinedDir_EmptyDestinedDir)
{
    DriverInstaller installer;
    std::string result = installer.CreateDriverSoDestinedDir("bundle", "module", "file", "", false);
    EXPECT_TRUE(result.empty());
}

TEST_F(BmsDriverInstallerTest, CreateDriverSoDestinedDir_DotDotInDestinedDir)
{
    DriverInstaller installer;
    std::string result = installer.CreateDriverSoDestinedDir("bundle", "module", "file", "/dest/../etc", false);
    EXPECT_TRUE(result.empty());
}

TEST_F(BmsDriverInstallerTest, CreateDriverSoDestinedDir_IsModuleExisted_True)
{
    DriverInstaller installer;
    std::string result = installer.CreateDriverSoDestinedDir("bundle", "module", "file", "/dest/", true);
    EXPECT_FALSE(result.empty());
    // Should contain TEMP_PREFIX "temp_"
    EXPECT_NE(result.find("temp_"), std::string::npos);
}

TEST_F(BmsDriverInstallerTest, CreateDriverSoDestinedDir_IsModuleExisted_False)
{
    DriverInstaller installer;
    std::string result = installer.CreateDriverSoDestinedDir("bundle", "module", "file", "/dest/", false);
    EXPECT_FALSE(result.empty());
    // Should NOT contain TEMP_PREFIX
    EXPECT_EQ(result.find("temp_"), std::string::npos);
}

TEST_F(BmsDriverInstallerTest, CreateDriverSoDestinedDir_NoTrailingSeparator)
{
    DriverInstaller installer;
    std::string result = installer.CreateDriverSoDestinedDir("bundle", "module", "file", "/dest", false);
    EXPECT_FALSE(result.empty());
    // Should have appended separator
    EXPECT_NE(result.find("/"), std::string::npos);
}

TEST_F(BmsDriverInstallerTest, CreateDriverSoDestinedDir_WithTrailingSeparator)
{
    DriverInstaller installer;
    std::string result = installer.CreateDriverSoDestinedDir("bundle", "module", "file", "/dest/", false);
    EXPECT_FALSE(result.empty());
}

// === FilterDriverSoFile ===

TEST_F(BmsDriverInstallerTest, FilterDriverSoFile_MetadataNotInProperties)
{
    DriverInstaller installer;
    InnerBundleInfo info;
    Metadata meta;
    meta.name = "unknownProperty";
    meta.resource = "libs/test.so";
    meta.value = "/system/lib/";
    std::unordered_multimap<std::string, std::string> dirMap;
    ErrCode ret = installer.FilterDriverSoFile(info, meta, dirMap, false);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(dirMap.empty());
}

TEST_F(BmsDriverInstallerTest, FilterDriverSoFile_RelativePathInOriginalDir)
{
    DriverInstaller installer;
    InnerBundleInfo info;
    Metadata meta;
    meta.name = "cupsFilter";
    meta.resource = "../test.so";
    meta.value = "/system/lib/";
    std::unordered_multimap<std::string, std::string> dirMap;
    ErrCode ret = installer.FilterDriverSoFile(info, meta, dirMap, false);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

TEST_F(BmsDriverInstallerTest, FilterDriverSoFile_RelativePathInDestinedDir)
{
    DriverInstaller installer;
    InnerBundleInfo info;
    Metadata meta;
    meta.name = "cupsFilter";
    meta.resource = "libs/test.so";
    meta.value = "/system/../lib/";
    std::unordered_multimap<std::string, std::string> dirMap;
    ErrCode ret = installer.FilterDriverSoFile(info, meta, dirMap, false);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

TEST_F(BmsDriverInstallerTest, FilterDriverSoFile_EmptyOriginalDirVec)
{
    DriverInstaller installer;
    InnerBundleInfo info;
    Metadata meta;
    meta.name = "cupsFilter";
    meta.resource = "";
    meta.value = "/system/lib/";
    std::unordered_multimap<std::string, std::string> dirMap;
    ErrCode ret = installer.FilterDriverSoFile(info, meta, dirMap, false);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

TEST_F(BmsDriverInstallerTest, FilterDriverSoFile_ValidMetadata)
{
    DriverInstaller installer;
    InnerBundleInfo info;
    // Set up bundle name and current module package for info
    info.baseBundleInfo_ = std::make_shared<BundleInfo>();
    info.baseBundleInfo_->name = "com.test.driver";
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "driver_module";
    info.innerModuleInfos_["driver_module"] = moduleInfo;
    info.currentPackage_ = "driver_module";

    Metadata meta;
    meta.name = "cupsFilter";
    meta.resource = "libs/test.so";
    meta.value = "/system/lib/";
    std::unordered_multimap<std::string, std::string> dirMap;
    ErrCode ret = installer.FilterDriverSoFile(info, meta, dirMap, false);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(dirMap.size(), 1u);
}

// === CopyAllDriverFile ===

TEST_F(BmsDriverInstallerTest, CopyAllDriverFile_EmptyNewInfos)
{
    DriverInstaller installer;
    InnerBundleInfo oldInfo;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    ErrCode ret = installer.CopyAllDriverFile(newInfos, oldInfo);
    EXPECT_EQ(ret, ERR_OK);
}

// === RemoveDriverSoFile ===

TEST_F(BmsDriverInstallerTest, RemoveDriverSoFile_EmptyModuleName_NoCrash)
{
    DriverInstaller installer;
    InnerBundleInfo info;
    // Should not crash with empty moduleName - iterates all extensions
    installer.RemoveDriverSoFile(info, "", false);
    // No assertion needed - just checking no crash
}

TEST_F(BmsDriverInstallerTest, RemoveDriverSoFile_NonDriverExtension_Skipped)
{
    DriverInstaller installer;
    InnerBundleInfo info;
    InnerExtensionInfo extInfo;
    extInfo.type = ExtensionAbilityType::FORM;  // Not DRIVER
    extInfo.moduleName = "module";
    info.baseExtensionInfos_["ext1"] = extInfo;
    // Should skip non-DRIVER extensions without crash
    installer.RemoveDriverSoFile(info, "module", false);
}
