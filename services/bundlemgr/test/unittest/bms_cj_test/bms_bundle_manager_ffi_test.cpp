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

#include <gtest/gtest.h>

#include "bundle_error.h"
#include "bundle_manager_ffi.h"
#include "bundle_manager_utils.h"
#include "zip_ffi.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class BundleManagerFfiTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number: FfiOHOSGetCallingUidAndFfiOHOSGetBundleInfoForSelf_0001
 * @tc.name: FfiOHOSGetCallingUid and FfiOHOSGetBundleInfoForSelf
 * @tc.desc: FfiOHOSGetCallingUid and FfiOHOSGetBundleInfoForSelf
 */
HWTEST_F(BundleManagerFfiTest, FfiOHOSGetCallingUidAndFfiOHOSGetBundleInfoForSelf_0001, Function | SmallTest | Level0)
{
    int32_t uid = CJSystemapi::BundleManager::FfiOHOSGetCallingUid();
    EXPECT_EQ(uid, 0);
    int32_t bundleFlags = 1;
    CJSystemapi::BundleManager::RetBundleInfo retBundleInfo =
        CJSystemapi::BundleManager::FfiOHOSGetBundleInfoForSelf(bundleFlags);
    EXPECT_EQ(retBundleInfo.minCompatibleVersionCode, 0);
}

/**
 * @tc.number: FfiOHOSVerifyAbc_0001
 * @tc.name: FfiOHOSVerifyAbc
 * @tc.desc: FfiOHOSVerifyAbc
 */
HWTEST_F(BundleManagerFfiTest, FfiOHOSVerifyAbc_0001, Function | SmallTest | Level0)
{
    CJSystemapi::BundleManager::CArrString cArrString;
    cArrString.size = 0;
    bool flag = false;
    int32_t code = CJSystemapi::BundleManager::FfiOHOSVerifyAbc(cArrString, flag);
    EXPECT_EQ(code, CJSystemapi::BundleManager::ERROR_VERIFY_ABC);
}

/**
 * @tc.number: FfiGetProfileByExtensionAbility_0001
 * @tc.name: FfiGetProfileByExtensionAbility
 * @tc.desc: FfiGetProfileByExtensionAbility
 */
HWTEST_F(BundleManagerFfiTest, FfiGetProfileByExtensionAbility_0001, Function | SmallTest | Level0)
{
    char moduleName;
    char extensionAbilityName;
    char metadataName;
    CJSystemapi::BundleManager::RetCArrString retCArrString =
        CJSystemapi::BundleManager::FfiGetProfileByExtensionAbility(&moduleName, &extensionAbilityName, &metadataName);
    EXPECT_EQ(retCArrString.code, CJSystemapi::BundleManager::ERROR_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: FfiGetProfileByAbility_0001
 * @tc.name: FfiGetProfileByAbility
 * @tc.desc: FfiGetProfileByAbility
 */
HWTEST_F(BundleManagerFfiTest, FfiGetProfileByAbility_0001, Function | SmallTest | Level0)
{
    char moduleName;
    char extensionAbilityName;
    char metadataName;
    CJSystemapi::BundleManager::RetCArrString retCArrString =
        CJSystemapi::BundleManager::FfiGetProfileByAbility(&moduleName, &extensionAbilityName, &metadataName);
    EXPECT_EQ(retCArrString.code, CJSystemapi::BundleManager::ERROR_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: FfiBundleManagerCanOpenLink_0001
 * @tc.name: FfiBundleManagerCanOpenLink
 * @tc.desc: FfiBundleManagerCanOpenLink
 */
HWTEST_F(BundleManagerFfiTest, FfiBundleManagerCanOpenLink_0001, Function | SmallTest | Level0)
{
    char link;
    int32_t code = 0;
    bool canOpen = CJSystemapi::BundleManager::FfiBundleManagerCanOpenLink(&link, code);
    EXPECT_FALSE(canOpen);
}

/**
 * @tc.number: FfiBundleManagerCompressFile_0001
 * @tc.name: FfiBundleManagerCompressFile
 * @tc.desc: FfiBundleManagerCompressFile
 */
HWTEST_F(BundleManagerFfiTest, FfiBundleManagerCompressFile_0001, Function | SmallTest | Level0)
{
    LIBZIP::CArrUI8 inFile = LIBZIP::CArrUI8{nullptr, 0};
    LIBZIP::CArrUI8 outFile = LIBZIP::CArrUI8{nullptr, 0};
    LIBZIP::RetOptions options = LIBZIP::RetOptions{0, 1, 0};
    int code = FfiBundleManagerCompressFile(inFile, outFile, options);
    EXPECT_EQ(code, CJSystemapi::BundleManager::ERR_ZLIB_SRC_FILE_INVALID);
}

/**
 * @tc.number: FfiBundleManagerDeCompressFileOptions_0001
 * @tc.name: FfiBundleManagerDeCompressFileOptions
 * @tc.desc: FfiBundleManagerDeCompressFileOptions
 */
HWTEST_F(BundleManagerFfiTest, FfiBundleManagerDeCompressFileOptions_0001, Function | SmallTest | Level0)
{
    LIBZIP::CArrUI8 inFile = LIBZIP::CArrUI8{nullptr, 0};
    LIBZIP::CArrUI8 outFile = LIBZIP::CArrUI8{nullptr, 0};
    LIBZIP::RetOptions options = LIBZIP::RetOptions{0, 1, 0};
    int code = FfiBundleManagerDeCompressFileOptions(inFile, outFile, options);
    EXPECT_EQ(code, CJSystemapi::BundleManager::ERR_ZLIB_DEST_FILE_INVALID);
}

/**
 * @tc.number: FfiBundleManagerDeCompressFile_0001
 * @tc.name: FfiBundleManagerDeCompressFile
 * @tc.desc: FfiBundleManagerDeCompressFile
 */
HWTEST_F(BundleManagerFfiTest, FfiBundleManagerDeCompressFile_0001, Function | SmallTest | Level0)
{
    LIBZIP::CArrUI8 inFile = LIBZIP::CArrUI8{nullptr, 0};
    LIBZIP::CArrUI8 outFile = LIBZIP::CArrUI8{nullptr, 0};
    int code = FfiBundleManagerDeCompressFile(inFile, outFile);
    EXPECT_EQ(code, CJSystemapi::BundleManager::ERR_ZLIB_DEST_FILE_INVALID);
}
} // namespace AppExecFwk
} // namespace OHOS