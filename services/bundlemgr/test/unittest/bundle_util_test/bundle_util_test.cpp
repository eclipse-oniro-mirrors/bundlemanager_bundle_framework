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

#include <fstream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "bundle_util.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
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
    std::string tempFile;
};

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
 * @tc.number: CheckOrphanNOdeUseRateIsSufficient_Normal
 * @tc.name: test the CheckOrphanNOdeUseRateIsSufficient_Normal.
 * @tc.desc: test the CheckOrphanNOdeUseRateIsSufficient_Normal.
 */
HWTEST_F(BundleUtilTest, CheckOrphanNOdeUseRateIsSufficient_Normal, TestSize.Level2)
{
    EXPECT_TRUE(BundleUtil::CheckOrphanNodeUseRateIsSufficient());
}
} // OHOS