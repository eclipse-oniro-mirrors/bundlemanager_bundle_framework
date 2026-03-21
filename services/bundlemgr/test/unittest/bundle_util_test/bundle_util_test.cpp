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

#include <cstring>
#include <fstream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "bundle_util.h"
#include "elf.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string TEST_FILE_PATH = "/data/local/tmp/test_elf_file";
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