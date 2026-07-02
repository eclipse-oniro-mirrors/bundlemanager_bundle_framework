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

#include <cstdint>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "bundle_extractor.h"
#include "directory_ex.h"
#include "installd/installd_operator.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
constexpr uint8_t BYTE_MASK = 0xFF;
constexpr uint16_t UINT16_MASK = 0xFFFF;
constexpr uint32_t CRC32_INITIAL_VALUE = 0xFFFFFFFF;
constexpr uint32_t CRC32_POLYNOMIAL = 0xEDB88320;
constexpr uint32_t ZIP_LOCAL_FILE_HEADER_SIGNATURE = 0x04034B50;
constexpr uint32_t ZIP_CENTRAL_DIR_HEADER_SIGNATURE = 0x02014B50;
constexpr uint32_t ZIP_END_OF_CENTRAL_DIR_SIGNATURE = 0x06054B50;
constexpr uint32_t ZIP_DIRECTORY_EXTERNAL_ATTR = 0x10;
constexpr uint16_t ZIP_VERSION_2_0 = 20;
constexpr int32_t BITS_PER_BYTE = 8;
constexpr int32_t UINT16_BIT_COUNT = 16;
struct TestZipEntry {
    std::string name;
    std::string content;
};

void AppendZipUint16(std::vector<uint8_t> &data, uint16_t value)
{
    data.emplace_back(static_cast<uint8_t>(value & BYTE_MASK));
    data.emplace_back(static_cast<uint8_t>((value >> BITS_PER_BYTE) & BYTE_MASK));
}

void AppendZipUint32(std::vector<uint8_t> &data, uint32_t value)
{
    AppendZipUint16(data, static_cast<uint16_t>(value & UINT16_MASK));
    AppendZipUint16(data, static_cast<uint16_t>((value >> UINT16_BIT_COUNT) & UINT16_MASK));
}

void AppendZipString(std::vector<uint8_t> &data, const std::string &value)
{
    data.insert(data.end(), value.begin(), value.end());
}

uint32_t CalculateCrc32(const std::string &content)
{
    uint32_t crc = CRC32_INITIAL_VALUE;
    for (const auto ch : content) {
        crc ^= static_cast<uint8_t>(ch);
        for (int32_t i = 0; i < BITS_PER_BYTE; ++i) {
            crc = (crc & 1) == 0 ? (crc >> 1) : ((crc >> 1) ^ CRC32_POLYNOMIAL);
        }
    }
    return crc ^ CRC32_INITIAL_VALUE;
}

void AppendLocalZipEntry(std::vector<uint8_t> &zipData, const TestZipEntry &entry, uint32_t crc)
{
    AppendZipUint32(zipData, ZIP_LOCAL_FILE_HEADER_SIGNATURE);
    AppendZipUint16(zipData, ZIP_VERSION_2_0);
    AppendZipUint16(zipData, 0);
    AppendZipUint16(zipData, 0);
    AppendZipUint16(zipData, 0);
    AppendZipUint16(zipData, 0);
    AppendZipUint32(zipData, crc);
    AppendZipUint32(zipData, static_cast<uint32_t>(entry.content.size()));
    AppendZipUint32(zipData, static_cast<uint32_t>(entry.content.size()));
    AppendZipUint16(zipData, static_cast<uint16_t>(entry.name.size()));
    AppendZipUint16(zipData, 0);
    AppendZipString(zipData, entry.name);
    AppendZipString(zipData, entry.content);
}

void AppendCentralZipEntry(std::vector<uint8_t> &central, const TestZipEntry &entry,
    uint32_t crc, uint32_t offset)
{
    AppendZipUint32(central, ZIP_CENTRAL_DIR_HEADER_SIGNATURE);
    AppendZipUint16(central, ZIP_VERSION_2_0);
    AppendZipUint16(central, ZIP_VERSION_2_0);
    AppendZipUint16(central, 0);
    AppendZipUint16(central, 0);
    AppendZipUint16(central, 0);
    AppendZipUint16(central, 0);
    AppendZipUint32(central, crc);
    AppendZipUint32(central, static_cast<uint32_t>(entry.content.size()));
    AppendZipUint32(central, static_cast<uint32_t>(entry.content.size()));
    AppendZipUint16(central, static_cast<uint16_t>(entry.name.size()));
    AppendZipUint16(central, 0);
    AppendZipUint16(central, 0);
    AppendZipUint16(central, 0);
    AppendZipUint16(central, 0);
    AppendZipUint32(central, entry.name.back() == '/' ? ZIP_DIRECTORY_EXTERNAL_ATTR : 0);
    AppendZipUint32(central, offset);
    AppendZipString(central, entry.name);
}

bool WriteTestZipFile(const std::string &zipPath, const std::vector<TestZipEntry> &entries)
{
    std::vector<uint8_t> zipData;
    std::vector<uint8_t> central;
    for (const auto &entry : entries) {
        uint32_t offset = static_cast<uint32_t>(zipData.size());
        uint32_t crc = CalculateCrc32(entry.content);
        AppendLocalZipEntry(zipData, entry, crc);
        AppendCentralZipEntry(central, entry, crc, offset);
    }
    uint32_t centralOffset = static_cast<uint32_t>(zipData.size());
    zipData.insert(zipData.end(), central.begin(), central.end());
    AppendZipUint32(zipData, ZIP_END_OF_CENTRAL_DIR_SIGNATURE);
    AppendZipUint16(zipData, 0);
    AppendZipUint16(zipData, 0);
    AppendZipUint16(zipData, static_cast<uint16_t>(entries.size()));
    AppendZipUint16(zipData, static_cast<uint16_t>(entries.size()));
    AppendZipUint32(zipData, static_cast<uint32_t>(central.size()));
    AppendZipUint32(zipData, centralOffset);
    AppendZipUint16(zipData, 0);
    std::ofstream file(zipPath, std::ios::binary);
    file.write(reinterpret_cast<const char *>(zipData.data()), zipData.size());
    return file.good();
}

class BmsInstallDaemonSkillExtractTest : public testing::Test {
public:
    BmsInstallDaemonSkillExtractTest() = default;
    ~BmsInstallDaemonSkillExtractTest() override = default;
};

/**
 * @tc.number: InstalldOperatorSkillExtractTest_0100
 * @tc.name: test ExtractSkillFromHsp function of InstalldOperator
 * @tc.desc: 1. calling ExtractSkillFromHsp with skill scripts entries
 *           2. verify scripts directory is skipped
*/
HWTEST_F(BmsInstallDaemonSkillExtractTest, InstalldOperatorSkillExtractTest_0100, Function | SmallTest | Level0)
{
    std::string testDir = "/data/test/skill_extract_test_0100";
    std::string testHapPath = testDir + "/skill_test.hap";
    std::string targetPath = testDir + "/target/testSkill";
    OHOS::ForceRemoveDirectory(testDir);
    ASSERT_TRUE(OHOS::ForceCreateDirectory(testDir));

    std::vector<TestZipEntry> entries = {
        { "skills/testSkill/SKILL.md", "---\nname: testSkill\ndescription: test skill\n---\n" },
        { "skills/testSkill/assets/info.txt", "asset" },
        { "skills/testSkill/scripts/", "" },
        { "skills/testSkill/scripts/main.ets", "console.info('skip');" },
    };
    ASSERT_TRUE(WriteTestZipFile(testHapPath, entries));

    BundleExtractor extractor(testHapPath);
    ASSERT_TRUE(extractor.Init());
    bool ret = InstalldOperator::ExtractSkillFromHsp(extractor, "testSkill", targetPath);

    EXPECT_TRUE(ret);
    EXPECT_TRUE(InstalldOperator::IsExistFile(targetPath + "/SKILL.md"));
    EXPECT_TRUE(InstalldOperator::IsExistFile(targetPath + "/assets/info.txt"));
    EXPECT_FALSE(InstalldOperator::IsExistFile(targetPath + "/scripts"));
    EXPECT_FALSE(InstalldOperator::IsExistFile(targetPath + "/scripts/main.ets"));

    OHOS::ForceRemoveDirectory(testDir);
}
} // namespace
} // namespace OHOS
