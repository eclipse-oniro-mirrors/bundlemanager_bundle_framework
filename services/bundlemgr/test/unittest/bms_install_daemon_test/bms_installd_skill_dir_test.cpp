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
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>

#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "directory_ex.h"
#include "installd/installd_host_impl.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace {
constexpr const char* LEGACY_SKILL_BACKUP_DIR = "/data/app/el1/skills_bms_ut_backup";

bool IsSkillTestPathExist(const std::string &path)
{
    struct stat buf = {};
    return fstatat(AT_FDCWD, path.c_str(), &buf, AT_SYMLINK_NOFOLLOW) == 0;
}

void RemoveSkillTestPath(const std::string &path)
{
    struct stat buf = {};
    if (fstatat(AT_FDCWD, path.c_str(), &buf, AT_SYMLINK_NOFOLLOW) != 0) {
        return;
    }
    if (S_ISDIR(buf.st_mode)) {
        (void)OHOS::ForceRemoveDirectory(path);
        return;
    }
    (void)unlink(path.c_str());
}

bool CreateSkillTestFile(const std::string &path)
{
    std::ofstream file(path);
    return file.good();
}

std::string GetLegacySkillPath()
{
    return std::string(ServiceConstants::LEGACY_SKILL_BASE_DIR) + "/public/com.example.skill/entry/skills/skillOne";
}
} // namespace

namespace OHOS {
class BmsInstalldSkillDirTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    InstalldHostImpl hostImpl_;
};

void BmsInstalldSkillDirTest::SetUpTestCase()
{
    // recover the legacy dir left by an interrupted run
    if (IsSkillTestPathExist(LEGACY_SKILL_BACKUP_DIR)) {
        RemoveSkillTestPath(ServiceConstants::LEGACY_SKILL_BASE_DIR);
        (void)rename(LEGACY_SKILL_BACKUP_DIR, ServiceConstants::LEGACY_SKILL_BASE_DIR);
    }
}

void BmsInstalldSkillDirTest::TearDownTestCase()
{}

void BmsInstalldSkillDirTest::SetUp()
{
    if (IsSkillTestPathExist(ServiceConstants::LEGACY_SKILL_BASE_DIR)) {
        ASSERT_EQ(rename(ServiceConstants::LEGACY_SKILL_BASE_DIR, LEGACY_SKILL_BACKUP_DIR), 0);
    }
}

void BmsInstalldSkillDirTest::TearDown()
{
    RemoveSkillTestPath(ServiceConstants::LEGACY_SKILL_BASE_DIR);
    if (IsSkillTestPathExist(LEGACY_SKILL_BACKUP_DIR)) {
        (void)rename(LEGACY_SKILL_BACKUP_DIR, ServiceConstants::LEGACY_SKILL_BASE_DIR);
    }
}

/**
 * @tc.number: RemoveLegacySkillDir_0100
 * @tc.name: test RemoveDir with REMOVE_LEGACY_SKILL_DIR
 * @tc.desc: 1. RemoveDir deletes the whole legacy skills dir synchronously
 */
HWTEST_F(BmsInstalldSkillDirTest, RemoveLegacySkillDir_0100, Function | SmallTest | Level0)
{
    ASSERT_TRUE(OHOS::ForceCreateDirectory(GetLegacySkillPath()));
    ASSERT_TRUE(CreateSkillTestFile(GetLegacySkillPath() + "/SKILL.md"));
    EXPECT_EQ(hostImpl_.RemoveDir(ServiceConstants::LEGACY_SKILL_BASE_DIR, BundleDirScene::REMOVE_LEGACY_SKILL_DIR),
        ERR_OK);
    EXPECT_FALSE(IsSkillTestPathExist(ServiceConstants::LEGACY_SKILL_BASE_DIR));
}

/**
 * @tc.number: RemoveLegacySkillDir_0200
 * @tc.name: test RemoveDir with REMOVE_LEGACY_SKILL_DIR
 * @tc.desc: 1. RemoveDir succeeds when the legacy skills dir does not exist
 */
HWTEST_F(BmsInstalldSkillDirTest, RemoveLegacySkillDir_0200, Function | SmallTest | Level0)
{
    ASSERT_FALSE(IsSkillTestPathExist(ServiceConstants::LEGACY_SKILL_BASE_DIR));
    EXPECT_EQ(hostImpl_.RemoveDir(ServiceConstants::LEGACY_SKILL_BASE_DIR, BundleDirScene::REMOVE_LEGACY_SKILL_DIR),
        ERR_OK);
    EXPECT_EQ(hostImpl_.RemoveDir(ServiceConstants::LEGACY_SKILL_BASE_DIR, BundleDirScene::REMOVE_LEGACY_SKILL_DIR,
        "", true), ERR_OK);
}

/**
 * @tc.number: RemoveLegacySkillDir_0300
 * @tc.name: test RemoveDir with REMOVE_LEGACY_SKILL_DIR
 * @tc.desc: 1. RemoveDir rejects every path other than the legacy skills dir and keeps it
 */
HWTEST_F(BmsInstalldSkillDirTest, RemoveLegacySkillDir_0300, Function | SmallTest | Level0)
{
    const std::string publicDir = std::string(ServiceConstants::LEGACY_SKILL_BASE_DIR) + "/public";
    ASSERT_TRUE(OHOS::ForceCreateDirectory(publicDir));
    const std::vector<std::string> invalidDirs = {
        publicDir,
        std::string(ServiceConstants::LEGACY_SKILL_BASE_DIR) + "/",
        std::string(ServiceConstants::LEGACY_SKILL_BASE_DIR) + "x",
        std::string(ServiceConstants::LEGACY_SKILL_BASE_DIR) + "/../skills",
        "/data/app/el1",
        Constants::BASE_SKILL_DIR,
        Constants::BUNDLE_CODE_DIR,
    };
    for (const auto &dir : invalidDirs) {
        EXPECT_EQ(hostImpl_.RemoveDir(dir, BundleDirScene::REMOVE_LEGACY_SKILL_DIR),
            ERR_APPEXECFWK_INSTALLD_PARAM_ERROR) << dir;
    }
    EXPECT_TRUE(IsSkillTestPathExist(publicDir));
}

/**
 * @tc.number: RemoveLegacySkillDir_0400
 * @tc.name: test RemoveDir with REMOVE_LEGACY_SKILL_DIR
 * @tc.desc: 1. RemoveDir returns REMOVE_DIR_FAILED when the legacy skills dir can not be opened
 */
HWTEST_F(BmsInstalldSkillDirTest, RemoveLegacySkillDir_0400, Function | SmallTest | Level0)
{
    ASSERT_TRUE(OHOS::ForceCreateDirectory(std::string(ServiceConstants::LEGACY_SKILL_BASE_DIR) + "/public"));
    struct rlimit oldLimit = {};
    ASSERT_EQ(getrlimit(RLIMIT_NOFILE, &oldLimit), 0);
    struct rlimit noFileLimit = oldLimit;
    // no new fd can be allocated, so opendir of the legacy dir fails with EMFILE
    noFileLimit.rlim_cur = 0;
    ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &noFileLimit), 0);
    ErrCode ret = hostImpl_.RemoveDir(ServiceConstants::LEGACY_SKILL_BASE_DIR, BundleDirScene::REMOVE_LEGACY_SKILL_DIR);
    ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &oldLimit), 0);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_REMOVE_DIR_FAILED);
    EXPECT_TRUE(IsSkillTestPathExist(ServiceConstants::LEGACY_SKILL_BASE_DIR));
}
} // namespace OHOS
