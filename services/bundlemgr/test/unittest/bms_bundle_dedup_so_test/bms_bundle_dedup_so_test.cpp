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

#include <gtest/gtest.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstring>
#include <fstream>
#include <limits>
#include <set>
#include <string>
#include <vector>

#include "bundle_constants.h"
#include "bundle_dedup_so_helper.h"
#include "bundle_extractor.h"
#include "bundle_parser.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "data/inner_extension_info.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "inner_bundle_info.h"
#include "installd/installd_host_impl.h"
#include "installd/installd_operator.h"
#include "ipc/installd_proxy.h"
#include "module_profile.h"
#include "so_dedup/so_dedup.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
// Accessors of the installd client LinkDedupedSo stub knobs
// (test/mock/src/installd_client.cpp); the knobs themselves are internal-linkage.
void ResetLinkDedupedSoStateForTest();
int32_t GetLinkDedupedSoCallCountForTest();
bool GetLastLinkDedupedSoParamForTest(std::string &bundleName, std::string &libraryPath, std::string &sha256);
void SetLinkDedupedSoIpcRetForTest(int32_t ipcRet);
void SetLinkDedupedSoResultCodeForTest(uint32_t resultCode);
// Mock knobs of the link-time libc OH_LinkDedupedSo stub (test/mock/src/so_dedup_mock.cpp).
extern uint32_t g_muslLinkDedupedSoResult;
extern int32_t g_muslLinkDedupedSoCallCount;
extern std::string g_muslLinkDedupedSoLastPath;
extern std::string g_muslLinkDedupedSoLastSha;

// Pin the Foundation-side musl result contract copy against the enum this TU includes: drift breaks the build.
static_assert(SO_DEDUP_RESULT_LINKED == SO_DEDUP_LINKED, "musl dedup result contract drifted");
static_assert(SO_DEDUP_RESULT_NO_MATCH == SO_DEDUP_NO_MATCH, "musl dedup result contract drifted");
static_assert(SO_DEDUP_RESULT_ALREADY_LINKED == SO_DEDUP_ALREADY_LINKED, "musl dedup result contract drifted");
static_assert(SO_DEDUP_RESULT_CONFIG_UNAVAILABLE == SO_DEDUP_CONFIG_UNAVAILABLE,
    "musl dedup result contract drifted");
static_assert(SO_DEDUP_RESULT_VERSION_MISMATCH == SO_DEDUP_VERSION_MISMATCH,
    "musl dedup result contract drifted");
static_assert(SO_DEDUP_RESULT_ERROR == SO_DEDUP_ERROR, "musl dedup result contract drifted");

namespace {
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/parse_bundle/";
const std::string DEDUP_SO_DIR = "dedup_so/";
const std::string WORK_DIR = "/data/test/resource/bms/dedup_helper/";
const std::string VALID_SHA = "31b7479487ad9f817f0fd66f6dcb1c2957e7ca68b432b6f95f1f56bfc976bd60";
const std::string BUNDLE_NAME = "com.example.dedupso";
const std::string CPU_ABI_ARM64 = "arm64-v8a";
const std::string CPU_ABI_X86_64 = "x86_64";
const std::string DEDUP_LIBS_PATH_ARM64 = "libs/arm64";
const std::string LINKED_SO = "libc++_shared.so";

InnerBundleInfo MakeDedupInfo()
{
    InnerBundleInfo info;
    info.SetIsNewVersion(true);
    info.SetCpuAbi(CPU_ABI_ARM64);
    return info;
}

std::string OwnTargetSoPath(const std::string &bundleName)
{
    return std::string(Constants::BUNDLE_CODE_DIR) + "/" + bundleName + "/libs/" + CPU_ABI_ARM64 + "/";
}

void ExpectLinkCall(const std::string &bundleName, const std::string &targetSoPath)
{
    std::string linkedName;
    std::string libraryPath;
    std::string sha256;
    EXPECT_TRUE(GetLastLinkDedupedSoParamForTest(linkedName, libraryPath, sha256));
    EXPECT_EQ(linkedName, bundleName);
    EXPECT_EQ(libraryPath, targetSoPath + LINKED_SO);
    EXPECT_EQ(sha256, VALID_SHA);
}
}  // namespace

class BmsBundleDedupSoTest : public testing::Test {
public:
    BmsBundleDedupSoTest();
    ~BmsBundleDedupSoTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void CreateFile(const std::string &filePath, const std::string &content) const;
    void CreateQuickFileDir(const std::string &dir) const;
    void DeleteQuickFileDir(const std::string &dir) const;
    void DeleteFile(const std::string &filePath) const;
    std::string ReadFile(const std::string &filePath) const;
    bool HasDedupBackupResidue(const std::string &dir) const;
};

BmsBundleDedupSoTest::BmsBundleDedupSoTest()
{}

BmsBundleDedupSoTest::~BmsBundleDedupSoTest()
{}

void BmsBundleDedupSoTest::SetUpTestCase()
{}

void BmsBundleDedupSoTest::TearDownTestCase()
{}

void BmsBundleDedupSoTest::SetUp()
{
    ResetLinkDedupedSoStateForTest();
}

void BmsBundleDedupSoTest::TearDown()
{
    ResetLinkDedupedSoStateForTest();
}

void BmsBundleDedupSoTest::CreateFile(const std::string &filePath, const std::string &content) const
{
    std::ofstream file(filePath, std::ios::out | std::ios::trunc);
    file << content;
    file.flush();
    file.close();
}

std::string BmsBundleDedupSoTest::ReadFile(const std::string &filePath) const
{
    std::ifstream file(filePath);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

// the rotate backup slot name is token-bearing and unpredictable, so the
// round-trip assertions scan the so dir for the marker family instead of
// lstat-ing one constructed name
bool BmsBundleDedupSoTest::HasDedupBackupResidue(const std::string &dir) const
{
    DIR *dirPtr = opendir(dir.c_str());
    if (dirPtr == nullptr) {
        return false;
    }
    struct dirent *entry = nullptr;
    bool found = false;
    while ((entry = readdir(dirPtr)) != nullptr) {
        if (strstr(entry->d_name, ServiceConstants::DEDUP_SO_BACKUP_SUFFIX) != nullptr) {
            found = true;
            break;
        }
    }
    closedir(dirPtr);
    return found;
}

void BmsBundleDedupSoTest::CreateQuickFileDir(const std::string &dir) const
{
    BundleUtil::CreateDir(dir);
}

void BmsBundleDedupSoTest::DeleteQuickFileDir(const std::string &dir) const
{
    BundleUtil::DeleteDir(dir);
}

void BmsBundleDedupSoTest::DeleteFile(const std::string &filePath) const
{
    RemoveFile(filePath);
}

/**
 * @tc.number: DedupSoHelperTest_0300
 * @tc.name: test the guards, manifest forms, abi filter and name derivation of the helper
 * @tc.desc: 1. the guards, the keepdir/stripped/multi-abi forms, the abi differential,
 *             invalid manifests, clone so dirs
 *           2. guards stay IPC-free except empty path + manifest (8519951); parse errors fail
 *              before any LinkDedupedSo IPC; the IPC name follows the target so dir
 */
HWTEST_F(BmsBundleDedupSoTest, DedupSoHelperTest_0300, Function | SmallTest | Level0)
{
    const std::string hapPath = RESOURCE_ROOT_PATH + DEDUP_SO_DIR + "dedup_valid.hap";
    const std::string noManifestPath = RESOURCE_ROOT_PATH + DEDUP_SO_DIR + "dedup_no_manifest.hap";
    const std::string targetSoPath = OwnTargetSoPath(BUNDLE_NAME);
    auto info = MakeDedupInfo();
    InnerBundleInfo faInfo;
    faInfo.SetIsNewVersion(false);
    faInfo.SetCpuAbi(CPU_ABI_ARM64);
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(hapPath, faInfo, targetSoPath, CPU_ABI_ARM64), ERR_OK);
    InnerBundleInfo driverInfo;
    driverInfo.SetIsNewVersion(true);
    driverInfo.SetCpuAbi(CPU_ABI_ARM64);
    InnerExtensionInfo driverExtension;
    driverExtension.type = ExtensionAbilityType::DRIVER;
    driverInfo.InsertExtensionInfo("entry.dedup.driver", driverExtension);
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(hapPath, driverInfo, targetSoPath, CPU_ABI_ARM64), ERR_OK);
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles("", info, targetSoPath, CPU_ABI_ARM64), ERR_OK);
    // empty target so path with a non-empty manifest: fail closed, never install without the so
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(hapPath, info, "", CPU_ABI_ARM64),
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED);
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(noManifestPath, info, "", CPU_ABI_ARM64), ERR_OK);
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(noManifestPath, info, targetSoPath, CPU_ABI_ARM64), ERR_OK);
    EXPECT_EQ(GetLinkDedupedSoCallCountForTest(), 0);
    const std::string keepdirPath = RESOURCE_ROOT_PATH + DEDUP_SO_DIR + "dedup_fulldedup_keepdir.hap";
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(keepdirPath, info, targetSoPath, CPU_ABI_ARM64), ERR_OK);
    EXPECT_EQ(GetLinkDedupedSoCallCountForTest(), 1);
    ExpectLinkCall(BUNDLE_NAME, targetSoPath);
    const std::string strippedPath = RESOURCE_ROOT_PATH + DEDUP_SO_DIR + "dedup_valid.hap";
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(strippedPath, info, "", CPU_ABI_ARM64),
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED);
    EXPECT_EQ(GetLinkDedupedSoCallCountForTest(), 1);
    // invalid manifests: the parse error propagates before any installd LinkDedupedSo call
    const std::vector<std::string> invalidManifests = {
        "dedup_invalid_json.hap",
        "dedup_path_traversal.hap",
        "dedup_sha_invalid.hap",
    };
    for (const auto &manifest : invalidManifests) {
        ResetLinkDedupedSoStateForTest();
        EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(
            RESOURCE_ROOT_PATH + DEDUP_SO_DIR + manifest, MakeDedupInfo(), targetSoPath,
            CPU_ABI_ARM64), ERR_APPEXECFWK_INSTALL_PARSE_FAILED) << manifest;
        EXPECT_EQ(GetLinkDedupedSoCallCountForTest(), 0) << manifest;
    }
    // a multi-abi manifest: only the entry matching the module cpu abi is linked
    const std::string multiAbiPath = RESOURCE_ROOT_PATH + DEDUP_SO_DIR + "dedup_valid_multi.hap";
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(multiAbiPath, info, targetSoPath,
        CPU_ABI_ARM64), ERR_OK);
    EXPECT_EQ(GetLinkDedupedSoCallCountForTest(), 1);
    ExpectLinkCall(BUNDLE_NAME, targetSoPath);
    // the abi filter follows the passed-in cpu abi, never the bundle info's own:
    // an arm64-only manifest with an x86_64 filter arg stays zero-link (WARN +
    // ERR_OK, no IPC); a GetCpuAbi() regression would link the arm64 entry and
    // trip the call count
    ResetLinkDedupedSoStateForTest();
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(hapPath, info, targetSoPath,
        CPU_ABI_X86_64), ERR_OK);
    EXPECT_EQ(GetLinkDedupedSoCallCountForTest(), 0);
    // the IPC bundleName derivation: staging and clone target so dirs, plus out-of-domain
    const std::string codeDir = std::string(Constants::BUNDLE_CODE_DIR) + "/";
    const std::string dualModeName = std::string(ServiceConstants::CLONE_PREFIX) +
        std::to_string(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX) +
        ServiceConstants::PLUS_SIGN + BUNDLE_NAME;
    const std::string cloneName = std::string(ServiceConstants::CLONE_PREFIX) + "2" +
        ServiceConstants::PLUS_SIGN + BUNDLE_NAME;
    const std::string stagingSoPath = codeDir + ServiceConstants::BUNDLE_NEW_CODE_DIR +
        BUNDLE_NAME + "/libs/" + CPU_ABI_ARM64 + "/";
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(hapPath, info, stagingSoPath,
        CPU_ABI_ARM64), ERR_OK);
    ExpectLinkCall(BUNDLE_NAME, stagingSoPath);
    ResetLinkDedupedSoStateForTest();
    const std::string dualModeSoPath = OwnTargetSoPath(dualModeName);
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(hapPath, info, dualModeSoPath,
        CPU_ABI_ARM64), ERR_OK);
    ExpectLinkCall(dualModeName, dualModeSoPath);
    ResetLinkDedupedSoStateForTest();
    const std::string cloneSoPath = OwnTargetSoPath(cloneName);
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(hapPath, info, cloneSoPath,
        CPU_ABI_ARM64), ERR_OK);
    ExpectLinkCall(cloneName, cloneSoPath);
    ResetLinkDedupedSoStateForTest();
    const std::string cloneStagingPath = codeDir +
        ServiceConstants::BUNDLE_NEW_CODE_DIR + dualModeName + "/libs/" + CPU_ABI_ARM64 + "/";
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(hapPath, info, cloneStagingPath,
        CPU_ABI_ARM64), ERR_OK);
    ExpectLinkCall(dualModeName, cloneStagingPath);
    // out-of-domain target so path: no effective bundle name, fail fast
    ResetLinkDedupedSoStateForTest();
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(hapPath, info,
        "/data/test/outofdomain/libs/", CPU_ABI_ARM64),
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED);
    EXPECT_EQ(GetLinkDedupedSoCallCountForTest(), 0);
}

/**
 * @tc.number: DedupSoHelperTest_1000
 * @tc.name: test every musl result code maps, decides the outcome and stops at the first entry
 * @tc.desc: 1. map every musl result code, then inject an IPC failure and every musl code
 *           2. 0/2 keep the flow, 1/3 map to their error codes, failures return 8519951 and
 *              stop at the first entry; CopyFileFast refuses symlink destinations
 */
HWTEST_F(BmsBundleDedupSoTest, DedupSoHelperTest_1000, Function | SmallTest | Level0)
{
    // the pure mapping: 0/2 keep the flow (2 idempotent), 4 fails closed with 8519952,
    // 1/3/UINT32_MAX map to their dedup so error codes
    EXPECT_EQ(DedupSoHelper::MapLinkResultCode(0), ERR_OK);
    EXPECT_EQ(DedupSoHelper::MapLinkResultCode(2), ERR_OK);
    EXPECT_EQ(DedupSoHelper::MapLinkResultCode(1), ERR_APPEXECFWK_INSTALL_DEDUP_SO_NO_MATCH);
    EXPECT_EQ(DedupSoHelper::MapLinkResultCode(3), ERR_APPEXECFWK_INSTALL_DEDUP_SO_CONFIG_UNAVAILABLE);
    EXPECT_EQ(DedupSoHelper::MapLinkResultCode(4), ERR_APPEXECFWK_INSTALL_DEDUP_SO_VERSION_MISMATCH);
    EXPECT_EQ(DedupSoHelper::MapLinkResultCode(std::numeric_limits<uint32_t>::max()),
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED);
    const std::string hapPath = RESOURCE_ROOT_PATH + DEDUP_SO_DIR + "dedup_valid.hap";
    const std::string targetSoPath = OwnTargetSoPath(BUNDLE_NAME);
    auto info = MakeDedupInfo();
    SetLinkDedupedSoIpcRetForTest(ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(hapPath, info, targetSoPath, CPU_ABI_ARM64),
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED);
    EXPECT_EQ(GetLinkDedupedSoCallCountForTest(), 1);
    ExpectLinkCall(BUNDLE_NAME, targetSoPath);
    const uint32_t resultCodes[] = {
        static_cast<uint32_t>(SO_DEDUP_RESULT_LINKED),
        static_cast<uint32_t>(SO_DEDUP_RESULT_NO_MATCH),
        static_cast<uint32_t>(SO_DEDUP_RESULT_CONFIG_UNAVAILABLE),
        static_cast<uint32_t>(SO_DEDUP_RESULT_ERROR),
    };
    const ErrCode expected[] = {
        ERR_OK,
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_NO_MATCH,
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_CONFIG_UNAVAILABLE,
        ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED,
    };
    for (size_t i = 0; i < sizeof(resultCodes) / sizeof(resultCodes[0]); ++i) {
        ResetLinkDedupedSoStateForTest();
        SetLinkDedupedSoResultCodeForTest(resultCodes[i]);
        EXPECT_EQ(DedupSoHelper::ProcessDedupSoFiles(hapPath, info, targetSoPath, CPU_ABI_ARM64),
            expected[i]) << "result code index " << i;
        EXPECT_EQ(GetLinkDedupedSoCallCountForTest(), 1) << "result code index " << i;
        ExpectLinkCall(BUNDLE_NAME, targetSoPath);
    }
    ResetLinkDedupedSoStateForTest();
    ASSERT_TRUE(OHOS::ForceCreateDirectory(WORK_DIR));
    const std::string sourcePath = WORK_DIR + "copy_source.so";
    const std::string targetPath = WORK_DIR + "link_target.so";
    const std::string destLink = WORK_DIR + "dest_link.so";
    CreateFile(sourcePath, "source-content");
    CreateFile(targetPath, "target-content");
    ASSERT_TRUE(unlink(destLink.c_str()) == 0 || errno == ENOENT);
    ASSERT_EQ(symlink("link_target.so", destLink.c_str()), 0);
    EXPECT_FALSE(BundleUtil::CopyFileFast(sourcePath, destLink));
    struct stat linkStat = {};
    EXPECT_EQ(lstat(destLink.c_str(), &linkStat), 0);
    EXPECT_TRUE(S_ISLNK(linkStat.st_mode));
    EXPECT_EQ(ReadFile(targetPath), "target-content");
    EXPECT_EQ(unlink(destLink.c_str()), 0);
    EXPECT_EQ(unlink(sourcePath.c_str()), 0);
    EXPECT_EQ(unlink(targetPath.c_str()), 0);
    OHOS::ForceRemoveDirectory(WORK_DIR);
}

/**
 * @tc.name: TestParse_8400
 * @tc.desc: 1. system running normally
 *           2. test ParseDedupFiles with valid manifests, the entry-count and size limits,
 *              the depth bomb and the depth scanner string/escape tracking
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleDedupSoTest, TestParse_8400, Function | SmallTest | Level1)
{
    BundleParser parser;
    DedupSoInfoList dedupSoInfoList;
    auto result = parser.ParseDedupFiles(RESOURCE_ROOT_PATH + "not_exist.hap", BUNDLE_NAME, dedupSoInfoList);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_UNEXPECTED);
    EXPECT_TRUE(dedupSoInfoList.empty());
    result = parser.ParseDedupFiles(RESOURCE_ROOT_PATH + "dedup_so/dedup_valid.hap", BUNDLE_NAME, dedupSoInfoList);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(dedupSoInfoList.size(), 1);
    EXPECT_EQ(dedupSoInfoList[0].originalPathInHap, "libs/arm64-v8a/libc++_shared.so");
    EXPECT_EQ(dedupSoInfoList[0].originalSha256, VALID_SHA);
    result = parser.ParseDedupFiles(RESOURCE_ROOT_PATH + "dedup_so/dedup_valid_multi.hap",
        BUNDLE_NAME, dedupSoInfoList);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(dedupSoInfoList.size(), 2);
    result = parser.ParseDedupFiles(RESOURCE_ROOT_PATH + "dedup_so/dedup_no_version.hap",
        BUNDLE_NAME, dedupSoInfoList);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(dedupSoInfoList.size(), 1);
    result = parser.ParseDedupFiles(RESOURCE_ROOT_PATH + "dedup_so/dedup_path_no_so_suffix.hap",
        BUNDLE_NAME, dedupSoInfoList);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(dedupSoInfoList.size(), 1);
    EXPECT_EQ(dedupSoInfoList[0].originalPathInHap, "libs/arm64-v8a/libx.txt");
    result = parser.ParseDedupFiles(RESOURCE_ROOT_PATH + "dedup_so/dedup_no_manifest.hap",
        BUNDLE_NAME, dedupSoInfoList);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(dedupSoInfoList.empty());
    // the entry-count and declared-size limits: over either limit is rejected with 8519683,
    // while a manifest of exactly MAX_DEDUP_FILES_SIZE bytes holding 65535 entries parses in full
    result = parser.ParseDedupFiles(RESOURCE_ROOT_PATH + "dedup_so/dedup_over_limit.hap",
        BUNDLE_NAME, dedupSoInfoList);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_PARSE_FAILED);
    EXPECT_TRUE(dedupSoInfoList.empty());
    result = parser.ParseDedupFiles(RESOURCE_ROOT_PATH + "dedup_so/dedup_size_over_limit.hap",
        BUNDLE_NAME, dedupSoInfoList);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_PARSE_FAILED);
    EXPECT_TRUE(dedupSoInfoList.empty());
    result = parser.ParseDedupFiles(RESOURCE_ROOT_PATH + "dedup_so/dedup_max_valid.hap",
        BUNDLE_NAME, dedupSoInfoList);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(dedupSoInfoList.size(), static_cast<size_t>(65535));
    // a deep-nesting payload is rejected before the DOM building: ~15MB of bare open brackets
    // stays under the size limit and shrinks under zip compression, yet is unbounded in depth;
    // the loose probe on the same bomb only disables the derivation
    result = parser.ParseDedupFiles(RESOURCE_ROOT_PATH + "dedup_so/dedup_depth_bomb.hap",
        BUNDLE_NAME, dedupSoInfoList);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_PARSE_FAILED);
    EXPECT_TRUE(dedupSoInfoList.empty());
    BundleExtractor bombExtractor(RESOURCE_ROOT_PATH + "dedup_so/dedup_depth_bomb.hap");
    ASSERT_TRUE(bombExtractor.Init());
    std::set<std::string> bombAbis;
    EXPECT_FALSE(bombExtractor.GetDedupSoAbiPrefixes(bombAbis));
    EXPECT_TRUE(bombAbis.empty());
    // IsDedupFilesDepthAllowed tracks strings and escapes: brackets inside string values never
    // count toward the depth, an escaped quote does not close the string, the 4th is the gate
    EXPECT_TRUE(BundleExtractor::IsDedupFilesDepthAllowed(R"({"a":"[[[["})"));
    EXPECT_TRUE(BundleExtractor::IsDedupFilesDepthAllowed(R"({"a":"x\"[[[[", "b":"y"})"));
    EXPECT_TRUE(BundleExtractor::IsDedupFilesDepthAllowed(R"({"a":"}][[", "b":"y"})"));
    EXPECT_TRUE(BundleExtractor::IsDedupFilesDepthAllowed(
        R"({"version":"1.0","removedSoFiles":[{"originalPathInHap":"libs/arm64-v8a/libx.so"}]})"));
    EXPECT_FALSE(BundleExtractor::IsDedupFilesDepthAllowed("[[[["));
}

/**
 * @tc.name: TestParse_8410
 * @tc.desc: 1. system running normally
 *           2. test ParseDedupFiles rejects invalid manifests, out-of-domain paths,
 *              backup-suffixed names, invalid sha256 values and contradictions with 8519683
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleDedupSoTest, TestParse_8410, Function | SmallTest | Level1)
{
    BundleParser parser;
    const std::vector<std::string> invalidManifests = {
        "dedup_so/dedup_invalid_json.hap",
        "dedup_so/dedup_json_array.hap",
        "dedup_so/dedup_no_removed.hap",
        "dedup_so/dedup_removed_not_array.hap",
        "dedup_so/dedup_item_not_object.hap",
        "dedup_so/dedup_no_path.hap",
        "dedup_so/dedup_no_sha.hap",
        "dedup_so/dedup_path_not_string.hap",
        "dedup_so/dedup_path_traversal.hap",
        "dedup_so/dedup_path_absolute.hap",
        "dedup_so/dedup_path_bad_prefix.hap",
        "dedup_so/dedup_path_backup_suffix.hap",
        "dedup_so/dedup_sha_invalid.hap",
    };
    for (const auto &manifest : invalidManifests) {
        DedupSoInfoList list;
        auto result = parser.ParseDedupFiles(RESOURCE_ROOT_PATH + manifest, BUNDLE_NAME, list);
        EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_PARSE_FAILED) << manifest;
        EXPECT_TRUE(list.empty()) << manifest;
    }
    // self-contradictory manifests: the same originalPathInHap twice with different sha256
    // digests, and an entry still present as a real zip entry in the same container
    DedupSoInfoList dupList;
    auto dupResult = parser.ParseDedupFiles(
        RESOURCE_ROOT_PATH + "dedup_so/dedup_duplicate_entry.hap", BUNDLE_NAME, dupList);
    EXPECT_EQ(dupResult, ERR_APPEXECFWK_INSTALL_PARSE_FAILED);
    // the list stays an intermediate state the caller must not consume on a failed parse
    EXPECT_EQ(dupList.size(), 1u);
    dupResult = parser.ParseDedupFiles(
        RESOURCE_ROOT_PATH + "dedup_so/dedup_cross_conflict.hap", BUNDLE_NAME, dupList);
    EXPECT_EQ(dupResult, ERR_APPEXECFWK_INSTALL_PARSE_FAILED);
    EXPECT_TRUE(dupList.empty());
}

/**
 * @tc.name: TestParse_8450
 * @tc.desc: 1. the full-dedup derivation over stripped/keepdir/libs-only/mismatch containers
 *           2. the so path follows the manifest abi set, a mismatch keeps the legacy empty
 *              path, the loose probe never turns into an install error
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleDedupSoTest, TestParse_8450, Function | SmallTest | Level1)
{
    const std::string strippedPath = RESOURCE_ROOT_PATH + "dedup_so/dedup_fulldedup_stripped.hap";
    BundleExtractor bundleExtractor(strippedPath);
    ASSERT_TRUE(bundleExtractor.Init());
    std::ostringstream profileFileBuffer;
    ASSERT_TRUE(bundleExtractor.ExtractProfile(profileFileBuffer));
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsNewVersion(true);
    ModuleProfile moduleProfile;
    auto result = moduleProfile.TransformTo(profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK);
    std::set<std::string> abis;
    EXPECT_TRUE(bundleExtractor.GetDedupSoAbiPrefixes(abis));
    EXPECT_EQ(abis.size(), 1u);
    EXPECT_EQ(*abis.begin(), CPU_ABI_ARM64);
    BundleExtractor keepdirExtractor(RESOURCE_ROOT_PATH + "dedup_so/dedup_fulldedup_keepdir.hap");
    ASSERT_TRUE(keepdirExtractor.Init());
    EXPECT_TRUE(keepdirExtractor.GetDedupSoAbiPrefixes(abis));
    EXPECT_EQ(abis.size(), 1u);
    EXPECT_EQ(*abis.begin(), CPU_ABI_ARM64);
    BundleExtractor noManifestExtractor(RESOURCE_ROOT_PATH + "dedup_so/dedup_no_manifest.hap");
    ASSERT_TRUE(noManifestExtractor.Init());
    EXPECT_FALSE(noManifestExtractor.GetDedupSoAbiPrefixes(abis));
    EXPECT_TRUE(abis.empty());
    BundleExtractor overSizeExtractor(RESOURCE_ROOT_PATH + "dedup_so/dedup_size_over_limit.hap");
    ASSERT_TRUE(overSizeExtractor.Init());
    EXPECT_FALSE(overSizeExtractor.GetDedupSoAbiPrefixes(abis));
    EXPECT_TRUE(abis.empty());
    BundleExtractor invalidExtractor(RESOURCE_ROOT_PATH + "dedup_so/dedup_invalid_json.hap");
    ASSERT_TRUE(invalidExtractor.Init());
    EXPECT_FALSE(invalidExtractor.GetDedupSoAbiPrefixes(abis));
    EXPECT_TRUE(abis.empty());
    // libs-only form: no libs/<abi>/ dir entry, the abi choice comes from the manifest
    BundleExtractor libsOnlyExtractor(RESOURCE_ROOT_PATH + "dedup_so/dedup_fulldedup_libsonly.hap");
    ASSERT_TRUE(libsOnlyExtractor.Init());
    ASSERT_FALSE(libsOnlyExtractor.IsDirExist(
        std::string(ServiceConstants::LIBS) + CPU_ABI_ARM64 + ServiceConstants::PATH_SEPARATOR));
    std::ostringstream libsOnlyBuffer;
    ASSERT_TRUE(libsOnlyExtractor.ExtractProfile(libsOnlyBuffer));
    InnerBundleInfo libsOnlyInfo;
    libsOnlyInfo.SetIsNewVersion(true);
    auto libsOnlyResult = moduleProfile.TransformTo(libsOnlyBuffer, libsOnlyExtractor, libsOnlyInfo);
    EXPECT_EQ(libsOnlyResult, ERR_OK);
    // mismatch form: falls back to the legacy empty path, the helper fails closed at install time
    BundleExtractor mismatchExtractor(RESOURCE_ROOT_PATH + "dedup_so/dedup_fulldedup_stripped_mismatch.hap");
    ASSERT_TRUE(mismatchExtractor.Init());
    EXPECT_TRUE(mismatchExtractor.GetDedupSoAbiPrefixes(abis));
    EXPECT_EQ(abis.size(), 1u);
    EXPECT_EQ(*abis.begin(), CPU_ABI_X86_64);
    std::ostringstream mismatchBuffer;
    ASSERT_TRUE(mismatchExtractor.ExtractProfile(mismatchBuffer));
    InnerBundleInfo mismatchInfo;
    mismatchInfo.SetIsNewVersion(true);
    auto mismatchResult = moduleProfile.TransformTo(mismatchBuffer, mismatchExtractor, mismatchInfo);
    EXPECT_EQ(mismatchResult, ERR_OK);
    EXPECT_TRUE(mismatchInfo.GetNativeLibraryPath().empty());
}

// Mock remote object driving the real InstalldProxy::LinkDedupedSo reply: [errCode][resultCode unless truncated].
class MockInstalldRemoteObject : public IRemoteObject {
public:
    MockInstalldRemoteObject() : IRemoteObject(u"ohos.bundleManager.Installd") {}
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        lastCode_ = code;
        reply.WriteInt32(ERR_OK);
        if (!truncatedReply_) {
            reply.WriteUint32(resultCode_);
        }
        return 0;
    }
    sptr<IRemoteBroker> AsInterface() override { return nullptr; }
    int32_t GetObjectRefCount() override { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) override { return 0; }

    bool truncatedReply_ = false;
    uint32_t resultCode_ = SO_DEDUP_RESULT_LINKED;
    uint32_t lastCode_ = 0;
};

/**
 * @tc.number: InstalldProxyTest_10000
 * @tc.name: test the LinkDedupedSo wire: the host uid gate fires first, the proxy fails closed
 * @tc.desc: 1. the host impl with a denied caller, then the real proxy against a mock remote
 *              with a truncated and a well-formed reply
 *           2. the uid gate fires before any param validation; a truncated reply fails closed
 */
HWTEST_F(BmsBundleDedupSoTest, InstalldProxyTest_10000, Function | SmallTest | Level0)
{
    sptr<InstalldHostImpl> hostImpl = new (std::nothrow) InstalldHostImpl();
    ASSERT_NE(hostImpl, nullptr);
    const std::string libraryPath = std::string(Constants::BUNDLE_CODE_DIR) + "/" + BUNDLE_NAME +
        "/libs/" + CPU_ABI_ARM64 + "/" + LINKED_SO;
    uint32_t resultCode = 0;
    EXPECT_EQ(hostImpl->LinkDedupedSo(BUNDLE_NAME, libraryPath, VALID_SHA, resultCode),
        ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
    // gate order: no param semantics can be probed by a non-Foundation caller
    EXPECT_EQ(hostImpl->LinkDedupedSo("", "", "", resultCode),
        ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
    auto mockRemote = sptr<MockInstalldRemoteObject>(new MockInstalldRemoteObject());
    InstalldProxy proxy(mockRemote);
    resultCode = SO_DEDUP_RESULT_NO_MATCH;
    mockRemote->truncatedReply_ = true;
    EXPECT_EQ(proxy.LinkDedupedSo(BUNDLE_NAME, libraryPath, VALID_SHA, resultCode),
        ERR_APPEXECFWK_PARCEL_ERROR);
    EXPECT_EQ(mockRemote->lastCode_,
        static_cast<uint32_t>(InstalldInterfaceCode::LINK_DEDUPED_SO));
    // the well-formed control reply keeps the contract: the payload code survives the IPC
    mockRemote->truncatedReply_ = false;
    mockRemote->resultCode_ = SO_DEDUP_RESULT_NO_MATCH;
    resultCode = SO_DEDUP_RESULT_LINKED;
    EXPECT_EQ(proxy.LinkDedupedSo(BUNDLE_NAME, libraryPath, VALID_SHA, resultCode), ERR_OK);
    EXPECT_EQ(resultCode, SO_DEDUP_RESULT_NO_MATCH);
}

/**
 * @tc.number: InstalldOperatorTest_20300
 * @tc.name: test IsValidDedupSoSha256 and IsValidDedupSoPath domain validation
 * @tc.desc: 1. the installd-side validators over malformed/cross-domain/clone/symlink inputs
 *           2. only exactly 64 hex chars pass the sha gate; the link path stays inside the
 *              bundle's own code, staging or clone dir whose domain root is a real dir
 */
HWTEST_F(BmsBundleDedupSoTest, InstalldOperatorTest_20300, Function | SmallTest | Level0)
{
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoSha256(""));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoSha256("abc"));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoSha256(std::string(63, 'a')));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoSha256(std::string(65, 'a')));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoSha256(
        "zzb7479487ad9f817f0fd66f6dcb1c2957e7ca68b432b6f95f1f56bfc976bd60"));
    EXPECT_TRUE(InstalldOperator::IsValidDedupSoSha256(VALID_SHA));
    EXPECT_TRUE(InstalldOperator::IsValidDedupSoSha256(
        "31B7479487AD9F817F0FD66F6DCB1C2957E7CA68B432B6F95F1F56BFC976BD60"));
    const std::string bundleName = "com.example.dedupso";
    const std::string codeDir = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR;
    const std::string ownLibsDir = codeDir + bundleName + "/libs/arm64-v8a/";
    const std::string stagingLibsDir = codeDir + ServiceConstants::BUNDLE_NEW_CODE_DIR + bundleName +
        "/libs/arm64-v8a/";
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath("", ownLibsDir + "libx.so"));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(bundleName, "/data/test/libx.so"));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(bundleName,
        codeDir + "com.example.other/libs/arm64-v8a/libx.so"));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(bundleName, ownLibsDir + "../libx.so"));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(bundleName, ownLibsDir + "libx.so"));
    // a non-dir entry cannot serve as the domain root: the lstat gate requires a real directory
    CreateFile(codeDir + bundleName, "not-a-dir");
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(bundleName, ownLibsDir + "libx.so"));
    DeleteFile(codeDir + bundleName);
    CreateQuickFileDir(codeDir + bundleName);
    EXPECT_TRUE(InstalldOperator::IsValidDedupSoPath(bundleName, ownLibsDir + "libx.so"));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(bundleName, stagingLibsDir + "libx.so"));
    CreateQuickFileDir(codeDir + ServiceConstants::BUNDLE_NEW_CODE_DIR + bundleName);
    EXPECT_TRUE(InstalldOperator::IsValidDedupSoPath(bundleName, stagingLibsDir + "libx.so"));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(bundleName,
        codeDir + ServiceConstants::BUNDLE_NEW_CODE_DIR + "com.example.other/libs/arm64-v8a/libx.so"));
    DeleteQuickFileDir(codeDir + bundleName);
    DeleteQuickFileDir(codeDir + ServiceConstants::BUNDLE_NEW_CODE_DIR + bundleName);
    // clone effective names: the link path stays inside the clone's own code dir
    const std::string dualModeName = std::string(ServiceConstants::CLONE_PREFIX) +
        std::to_string(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX) + ServiceConstants::PLUS_SIGN + BUNDLE_NAME;
    const std::string cloneName = std::string(ServiceConstants::CLONE_PREFIX) + "2" +
        ServiceConstants::PLUS_SIGN + BUNDLE_NAME;
    const std::string dualModeLibsDir = codeDir + dualModeName + "/libs/arm64-v8a/";
    const std::string cloneLibsDir = codeDir + cloneName + "/libs/arm64-v8a/";
    const std::string cloneStagingLibsDir = codeDir + ServiceConstants::BUNDLE_NEW_CODE_DIR + dualModeName +
        "/libs/arm64-v8a/";
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(
        std::string(ServiceConstants::CLONE_PREFIX) + "abc" + ServiceConstants::PLUS_SIGN + BUNDLE_NAME,
        dualModeLibsDir + "libx.so"));
    CreateQuickFileDir(dualModeLibsDir);
    CreateQuickFileDir(cloneLibsDir);
    CreateQuickFileDir(cloneStagingLibsDir);
    EXPECT_TRUE(InstalldOperator::IsValidDedupSoPath(dualModeName, dualModeLibsDir + "libx.so"));
    EXPECT_TRUE(InstalldOperator::IsValidDedupSoPath(cloneName, cloneLibsDir + "libx.so"));
    EXPECT_TRUE(InstalldOperator::IsValidDedupSoPath(dualModeName, cloneStagingLibsDir + "libx.so"));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(dualModeName,
        codeDir + "com.example.other/libs/arm64-v8a/libx.so"));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(BUNDLE_NAME, dualModeLibsDir + "libx.so"));
    DeleteQuickFileDir(codeDir + dualModeName);
    DeleteQuickFileDir(codeDir + cloneName);
    DeleteQuickFileDir(codeDir + ServiceConstants::BUNDLE_NEW_CODE_DIR + dualModeName);
    // a symlink at the domain root: the gate judges the link inode and rejects the domain
    const std::string escapeBundleName = "com.example.dedupdomain";
    const std::string escapeLibsDir = codeDir + escapeBundleName + "/libs/arm64-v8a/";
    const std::string escapeStagingLibsDir = codeDir + ServiceConstants::BUNDLE_NEW_CODE_DIR + escapeBundleName +
        "/libs/arm64-v8a/";
    const std::string escapeRoot = codeDir + escapeBundleName;
    const std::string escapeStagingRoot = codeDir + ServiceConstants::BUNDLE_NEW_CODE_DIR + escapeBundleName;
    const std::string outsideDir = "/data/test/dedup_domain_escape";
    ASSERT_TRUE(OHOS::ForceCreateDirectory(outsideDir));
    ASSERT_EQ(symlink(outsideDir.c_str(), escapeRoot.c_str()), 0);
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(escapeBundleName, escapeLibsDir + "libx.so"));
    ASSERT_EQ(symlink(outsideDir.c_str(), escapeStagingRoot.c_str()), 0);
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(escapeBundleName, escapeStagingLibsDir + "libx.so"));
    EXPECT_FALSE(InstalldOperator::IsValidDedupSoPath(escapeBundleName,
        codeDir + ServiceConstants::BUNDLE_NEW_CODE_DIR + "com.example.other/libs/arm64-v8a/libx.so"));
    EXPECT_EQ(unlink(escapeRoot.c_str()), 0);
    EXPECT_EQ(unlink(escapeStagingRoot.c_str()), 0);
    CreateQuickFileDir(escapeRoot);
    CreateQuickFileDir(escapeStagingRoot);
    EXPECT_TRUE(InstalldOperator::IsValidDedupSoPath(escapeBundleName, escapeLibsDir + "libx.so"));
    EXPECT_TRUE(InstalldOperator::IsValidDedupSoPath(escapeBundleName, escapeStagingLibsDir + "libx.so"));
    DeleteQuickFileDir(escapeRoot);
    DeleteQuickFileDir(escapeStagingRoot);
    OHOS::ForceRemoveDirectory(outsideDir);
}

/**
 * @tc.number: InstalldOperatorTest_20600
 * @tc.name: test LinkDedupedSo passes codes through and restores the rotated placeholder
 * @tc.desc: 1. call the wrapper over every result code and abnormal codes over an occupied position
 *           2. codes pass through with the path/sha args; the placeholder is rotated to a backup
 *              and renamed back, no backup left, the symlink target never touched
 */
HWTEST_F(BmsBundleDedupSoTest, InstalldOperatorTest_20600, Function | SmallTest | Level0)
{
    const std::string bundleName = "com.example.dedupso";
    const std::string ownLibsDir = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR +
        bundleName + "/libs/arm64-v8a/";
    const std::string provisionedFile = ownLibsDir + "libprovisioned.so";
    const std::string foreignLink = ownLibsDir + "libforeign.so";
    const std::string foreignTarget = ownLibsDir + "libforeign_target.so";
    CreateQuickFileDir(ownLibsDir);
    CreateFile(foreignTarget, "foreign-target-content");
    // the wrapper passes the remaining result codes through with the path/sha arguments
    const std::string libPath = ownLibsDir + LINKED_SO;
    const uint32_t passthroughCodes[] = {
        static_cast<uint32_t>(SO_DEDUP_LINKED),
        static_cast<uint32_t>(SO_DEDUP_ALREADY_LINKED),
        static_cast<uint32_t>(SO_DEDUP_VERSION_MISMATCH),
    };
    for (uint32_t injected : passthroughCodes) {
        g_muslLinkDedupedSoCallCount = 0;
        g_muslLinkDedupedSoResult = injected;
        uint32_t resultCode = SO_DEDUP_ERROR;
        EXPECT_EQ(InstalldOperator::LinkDedupedSo(libPath, VALID_SHA, resultCode), ERR_OK);
        EXPECT_EQ(resultCode, injected);
        EXPECT_EQ(g_muslLinkDedupedSoCallCount, 1);
        EXPECT_EQ(g_muslLinkDedupedSoLastPath, libPath);
        EXPECT_EQ(g_muslLinkDedupedSoLastSha, VALID_SHA);
    }
    const uint32_t abnormalCodes[] = {
        static_cast<uint32_t>(SO_DEDUP_NO_MATCH),
        static_cast<uint32_t>(SO_DEDUP_CONFIG_UNAVAILABLE),
        static_cast<uint32_t>(SO_DEDUP_ERROR),
    };
    for (uint32_t abnormal : abnormalCodes) {
        // the previous round's restore left the symlink at the link position:
        // clear it before re-provisioning the stale placeholder forms
        DeleteFile(foreignLink);
        CreateFile(provisionedFile, "provisioned-content");
        EXPECT_EQ(symlink("libforeign_target.so", foreignLink.c_str()), 0);
        g_muslLinkDedupedSoResult = abnormal;
        g_muslLinkDedupedSoCallCount = 0;
        uint32_t resultCode = SO_DEDUP_ERROR;
        auto ret = InstalldOperator::LinkDedupedSo(provisionedFile, VALID_SHA, resultCode);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_EQ(resultCode, abnormal);
        EXPECT_EQ(g_muslLinkDedupedSoCallCount, 1);
        EXPECT_EQ(g_muslLinkDedupedSoLastPath, provisionedFile);
        struct stat placeholderStat = {};
        EXPECT_EQ(lstat(provisionedFile.c_str(), &placeholderStat), 0);
        EXPECT_TRUE(S_ISREG(placeholderStat.st_mode));
        EXPECT_EQ(ReadFile(provisionedFile), "provisioned-content");
        EXPECT_FALSE(HasDedupBackupResidue(ownLibsDir));
        resultCode = SO_DEDUP_ERROR;
        ret = InstalldOperator::LinkDedupedSo(foreignLink, VALID_SHA, resultCode);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_EQ(resultCode, abnormal);
        EXPECT_EQ(g_muslLinkDedupedSoCallCount, 2);
        EXPECT_EQ(g_muslLinkDedupedSoLastPath, foreignLink);
        // the rotate moves the link inode and never goes through it, so the target survives
        EXPECT_EQ(lstat(foreignLink.c_str(), &placeholderStat), 0);
        EXPECT_TRUE(S_ISLNK(placeholderStat.st_mode));
        EXPECT_EQ(ReadFile(foreignTarget), "foreign-target-content");
        EXPECT_FALSE(HasDedupBackupResidue(ownLibsDir));
    }
    DeleteQuickFileDir(std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName);
}

/**
 * @tc.number: InstalldOperatorTest_20700
 * @tc.name: test ChangeDirOwnerRecursively never follows symlinks
 * @tc.desc: 1. chown a tree holding a regular file and an outside-pointing symlink
 *           2. the file gets the new owner while the link entry is skipped entirely: the
 *              link inode and its target both keep their original owners
 */
HWTEST_F(BmsBundleDedupSoTest, InstalldOperatorTest_20700, Function | SmallTest | Level0)
{
    if (getuid() != 0) {
        GTEST_SKIP() << "root privilege is required to change ownership, skip";
    }
    const std::string treeDir = "/data/app/el1/bundle/public/com.example.deduptrav/libs/arm64-v8a";
    const std::string insideFile = treeDir + "/libinside.so";
    const std::string insideLink = treeDir + "/libdedup.so";
    const std::string outsideTarget = "/data/test/dedup_traversal_target.so";
    const int targetUid = 1000;
    const int targetGid = 1000;
    CreateQuickFileDir(treeDir);
    CreateFile(insideFile, "inside-content");
    CreateFile(outsideTarget, "outside-content");
    EXPECT_EQ(symlink(outsideTarget.c_str(), insideLink.c_str()), 0);
    struct stat linkStatBefore = {};
    EXPECT_EQ(lstat(insideLink.c_str(), &linkStatBefore), 0);
    struct stat targetStatBefore = {};
    EXPECT_EQ(lstat(outsideTarget.c_str(), &targetStatBefore), 0);
    EXPECT_TRUE(InstalldOperator::ChangeDirOwnerRecursively(treeDir, targetUid, targetGid));
    struct stat fileStat;
    EXPECT_EQ(lstat(insideFile.c_str(), &fileStat), 0);
    EXPECT_EQ(fileStat.st_uid, static_cast<unsigned int>(targetUid));
    // chown never goes through the link: the link inode and the target keep their owners
    struct stat linkStat;
    EXPECT_EQ(lstat(insideLink.c_str(), &linkStat), 0);
    EXPECT_TRUE(S_ISLNK(linkStat.st_mode));
    EXPECT_EQ(linkStat.st_uid, linkStatBefore.st_uid);
    EXPECT_EQ(linkStat.st_gid, linkStatBefore.st_gid);
    struct stat targetStat;
    EXPECT_EQ(lstat(outsideTarget.c_str(), &targetStat), 0);
    EXPECT_EQ(targetStat.st_uid, targetStatBefore.st_uid);
    EXPECT_EQ(targetStat.st_gid, targetStatBefore.st_gid);
    EXPECT_EQ(chown(outsideTarget.c_str(), 0, 0), 0);
    DeleteQuickFileDir("/data/app/el1/bundle/public/com.example.deduptrav");
    DeleteFile(outsideTarget);
}

/**
 * @tc.number: InstalldOperatorTest_20800
 * @tc.name: test the file ops move, dispatch and copy so trees without following links
 * @tc.desc: 1. move a mixed so tree, dispatch a link/file/dir and copy a dir of links
 *           2. files land with the chmod contract, links land or are rebuilt as links with their
 *              targets untouched, socket/fifo stay in place, nothing is silently lost
 */
HWTEST_F(BmsBundleDedupSoTest, InstalldOperatorTest_20800, Function | SmallTest | Level0)
{
    ASSERT_TRUE(OHOS::ForceCreateDirectory(WORK_DIR));
    const std::string srcTree = WORK_DIR + "move_src";
    const std::string destTree = WORK_DIR + "move_dest";
    const std::string symlinkTarget = WORK_DIR + "move_target.so";
    const std::string sockPath = srcTree + "/dedup.sock";
    const std::string fifoPath = srcTree + "/dedup.fifo";
    OHOS::ForceRemoveDirectory(srcTree);
    OHOS::ForceRemoveDirectory(destTree);
    CreateQuickFileDir(srcTree);
    CreateQuickFileDir(srcTree + "/sub");
    CreateFile(srcTree + "/libnormal.so", "normal-content");
    CreateFile(srcTree + "/sub/libinner.so", "inner-content");
    CreateFile(symlinkTarget, "target-content");
    ASSERT_EQ(chmod(symlinkTarget.c_str(), S_IRUSR), 0);
    ASSERT_EQ(symlink(symlinkTarget.c_str(), (srcTree + "/libdedup.so").c_str()), 0);
    ASSERT_EQ(symlink("no_such_target.so", (srcTree + "/libdangling.so").c_str()), 0);
    int sockFd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_GE(sockFd, 0);
    struct sockaddr_un sockAddr = {};
    sockAddr.sun_family = AF_UNIX;
    strncpy(sockAddr.sun_path, sockPath.c_str(), sizeof(sockAddr.sun_path) - 1);
    ASSERT_EQ(bind(sockFd, reinterpret_cast<struct sockaddr *>(&sockAddr), sizeof(sockAddr)), 0);
    close(sockFd);
    ASSERT_EQ(mkfifo(fifoPath.c_str(), S_IRUSR | S_IWUSR), 0);
    EXPECT_TRUE(InstalldOperator::MoveFiles(srcTree, destTree, true));
    struct stat fileStat = {};
    EXPECT_EQ(lstat((destTree + "/libnormal.so").c_str(), &fileStat), 0);
    EXPECT_TRUE(S_ISREG(fileStat.st_mode));
    EXPECT_EQ(fileStat.st_mode & 0777, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    EXPECT_EQ(lstat((destTree + "/sub/libinner.so").c_str(), &fileStat), 0);
    EXPECT_TRUE(S_ISREG(fileStat.st_mode));
    EXPECT_EQ(ReadFile(destTree + "/sub/libinner.so"), "inner-content");
    struct stat linkStat = {};
    EXPECT_EQ(lstat((destTree + "/libdedup.so").c_str(), &linkStat), 0);
    EXPECT_TRUE(S_ISLNK(linkStat.st_mode));
    char readTarget[PATH_MAX] = {0};
    auto readSize = readlink((destTree + "/libdedup.so").c_str(), readTarget, sizeof(readTarget) - 1);
    EXPECT_GT(readSize, 0);
    EXPECT_EQ(std::string(readTarget), symlinkTarget);
    // the target keeps its content and pinned mode: never chmod'ed through the link
    struct stat targetStat = {};
    EXPECT_EQ(lstat(symlinkTarget.c_str(), &targetStat), 0);
    EXPECT_EQ(targetStat.st_mode & 0777, S_IRUSR);
    EXPECT_EQ(ReadFile(symlinkTarget), "target-content");
    EXPECT_EQ(lstat((destTree + "/libdangling.so").c_str(), &linkStat), 0);
    EXPECT_TRUE(S_ISLNK(linkStat.st_mode));
    EXPECT_EQ(lstat(sockPath.c_str(), &linkStat), 0);
    EXPECT_TRUE(S_ISSOCK(linkStat.st_mode));
    EXPECT_EQ(lstat(fifoPath.c_str(), &linkStat), 0);
    EXPECT_TRUE(S_ISFIFO(linkStat.st_mode));
    EXPECT_EQ(lstat((destTree + "/dedup.sock").c_str(), &linkStat), -1);
    EXPECT_EQ(lstat((destTree + "/dedup.fifo").c_str(), &linkStat), -1);
    DeleteQuickFileDir(srcTree);
    DeleteQuickFileDir(destTree);
    DeleteFile(symlinkTarget);
    // MoveFileOrDir dispatches on the lstat'ed mode: link, regular file, then dir
    const std::string targetPath = WORK_DIR + "dispatch_target.so";
    const std::string srcLink = WORK_DIR + "dispatch_link.so";
    const std::string destLink = WORK_DIR + "dispatch_link_dest.so";
    const std::string srcFile = WORK_DIR + "dispatch_file.so";
    const std::string destFile = WORK_DIR + "dispatch_file_dest.so";
    const std::string innerDir = WORK_DIR + "dispatch_inner";
    const std::string innerSo = innerDir + "/libinner.so";
    const std::string movedDir = WORK_DIR + "dispatch_moved_dir";
    ASSERT_TRUE(unlink(srcLink.c_str()) == 0 || errno == ENOENT);
    ASSERT_TRUE(unlink(destLink.c_str()) == 0 || errno == ENOENT);
    ASSERT_TRUE(unlink(destFile.c_str()) == 0 || errno == ENOENT);
    CreateFile(targetPath, "target-content");
    CreateFile(srcFile, "file-content");
    CreateQuickFileDir(innerDir);
    CreateFile(innerSo, "inner-content");
    ASSERT_EQ(chmod(targetPath.c_str(), S_IRUSR), 0);
    ASSERT_EQ(symlink(targetPath.c_str(), srcLink.c_str()), 0);
    struct stat srcLinkStat = {};
    ASSERT_EQ(lstat(srcLink.c_str(), &srcLinkStat), 0);
    EXPECT_TRUE(InstalldOperator::MoveFileOrDir(srcLink, destLink, srcLinkStat.st_mode));
    struct stat destLinkStat = {};
    EXPECT_EQ(lstat(destLink.c_str(), &destLinkStat), 0);
    EXPECT_TRUE(S_ISLNK(destLinkStat.st_mode));
    char dispatchReadTarget[PATH_MAX] = {0};
    auto dispatchReadSize = readlink(destLink.c_str(), dispatchReadTarget, sizeof(dispatchReadTarget) - 1);
    EXPECT_GT(dispatchReadSize, 0);
    EXPECT_EQ(std::string(dispatchReadTarget), targetPath);
    struct stat goneStat = {};
    EXPECT_NE(lstat(srcLink.c_str(), &goneStat), 0);
    // no chmod went through the link: the target keeps the pinned 0400 mode
    struct stat dispatchTargetStat = {};
    EXPECT_EQ(lstat(targetPath.c_str(), &dispatchTargetStat), 0);
    EXPECT_EQ(dispatchTargetStat.st_mode & 0777, S_IRUSR);
    EXPECT_EQ(ReadFile(targetPath), "target-content");
    struct stat srcFileStat = {};
    ASSERT_EQ(lstat(srcFile.c_str(), &srcFileStat), 0);
    EXPECT_TRUE(InstalldOperator::MoveFileOrDir(srcFile, destFile, srcFileStat.st_mode));
    struct stat destFileStat = {};
    EXPECT_EQ(lstat(destFile.c_str(), &destFileStat), 0);
    EXPECT_TRUE(S_ISREG(destFileStat.st_mode));
    EXPECT_EQ(destFileStat.st_mode & 0777, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    EXPECT_EQ(ReadFile(destFile), "file-content");
    // the dir dispatch moves only the contents, the source dir stays for the caller
    struct stat dirStat = {};
    ASSERT_EQ(lstat(innerDir.c_str(), &dirStat), 0);
    EXPECT_TRUE(InstalldOperator::MoveFileOrDir(innerDir, movedDir, dirStat.st_mode));
    struct stat movedDirStat = {};
    EXPECT_EQ(lstat(movedDir.c_str(), &movedDirStat), 0);
    EXPECT_TRUE(S_ISDIR(movedDirStat.st_mode));
    EXPECT_EQ(lstat((movedDir + "/libinner.so").c_str(), &movedDirStat), 0);
    EXPECT_TRUE(S_ISREG(movedDirStat.st_mode));
    EXPECT_EQ(ReadFile(movedDir + "/libinner.so"), "inner-content");
    EXPECT_EQ(lstat(innerDir.c_str(), &movedDirStat), 0);
    EXPECT_TRUE(S_ISDIR(movedDirStat.st_mode));
    EXPECT_EQ(lstat(innerSo.c_str(), &movedDirStat), -1);
    EXPECT_EQ(unlink(destLink.c_str()), 0);
    DeleteFile(destFile);
    DeleteFile(targetPath);
    DeleteQuickFileDir(innerDir);
    DeleteQuickFileDir(movedDir);
    // CopyDir rebuilds symlinks instead of copying their targets
    const std::string copyRootDir = WORK_DIR + "dedup_copydir";
    const std::string srcDir = copyRootDir + "/src/libs/arm64-v8a";
    const std::string destDir = copyRootDir + "/dest/libs/arm64-v8a";
    const std::string plainFile = srcDir + "/libplain.so";
    const std::string linkTarget = "libdedup_target.so";
    const std::string copySrcLink = srcDir + "/libdedup.so";
    const std::string danglingLink = srcDir + "/libdangling.so";
    CreateQuickFileDir(srcDir);
    CreateFile(plainFile, "plain-content");
    CreateFile(srcDir + "/" + linkTarget, "target-content");
    EXPECT_EQ(symlink(linkTarget.c_str(), copySrcLink.c_str()), 0);
    EXPECT_EQ(symlink("no_such_target.so", danglingLink.c_str()), 0);
    EXPECT_EQ(chmod(plainFile.c_str(), S_IRUSR | S_IWUSR | S_IRGRP), 0);
    EXPECT_TRUE(InstalldOperator::CopyDir(srcDir, destDir));
    struct stat copyFileStat = {};
    EXPECT_EQ(lstat((destDir + "/libplain.so").c_str(), &copyFileStat), 0);
    EXPECT_TRUE(S_ISREG(copyFileStat.st_mode));
    EXPECT_EQ(copyFileStat.st_mode & 0777, S_IRUSR | S_IWUSR | S_IRGRP);
    EXPECT_EQ(ReadFile(destDir + "/libplain.so"), "plain-content");
    // the live link is rebuilt as a link to the same target: never a copy of the target content
    struct stat copyLinkStat = {};
    EXPECT_EQ(lstat((destDir + "/libdedup.so").c_str(), &copyLinkStat), 0);
    EXPECT_TRUE(S_ISLNK(copyLinkStat.st_mode));
    char copiedTarget[PATH_MAX] = {0};
    auto copiedSize = readlink((destDir + "/libdedup.so").c_str(), copiedTarget, sizeof(copiedTarget) - 1);
    EXPECT_GT(copiedSize, 0);
    copiedTarget[copiedSize] = '\0';
    EXPECT_EQ(std::string(copiedTarget), linkTarget);
    struct stat destDanglingStat = {};
    EXPECT_EQ(lstat((destDir + "/libdangling.so").c_str(), &destDanglingStat), 0);
    EXPECT_TRUE(S_ISLNK(destDanglingStat.st_mode));
    char copiedDangling[PATH_MAX] = {0};
    auto danglingSize = readlink((destDir + "/libdangling.so").c_str(), copiedDangling,
        sizeof(copiedDangling) - 1);
    EXPECT_GT(danglingSize, 0);
    copiedDangling[danglingSize] = '\0';
    EXPECT_EQ(std::string(copiedDangling), "no_such_target.so");
    DeleteQuickFileDir(copyRootDir);
    OHOS::ForceRemoveDirectory(WORK_DIR);
}

/**
 * @tc.number: InstalldOperatorTest_21100
 * @tc.name: test LinkDedupedSo placeholder rotate, backup cleanup and interrupted recovery
 * @tc.desc: 1. a stale file/symlink, a directory, a leftover backup, position plus backup
 *           2. success deletes the rotated token backup; a directory is refused
 *              fail-closed; a leftover backup is an unrecognized inert orphan;
 *              position plus leftover proceeds with the rotation
 */
HWTEST_F(BmsBundleDedupSoTest, InstalldOperatorTest_21100, Function | SmallTest | Level0)
{
    const std::string bundleName = "com.example.dedupclear";
    const std::string libsDir = std::string(Constants::BUNDLE_CODE_DIR) + "/" + bundleName +
        "/libs/" + CPU_ABI_ARM64 + "/";
    const std::string libPath = libsDir + "libclear.so";
    const std::string linkTarget = libsDir + "libclear_target.so";
    const std::string backupPath = libPath + ServiceConstants::DEDUP_SO_BACKUP_SUFFIX;
    CreateQuickFileDir(libsDir);
    struct stat placeholderStat = {};
    g_muslLinkDedupedSoResult = SO_DEDUP_LINKED;
    CreateFile(libPath, "stale-so-content");
    g_muslLinkDedupedSoCallCount = 0;
    uint32_t resultCode = SO_DEDUP_ERROR;
    EXPECT_EQ(InstalldOperator::LinkDedupedSo(libPath, VALID_SHA, resultCode), ERR_OK);
    EXPECT_EQ(resultCode, SO_DEDUP_LINKED);
    EXPECT_EQ(g_muslLinkDedupedSoCallCount, 1);
    EXPECT_EQ(g_muslLinkDedupedSoLastPath, libPath);
    EXPECT_EQ(g_muslLinkDedupedSoLastSha, VALID_SHA);
    EXPECT_EQ(lstat(libPath.c_str(), &placeholderStat), -1);
    EXPECT_FALSE(HasDedupBackupResidue(libsDir));
    CreateFile(linkTarget, "target-content");
    EXPECT_EQ(symlink("libclear_target.so", libPath.c_str()), 0);
    g_muslLinkDedupedSoCallCount = 0;
    resultCode = SO_DEDUP_ERROR;
    EXPECT_EQ(InstalldOperator::LinkDedupedSo(libPath, VALID_SHA, resultCode), ERR_OK);
    EXPECT_EQ(resultCode, SO_DEDUP_LINKED);
    EXPECT_EQ(g_muslLinkDedupedSoCallCount, 1);
    EXPECT_EQ(g_muslLinkDedupedSoLastPath, libPath);
    EXPECT_EQ(lstat(libPath.c_str(), &placeholderStat), -1);
    EXPECT_EQ(ReadFile(linkTarget), "target-content");
    EXPECT_FALSE(HasDedupBackupResidue(libsDir));
    // a dir placeholder is kept as-is: an unknown tree is never deleted recursively
    CreateQuickFileDir(libPath);
    CreateFile(libPath + "/inner.so", "inner-content");
    g_muslLinkDedupedSoCallCount = 0;
    resultCode = SO_DEDUP_LINKED;
    EXPECT_EQ(InstalldOperator::LinkDedupedSo(libPath, VALID_SHA, resultCode),
        ERR_APPEXECFWK_INSTALLD_DEDUP_SO_LINK_FAILED);
    EXPECT_EQ(g_muslLinkDedupedSoCallCount, 0);
    struct stat dirStat = {};
    EXPECT_EQ(lstat(libPath.c_str(), &dirStat), 0);
    EXPECT_TRUE(S_ISDIR(dirStat.st_mode));
    EXPECT_EQ(ReadFile(libPath + "/inner.so"), "inner-content");
    DeleteQuickFileDir(libPath);
    g_muslLinkDedupedSoCallCount = 0;
    resultCode = SO_DEDUP_ERROR;
    EXPECT_EQ(InstalldOperator::LinkDedupedSo(libPath, VALID_SHA, resultCode), ERR_OK);
    EXPECT_EQ(resultCode, SO_DEDUP_LINKED);
    EXPECT_EQ(g_muslLinkDedupedSoCallCount, 1);
    EXPECT_EQ(g_muslLinkDedupedSoLastPath, libPath);
    // a leftover backup of an interrupted attempt: the token scheme cannot
    // recognize it by name, so nothing is adopted or restored - the position
    // links fresh and the orphan waits for the directory-level cleanup
    CreateFile(backupPath, "interrupted-old-so");
    g_muslLinkDedupedSoResult = static_cast<uint32_t>(SO_DEDUP_NO_MATCH);
    g_muslLinkDedupedSoCallCount = 0;
    resultCode = SO_DEDUP_ERROR;
    EXPECT_EQ(InstalldOperator::LinkDedupedSo(libPath, VALID_SHA, resultCode), ERR_OK);
    EXPECT_EQ(resultCode, static_cast<uint32_t>(SO_DEDUP_NO_MATCH));
    EXPECT_EQ(g_muslLinkDedupedSoCallCount, 1);
    EXPECT_EQ(g_muslLinkDedupedSoLastPath, libPath);
    struct stat orphanStat = {};
    EXPECT_EQ(lstat(libPath.c_str(), &orphanStat), -1);
    EXPECT_EQ(lstat(backupPath.c_str(), &orphanStat), 0);
    EXPECT_TRUE(S_ISREG(orphanStat.st_mode));
    EXPECT_EQ(ReadFile(backupPath), "interrupted-old-so");
    CreateFile(backupPath, "interrupted-old-so");
    g_muslLinkDedupedSoResult = SO_DEDUP_LINKED;
    g_muslLinkDedupedSoCallCount = 0;
    resultCode = SO_DEDUP_ERROR;
    EXPECT_EQ(InstalldOperator::LinkDedupedSo(libPath, VALID_SHA, resultCode), ERR_OK);
    EXPECT_EQ(resultCode, SO_DEDUP_LINKED);
    EXPECT_EQ(g_muslLinkDedupedSoCallCount, 1);
    EXPECT_EQ(lstat(libPath.c_str(), &orphanStat), -1);
    // the success path only cleans the backup this call rotated itself: the
    // unrecognized pre-token orphan is never unlinked
    EXPECT_EQ(lstat(backupPath.c_str(), &orphanStat), 0);
    // position plus a pre-token leftover backup is no longer an ambiguous
    // interruption state: the unrecognized orphan is ignored, the stale
    // placeholder is rotated away (it yields to the link), and only the
    // orphan file survives untouched
    CreateFile(libPath, "position-content");
    CreateFile(backupPath, "stale-backup-content");
    g_muslLinkDedupedSoCallCount = 0;
    resultCode = SO_DEDUP_LINKED;
    EXPECT_EQ(InstalldOperator::LinkDedupedSo(libPath, VALID_SHA, resultCode), ERR_OK);
    EXPECT_EQ(resultCode, SO_DEDUP_LINKED);
    EXPECT_EQ(g_muslLinkDedupedSoCallCount, 1);
    EXPECT_EQ(lstat(libPath.c_str(), &orphanStat), -1);
    EXPECT_EQ(ReadFile(backupPath), "stale-backup-content");
    DeleteQuickFileDir(std::string(Constants::BUNDLE_CODE_DIR) + "/" + bundleName);
}
}  // namespace AppExecFwk
}  // namespace OHOS
