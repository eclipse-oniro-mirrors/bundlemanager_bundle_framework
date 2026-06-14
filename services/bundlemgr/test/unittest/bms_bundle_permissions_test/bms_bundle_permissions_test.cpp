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

// keep token sequence identical to the sibling TU in this test binary
#define private public
#define protected public

#include <algorithm>
#include <atomic>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

#include "bundle_info.h"
#include "bundle_permissions.h"
#include "inner_bundle_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
RequestPermission MakeSimplePermission(const std::string &name)
{
    RequestPermission perm;
    perm.name = name;
    return perm;
}

RequestPermission MakeComplexPermission(const std::string &name)
{
    RequestPermission perm;
    perm.name = name;
    perm.reasonId = 1;
    perm.reason = "reason_" + name;
    perm.requiredFeature = "feature_" + name;
    perm.usedScene.when = "always";
    perm.usedScene.abilities = { "ability_" + name };
    return perm;
}

// Builds a RequestPermission with just the fields ShouldReplacePermission inspects:
// the permission name, the owning moduleName (looked up in the type map) and reasonId.
RequestPermission MakeReqPermission(const std::string &name, const std::string &moduleName, uint32_t reasonId)
{
    RequestPermission perm;
    perm.name = name;
    perm.moduleName = moduleName;
    perm.reasonId = reasonId;
    return perm;
}

bool Contains(const std::vector<std::string> &vec, const std::string &target)
{
    return std::find(vec.begin(), vec.end(), target) != vec.end();
}

size_t PoolSize()
{
    return PermissionStringPool::GetInstance().strings_.size();
}

// Returns a permission name that is unique within this process, including across
// --gtest_repeat iterations, so "a fresh name grows the pool by N" assertions stay
// valid on every run (the pool is a process-global singleton that never shrinks).
std::string UniquePermissionName(const std::string &tag)
{
    static std::atomic<uint32_t> counter{0};
    return "ohos.permission.bms_perm_ut_" + tag + "_" + std::to_string(counter.fetch_add(1));
}
}  // namespace

class BmsBundlePermissionsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.number: PermissionStringPool_GetOrAddIndex_0100
 * @tc.name: GetOrAddIndex empty string branch
 * @tc.desc: empty string returns INVALID_STRING_IDX and never grows the pool
 */
HWTEST_F(BmsBundlePermissionsTest, GetOrAddIndex_0100, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    size_t before = PoolSize();
    EXPECT_EQ(pool.GetOrAddIndex(""), INVALID_STRING_IDX);
    EXPECT_EQ(PoolSize(), before);
}

/**
 * @tc.number: PermissionStringPool_GetOrAddIndex_0200
 * @tc.name: GetOrAddIndex add branch and dedup hit branch
 * @tc.desc: a new name grows the pool by one and returns a valid index;
 *           re-adding the same name hits the cache and does not grow the pool
 */
HWTEST_F(BmsBundlePermissionsTest, GetOrAddIndex_0200, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    const std::string name = UniquePermissionName("getoradd");

    size_t before = PoolSize();
    uint32_t idx = pool.GetOrAddIndex(name);
    EXPECT_NE(idx, INVALID_STRING_IDX);
    EXPECT_EQ(PoolSize(), before + 1);

    // dedup: same name -> same index, pool unchanged
    uint32_t idxAgain = pool.GetOrAddIndex(name);
    EXPECT_EQ(idxAgain, idx);
    EXPECT_EQ(PoolSize(), before + 1);

    // a different name -> different index, pool grows
    uint32_t idxOther = pool.GetOrAddIndex(UniquePermissionName("getoradd"));
    EXPECT_NE(idxOther, idx);
    EXPECT_EQ(PoolSize(), before + 2);
}

/**
 * @tc.number: PermissionStringPool_AppendStrings_0100
 * @tc.name: AppendStrings valid-index and invalid-index branches
 * @tc.desc: valid index resolves to the stored string, invalid index yields an
 *           empty string, and existing content of out is preserved (append)
 */
HWTEST_F(BmsBundlePermissionsTest, AppendStrings_0100, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    const std::string name = "ohos.permission.TEST_APPENDSTRINGS_0100";
    uint32_t idx = pool.GetOrAddIndex(name);
    ASSERT_NE(idx, INVALID_STRING_IDX);

    std::vector<std::string> out = { "preset" };
    pool.AppendStrings({ idx, INVALID_STRING_IDX }, out);

    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], "preset");   // append preserves existing content
    EXPECT_EQ(out[1], name);       // valid index branch
    EXPECT_EQ(out[2], "");         // invalid index branch -> empty string
}

/**
 * @tc.number: PermissionStringPool_Defrag_0100
 * @tc.name: Defrag keeps index->content mapping and dedup map valid
 * @tc.desc: after Defrag, an existing index still resolves to the same string
 *           and GetOrAddIndex of the same name returns the same index (the
 *           string_view dedup keys must be rebuilt against the new storage)
 */
HWTEST_F(BmsBundlePermissionsTest, Defrag_0100, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    const std::string name = "ohos.permission.TEST_DEFRAG_0100";
    uint32_t idx = pool.GetOrAddIndex(name);
    ASSERT_NE(idx, INVALID_STRING_IDX);

    pool.Defrag();

    std::vector<std::string> out;
    pool.AppendStrings({ idx }, out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], name);                    // index -> content preserved

    EXPECT_EQ(pool.GetOrAddIndex(name), idx);   // dedup map rebuilt correctly
}

/**
 * @tc.number: BundlePermissions_IsComplexPermission_0100
 * @tc.name: IsComplexPermission each true branch and the false branch
 * @tc.desc: every distinguishing field independently makes a permission complex,
 *           and an all-empty permission is simple
 */
HWTEST_F(BmsBundlePermissionsTest, IsComplexPermission_0100, Function | SmallTest | Level1)
{
    // false branch: nothing set
    RequestPermission simple;
    simple.name = "p";
    EXPECT_FALSE(BundlePermissions::IsComplexPermission(simple));

    // reasonId != 0
    RequestPermission byReasonId = simple;
    byReasonId.reasonId = 1;
    EXPECT_TRUE(BundlePermissions::IsComplexPermission(byReasonId));

    // reason not empty
    RequestPermission byReason = simple;
    byReason.reason = "r";
    EXPECT_TRUE(BundlePermissions::IsComplexPermission(byReason));

    // requiredFeature not empty
    RequestPermission byFeature = simple;
    byFeature.requiredFeature = "f";
    EXPECT_TRUE(BundlePermissions::IsComplexPermission(byFeature));

    // usedScene.when not empty
    RequestPermission byWhen = simple;
    byWhen.usedScene.when = "always";
    EXPECT_TRUE(BundlePermissions::IsComplexPermission(byWhen));

    // usedScene.abilities not empty
    RequestPermission byAbilities = simple;
    byAbilities.usedScene.abilities = { "a" };
    EXPECT_TRUE(BundlePermissions::IsComplexPermission(byAbilities));
}

/**
 * @tc.number: BundlePermissions_AddPermission_0100
 * @tc.name: AddPermission empty-name / simple / complex branches
 * @tc.desc: empty name is dropped, simple goes to simplePermissions, complex
 *           goes to complexPermissions with all fields kept
 */
HWTEST_F(BmsBundlePermissionsTest, AddPermission_0100, Function | SmallTest | Level1)
{
    BundlePermissions bp;

    // empty name -> dropped
    bp.AddPermission(MakeSimplePermission(""));
    EXPECT_TRUE(bp.simplePermissions.empty());
    EXPECT_TRUE(bp.complexPermissions.empty());

    // simple -> simplePermissions
    bp.AddPermission(MakeSimplePermission("ohos.permission.ADD_SIMPLE_0100"));
    EXPECT_EQ(bp.simplePermissions.size(), 1u);
    EXPECT_TRUE(bp.complexPermissions.empty());

    // complex -> complexPermissions with fields preserved
    bp.AddPermission(MakeComplexPermission("ohos.permission.ADD_COMPLEX_0100"));
    EXPECT_EQ(bp.simplePermissions.size(), 1u);
    ASSERT_EQ(bp.complexPermissions.size(), 1u);
    EXPECT_EQ(bp.complexPermissions[0].reasonId, 1u);
    EXPECT_EQ(bp.complexPermissions[0].reason, "reason_ohos.permission.ADD_COMPLEX_0100");
    EXPECT_EQ(bp.complexPermissions[0].requiredFeature, "feature_ohos.permission.ADD_COMPLEX_0100");
    EXPECT_EQ(bp.complexPermissions[0].usedScene.when, "always");
    ASSERT_EQ(bp.complexPermissions[0].usedScene.abilities.size(), 1u);
}

/**
 * @tc.number: BundlePermissions_AppendPermissionNames_0100
 * @tc.name: AppendPermissionNames empty bundle branch
 * @tc.desc: an empty BundlePermissions appends nothing and keeps out intact
 */
HWTEST_F(BmsBundlePermissionsTest, AppendPermissionNames_0100, Function | SmallTest | Level1)
{
    BundlePermissions bp;
    std::vector<std::string> out = { "keep" };
    bp.AppendPermissionNames(out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], "keep");
}

/**
 * @tc.number: BundlePermissions_AppendPermissionNames_0200
 * @tc.name: AppendPermissionNames simple-only / complex-only / both branches
 * @tc.desc: names are appended simple-first-then-complex, in insertion order,
 *           after the caller's existing content
 */
HWTEST_F(BmsBundlePermissionsTest, AppendPermissionNames_0200, Function | SmallTest | Level1)
{
    // simple only
    BundlePermissions simpleOnly;
    simpleOnly.AddPermission(MakeSimplePermission("S1_0200"));
    simpleOnly.AddPermission(MakeSimplePermission("S2_0200"));
    std::vector<std::string> out1;
    simpleOnly.AppendPermissionNames(out1);
    ASSERT_EQ(out1.size(), 2u);
    EXPECT_EQ(out1[0], "S1_0200");
    EXPECT_EQ(out1[1], "S2_0200");

    // complex only
    BundlePermissions complexOnly;
    complexOnly.AddPermission(MakeComplexPermission("C1_0200"));
    std::vector<std::string> out2;
    complexOnly.AppendPermissionNames(out2);
    ASSERT_EQ(out2.size(), 1u);
    EXPECT_EQ(out2[0], "C1_0200");

    // both, with non-empty out: order is [existing..., simple..., complex...]
    BundlePermissions both;
    both.AddPermission(MakeSimplePermission("S1_0200B"));
    both.AddPermission(MakeComplexPermission("C1_0200B"));
    both.AddPermission(MakeSimplePermission("S2_0200B"));
    std::vector<std::string> out3 = { "pre" };
    both.AppendPermissionNames(out3);
    ASSERT_EQ(out3.size(), 4u);
    EXPECT_EQ(out3[0], "pre");
    EXPECT_EQ(out3[1], "S1_0200B");   // simple, insertion order
    EXPECT_EQ(out3[2], "S2_0200B");
    EXPECT_EQ(out3[3], "C1_0200B");   // complex after all simple
}

/**
 * @tc.number: BundlePermissions_AppendPermissionNames_0300
 * @tc.name: AppendPermissionNames invalid stored index branch
 * @tc.desc: a stale/invalid index resolves to an empty string instead of OOB
 */
HWTEST_F(BmsBundlePermissionsTest, AppendPermissionNames_0300, Function | SmallTest | Level1)
{
    BundlePermissions bp;
    bp.simplePermissions.push_back(INVALID_STRING_IDX);   // crafted invalid index
    std::vector<std::string> out;
    bp.AppendPermissionNames(out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], "");
}

/**
 * @tc.number: BundlePermissions_ToBundlePermissions_0100
 * @tc.name: ToBundlePermissions empty input and empty-name filtering
 * @tc.desc: empty input yields empty result; empty-name entries are skipped
 */
HWTEST_F(BmsBundlePermissionsTest, ToBundlePermissions_0100, Function | SmallTest | Level1)
{
    BundlePermissions empty = ToBundlePermissions({});
    EXPECT_TRUE(empty.simplePermissions.empty());
    EXPECT_TRUE(empty.complexPermissions.empty());

    BundlePermissions bp = ToBundlePermissions({
        MakeSimplePermission(""),                              // skipped
        MakeSimplePermission("ohos.permission.TOBP_0100"),     // kept
    });
    EXPECT_EQ(bp.simplePermissions.size(), 1u);
    EXPECT_TRUE(bp.complexPermissions.empty());
}

/**
 * @tc.number: BundlePermissions_ToRequestPermissions_0100
 * @tc.name: ToRequestPermissions empty / simple-only / default moduleName
 * @tc.desc: empty bundle returns empty; simple-only runs the first loop only and
 *           defaults moduleName to ""
 */
HWTEST_F(BmsBundlePermissionsTest, ToRequestPermissions_0100, Function | SmallTest | Level1)
{
    EXPECT_TRUE(ToRequestPermissions(BundlePermissions{}).empty());

    BundlePermissions simpleOnly;
    simpleOnly.AddPermission(MakeSimplePermission("ohos.permission.TORP_SIMPLE_0100"));
    auto result = ToRequestPermissions(simpleOnly);   // default moduleName
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].name, "ohos.permission.TORP_SIMPLE_0100");
    EXPECT_EQ(result[0].moduleName, "");
    EXPECT_EQ(result[0].reasonId, 0u);
}

/**
 * @tc.number: BundlePermissions_ToRequestPermissions_0200
 * @tc.name: ToRequestPermissions complex-only branch, fields and moduleName
 * @tc.desc: complex-only runs the second loop only; all complex fields and the
 *           supplied moduleName are propagated
 */
HWTEST_F(BmsBundlePermissionsTest, ToRequestPermissions_0200, Function | SmallTest | Level1)
{
    BundlePermissions complexOnly;
    complexOnly.AddPermission(MakeComplexPermission("ohos.permission.TORP_COMPLEX_0200"));
    auto result = ToRequestPermissions(complexOnly, "entry");
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].name, "ohos.permission.TORP_COMPLEX_0200");
    EXPECT_EQ(result[0].moduleName, "entry");
    EXPECT_EQ(result[0].reasonId, 1u);
    EXPECT_EQ(result[0].reason, "reason_ohos.permission.TORP_COMPLEX_0200");
    EXPECT_EQ(result[0].requiredFeature, "feature_ohos.permission.TORP_COMPLEX_0200");
    EXPECT_EQ(result[0].usedScene.when, "always");
    ASSERT_EQ(result[0].usedScene.abilities.size(), 1u);
}

/**
 * @tc.number: BundlePermissions_ToRequestPermissions_0300
 * @tc.name: ToRequestPermissions both branches, order and invalid index
 * @tc.desc: output is simple-first-then-complex; an invalid complex index maps
 *           to an empty name without crashing
 */
HWTEST_F(BmsBundlePermissionsTest, ToRequestPermissions_0300, Function | SmallTest | Level1)
{
    BundlePermissions bp;
    bp.AddPermission(MakeSimplePermission("ohos.permission.TORP_S_0300"));
    bp.AddPermission(MakeComplexPermission("ohos.permission.TORP_C_0300"));
    // crafted complex entry with an invalid name index
    ComplexPermission bogus;
    bogus.nameIdx = INVALID_STRING_IDX;
    bp.complexPermissions.push_back(bogus);

    auto result = ToRequestPermissions(bp, "feature");
    ASSERT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0].name, "ohos.permission.TORP_S_0300");   // simple first
    EXPECT_EQ(result[1].name, "ohos.permission.TORP_C_0300");   // then complex
    EXPECT_EQ(result[2].name, "");                              // invalid index
    EXPECT_EQ(result[2].moduleName, "feature");
}

/**
 * @tc.number: BundlePermissions_RoundTrip_0100
 * @tc.name: ToBundlePermissions -> ToRequestPermissions preserves all fields
 * @tc.desc: a mixed permission set round-trips through the pool with names and
 *           complex fields intact (order normalized to simple-then-complex)
 */
HWTEST_F(BmsBundlePermissionsTest, RoundTrip_0100, Function | SmallTest | Level1)
{
    std::vector<RequestPermission> input = {
        MakeSimplePermission("ohos.permission.RT_S1_0100"),
        MakeComplexPermission("ohos.permission.RT_C1_0100"),
        MakeSimplePermission("ohos.permission.RT_S2_0100"),
    };
    auto bp = ToBundlePermissions(input);
    auto out = ToRequestPermissions(bp, "rtModule");
    ASSERT_EQ(out.size(), 3u);

    std::vector<std::string> names;
    for (const auto &p : out) {
        names.push_back(p.name);
        EXPECT_EQ(p.moduleName, "rtModule");
    }
    EXPECT_TRUE(Contains(names, "ohos.permission.RT_S1_0100"));
    EXPECT_TRUE(Contains(names, "ohos.permission.RT_S2_0100"));
    EXPECT_TRUE(Contains(names, "ohos.permission.RT_C1_0100"));

    // complex fields preserved on the complex entry
    auto it = std::find_if(out.begin(), out.end(),
        [](const RequestPermission &p) { return p.name == "ohos.permission.RT_C1_0100"; });
    ASSERT_NE(it, out.end());
    EXPECT_EQ(it->reasonId, 1u);
    EXPECT_EQ(it->reason, "reason_ohos.permission.RT_C1_0100");
    EXPECT_EQ(it->requiredFeature, "feature_ohos.permission.RT_C1_0100");
}

/**
 * @tc.number: PermissionStringPool_Concurrency_0100
 * @tc.name: concurrent readers while Defrag rebuilds the pool
 * @tc.desc: AppendPermissionNames/ToRequestPermissions stay correct while
 *           another thread keeps calling Defrag (string_view keys must remain
 *           valid across deque swap); run under TSAN to catch data races
 */
HWTEST_F(BmsBundlePermissionsTest, Concurrency_0100, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    std::vector<RequestPermission> reqs;
    for (int i = 0; i < 50; ++i) {
        reqs.push_back(MakeSimplePermission("ohos.permission.CONC_0100_" + std::to_string(i)));
    }
    BundlePermissions bp = ToBundlePermissions(reqs);

    constexpr int rounds = 200;
    // The writer runs a bounded number of Defrag calls and yields between them, so it
    // always terminates on its own. The previous unbounded `while (!stop)` spin hammered
    // the write lock with no pause: it could starve the reader so the reader loop never
    // finished, the stop flag was never set, and join() blocked forever (test hang).
    std::thread defragThread([&pool]() {
        for (int i = 0; i < rounds; ++i) {
            pool.Defrag();
            std::this_thread::yield();
        }
    });

    for (int round = 0; round < rounds; ++round) {
        std::vector<std::string> names;
        bp.AppendPermissionNames(names);
        EXPECT_EQ(names.size(), 50u);
        auto rp = ToRequestPermissions(bp, "m");
        EXPECT_EQ(rp.size(), 50u);
    }

    defragThread.join();
}

/**
 * @tc.number: PermissionStringPool_Dedup_0100
 * @tc.name: the pool keeps a single physical copy shared by independent owners
 * @tc.desc: adding the same name through two separate BundlePermissions grows the
 *           pool by exactly one and yields the same index - the core memory-dedup
 *           guarantee of this change
 */
HWTEST_F(BmsBundlePermissionsTest, Dedup_0100, Function | SmallTest | Level1)
{
    const std::string name = UniquePermissionName("dedup");
    size_t before = PoolSize();

    BundlePermissions bp1;
    bp1.AddPermission(MakeSimplePermission(name));
    BundlePermissions bp2;
    bp2.AddPermission(MakeSimplePermission(name));

    EXPECT_EQ(PoolSize(), before + 1);   // only one physical copy stored
    ASSERT_EQ(bp1.simplePermissions.size(), 1u);
    ASSERT_EQ(bp2.simplePermissions.size(), 1u);
    EXPECT_EQ(bp1.simplePermissions[0], bp2.simplePermissions[0]);   // shared index
}

/**
 * @tc.number: PermissionStringPool_Dedup_0200
 * @tc.name: a simple and a complex permission with the same name share one index
 * @tc.desc: name dedup spans the simple/complex split; the pool grows by one and
 *           both entries reference the same index
 */
HWTEST_F(BmsBundlePermissionsTest, Dedup_0200, Function | SmallTest | Level1)
{
    const std::string name = UniquePermissionName("dedup");
    size_t before = PoolSize();

    BundlePermissions bp;
    bp.AddPermission(MakeSimplePermission(name));
    bp.AddPermission(MakeComplexPermission(name));

    EXPECT_EQ(PoolSize(), before + 1);
    ASSERT_EQ(bp.simplePermissions.size(), 1u);
    ASSERT_EQ(bp.complexPermissions.size(), 1u);
    EXPECT_EQ(bp.simplePermissions[0], bp.complexPermissions[0].nameIdx);
}

/**
 * @tc.number: BundlePermissions_AddPermission_0200
 * @tc.name: AddPermission keeps duplicates at module scope but pools one copy
 * @tc.desc: adding the same simple name twice produces two entries (no module-level
 *           dedup) that share a single pooled string
 */
HWTEST_F(BmsBundlePermissionsTest, AddPermission_0200, Function | SmallTest | Level1)
{
    const std::string name = UniquePermissionName("adddup");
    size_t before = PoolSize();

    BundlePermissions bp;
    bp.AddPermission(MakeSimplePermission(name));
    bp.AddPermission(MakeSimplePermission(name));

    ASSERT_EQ(bp.simplePermissions.size(), 2u);                    // both kept
    EXPECT_EQ(bp.simplePermissions[0], bp.simplePermissions[1]);   // same pooled index
    EXPECT_EQ(PoolSize(), before + 1);                             // one pooled copy
}

/**
 * @tc.number: PermissionStringPool_AppendStrings_0200
 * @tc.name: AppendStrings with an empty index list is a no-op
 * @tc.desc: no indices appends nothing and leaves existing content untouched
 */
HWTEST_F(BmsBundlePermissionsTest, AppendStrings_0200, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    std::vector<std::string> out = { "a", "b" };
    pool.AppendStrings({}, out);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], "a");
    EXPECT_EQ(out[1], "b");
}

/**
 * @tc.number: PermissionStringPool_Defrag_0200
 * @tc.name: Defrag keeps every existing index resolvable and the dedup map valid
 * @tc.desc: after adding several names and calling Defrag, all indices still map
 *           to their original strings and a subsequent add of an existing name
 *           still returns its original index
 */
HWTEST_F(BmsBundlePermissionsTest, Defrag_0200, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    std::vector<std::string> names = {
        "ohos.permission.DEFRAG2_A", "ohos.permission.DEFRAG2_B", "ohos.permission.DEFRAG2_C"
    };
    std::vector<uint32_t> idx;
    for (const auto &name : names) {
        idx.push_back(pool.GetOrAddIndex(name));
    }

    pool.Defrag();

    std::vector<std::string> out;
    pool.AppendStrings(idx, out);
    ASSERT_EQ(out.size(), names.size());
    for (size_t i = 0; i < names.size(); ++i) {
        EXPECT_EQ(out[i], names[i]);   // index -> content preserved across defrag
    }
    EXPECT_EQ(pool.GetOrAddIndex(names[0]), idx[0]);   // dedup map rebuilt correctly
}

/**
 * @tc.number: InnerModuleInfo_JsonRoundTrip_0100
 * @tc.name: to_json/from_json preserves simple and complex permissions
 * @tc.desc: serializing an InnerModuleInfo to the on-disk format and reading it
 *           back keeps every permission name and all complex fields - the storage
 *           and OTA persistence path
 */
HWTEST_F(BmsBundlePermissionsTest, InnerModuleInfo_JsonRoundTrip_0100, Function | SmallTest | Level1)
{
    InnerModuleInfo module;
    module.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.JRT0100_S1"),
        MakeComplexPermission("ohos.permission.JRT0100_C1"),
        MakeSimplePermission("ohos.permission.JRT0100_S2"),
    });

    nlohmann::json jsonObject;
    to_json(jsonObject, module);
    InnerModuleInfo restored;
    from_json(jsonObject, restored);

    // simple/complex split survives the round trip
    EXPECT_EQ(restored.bundlePermissions.simplePermissions.size(), 2u);
    ASSERT_EQ(restored.bundlePermissions.complexPermissions.size(), 1u);

    auto perms = ToRequestPermissions(restored.bundlePermissions);
    ASSERT_EQ(perms.size(), 3u);
    std::vector<std::string> names;
    for (const auto &perm : perms) {
        names.push_back(perm.name);
    }
    EXPECT_TRUE(Contains(names, "ohos.permission.JRT0100_S1"));
    EXPECT_TRUE(Contains(names, "ohos.permission.JRT0100_S2"));
    EXPECT_TRUE(Contains(names, "ohos.permission.JRT0100_C1"));

    auto it = std::find_if(perms.begin(), perms.end(),
        [](const RequestPermission &perm) { return perm.name == "ohos.permission.JRT0100_C1"; });
    ASSERT_NE(it, perms.end());
    EXPECT_EQ(it->reasonId, 1u);
    EXPECT_EQ(it->reason, "reason_ohos.permission.JRT0100_C1");
    EXPECT_EQ(it->requiredFeature, "feature_ohos.permission.JRT0100_C1");
    EXPECT_EQ(it->usedScene.when, "always");
    ASSERT_EQ(it->usedScene.abilities.size(), 1u);
    EXPECT_EQ(it->usedScene.abilities[0], "ability_ohos.permission.JRT0100_C1");
}

/**
 * @tc.number: InnerModuleInfo_JsonRoundTrip_0200
 * @tc.name: the serialized requestPermissions array matches the legacy format
 * @tc.desc: each persisted entry carries an empty moduleName, so an older image
 *           rolling back after OTA can still read data written by the new code
 */
HWTEST_F(BmsBundlePermissionsTest, InnerModuleInfo_JsonRoundTrip_0200, Function | SmallTest | Level1)
{
    InnerModuleInfo module;
    module.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.JRT0200"),
    });

    nlohmann::json jsonObject;
    to_json(jsonObject, module);

    ASSERT_TRUE(jsonObject.contains("requestPermissions"));
    const auto &arr = jsonObject["requestPermissions"];
    ASSERT_TRUE(arr.is_array());
    ASSERT_EQ(arr.size(), 1u);
    EXPECT_EQ(arr[0]["name"].get<std::string>(), "ohos.permission.JRT0200");
    EXPECT_EQ(arr[0]["moduleName"].get<std::string>(), "");   // legacy on-disk format
}

/**
 * @tc.number: InnerModuleInfo_JsonRoundTrip_0300
 * @tc.name: round-tripping a module without permissions yields empty permissions
 * @tc.desc: an empty permission set serializes and reads back as empty without
 *           crashing or fabricating entries
 */
HWTEST_F(BmsBundlePermissionsTest, InnerModuleInfo_JsonRoundTrip_0300, Function | SmallTest | Level1)
{
    InnerModuleInfo module;   // no permissions
    nlohmann::json jsonObject;
    to_json(jsonObject, module);
    InnerModuleInfo restored;
    from_json(jsonObject, restored);

    EXPECT_TRUE(restored.bundlePermissions.simplePermissions.empty());
    EXPECT_TRUE(restored.bundlePermissions.complexPermissions.empty());
}

/**
 * @tc.number: InnerBundleInfo_GetAllRequestPermissions_0100
 * @tc.name: GetAllRequestPermissions tags moduleName, dedups by name and sorts
 * @tc.desc: permissions from multiple modules are tagged with their owning
 *           moduleName, duplicate names are merged into a single entry, and the
 *           result is ordered by permission name
 */
HWTEST_F(BmsBundlePermissionsTest, InnerBundleInfo_GetAllRequestPermissions_0100, Function | SmallTest | Level1)
{
    InnerModuleInfo entryModule;
    entryModule.moduleName = "entry";
    entryModule.distro.moduleType = "entry";
    entryModule.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.GARP_ENTRY_ONLY"),
        MakeSimplePermission("ohos.permission.GARP_SHARED"),
    });

    InnerModuleInfo featureModule;
    featureModule.moduleName = "feature";
    featureModule.distro.moduleType = "feature";
    featureModule.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.GARP_FEATURE_ONLY"),
        MakeSimplePermission("ohos.permission.GARP_SHARED"),
    });

    InnerBundleInfo info;
    info.innerModuleInfos_.try_emplace("entryPkg", entryModule);
    info.innerModuleInfos_.try_emplace("featurePkg", featureModule);

    auto perms = info.GetAllRequestPermissions();

    // GARP_ENTRY_ONLY, GARP_FEATURE_ONLY, GARP_SHARED -> three unique entries
    ASSERT_EQ(perms.size(), 3u);

    std::vector<std::string> names;
    for (const auto &perm : perms) {
        names.push_back(perm.name);
    }
    EXPECT_TRUE(std::is_sorted(names.begin(), names.end()));                    // ordered by name
    EXPECT_TRUE(std::adjacent_find(names.begin(), names.end()) == names.end()); // no duplicate name

    auto moduleNameOf = [&perms](const std::string &permName) -> std::string {
        auto it = std::find_if(perms.begin(), perms.end(),
            [&permName](const RequestPermission &perm) { return perm.name == permName; });
        return it == perms.end() ? std::string("<missing>") : it->moduleName;
    };
    // module-unique permissions carry their owning moduleName
    EXPECT_EQ(moduleNameOf("ohos.permission.GARP_ENTRY_ONLY"), "entry");
    EXPECT_EQ(moduleNameOf("ohos.permission.GARP_FEATURE_ONLY"), "feature");
}

/**
 * @tc.number: PermissionStringPool_GetOrAddIndex_0300
 * @tc.name: GetOrAddIndex assigns fresh names consecutive indices
 * @tc.desc: adding N brand-new names grows the pool by exactly N, every index is
 *           distinct, and indices are handed out as consecutive ascending slots
 *           (the new index equals the previous pool size)
 */
HWTEST_F(BmsBundlePermissionsTest, GetOrAddIndex_0300, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    const std::string a = UniquePermissionName("seq");
    const std::string b = UniquePermissionName("seq");
    const std::string c = UniquePermissionName("seq");

    size_t before = PoolSize();
    uint32_t ia = pool.GetOrAddIndex(a);
    uint32_t ib = pool.GetOrAddIndex(b);
    uint32_t ic = pool.GetOrAddIndex(c);

    EXPECT_EQ(PoolSize(), before + 3);
    // all distinct
    EXPECT_NE(ia, ib);
    EXPECT_NE(ib, ic);
    EXPECT_NE(ia, ic);
    // consecutive ascending slots: first fresh slot is the old size
    EXPECT_EQ(ia, static_cast<uint32_t>(before));
    EXPECT_EQ(ib, ia + 1);
    EXPECT_EQ(ic, ib + 1);
}

/**
 * @tc.number: PermissionStringPool_GetOrAddIndex_0400
 * @tc.name: GetOrAddIndex treats a whitespace-only name as a valid (non-empty) name
 * @tc.desc: only the truly empty string takes the INVALID_STRING_IDX early-return;
 *           a single space is non-empty, so it is stored, resolves back verbatim
 *           and dedups to the same index on a second add
 */
HWTEST_F(BmsBundlePermissionsTest, GetOrAddIndex_0400, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();

    uint32_t idx = pool.GetOrAddIndex(" ");
    EXPECT_NE(idx, INVALID_STRING_IDX);
    // dedup: the same whitespace name maps to the same index
    EXPECT_EQ(pool.GetOrAddIndex(" "), idx);

    std::vector<std::string> out;
    pool.AppendStrings({ idx }, out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], " ");   // stored and resolved verbatim
}

/**
 * @tc.number: PermissionStringPool_GetOrAddIndex_0500
 * @tc.name: distinct names resolve back to their own content
 * @tc.desc: two distinct fresh names get two distinct indices, and AppendStrings
 *           resolves each index back to exactly the string that was added
 */
HWTEST_F(BmsBundlePermissionsTest, GetOrAddIndex_0500, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    const std::string a = UniquePermissionName("resolve");
    const std::string b = UniquePermissionName("resolve");

    uint32_t ia = pool.GetOrAddIndex(a);
    uint32_t ib = pool.GetOrAddIndex(b);
    ASSERT_NE(ia, INVALID_STRING_IDX);
    ASSERT_NE(ib, INVALID_STRING_IDX);
    EXPECT_NE(ia, ib);

    std::vector<std::string> out;
    pool.AppendStrings({ ia, ib }, out);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], a);
    EXPECT_EQ(out[1], b);
}

/**
 * @tc.number: PermissionStringPool_AppendStrings_0300
 * @tc.name: AppendStrings preserves order, repeats duplicates, blanks invalid
 * @tc.desc: a mixed list [valid, invalid, valid, duplicate-of-first] produces the
 *           strings in the same positions, an invalid index in the middle becomes
 *           an empty string without shifting its neighbours, and a repeated index
 *           yields the string again
 */
HWTEST_F(BmsBundlePermissionsTest, AppendStrings_0300, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    const std::string nameA = "ohos.permission.APPENDSTR_0300_A";
    const std::string nameB = "ohos.permission.APPENDSTR_0300_B";
    uint32_t idxA = pool.GetOrAddIndex(nameA);
    uint32_t idxB = pool.GetOrAddIndex(nameB);
    ASSERT_NE(idxA, INVALID_STRING_IDX);
    ASSERT_NE(idxB, INVALID_STRING_IDX);

    std::vector<std::string> out;
    pool.AppendStrings({ idxA, INVALID_STRING_IDX, idxB, idxA }, out);
    ASSERT_EQ(out.size(), 4u);
    EXPECT_EQ(out[0], nameA);   // valid
    EXPECT_EQ(out[1], "");      // invalid in the middle -> empty, neighbours intact
    EXPECT_EQ(out[2], nameB);   // valid
    EXPECT_EQ(out[3], nameA);   // duplicate index -> string repeated
}

/**
 * @tc.number: PermissionStringPool_AppendStrings_0400
 * @tc.name: AppendStrings accumulates across successive calls into the same vector
 * @tc.desc: two separate AppendStrings calls append to the same out vector in call
 *           order, never clearing what an earlier call wrote
 */
HWTEST_F(BmsBundlePermissionsTest, AppendStrings_0400, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    const std::string nameA = "ohos.permission.APPENDSTR_0400_A";
    const std::string nameB = "ohos.permission.APPENDSTR_0400_B";
    uint32_t idxA = pool.GetOrAddIndex(nameA);
    uint32_t idxB = pool.GetOrAddIndex(nameB);

    std::vector<std::string> out;
    pool.AppendStrings({ idxA }, out);
    pool.AppendStrings({ idxB }, out);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], nameA);
    EXPECT_EQ(out[1], nameB);
}

/**
 * @tc.number: PermissionStringPool_Defrag_0300
 * @tc.name: Defrag never changes the entry count and is idempotent
 * @tc.desc: Defrag preserves the pool size (it only reallocates storage), calling
 *           it twice keeps the size, and a name added afterwards still takes the
 *           next consecutive slot
 */
HWTEST_F(BmsBundlePermissionsTest, Defrag_0300, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();

    size_t before = PoolSize();
    pool.Defrag();
    pool.Defrag();
    EXPECT_EQ(PoolSize(), before);   // defrag is count-stable and idempotent

    const std::string fresh = UniquePermissionName("postdefrag");
    uint32_t idx = pool.GetOrAddIndex(fresh);
    EXPECT_EQ(idx, static_cast<uint32_t>(before));   // next consecutive slot
    EXPECT_EQ(PoolSize(), before + 1);
}

/**
 * @tc.number: PermissionStringPool_Defrag_0400
 * @tc.name: Defrag keeps invalid indices invalid and valid indices resolvable
 * @tc.desc: after Defrag a previously valid index still resolves to its string and
 *           an out-of-range index still maps to an empty string - defrag never
 *           fabricates entries
 */
HWTEST_F(BmsBundlePermissionsTest, Defrag_0400, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    const std::string name = "ohos.permission.DEFRAG4_X";
    uint32_t idx = pool.GetOrAddIndex(name);
    ASSERT_NE(idx, INVALID_STRING_IDX);

    pool.Defrag();

    std::vector<std::string> out;
    pool.AppendStrings({ idx, INVALID_STRING_IDX }, out);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], name);   // valid index preserved across defrag
    EXPECT_EQ(out[1], "");     // invalid index still empty
}

/**
 * @tc.number: BundlePermissions_IsComplexPermission_0200
 * @tc.name: IsComplexPermission combined fields and non-signal fields
 * @tc.desc: a permission with several distinguishing fields set at once is complex,
 *           while name and moduleName are not complexity signals - a permission
 *           carrying only those (even a very long name) stays simple
 */
HWTEST_F(BmsBundlePermissionsTest, IsComplexPermission_0200, Function | SmallTest | Level1)
{
    // every distinguishing field set together -> still just complex
    RequestPermission combo;
    combo.name = "ohos.permission.COMBO";
    combo.reasonId = 3;
    combo.reason = "r";
    combo.requiredFeature = "f";
    combo.usedScene.when = "always";
    combo.usedScene.abilities = { "a" };
    EXPECT_TRUE(BundlePermissions::IsComplexPermission(combo));

    // a long name alone is not a complexity signal
    RequestPermission longName;
    longName.name = std::string(256, 'x');
    EXPECT_FALSE(BundlePermissions::IsComplexPermission(longName));

    // moduleName alone is not a complexity signal
    RequestPermission withModule;
    withModule.name = "ohos.permission.MOD";
    withModule.moduleName = "entry";
    EXPECT_FALSE(BundlePermissions::IsComplexPermission(withModule));
}

/**
 * @tc.number: BundlePermissions_AddPermission_0300
 * @tc.name: AddPermission routes each single complex-field variant to complex
 * @tc.desc: a permission made complex by reasonId alone and one made complex by
 *           abilities alone both land in complexPermissions in insertion order,
 *           with their unset complex fields left at defaults, while interleaved
 *           simple permissions go to simplePermissions
 */
HWTEST_F(BmsBundlePermissionsTest, AddPermission_0300, Function | SmallTest | Level1)
{
    BundlePermissions bp;
    bp.AddPermission(MakeSimplePermission("ohos.permission.ADD3_S1"));

    RequestPermission byReasonId;
    byReasonId.name = "ohos.permission.ADD3_C1";
    byReasonId.reasonId = 5;   // complex by reasonId only
    bp.AddPermission(byReasonId);

    bp.AddPermission(MakeSimplePermission("ohos.permission.ADD3_S2"));

    RequestPermission byAbilities;
    byAbilities.name = "ohos.permission.ADD3_C2";
    byAbilities.usedScene.abilities = { "a1" };   // complex by abilities only
    bp.AddPermission(byAbilities);

    ASSERT_EQ(bp.simplePermissions.size(), 2u);
    ASSERT_EQ(bp.complexPermissions.size(), 2u);

    // complex-by-reasonId: reasonId kept, other complex fields default
    EXPECT_EQ(bp.complexPermissions[0].reasonId, 5u);
    EXPECT_TRUE(bp.complexPermissions[0].reason.empty());
    EXPECT_TRUE(bp.complexPermissions[0].usedScene.abilities.empty());

    // complex-by-abilities: abilities kept, reasonId default
    EXPECT_EQ(bp.complexPermissions[1].reasonId, 0u);
    ASSERT_EQ(bp.complexPermissions[1].usedScene.abilities.size(), 1u);
    EXPECT_EQ(bp.complexPermissions[1].usedScene.abilities[0], "a1");
}

/**
 * @tc.number: BundlePermissions_AddPermission_0400
 * @tc.name: AddPermission keeps a whitespace-only name (boundary of empty guard)
 * @tc.desc: the empty-name guard rejects only the truly empty string; a single
 *           space is non-empty, so it is stored as a simple permission and resolves
 *           back verbatim
 */
HWTEST_F(BmsBundlePermissionsTest, AddPermission_0400, Function | SmallTest | Level1)
{
    BundlePermissions bp;
    bp.AddPermission(MakeSimplePermission(" "));   // non-empty -> kept

    ASSERT_EQ(bp.simplePermissions.size(), 1u);
    EXPECT_TRUE(bp.complexPermissions.empty());

    std::vector<std::string> out;
    bp.AppendPermissionNames(out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], " ");
}

/**
 * @tc.number: BundlePermissions_AppendPermissionNames_0400
 * @tc.name: AppendPermissionNames with multiple complex entries and one invalid
 * @tc.desc: names come out simple-first-then-complex in insertion order; an invalid
 *           index sitting among valid complex entries resolves to an empty string in
 *           place, leaving every other name in its original position
 */
HWTEST_F(BmsBundlePermissionsTest, AppendPermissionNames_0400, Function | SmallTest | Level1)
{
    BundlePermissions bp;
    bp.AddPermission(MakeSimplePermission("ohos.permission.APN4_S1"));
    bp.AddPermission(MakeSimplePermission("ohos.permission.APN4_S2"));
    bp.AddPermission(MakeComplexPermission("ohos.permission.APN4_C1"));
    bp.AddPermission(MakeComplexPermission("ohos.permission.APN4_C2"));
    // crafted trailing complex entry with an invalid name index
    ComplexPermission bogus;
    bogus.nameIdx = INVALID_STRING_IDX;
    bp.complexPermissions.push_back(bogus);

    std::vector<std::string> out;
    bp.AppendPermissionNames(out);
    ASSERT_EQ(out.size(), 5u);
    EXPECT_EQ(out[0], "ohos.permission.APN4_S1");   // simple, insertion order
    EXPECT_EQ(out[1], "ohos.permission.APN4_S2");
    EXPECT_EQ(out[2], "ohos.permission.APN4_C1");   // complex, insertion order
    EXPECT_EQ(out[3], "ohos.permission.APN4_C2");
    EXPECT_EQ(out[4], "");                          // invalid complex index -> empty
}

/**
 * @tc.number: BundlePermissions_ToBundlePermissions_0200
 * @tc.name: ToBundlePermissions all-complex input branch
 * @tc.desc: an all-complex input fills only complexPermissions, keeps insertion
 *           order, and preserves each entry's fields; simplePermissions stays empty
 */
HWTEST_F(BmsBundlePermissionsTest, ToBundlePermissions_0200, Function | SmallTest | Level1)
{
    BundlePermissions bp = ToBundlePermissions({
        MakeComplexPermission("ohos.permission.TOBP2_C1"),
        MakeComplexPermission("ohos.permission.TOBP2_C2"),
        MakeComplexPermission("ohos.permission.TOBP2_C3"),
    });

    EXPECT_TRUE(bp.simplePermissions.empty());
    ASSERT_EQ(bp.complexPermissions.size(), 3u);
    EXPECT_EQ(bp.complexPermissions[0].reason, "reason_ohos.permission.TOBP2_C1");
    EXPECT_EQ(bp.complexPermissions[1].requiredFeature, "feature_ohos.permission.TOBP2_C2");
    ASSERT_EQ(bp.complexPermissions[2].usedScene.abilities.size(), 1u);
    EXPECT_EQ(bp.complexPermissions[2].usedScene.abilities[0], "ability_ohos.permission.TOBP2_C3");
}

/**
 * @tc.number: BundlePermissions_ToBundlePermissions_0300
 * @tc.name: ToBundlePermissions skips multiple empty names, keeps order
 * @tc.desc: several empty-name entries interleaved with real ones are all dropped,
 *           and the surviving simple/complex entries keep their relative order
 */
HWTEST_F(BmsBundlePermissionsTest, ToBundlePermissions_0300, Function | SmallTest | Level1)
{
    BundlePermissions bp = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.TOBP3_S1"),
        MakeSimplePermission(""),                          // skipped
        MakeComplexPermission("ohos.permission.TOBP3_C1"),
        MakeSimplePermission(""),                          // skipped
        MakeSimplePermission("ohos.permission.TOBP3_S2"),
    });

    ASSERT_EQ(bp.simplePermissions.size(), 2u);
    ASSERT_EQ(bp.complexPermissions.size(), 1u);

    std::vector<std::string> out;
    bp.AppendPermissionNames(out);
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], "ohos.permission.TOBP3_S1");   // simple, insertion order
    EXPECT_EQ(out[1], "ohos.permission.TOBP3_S2");
    EXPECT_EQ(out[2], "ohos.permission.TOBP3_C1");   // complex after all simple
}

/**
 * @tc.number: BundlePermissions_ToRequestPermissions_0400
 * @tc.name: ToRequestPermissions complex-only with an explicit empty moduleName
 * @tc.desc: multiple complex entries keep their order and fields, and an explicitly
 *           passed empty moduleName is applied to every entry just like the default
 */
HWTEST_F(BmsBundlePermissionsTest, ToRequestPermissions_0400, Function | SmallTest | Level1)
{
    BundlePermissions bp;
    bp.AddPermission(MakeComplexPermission("ohos.permission.TORP4_C1"));
    bp.AddPermission(MakeComplexPermission("ohos.permission.TORP4_C2"));

    auto result = ToRequestPermissions(bp, "");   // explicit empty moduleName
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].name, "ohos.permission.TORP4_C1");
    EXPECT_EQ(result[0].moduleName, "");
    EXPECT_EQ(result[0].reason, "reason_ohos.permission.TORP4_C1");
    EXPECT_EQ(result[1].name, "ohos.permission.TORP4_C2");
    EXPECT_EQ(result[1].moduleName, "");
    EXPECT_EQ(result[1].requiredFeature, "feature_ohos.permission.TORP4_C2");
}

/**
 * @tc.number: BundlePermissions_ToRequestPermissions_0500
 * @tc.name: ToRequestPermissions leaves complex fields at defaults for simple entries
 * @tc.desc: simple permissions come back with the supplied moduleName but with every
 *           complex field at its default (reasonId 0, empty reason/feature/usedScene)
 */
HWTEST_F(BmsBundlePermissionsTest, ToRequestPermissions_0500, Function | SmallTest | Level1)
{
    BundlePermissions bp;
    bp.AddPermission(MakeSimplePermission("ohos.permission.TORP5_S1"));
    bp.AddPermission(MakeSimplePermission("ohos.permission.TORP5_S2"));

    auto result = ToRequestPermissions(bp, "mod");
    ASSERT_EQ(result.size(), 2u);
    for (const auto &perm : result) {
        EXPECT_EQ(perm.moduleName, "mod");
        EXPECT_EQ(perm.reasonId, 0u);
        EXPECT_TRUE(perm.reason.empty());
        EXPECT_TRUE(perm.requiredFeature.empty());
        EXPECT_TRUE(perm.usedScene.when.empty());
        EXPECT_TRUE(perm.usedScene.abilities.empty());
    }
}

/**
 * @tc.number: BundlePermissions_RoundTrip_0200
 * @tc.name: an all-complex set round-trips through the pool with fields intact
 * @tc.desc: ToBundlePermissions -> ToRequestPermissions on a complex-only set keeps
 *           every complex field and tags each entry with the supplied moduleName
 */
HWTEST_F(BmsBundlePermissionsTest, RoundTrip_0200, Function | SmallTest | Level1)
{
    std::vector<RequestPermission> input = {
        MakeComplexPermission("ohos.permission.RT2_C1"),
        MakeComplexPermission("ohos.permission.RT2_C2"),
    };
    auto bp = ToBundlePermissions(input);
    auto out = ToRequestPermissions(bp, "rt2Module");
    ASSERT_EQ(out.size(), 2u);

    for (const auto &perm : out) {
        EXPECT_EQ(perm.moduleName, "rt2Module");
        EXPECT_EQ(perm.reasonId, 1u);
        EXPECT_EQ(perm.usedScene.when, "always");
        EXPECT_EQ(perm.reason, "reason_" + perm.name);
        EXPECT_EQ(perm.requiredFeature, "feature_" + perm.name);
    }
    std::vector<std::string> names;
    for (const auto &perm : out) {
        names.push_back(perm.name);
    }
    EXPECT_TRUE(Contains(names, "ohos.permission.RT2_C1"));
    EXPECT_TRUE(Contains(names, "ohos.permission.RT2_C2"));
}

/**
 * @tc.number: InnerModuleInfo_JsonRoundTrip_0400
 * @tc.name: to_json/from_json preserves several complex permissions
 * @tc.desc: a module carrying two complex and one simple permission round-trips
 *           through the on-disk format keeping the simple/complex split and every
 *           complex entry's fields
 */
HWTEST_F(BmsBundlePermissionsTest, InnerModuleInfo_JsonRoundTrip_0400, Function | SmallTest | Level1)
{
    InnerModuleInfo module;
    module.bundlePermissions = ToBundlePermissions({
        MakeComplexPermission("ohos.permission.JRT4_C1"),
        MakeSimplePermission("ohos.permission.JRT4_S1"),
        MakeComplexPermission("ohos.permission.JRT4_C2"),
    });

    nlohmann::json jsonObject;
    to_json(jsonObject, module);
    InnerModuleInfo restored;
    from_json(jsonObject, restored);

    EXPECT_EQ(restored.bundlePermissions.simplePermissions.size(), 1u);
    ASSERT_EQ(restored.bundlePermissions.complexPermissions.size(), 2u);

    auto perms = ToRequestPermissions(restored.bundlePermissions);
    ASSERT_EQ(perms.size(), 3u);
    auto fieldsOf = [&perms](const std::string &name) -> const RequestPermission * {
        auto it = std::find_if(perms.begin(), perms.end(),
            [&name](const RequestPermission &perm) { return perm.name == name; });
        return it == perms.end() ? nullptr : &(*it);
    };

    const RequestPermission *c1 = fieldsOf("ohos.permission.JRT4_C1");
    ASSERT_NE(c1, nullptr);
    EXPECT_EQ(c1->reason, "reason_ohos.permission.JRT4_C1");
    EXPECT_EQ(c1->requiredFeature, "feature_ohos.permission.JRT4_C1");

    const RequestPermission *c2 = fieldsOf("ohos.permission.JRT4_C2");
    ASSERT_NE(c2, nullptr);
    EXPECT_EQ(c2->reasonId, 1u);
    EXPECT_EQ(c2->usedScene.when, "always");
}

/**
 * @tc.number: InnerModuleInfo_JsonRoundTrip_0500
 * @tc.name: from_json without a requestPermissions key yields empty permissions
 * @tc.desc: requestPermissions is an optional field; a json object missing it reads
 *           back as empty permissions instead of failing - the optional-key-absent
 *           branch of from_json
 */
HWTEST_F(BmsBundlePermissionsTest, InnerModuleInfo_JsonRoundTrip_0500, Function | SmallTest | Level1)
{
    InnerModuleInfo module;
    module.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.JRT5"),
    });

    nlohmann::json jsonObject;
    to_json(jsonObject, module);
    ASSERT_TRUE(jsonObject.contains("requestPermissions"));
    jsonObject.erase("requestPermissions");   // simulate a record without the key

    InnerModuleInfo restored;
    from_json(jsonObject, restored);
    EXPECT_TRUE(restored.bundlePermissions.simplePermissions.empty());
    EXPECT_TRUE(restored.bundlePermissions.complexPermissions.empty());
}

/**
 * @tc.number: InnerBundleInfo_GetAllRequestPermissions_0200
 * @tc.name: GetAllRequestPermissions on a bundle with no modules returns empty
 * @tc.desc: with no inner modules the collection loop never runs and the
 *           post-processing is skipped, yielding an empty result without crashing
 */
HWTEST_F(BmsBundlePermissionsTest, InnerBundleInfo_GetAllRequestPermissions_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo info;   // no modules
    auto perms = info.GetAllRequestPermissions();
    EXPECT_TRUE(perms.empty());
}

/**
 * @tc.number: InnerBundleInfo_GetAllRequestPermissions_0300
 * @tc.name: GetAllRequestPermissions on a single module tags, sorts and keeps fields
 * @tc.desc: a single module's permissions are all tagged with its moduleName, the
 *           result is ordered by permission name, and complex fields survive
 */
HWTEST_F(BmsBundlePermissionsTest, InnerBundleInfo_GetAllRequestPermissions_0300, Function | SmallTest | Level1)
{
    InnerModuleInfo module;
    module.moduleName = "entry";
    module.distro.moduleType = "entry";
    module.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.GARP3_B"),
        MakeComplexPermission("ohos.permission.GARP3_A"),
    });

    InnerBundleInfo info;
    info.innerModuleInfos_.try_emplace("entryPkg", module);

    auto perms = info.GetAllRequestPermissions();
    ASSERT_EQ(perms.size(), 2u);
    // ordered by name: ...GARP3_A precedes ...GARP3_B
    EXPECT_EQ(perms[0].name, "ohos.permission.GARP3_A");
    EXPECT_EQ(perms[1].name, "ohos.permission.GARP3_B");
    for (const auto &perm : perms) {
        EXPECT_EQ(perm.moduleName, "entry");
    }
    // complex fields preserved on the complex entry
    EXPECT_EQ(perms[0].reasonId, 1u);
    EXPECT_EQ(perms[0].reason, "reason_ohos.permission.GARP3_A");
    EXPECT_EQ(perms[0].requiredFeature, "feature_ohos.permission.GARP3_A");
}

/**
 * @tc.number: InnerBundleInfo_GetAllRequestPermissions_0400
 * @tc.name: GetAllRequestPermissions ignores modules that carry no permissions
 * @tc.desc: a permission-less module contributes nothing while a sibling module's
 *           permissions are still collected and tagged with the owning moduleName
 */
HWTEST_F(BmsBundlePermissionsTest, InnerBundleInfo_GetAllRequestPermissions_0400, Function | SmallTest | Level1)
{
    InnerModuleInfo emptyModule;
    emptyModule.moduleName = "empty";
    emptyModule.distro.moduleType = "feature";   // no permissions

    InnerModuleInfo withPerms;
    withPerms.moduleName = "entry";
    withPerms.distro.moduleType = "entry";
    withPerms.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.GARP4_X"),
    });

    InnerBundleInfo info;
    info.innerModuleInfos_.try_emplace("emptyPkg", emptyModule);
    info.innerModuleInfos_.try_emplace("entryPkg", withPerms);

    auto perms = info.GetAllRequestPermissions();
    ASSERT_EQ(perms.size(), 1u);
    EXPECT_EQ(perms[0].name, "ohos.permission.GARP4_X");
    EXPECT_EQ(perms[0].moduleName, "entry");
}

/**
 * @tc.number: PermissionStringPool_Dedup_0300
 * @tc.name: two owners of the same name resolve to one identical string
 * @tc.desc: the same name added through two independent BundlePermissions resolves,
 *           via AppendPermissionNames, to the exact same content - the single
 *           pooled copy is shared rather than duplicated per owner
 */
HWTEST_F(BmsBundlePermissionsTest, Dedup_0300, Function | SmallTest | Level1)
{
    const std::string name = UniquePermissionName("dedupstr");

    BundlePermissions bp1;
    bp1.AddPermission(MakeSimplePermission(name));
    BundlePermissions bp2;
    bp2.AddPermission(MakeSimplePermission(name));

    std::vector<std::string> out1;
    bp1.AppendPermissionNames(out1);
    std::vector<std::string> out2;
    bp2.AppendPermissionNames(out2);

    ASSERT_EQ(out1.size(), 1u);
    ASSERT_EQ(out2.size(), 1u);
    EXPECT_EQ(out1[0], name);
    EXPECT_EQ(out2[0], name);
    EXPECT_EQ(out1[0], out2[0]);   // identical content from the shared pooled copy
}

/**
 * @tc.number: BundlePermissions_AddPermission_0500
 * @tc.name: AddPermission routes the remaining single complex-field variants
 * @tc.desc: a permission made complex only by reason, only by requiredFeature, and
 *           only by usedScene.when each lands in complexPermissions with its field
 *           preserved; none of them is mistaken for a simple permission
 */
HWTEST_F(BmsBundlePermissionsTest, AddPermission_0500, Function | SmallTest | Level1)
{
    BundlePermissions bp;

    RequestPermission byReason;
    byReason.name = "ohos.permission.ADD5_C1";
    byReason.reason = "r";   // complex by reason only
    bp.AddPermission(byReason);

    RequestPermission byFeature;
    byFeature.name = "ohos.permission.ADD5_C2";
    byFeature.requiredFeature = "f";   // complex by requiredFeature only
    bp.AddPermission(byFeature);

    RequestPermission byWhen;
    byWhen.name = "ohos.permission.ADD5_C3";
    byWhen.usedScene.when = "inuse";   // complex by usedScene.when only
    bp.AddPermission(byWhen);

    EXPECT_TRUE(bp.simplePermissions.empty());
    ASSERT_EQ(bp.complexPermissions.size(), 3u);
    EXPECT_EQ(bp.complexPermissions[0].reason, "r");
    EXPECT_EQ(bp.complexPermissions[1].requiredFeature, "f");
    EXPECT_EQ(bp.complexPermissions[2].usedScene.when, "inuse");
}

/**
 * @tc.number: BundlePermissions_AppendPermissionNames_0500
 * @tc.name: AppendPermissionNames from two bundles accumulates into one vector
 * @tc.desc: calling AppendPermissionNames on two separate bundles in turn appends to
 *           the same out vector in call order and never clears what is already there
 */
HWTEST_F(BmsBundlePermissionsTest, AppendPermissionNames_0500, Function | SmallTest | Level1)
{
    BundlePermissions bp1;
    bp1.AddPermission(MakeSimplePermission("ohos.permission.APN5_A"));
    BundlePermissions bp2;
    bp2.AddPermission(MakeSimplePermission("ohos.permission.APN5_B"));

    std::vector<std::string> out = { "pre" };
    bp1.AppendPermissionNames(out);
    bp2.AppendPermissionNames(out);

    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], "pre");                       // pre-existing content kept
    EXPECT_EQ(out[1], "ohos.permission.APN5_A");    // first bundle
    EXPECT_EQ(out[2], "ohos.permission.APN5_B");    // second bundle
}

/**
 * @tc.number: BundlePermissions_ToRequestPermissions_0600
 * @tc.name: ToRequestPermissions both loops with multiple valid entries each
 * @tc.desc: with several simple and several complex permissions, the output is all
 *           simple (in order) followed by all complex (in order), every entry tagged
 *           with the supplied moduleName and only complex entries carrying a reasonId
 */
HWTEST_F(BmsBundlePermissionsTest, ToRequestPermissions_0600, Function | SmallTest | Level1)
{
    BundlePermissions bp;
    bp.AddPermission(MakeSimplePermission("ohos.permission.TORP6_S1"));
    bp.AddPermission(MakeSimplePermission("ohos.permission.TORP6_S2"));
    bp.AddPermission(MakeComplexPermission("ohos.permission.TORP6_C1"));
    bp.AddPermission(MakeComplexPermission("ohos.permission.TORP6_C2"));

    auto result = ToRequestPermissions(bp, "mixed");
    ASSERT_EQ(result.size(), 4u);
    EXPECT_EQ(result[0].name, "ohos.permission.TORP6_S1");   // simple, insertion order
    EXPECT_EQ(result[1].name, "ohos.permission.TORP6_S2");
    EXPECT_EQ(result[2].name, "ohos.permission.TORP6_C1");   // complex after all simple
    EXPECT_EQ(result[3].name, "ohos.permission.TORP6_C2");
    for (const auto &perm : result) {
        EXPECT_EQ(perm.moduleName, "mixed");
    }
    EXPECT_EQ(result[0].reasonId, 0u);   // simple keeps default reasonId
    EXPECT_EQ(result[1].reasonId, 0u);
    EXPECT_EQ(result[2].reasonId, 1u);   // complex carries its reasonId
    EXPECT_EQ(result[3].reasonId, 1u);
}

/**
 * @tc.number: InnerModuleInfo_JsonRoundTrip_0600
 * @tc.name: a complex permission serializes with all its fields in the array element
 * @tc.desc: the persisted requestPermissions entry of a complex permission carries
 *           name, reason, reasonId, requiredFeature and usedScene, with an empty
 *           moduleName to match the legacy on-disk format
 */
HWTEST_F(BmsBundlePermissionsTest, InnerModuleInfo_JsonRoundTrip_0600, Function | SmallTest | Level1)
{
    InnerModuleInfo module;
    module.bundlePermissions = ToBundlePermissions({
        MakeComplexPermission("ohos.permission.JRT6_C"),
    });

    nlohmann::json jsonObject;
    to_json(jsonObject, module);

    ASSERT_TRUE(jsonObject.contains("requestPermissions"));
    const auto &arr = jsonObject["requestPermissions"];
    ASSERT_TRUE(arr.is_array());
    ASSERT_EQ(arr.size(), 1u);
    const auto &entry = arr[0];
    EXPECT_EQ(entry["name"].get<std::string>(), "ohos.permission.JRT6_C");
    EXPECT_EQ(entry["reason"].get<std::string>(), "reason_ohos.permission.JRT6_C");
    EXPECT_EQ(entry["reasonId"].get<uint32_t>(), 1u);
    EXPECT_EQ(entry["requiredFeature"].get<std::string>(), "feature_ohos.permission.JRT6_C");
    EXPECT_EQ(entry["moduleName"].get<std::string>(), "");   // legacy on-disk format
    ASSERT_TRUE(entry.contains("usedScene"));
    EXPECT_EQ(entry["usedScene"]["when"].get<std::string>(), "always");
    ASSERT_TRUE(entry["usedScene"]["abilities"].is_array());
    ASSERT_EQ(entry["usedScene"]["abilities"].size(), 1u);
    EXPECT_EQ(entry["usedScene"]["abilities"][0].get<std::string>(), "ability_ohos.permission.JRT6_C");
}

/**
 * @tc.number: InnerBundleInfo_GetAllRequestPermissions_0500
 * @tc.name: GetAllRequestPermissions skips modules flagged needDelete
 * @tc.desc: a module whose needDelete flag is set contributes none of its
 *           permissions, while a live sibling module's permissions are still
 *           collected - the `if (needDelete) continue;` branch of the collector.
 *           This only sets an in-memory flag and calls a const query; it does not
 *           run any uninstall flow.
 */
HWTEST_F(BmsBundlePermissionsTest, InnerBundleInfo_GetAllRequestPermissions_0500, Function | SmallTest | Level1)
{
    InnerModuleInfo liveModule;
    liveModule.moduleName = "entry";
    liveModule.distro.moduleType = "entry";
    liveModule.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.GARP5_LIVE"),
    });

    InnerModuleInfo deletedModule;
    deletedModule.moduleName = "feature";
    deletedModule.distro.moduleType = "feature";
    deletedModule.needDelete = true;   // marked for deletion -> skipped by the collector
    deletedModule.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.GARP5_DELETED"),
    });

    InnerBundleInfo info;
    info.innerModuleInfos_.try_emplace("entryPkg", liveModule);
    info.innerModuleInfos_.try_emplace("featurePkg", deletedModule);

    auto perms = info.GetAllRequestPermissions();
    ASSERT_EQ(perms.size(), 1u);
    EXPECT_EQ(perms[0].name, "ohos.permission.GARP5_LIVE");

    std::vector<std::string> names;
    for (const auto &perm : perms) {
        names.push_back(perm.name);
    }
    EXPECT_FALSE(Contains(names, "ohos.permission.GARP5_DELETED"));   // needDelete module excluded
}

/**
 * @tc.number: PermissionStringPool_Concurrency_0200
 * @tc.name: many threads adding the same fresh name still store exactly one copy
 * @tc.desc: exercises the double-checked-locking add path of GetOrAddIndex - when
 *           several threads race to insert the same brand-new name, exactly one
 *           physical copy is stored and every thread observes the same index. This
 *           is the invariant the write-lock re-check (the second find under the
 *           unique_lock) exists to guarantee; run under TSAN/--gtest_repeat to stress
 *           the race window.
 */
HWTEST_F(BmsBundlePermissionsTest, Concurrency_0200, Function | SmallTest | Level1)
{
    auto &pool = PermissionStringPool::GetInstance();
    const std::string name = UniquePermissionName("dcl");
    size_t before = PoolSize();

    constexpr int threadCount = 16;
    std::vector<std::thread> threads;
    std::vector<uint32_t> results(threadCount, INVALID_STRING_IDX);
    std::atomic<int> ready{0};
    for (int i = 0; i < threadCount; ++i) {
        threads.emplace_back([&pool, &name, &results, &ready, i]() {
            ready.fetch_add(1);
            // spin until every thread is in, to maximize the overlap on the same name
            while (ready.load() < threadCount) {
            }
            results[i] = pool.GetOrAddIndex(name);
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }

    // exactly one physical copy despite the concurrent insert race
    EXPECT_EQ(PoolSize(), before + 1);
    // every thread observes the same single index
    for (int i = 0; i < threadCount; ++i) {
        EXPECT_NE(results[i], INVALID_STRING_IDX);
        EXPECT_EQ(results[i], results[0]);
    }
}

/**
 * @tc.number: InnerBundleInfo_ShouldReplacePermission_0100
 * @tc.name: ShouldReplacePermission short-circuits on a name mismatch
 * @tc.desc: when the two permissions have different names the helper returns false
 *           immediately, regardless of moduleType or reasonId - the dedup tie-break
 *           only ever compares same-named permissions. The helper is a pure const
 *           function of its arguments, so it is tested directly for deterministic,
 *           repeatable branch coverage.
 */
HWTEST_F(BmsBundlePermissionsTest, ShouldReplacePermission_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::unordered_map<std::string, std::string> typeMap = {
        { "entryMod", "entry" }, { "featureMod", "feature" }
    };

    // different names -> false even though the "new" one would otherwise win
    RequestPermission oldPerm = MakeReqPermission("ohos.permission.SRP1_A", "featureMod", 0);
    RequestPermission newPerm = MakeReqPermission("ohos.permission.SRP1_B", "entryMod", 9);
    EXPECT_FALSE(info.ShouldReplacePermission(oldPerm, newPerm, typeMap));
}

/**
 * @tc.number: InnerBundleInfo_ShouldReplacePermission_0200
 * @tc.name: ShouldReplacePermission when the existing permission has reasonId 0
 * @tc.desc: with the same name and an existing reasonId of 0, a new permission wins
 *           if it has a non-zero reasonId or comes from an entry module, and loses
 *           otherwise (including when the new module has no/unknown type)
 */
HWTEST_F(BmsBundlePermissionsTest, ShouldReplacePermission_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::unordered_map<std::string, std::string> typeMap = {
        { "entryMod", "entry" }, { "featureMod", "feature" }
    };
    const std::string name = "ohos.permission.SRP2";

    // new has a non-zero reasonId -> replace
    EXPECT_TRUE(info.ShouldReplacePermission(
        MakeReqPermission(name, "featureMod", 0), MakeReqPermission(name, "featureMod", 5), typeMap));

    // both reasonId 0 but new comes from an entry module -> replace
    EXPECT_TRUE(info.ShouldReplacePermission(
        MakeReqPermission(name, "featureMod", 0), MakeReqPermission(name, "entryMod", 0), typeMap));

    // both reasonId 0 and new is a non-entry module -> keep old
    EXPECT_FALSE(info.ShouldReplacePermission(
        MakeReqPermission(name, "featureMod", 0), MakeReqPermission(name, "featureMod", 0), typeMap));

    // both reasonId 0 and new module is unknown (absent from the map -> empty type) -> keep old
    EXPECT_FALSE(info.ShouldReplacePermission(
        MakeReqPermission(name, "featureMod", 0), MakeReqPermission(name, "ghostMod", 0), typeMap));
}

/**
 * @tc.number: InnerBundleInfo_ShouldReplacePermission_0300
 * @tc.name: ShouldReplacePermission when existing reasonId != 0 and old is non-entry
 * @tc.desc: with a non-zero existing reasonId from a non-entry (or unknown) module,
 *           a new permission wins when it comes from an entry module or has a strictly
 *           greater reasonId, loses when its reasonId is 0 or not greater
 */
HWTEST_F(BmsBundlePermissionsTest, ShouldReplacePermission_0300, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::unordered_map<std::string, std::string> typeMap = {
        { "entryMod", "entry" }, { "featureMod", "feature" }
    };
    const std::string name = "ohos.permission.SRP3";

    // new.reasonId == 0 -> never replaces a non-zero existing reasonId
    EXPECT_FALSE(info.ShouldReplacePermission(
        MakeReqPermission(name, "featureMod", 3), MakeReqPermission(name, "featureMod", 0), typeMap));

    // old non-entry, new from an entry module -> replace (entry wins regardless of value)
    EXPECT_TRUE(info.ShouldReplacePermission(
        MakeReqPermission(name, "featureMod", 3), MakeReqPermission(name, "entryMod", 2), typeMap));

    // old non-entry, new non-entry with a strictly greater reasonId -> replace
    EXPECT_TRUE(info.ShouldReplacePermission(
        MakeReqPermission(name, "featureMod", 3), MakeReqPermission(name, "featureMod", 5), typeMap));

    // old non-entry, new non-entry but reasonId not greater -> keep old
    EXPECT_FALSE(info.ShouldReplacePermission(
        MakeReqPermission(name, "featureMod", 3), MakeReqPermission(name, "featureMod", 2), typeMap));

    // old module unknown (absent -> empty type, treated as non-entry), new greater -> replace
    EXPECT_TRUE(info.ShouldReplacePermission(
        MakeReqPermission(name, "ghostMod", 3), MakeReqPermission(name, "featureMod", 5), typeMap));
}

/**
 * @tc.number: InnerBundleInfo_ShouldReplacePermission_0400
 * @tc.name: ShouldReplacePermission when existing reasonId != 0 and old is an entry
 * @tc.desc: when the existing non-zero-reasonId permission is already from an entry
 *           module, only another entry module with a strictly greater reasonId may
 *           replace it; a non-entry challenger or an equal/smaller reasonId loses
 */
HWTEST_F(BmsBundlePermissionsTest, ShouldReplacePermission_0400, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::unordered_map<std::string, std::string> typeMap = {
        { "entryMod", "entry" }, { "featureMod", "feature" }
    };
    const std::string name = "ohos.permission.SRP4";

    // old entry, new entry with a strictly greater reasonId -> replace
    EXPECT_TRUE(info.ShouldReplacePermission(
        MakeReqPermission(name, "entryMod", 3), MakeReqPermission(name, "entryMod", 5), typeMap));

    // old entry, new from a non-entry module -> keep old (only entry may displace entry)
    EXPECT_FALSE(info.ShouldReplacePermission(
        MakeReqPermission(name, "entryMod", 3), MakeReqPermission(name, "featureMod", 5), typeMap));

    // old entry, new entry but reasonId not greater (smaller) -> keep old
    EXPECT_FALSE(info.ShouldReplacePermission(
        MakeReqPermission(name, "entryMod", 3), MakeReqPermission(name, "entryMod", 2), typeMap));

    // old entry, new entry with an equal reasonId -> keep old (strictly greater required)
    EXPECT_FALSE(info.ShouldReplacePermission(
        MakeReqPermission(name, "entryMod", 3), MakeReqPermission(name, "entryMod", 3), typeMap));
}

/**
 * @tc.number: InnerBundleInfo_GetRequestPermissions_0100
 * @tc.name: GetRequestPermissions returns only the current package's permissions
 * @tc.desc: with currentPackage_ pointing at one module, the compactly stored simple
 *           and complex permissions of that module are restored (complex fields kept,
 *           moduleName left empty to match the legacy behaviour) while a sibling
 *           module's permissions are not included
 */
HWTEST_F(BmsBundlePermissionsTest, InnerBundleInfo_GetRequestPermissions_0100, Function | SmallTest | Level1)
{
    InnerModuleInfo entryModule;
    entryModule.moduleName = "entry";
    entryModule.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.GRP_SIMPLE"),
        MakeComplexPermission("ohos.permission.GRP_COMPLEX"),
    });

    InnerModuleInfo featureModule;
    featureModule.moduleName = "feature";
    featureModule.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.GRP_FEATURE_ONLY"),
    });

    InnerBundleInfo info;
    info.innerModuleInfos_.try_emplace("entryPkg", entryModule);
    info.innerModuleInfos_.try_emplace("featurePkg", featureModule);
    info.currentPackage_ = "entryPkg";

    auto perms = info.GetRequestPermissions();

    // only the current package's two permissions, the sibling module is excluded
    ASSERT_EQ(perms.size(), 2u);
    std::vector<std::string> names;
    for (const auto &perm : perms) {
        names.push_back(perm.name);
        EXPECT_TRUE(perm.moduleName.empty());   // moduleName intentionally left empty
    }
    EXPECT_TRUE(Contains(names, "ohos.permission.GRP_SIMPLE"));
    EXPECT_TRUE(Contains(names, "ohos.permission.GRP_COMPLEX"));
    EXPECT_FALSE(Contains(names, "ohos.permission.GRP_FEATURE_ONLY"));

    // the complex permission keeps every restored field
    auto it = std::find_if(perms.begin(), perms.end(),
        [](const RequestPermission &perm) { return perm.name == "ohos.permission.GRP_COMPLEX"; });
    ASSERT_NE(it, perms.end());
    EXPECT_EQ(it->reasonId, 1u);
    EXPECT_EQ(it->reason, "reason_ohos.permission.GRP_COMPLEX");
    EXPECT_EQ(it->requiredFeature, "feature_ohos.permission.GRP_COMPLEX");
    EXPECT_EQ(it->usedScene.when, "always");
    ASSERT_EQ(it->usedScene.abilities.size(), 1u);
    EXPECT_EQ(it->usedScene.abilities[0], "ability_ohos.permission.GRP_COMPLEX");
}

/**
 * @tc.number: InnerBundleInfo_GetRequestPermissions_0200
 * @tc.name: GetRequestPermissions returns empty when currentPackage_ has no module
 * @tc.desc: when currentPackage_ does not match any entry in innerModuleInfos_, the
 *           count == 0 branch is taken and an empty list is returned even though
 *           another module carries permissions
 */
HWTEST_F(BmsBundlePermissionsTest, InnerBundleInfo_GetRequestPermissions_0200, Function | SmallTest | Level1)
{
    InnerModuleInfo entryModule;
    entryModule.moduleName = "entry";
    entryModule.bundlePermissions = ToBundlePermissions({
        MakeSimplePermission("ohos.permission.GRP2_X"),
    });

    InnerBundleInfo info;
    info.innerModuleInfos_.try_emplace("entryPkg", entryModule);
    info.currentPackage_ = "noSuchPkg";   // not present in innerModuleInfos_

    auto perms = info.GetRequestPermissions();
    EXPECT_TRUE(perms.empty());
}

/**
 * @tc.number: InnerBundleInfo_GetRequestPermissions_0300
 * @tc.name: GetRequestPermissions returns empty for a current package without perms
 * @tc.desc: when currentPackage_ resolves to a module that declares no permissions,
 *           the count == 1 branch is taken but the restored list is empty
 */
HWTEST_F(BmsBundlePermissionsTest, InnerBundleInfo_GetRequestPermissions_0300, Function | SmallTest | Level1)
{
    InnerModuleInfo entryModule;
    entryModule.moduleName = "entry";   // no permissions added

    InnerBundleInfo info;
    info.innerModuleInfos_.try_emplace("entryPkg", entryModule);
    info.currentPackage_ = "entryPkg";

    auto perms = info.GetRequestPermissions();
    EXPECT_TRUE(perms.empty());
}
}  // namespace OHOS
