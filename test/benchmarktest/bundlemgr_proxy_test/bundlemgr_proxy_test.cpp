/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <benchmark/benchmark.h>

#include "bundle_constants.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_status_callback_host.h"
#include "clean_cache_callback_host.h"
#include "common_tool.h"
#include "iservice_registry.h"
#include "status_receiver_host.h"
#include "system_ability_definition.h"

using OHOS::AAFwk::Want;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const std::string SYSTEM_SETTINGS_BUNDLE_NAME = "com.ohos.settings";
const std::string BUNDLE_NAME = "com.ohos.contactsdataability";
const std::string ABILITY_NAME = "com.ohos.contactsdataability.MainAbility";
const std::string HAP_FILE = "/data/test/benchmark/test.hap";
const std::string MODULE_NAME_TEST = "entry";
const std::string COMMON_EVENT_EVENT = "usual.event.PACKAGE_ADDED";
constexpr int32_t DEFAULT_USERID = 100;
constexpr int32_t BENCHMARK_TIMES = 1000;
constexpr int32_t DEFAULT_DISPOSED_STATUS = 0;

class BundleStatusCallbackImpl : public BundleStatusCallbackHost {
public:
    BundleStatusCallbackImpl() = default;
    virtual ~BundleStatusCallbackImpl() override {};
    virtual void OnBundleStateChanged(const uint8_t installType, const int32_t resultCode, const std::string &resultMsg,
        const std::string &bundleName) override;
    virtual void OnBundleAdded(const std::string &bundleName, const int userId) override {};
    virtual void OnBundleUpdated(const std::string &bundleName, const int userId) override {};
    virtual void OnBundleRemoved(const std::string &bundleName, const int userId) override {};

private:
    DISALLOW_COPY_AND_MOVE(BundleStatusCallbackImpl);
};

void BundleStatusCallbackImpl::OnBundleStateChanged(
    const uint8_t installType, const int32_t resultCode, const std::string &resultMsg, const std::string &bundleName)
{}

class CleanCacheCallBackImpl : public CleanCacheCallbackHost {
public:
    CleanCacheCallBackImpl() = default;
    virtual ~CleanCacheCallBackImpl() override {};
    virtual void OnCleanCacheFinished(bool succeeded) override {};

private:
    DISALLOW_COPY_AND_MOVE(CleanCacheCallBackImpl);
};

class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl() = default;
    virtual ~StatusReceiverImpl() {};
    virtual void OnStatusNotify(const int progress) override {};
    virtual void OnFinished(const int32_t resultCode, const std::string &resultMsg) override {};

private:
    DISALLOW_COPY_AND_MOVE(StatusReceiverImpl);
};

class BundleMgrProxyTest {
public:
    static sptr<IBundleMgr> GetBundleMgrProxy();
};

sptr<IBundleMgr> BundleMgrProxyTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        return nullptr;
    }

    return iface_cast<IBundleMgr>(remoteObject);
}

/**
 * @tc.name: BenchmarkTestGetApplicationInfo
 * @tc.desc: Testcase for testing GetApplicationInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetApplicationInfoByFlag(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    ApplicationInfo appInfo;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetApplicationInfo in loop */
        bundleMgrProxy->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO,
            Constants::DEFAULT_USERID, appInfo);
    }
}

/**
 * @tc.name: BenchmarkTestGetApplicationInfo
 * @tc.desc: Testcase for testing GetApplicationInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
static void BenchmarkTestGetApplicationInfoByUserId(benchmark::State &state)
{
    int32_t flags = 0;
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    ApplicationInfo appInfo;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetApplicationInfo in loop */
        bundleMgrProxy->GetApplicationInfo(BUNDLE_NAME, flags, DEFAULT_USERID, appInfo);
    }
}

/**
 * @tc.name: BenchmarkTestGetApplicationInfosByApplicationFlag
 * @tc.desc: Testcase for testing GetApplicationInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetApplicationInfosByApplicationFlag(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<ApplicationInfo> appInfos;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetApplicationInfos in loop */
        bundleMgrProxy->GetApplicationInfos(ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION, DEFAULT_USERID,
            appInfos);
    }
}

/**
 * @tc.name: BenchmarkTestGetApplicationInfosByFlags
 * @tc.desc: Testcase for testing GetApplicationInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetApplicationInfosByFlags(benchmark::State &state)
{
    int32_t flags = 0;
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<ApplicationInfo> appInfos;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetApplicationInfos in loop */
        bundleMgrProxy->GetApplicationInfos(flags, DEFAULT_USERID, appInfos);
    }
}

/**
 * @tc.name: BenchmarkTestGetBundleInfoByBundleFlag
 * @tc.desc: Testcase for testing GetBundleInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetBundleInfoByBundleFlag(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    BundleInfo info;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetBundleInfo in loop */
        bundleMgrProxy->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, info);
    }
}

/**
 * @tc.name: BenchmarkTestGetBundleInfoByFlags
 * @tc.desc: Testcase for testing GetBundleInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
static void BenchmarkTestGetBundleInfoByFlags(benchmark::State &state)
{
    int32_t flags = 0;
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    BundleInfo info;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetBundleInfo in loop */
        bundleMgrProxy->GetBundleInfo(BUNDLE_NAME, flags, info);
    }
}

/**
 * @tc.name: BenchmarkTestGetBundleInfosByBundleFlag
 * @tc.desc: Testcase for testing GetBundleInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetBundleInfosByBundleFlag(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<BundleInfo> bundleInfos;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetBundleInfos in loop */
        bundleMgrProxy->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos);
    }
}

/**
 * @tc.name: BenchmarkTestGetBundleInfosByFlags
 * @tc.desc: Testcase for testing GetBundleInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetBundleInfosByFlags(benchmark::State &state)
{
    int32_t flags = 0;
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<BundleInfo> bundleInfos;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetBundleInfos in loop */
        bundleMgrProxy->GetBundleInfos(flags, bundleInfos);
    }
}

/**
 * @tc.name: BenchmarkTestGetUidByBundleName
 * @tc.desc: Obtains the application ID based on the given bundle name and user ID.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetUidByBundleName(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetUidByBundleName in loop */
        bundleMgrProxy->GetUidByBundleName(BUNDLE_NAME, DEFAULT_USERID);
    }
}

/**
 * @tc.name: BenchmarkTestGetAppIdByBundleName
 * @tc.desc: Obtains the application ID based on the given bundle name and user ID.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
static void BenchmarkTestGetAppIdByBundleName(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetAppIdByBundleName in loop */
        bundleMgrProxy->GetAppIdByBundleName(BUNDLE_NAME, DEFAULT_USERID);
    }
}

/**
 * @tc.name: BenchmarkTestGetBundleNameForUid
 * @tc.desc: Testcase for testing GetBundleNameForUid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
static void BenchmarkTestGetBundleNameForUid(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::string bundleName;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetBundleNameForUid in loop */
        bundleMgrProxy->GetBundleNameForUid(Constants::INVALID_UID, bundleName);
    }
}

/**
 * @tc.name: BenchmarkTestGetBundlesForUid
 * @tc.desc: Testcase for testing GetBundlesForUid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
static void BenchmarkTestGetBundlesForUid(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<std::string> bundleNames;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetBundlesForUid in loop */
        bundleMgrProxy->GetBundlesForUid(Constants::INVALID_UID, bundleNames);
    }
}

/**
 * @tc.name: BenchmarkTestGetNameForUid
 * @tc.desc: Testcase for testing GetNameForUid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
static void BenchmarkTestGetNameForUid(benchmark::State &state)
{
    std::string name;
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetNameForUid in loop */
        bundleMgrProxy->GetNameForUid(Constants::INVALID_UID, name);
    }
}

/**
 * @tc.name: BenchmarkTestGetAppType
 * @tc.desc: Testcase for testing GetAppType.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetAppType(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetAppType in loop */
        bundleMgrProxy->GetAppType(SYSTEM_SETTINGS_BUNDLE_NAME);
    }
}

/**
 * @tc.name: BenchmarkTestCheckIsSystemAppByUid
 * @tc.desc: Testcase for testing CheckIsSystemAppByUid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestCheckIsSystemAppByUid(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call CheckIsSystemAppByUid in loop */
        bundleMgrProxy->CheckIsSystemAppByUid(Constants::INVALID_UID);
    }
}

/**
 * @tc.name: BenchmarkTestGetBundleInfosByMetaData
 * @tc.desc: Testcase for testing GetBundleInfosByMetaData.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetBundleInfosByMetaData(benchmark::State &state)
{
    std::vector<BundleInfo> bundleInfos;
    std::string metadata = "string";
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetBundleInfosByMetaData in loop */
        bundleMgrProxy->GetBundleInfosByMetaData(metadata, bundleInfos);
    }
}

/**
 * @tc.name: BenchmarkTestQueryAbilityInfo
 * @tc.desc: Testcase for testing QueryAbilityInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryAbilityInfo(benchmark::State &state)
{
    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);
    AbilityInfo info;
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();

    for (auto _ : state) {
        /* @tc.steps: step1.call QueryAbilityInfo in loop */
        bundleMgrProxy->QueryAbilityInfo(want, info);
    }
}

/**
 * @tc.name: BenchmarkTestQueryAbilityInfoByFlags
 * @tc.desc: Testcase for testing QueryAbilityInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryAbilityInfoByFlags(benchmark::State &state)
{
    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);

    AbilityInfo info;

    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryAbilityInfo in loop */
        bundleMgrProxy->QueryAbilityInfo(want, 0, DEFAULT_USERID, info);
    }
}

/**
 * @tc.name: BenchmarkTestQueryAbilityInfos
 * @tc.desc: Testcase for testing QueryAbilityInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryAbilityInfos(benchmark::State &state)
{
    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);

    std::vector<AbilityInfo> abilityInfos;

    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryAbilityInfos in loop */
        bundleMgrProxy->QueryAbilityInfos(want, abilityInfos);
    }
}

/**
 * @tc.name: BenchmarkTestQueryAbilityInfosByFlags
 * @tc.desc: Testcase for testing QueryAbilityInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryAbilityInfosByFlags(benchmark::State &state)
{
    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);

    std::vector<AbilityInfo> abilityInfos;
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryAbilityInfos in loop */
        bundleMgrProxy->QueryAbilityInfos(want, 0, DEFAULT_USERID, abilityInfos);
    }
}

/**
 * @tc.name: BenchmarkTestQueryAbilityInfosById
 * @tc.desc: Testcase for testing QueryAllAbilityInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryAbilityInfosById(benchmark::State &state)
{
    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);

    std::vector<AbilityInfo> abilityInfos;

    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryAllAbilityInfos in loop */
        bundleMgrProxy->QueryAllAbilityInfos(want, 0, abilityInfos);
    }
}

/**
 * @tc.name: BenchmarkTestQueryAbilityInfoByUri
 * @tc.desc: Testcase for testing QueryAbilityInfoByUri.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryAbilityInfoByUri(benchmark::State &state)
{
    std::string abilityUri = "err://com.test.demo.weatherfa.UserADataAbility";
    AbilityInfo info;

    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryAbilityInfoByUri in loop */
        bundleMgrProxy->QueryAbilityInfoByUri(abilityUri, info);
    }
}

/**
 * @tc.name: BenchmarkTestQueryAbilityInfoByUriAndId
 * @tc.desc: Testcase for testing QueryAbilityInfoByUri.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryAbilityInfoByUriAndId(benchmark::State &state)
{
    std::string abilityUri = "err://com.test.demo.weatherfa.UserADataAbility";
    AbilityInfo info;

    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryAbilityInfoByUri in loop */
        bundleMgrProxy->QueryAbilityInfoByUri(abilityUri, DEFAULT_USERID, info);
    }
}

/**
 * @tc.name: BenchmarkTestQueryAbilityInfosByUri
 * @tc.desc: Testcase for testing QueryAbilityInfosByUri.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryAbilityInfosByUri(benchmark::State &state)
{
    std::string abilityUri = "err://com.test.demo.weatherfa.UserADataAbility";
    std::vector<AbilityInfo> abilityInfos;

    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryAbilityInfosByUri in loop */
        bundleMgrProxy->QueryAbilityInfosByUri(abilityUri, abilityInfos);
    }
}

/**
 * @tc.name: BenchmarkTestQueryKeepAliveBundleInfos
 * @tc.desc: Testcase for testing QueryKeepAliveBundleInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryKeepAliveBundleInfos(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<BundleInfo> bundleInfos;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryKeepAliveBundleInfos in loop */
        bundleMgrProxy->QueryKeepAliveBundleInfos(bundleInfos);
    }
}

/**
 * @tc.name: BenchmarkTestGetAbilityLabel
 * @tc.desc: Testcase for testing GetAbilityLabel.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetAbilityLabel(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetAbilityLabel in loop */
        bundleMgrProxy->GetAbilityLabel(BUNDLE_NAME, ABILITY_NAME);
    }
}

/**
 * @tc.name: BenchmarkTestGetBundleArchiveInfo
 * @tc.desc: Testcase for testing GetBundleArchiveInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetBundleArchiveInfo(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    BundleInfo info;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetBundleArchiveInfo in loop */
        bundleMgrProxy->GetBundleArchiveInfo(HAP_FILE, 0, info);
    }
}

/**
 * @tc.name: BenchmarkTestGetBundleArchiveInfoByFlag
 * @tc.desc: Testcase for testing GetBundleArchiveInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetBundleArchiveInfoByFlag(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    BundleInfo info;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetBundleArchiveInfo in loop */
        bundleMgrProxy->GetBundleArchiveInfo(HAP_FILE, BundleFlag::GET_BUNDLE_DEFAULT, info);
    }
}

/**
 * @tc.name: BenchmarkTestGetLaunchWantForBundle
 * @tc.desc: Testcase for testing GetLaunchWantForBundle.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetLaunchWantForBundle(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    Want want;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetLaunchWantForBundle in loop */
        bundleMgrProxy->GetLaunchWantForBundle(BUNDLE_NAME, want);
    }
}

/**
 * @tc.name: BenchmarkTestGetPermissionDef
 * @tc.desc: Testcase for testing GetPermissionDef.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetPermissionDef(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::string permissionName;
    PermissionDef info;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetPermissionDef in loop */
        bundleMgrProxy->GetPermissionDef(permissionName, info);
    }
}

/**
 * @tc.name: BenchmarkTestHasSystemCapability
 * @tc.desc: Testcase for testing HasSystemCapability.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestHasSystemCapability(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call HasSystemCapability in loop */
        bundleMgrProxy->HasSystemCapability(ABILITY_NAME);
    }
}

/**
 * @tc.name: BenchmarkTestGetSystemAvailableCapabilities
 * @tc.desc: Testcase for testing GetSystemAvailableCapabilities.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetSystemAvailableCapabilities(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<std::string> systemCaps = {"bmsSystemBundle_A1"};
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetSystemAvailableCapabilities in loop */
        bundleMgrProxy->GetSystemAvailableCapabilities(systemCaps);
    }
}

/**
 * @tc.name: BenchmarkTestIsSafeMode
 * @tc.desc: Testcase for testing IsSafeMode.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestIsSafeMode(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call IsSafeMode in loop */
        bundleMgrProxy->IsSafeMode();
    }
}

/**
 * @tc.name: BenchmarkTestCleanBundleDataFiles
 * @tc.desc: Testcase for testing CleanBundleDataFiles.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestCleanBundleDataFiles(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call CleanBundleDataFiles in loop */
        bundleMgrProxy->CleanBundleDataFiles(BUNDLE_NAME, 0);
    }
}

/**
 * @tc.name: BenchmarkTestRegisterBundleStatusCallback
 * @tc.desc: Testcase for testing RegisterBundleStatusCallback.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestRegisterBundleStatusCallback(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    sptr<BundleStatusCallbackImpl> bundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
    bundleStatusCallback->SetBundleName(BUNDLE_NAME);
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call RegisterBundleStatusCallback in loop */
        bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallback);
    }
}

/**
 * @tc.name: BenchmarkTestClearBundleStatusCallback
 * @tc.desc: Testcase for testing ClearBundleStatusCallback.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestClearBundleStatusCallback(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    sptr<BundleStatusCallbackImpl> bundleStatusCallback = (new (std::nothrow) BundleStatusCallbackImpl());
    bundleStatusCallback->SetBundleName(BUNDLE_NAME);
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call ClearBundleStatusCallback in loop */
        bundleMgrProxy->ClearBundleStatusCallback(bundleStatusCallback);
    }
}

/**
 * @tc.name: BenchmarkTestUnregisterBundleStatusCallback
 * @tc.desc: Testcase for testing UnregisterBundleStatusCallback.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestUnregisterBundleStatusCallback(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call UnregisterBundleStatusCallback in loop */
        bundleMgrProxy->UnregisterBundleStatusCallback();
    }
}

/**
 * @tc.name: BenchmarkTestDumpInfos
 * @tc.desc: Testcase for testing DumpInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestDumpInfos(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    const std::string EMPTY_STRING = "";
    std::string bundleNames;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call DumpInfos in loop */
        bundleMgrProxy->DumpInfos(
            DumpFlag::DUMP_BUNDLE_LIST, EMPTY_STRING, DEFAULT_USERID, bundleNames);
    }
}

/**
 * @tc.name: BenchmarkTestIsApplicationEnabled
 * @tc.desc: Testcase for testing IsApplicationEnabled.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestIsApplicationEnabled(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call IsApplicationEnabled in loop */
        bool isEnable = false;
        bundleMgrProxy->IsApplicationEnabled(BUNDLE_NAME, isEnable);
    }
}

/**
 * @tc.name: BenchmarkTestSetApplicationEnabled
 * @tc.desc: Testcase for testing SetApplicationEnabled.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestSetApplicationEnabled(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call SetApplicationEnabled in loop */
        bundleMgrProxy->SetApplicationEnabled(BUNDLE_NAME, false);
    }
}

/**
 * @tc.name: BenchmarkTestIsAbilityEnabled
 * @tc.desc: Testcase for testing IsAbilityEnabled.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestIsAbilityEnabled(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    AbilityInfo info;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call IsAbilityEnabled in loop */
        bool isEnable = false;
        bundleMgrProxy->IsAbilityEnabled(info, isEnable);
    }
}

/**
 * @tc.name: BenchmarkTestSetAbilityEnabled
 * @tc.desc: Testcase for testing SetAbilityEnabled.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestSetAbilityEnabled(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    AbilityInfo info;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call SetAbilityEnabled in loop */
        bundleMgrProxy->SetAbilityEnabled(info, false);
    }
}

/**
 * @tc.name: BenchmarkTestGetBundleInstaller
 * @tc.desc: Testcase for testing GetBundleInstaller.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetBundleInstaller(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetBundleInstaller in loop */
        bundleMgrProxy->GetBundleInstaller();
    }
}

/**
 * @tc.name: BenchmarkTestGetBundleUserMgr
 * @tc.desc: Testcase for testing GetBundleUserMgr.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetBundleUserMgr(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetBundleUserMgr in loop */
        bundleMgrProxy->GetBundleUserMgr();
    }
}

/**
 * @tc.name: BenchmarkTestGetAllFormsInfo
 * @tc.desc: Testcase for testing GetAllFormsInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetAllFormsInfo(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<FormInfo> formInfos;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetAllFormsInfo in loop */
        bundleMgrProxy->GetAllFormsInfo(formInfos);
    }
}

/**
 * @tc.name: BenchmarkTestGetFormsInfoByApp
 * @tc.desc: Testcase for testing GetFormsInfoByApp.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetFormsInfoByApp(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<FormInfo> formInfos;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetFormsInfoByApp in loop */
        bundleMgrProxy->GetFormsInfoByApp(BUNDLE_NAME, formInfos);
    }
}

/**
 * @tc.name: BenchmarkTestGetFormsInfoByModule
 * @tc.desc: Testcase for testing GetFormsInfoByModule.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetFormsInfoByModule(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<FormInfo> formInfos;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetFormsInfoByModule in loop */
        bundleMgrProxy->GetFormsInfoByModule(BUNDLE_NAME, MODULE_NAME_TEST, formInfos);
    }
}

/**
 * @tc.name: BenchmarkTestGetShortcutInfos
 * @tc.desc: Testcase for testing GetShortcutInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetShortcutInfos(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<ShortcutInfo> shortcutInfos;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetShortcutInfos in loop */
        bundleMgrProxy->GetShortcutInfos(BUNDLE_NAME, shortcutInfos);
    }
}

/**
 * @tc.name: BenchmarkTestGetAllCommonEventInfo
 * @tc.desc: Testcase for testing GetAllCommonEventInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetAllCommonEventInfo(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<CommonEventInfo> commonEventInfos;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetAllCommonEventInfo in loop */
        bundleMgrProxy->GetAllCommonEventInfo(COMMON_EVENT_EVENT, commonEventInfos);
    }
}

/**
 * @tc.name: BenchmarkTestGetDistributedBundleInfo
 * @tc.desc: Testcase for testing GetDistributedBundleInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetDistributedBundleInfo(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::string networkId = "com.ohos.contactsdataability_BNtg4JBClbl92Rgc3jm"\
        "/RfcAdrHXaM8F0QOiwVEhnV5ebE5jNIYnAx+weFRT3QTyUjRNdhmc2aAzWyi+5t5CoBM=";
    DistributedBundleInfo distributedBundleInfo;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetDistributedBundleInfo in loop */
        bundleMgrProxy->GetDistributedBundleInfo(networkId, BUNDLE_NAME, distributedBundleInfo);
    }
}

/**
 * @tc.name: BenchmarkTestGetAppPrivilegeLevel
 * @tc.desc: Testcase for testing GetAppPrivilegeLevel.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetAppPrivilegeLevel(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetAppPrivilegeLevel in loop */
        bundleMgrProxy->GetAppPrivilegeLevel(BUNDLE_NAME);
    }
}

/**
 * @tc.name: BenchmarkTestQueryExtensionAbilityInfosByWant
 * @tc.desc: Testcase for testing QueryExtensionAbilityInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryExtensionAbilityInfosByWant(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);
    int32_t flags = 0;
    std::vector<ExtensionAbilityInfo> infos;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryExtensionAbilityInfos in loop */
        bundleMgrProxy->QueryExtensionAbilityInfos(want, flags, DEFAULT_USERID, infos);
    }
}

/**
 * @tc.name: BenchmarkTestQueryExtensionAbilityInfosByType
 * @tc.desc: Testcase for testing QueryExtensionAbilityInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryExtensionAbilityInfosByType(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<ExtensionAbilityInfo> infos;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryExtensionAbilityInfos in loop */
        bundleMgrProxy->QueryExtensionAbilityInfos(ExtensionAbilityType::FORM, DEFAULT_USERID, infos);
    }
}

/**
 * @tc.name: BenchmarkTestQueryExtensionAbilityInfos
 * @tc.desc: Testcase for testing QueryExtensionAbilityInfos.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryExtensionAbilityInfos(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);
    int32_t flags = 0;
    std::vector<ExtensionAbilityInfo> infos;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryExtensionAbilityInfos in loop */
        bundleMgrProxy->QueryExtensionAbilityInfos(want, ExtensionAbilityType::FORM, flags, DEFAULT_USERID, infos);
    }
}

/**
 * @tc.name: BenchmarkTestVerifyCallingPermission
 * @tc.desc: Testcase for testing VerifyCallingPermission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestVerifyCallingPermission(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::string appPermission = "USER_GRANT";
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call VerifyCallingPermission in loop */
        bundleMgrProxy->VerifyCallingPermission(appPermission);
    }
}

/**
 * @tc.name: BenchmarkTestGetAccessibleAppCodePaths
 * @tc.desc: Testcase for testing GetAccessibleAppCodePaths.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetAccessibleAppCodePaths(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetAccessibleAppCodePaths in loop */
        bundleMgrProxy->GetAccessibleAppCodePaths(DEFAULT_USERID);
    }
}

/**
 * @tc.name: BenchmarkTestQueryExtensionAbilityInfoByUri
 * @tc.desc: Testcase for testing QueryExtensionAbilityInfoByUri.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestQueryExtensionAbilityInfoByUri(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    ExtensionAbilityInfo info;
    const std::string URI = "dataability://com.example.hiworld.himusic.UserADataAbility";
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call QueryExtensionAbilityInfoByUri in loop */
        bundleMgrProxy->QueryExtensionAbilityInfoByUri(URI, DEFAULT_USERID, info);
    }
}

/**
 * @tc.name: BenchmarkTestImplicitQueryInfoByPriority
 * @tc.desc: Testcase for testing ImplicitQueryInfoByPriority.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestImplicitQueryInfoByPriority(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);
    int32_t flags = 0;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call ImplicitQueryInfoByPriority in loop */
        bundleMgrProxy->ImplicitQueryInfoByPriority(want, flags, DEFAULT_USERID, abilityInfo, extensionInfo);
    }
}

/**
 * @tc.name: BenchmarkTestGetSandboxBundleInfo
 * @tc.desc: Testcase for testing GetSandboxBundleInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetSandboxBundleInfo(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    BundleInfo info;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetSandboxBundleInfo in loop */
        bundleMgrProxy->GetSandboxBundleInfo(BUNDLE_NAME, 0, DEFAULT_USERID, info);
    }
}

/**
 * @tc.name: BenchmarkTestGetAbilityInfo
 * @tc.desc: Testcase for testing GetAbilityInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetAbilityInfo(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    AbilityInfo info;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }

        /* @tc.steps: step1.call GetAbilityInfo in loop */
        bundleMgrProxy->GetAbilityInfo(BUNDLE_NAME, ABILITY_NAME, info);
    }
}

/**
 * @tc.name: BenchmarkTestGetAbilityInfoByModuleName
 * @tc.desc: Testcase for testing GetAbilityInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetAbilityInfoByModuleName(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    AbilityInfo info;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetAbilityInfo in loop */
        bundleMgrProxy->GetAbilityInfo(BUNDLE_NAME, MODULE_NAME_TEST, ABILITY_NAME, info);
    }
}

/**
 * @tc.name: BenchmarkTestGetAllDependentModuleNames
 * @tc.desc: Testcase for testing GetAllDependentModuleNames.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetAllDependentModuleNames(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::vector<std::string> dependentModuleNames;
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetAllDependentModuleNames in loop */
        bundleMgrProxy->GetAllDependentModuleNames(BUNDLE_NAME, MODULE_NAME_TEST, dependentModuleNames);
    }
}

/**
 * @tc.name: BenchmarkTestSetDisposedStatus
 * @tc.desc: Testcase for testing SetDisposedStatus.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestSetDisposedStatus(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call SetDisposedStatus in loop */
        bundleMgrProxy->SetDisposedStatus(BUNDLE_NAME, DEFAULT_DISPOSED_STATUS);
    }
}

/**
 * @tc.name: BenchmarkTestSetDisposedStatus
 * @tc.desc: Testcase for testing GetDisposedStatus.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestGetDisposedStatus(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call GetDisposedStatus in loop */
        bundleMgrProxy->GetDisposedStatus(BUNDLE_NAME);
    }
}

/**
 * @tc.name: BenchmarkTestObtainCallingBundleName
 * @tc.desc: Testcase for testing ObtainCallingBundleName.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */

static void BenchmarkTestObtainCallingBundleName(benchmark::State &state)
{
    sptr<IBundleMgr> bundleMgrProxy = BundleMgrProxyTest::GetBundleMgrProxy();
    std::string bundleName;

    for (auto _ : state) {
        if (bundleMgrProxy == nullptr) {
            break;
        }
        /* @tc.steps: step1.call ObtainCallingBundleName in loop */
        bundleMgrProxy->ObtainCallingBundleName(bundleName);
    }
}

BENCHMARK(BenchmarkTestGetApplicationInfoByFlag)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetApplicationInfoByUserId)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetApplicationInfosByApplicationFlag)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetApplicationInfosByFlags)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetBundleInfoByBundleFlag)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetBundleInfoByFlags)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetBundleInfosByBundleFlag)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetBundleInfosByFlags)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetUidByBundleName)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetAppIdByBundleName)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetBundleNameForUid)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetBundlesForUid)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetNameForUid)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetAppType)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestCheckIsSystemAppByUid)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetBundleInfosByMetaData)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryAbilityInfo)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryAbilityInfoByFlags)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryAbilityInfos)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryAbilityInfosByFlags)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryAbilityInfosById)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryAbilityInfoByUriAndId)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryAbilityInfoByUri)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryAbilityInfosByUri)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryKeepAliveBundleInfos)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetAbilityLabel)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetBundleArchiveInfo)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetBundleArchiveInfoByFlag)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetLaunchWantForBundle)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetPermissionDef)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestHasSystemCapability)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetSystemAvailableCapabilities)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestIsSafeMode)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestCleanBundleDataFiles)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestRegisterBundleStatusCallback)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestClearBundleStatusCallback)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestUnregisterBundleStatusCallback)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestDumpInfos)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestIsApplicationEnabled)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestSetApplicationEnabled)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestIsAbilityEnabled)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestSetAbilityEnabled)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetBundleInstaller)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetBundleUserMgr)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetAllFormsInfo)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetFormsInfoByApp)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetFormsInfoByModule)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetShortcutInfos)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetAllCommonEventInfo)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetDistributedBundleInfo)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetAppPrivilegeLevel)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryExtensionAbilityInfosByWant)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryExtensionAbilityInfos)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryExtensionAbilityInfosByType)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestVerifyCallingPermission)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetAccessibleAppCodePaths)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestQueryExtensionAbilityInfoByUri)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestImplicitQueryInfoByPriority)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetSandboxBundleInfo)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetAbilityInfo)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetAbilityInfoByModuleName)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetAllDependentModuleNames)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestSetDisposedStatus)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestGetDisposedStatus)->Iterations(BENCHMARK_TIMES);
BENCHMARK(BenchmarkTestObtainCallingBundleName)->Iterations(BENCHMARK_TIMES);
}  // namespace

BENCHMARK_MAIN();