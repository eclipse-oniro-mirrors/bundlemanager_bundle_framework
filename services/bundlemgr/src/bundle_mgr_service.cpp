/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "bundle_mgr_service.h"

#include <sys/stat.h>

#include "account_helper.h"
#include "app_log_wrapper.h"
#include "bundle_common_event.h"
#include "bundle_constants.h"
#include "bundle_distributed_manager.h"
#include "bundle_memory_guard.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_helper.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "datetime_ex.h"
#include "ffrt.h"
#include "installd_client.h"
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
#include "app_control_manager_host_impl.h"
#endif
#include "perf_profile.h"
#include "system_ability_definition.h"
#include "system_ability_helper.h"
#include "want.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/watchdog.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t BUNDLE_BROKER_SERVICE_ABILITY_ID = 0x00010500;
} // namespace

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<BundleMgrService>::GetInstance().get());

BundleMgrService::BundleMgrService() : SystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, true)
{
    APP_LOGI("instance is created");
    PerfProfile::GetInstance().SetBmsLoadStartTime(GetTickCount());
}

BundleMgrService::~BundleMgrService()
{
    host_ = nullptr;
    installer_ = nullptr;
    if (handler_) {
        handler_.reset();
    }
    if (dataMgr_) {
        dataMgr_.reset();
    }
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
    if (connectAbilityMgr_ != nullptr) {
        connectAbilityMgr_.reset();
    }
#endif
    if (hidumpHelper_) {
        hidumpHelper_.reset();
    }
    APP_LOGI("BundleMgrService instance is destroyed");
}

void BundleMgrService::OnStart()
{
    APP_LOGI("BundleMgrService OnStart start");
    if (!Init()) {
        APP_LOGE("BundleMgrService init fail");
        return;
    }

    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    AddSystemAbilityListener(BUNDLE_BROKER_SERVICE_ABILITY_ID);
    APP_LOGI("BundleMgrService OnStart end");
}

void BundleMgrService::OnStop()
{
    APP_LOGI("OnStop is called");
    SelfClean();
}

bool BundleMgrService::IsServiceReady() const
{
    return ready_;
}

bool BundleMgrService::Init()
{
    if (ready_) {
        APP_LOGW("init more than one time");
        return false;
    }

    APP_LOGI("BundleMgrService Init begin");
    CreateBmsServiceDir();
    InitBmsParam();
    InitPreInstallExceptionMgr();
    CHECK_INIT_RESULT(InitBundleMgrHost(), "Init bundleMgr fail");
    CHECK_INIT_RESULT(InitBundleInstaller(), "Init bundleInstaller fail");
    InitBundleDataMgr();
    CHECK_INIT_RESULT(InitBundleUserMgr(), "Init bundleUserMgr fail");
    CHECK_INIT_RESULT(InitVerifyManager(), "Init verifyManager fail");
    CHECK_INIT_RESULT(InitExtendResourceManager(), "Init extendResourceManager fail");
    CHECK_INIT_RESULT(InitBundleEventHandler(), "Init bundleEventHandler fail");
    InitHidumpHelper();
    InitFreeInstall();
    CHECK_INIT_RESULT(InitDefaultApp(), "Init defaultApp fail");
    CHECK_INIT_RESULT(InitAppControl(), "Init appControl fail");
    CHECK_INIT_RESULT(InitQuickFixManager(), "Init quickFixManager fail");
    CHECK_INIT_RESULT(InitOverlayManager(), "Init overlayManager fail");
    CHECK_INIT_RESULT(InitBundleResourceMgr(), "Init BundleResourceMgr fail");
    BundleResourceHelper::BundleSystemStateInit();
    ready_ = true;
    APP_LOGI("BundleMgrService Init success");
    return true;
}

void BundleMgrService::InitBmsParam()
{
    bmsParam_ = std::make_shared<BmsParam>();
}

void BundleMgrService::InitPreInstallExceptionMgr()
{
    preInstallExceptionMgr_ = std::make_shared<PreInstallExceptionMgr>();
}

bool BundleMgrService::InitBundleMgrHost()
{
    if (host_ == nullptr) {
        host_ = new (std::nothrow) BundleMgrHostImpl();
    }

    return host_ != nullptr;
}

bool BundleMgrService::InitBundleInstaller()
{
    if (installer_ == nullptr) {
        installer_ = new (std::nothrow) BundleInstallerHost();
        if (installer_ == nullptr || !installer_->Init()) {
            APP_LOGE("init installer fail");
            return false;
        }
    }

    return true;
}

void BundleMgrService::InitBundleDataMgr()
{
    if (dataMgr_ == nullptr) {
        APP_LOGI("Create BundledataMgr");
        dataMgr_ = std::make_shared<BundleDataMgr>();
        dataMgr_->AddUserId(Constants::DEFAULT_USERID);
    }
}

bool BundleMgrService::InitBundleUserMgr()
{
    if (userMgrHost_ == nullptr) {
        userMgrHost_ = new (std::nothrow) BundleUserMgrHostImpl();
    }

    return userMgrHost_ != nullptr;
}

bool BundleMgrService::InitVerifyManager()
{
    if (verifyManager_ == nullptr) {
        verifyManager_ = new (std::nothrow) VerifyManagerHostImpl();
    }

    return verifyManager_ != nullptr;
}

bool BundleMgrService::InitExtendResourceManager()
{
    if (extendResourceManager_ == nullptr) {
        extendResourceManager_ = new (std::nothrow) ExtendResourceManagerHostImpl();
    }

    return extendResourceManager_ != nullptr;
}

bool BundleMgrService::InitBundleEventHandler()
{
    if (handler_ == nullptr) {
        handler_ = std::make_shared<BMSEventHandler>();
    }
    auto task = [this]() {
        BundleMemoryGuard memoryGuard;
        handler_->BmsStartEvent();
    };
    ffrt::submit(task);
    return true;
}

void BundleMgrService::InitHidumpHelper()
{
    if (hidumpHelper_ == nullptr) {
        APP_LOGI("Create hidump helper");
        hidumpHelper_ = std::make_shared<HidumpHelper>(dataMgr_);
    }
}

void BundleMgrService::InitFreeInstall()
{
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
    if (agingMgr_ == nullptr) {
        APP_LOGI("Create aging manager");
        agingMgr_ = std::make_shared<BundleAgingMgr>();
        agingMgr_->InitAgingtTimer();
    }
    if (connectAbilityMgr_ == nullptr) {
        APP_LOGI("Create BundleConnectAbility");
        connectAbilityMgr_ = std::make_shared<BundleConnectAbilityMgr>();
    }
    if (bundleDistributedManager_ == nullptr) {
        APP_LOGI("Create bundleDistributedManager");
        bundleDistributedManager_ = std::make_shared<BundleDistributedManager>();
    }
#endif
}

bool BundleMgrService::InitDefaultApp()
{
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
    if (defaultAppHostImpl_ == nullptr) {
        defaultAppHostImpl_ = new (std::nothrow) DefaultAppHostImpl();
        if (defaultAppHostImpl_ == nullptr) {
            APP_LOGE("create DefaultAppHostImpl failed.");
            return false;
        }
    }
#endif
    return true;
}

bool BundleMgrService::InitAppControl()
{
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
    if (appControlManagerHostImpl_ == nullptr) {
        appControlManagerHostImpl_ = new (std::nothrow) AppControlManagerHostImpl();
        if (appControlManagerHostImpl_ == nullptr) {
            APP_LOGE("create appControlManagerHostImpl failed.");
            return false;
        }
    }
#endif
    return true;
}

bool BundleMgrService::InitQuickFixManager()
{
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    if (quickFixManagerHostImpl_ == nullptr) {
        quickFixManagerHostImpl_ = new (std::nothrow) QuickFixManagerHostImpl();
        if (quickFixManagerHostImpl_ == nullptr) {
            APP_LOGE("create QuickFixManagerHostImpl failed.");
            return false;
        }
    }
#endif
    return true;
}

bool BundleMgrService::InitOverlayManager()
{
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    if (overlayManagerHostImpl_ == nullptr) {
        overlayManagerHostImpl_ = new (std::nothrow) OverlayManagerHostImpl();
        if (overlayManagerHostImpl_ == nullptr) {
            APP_LOGE("create OverlayManagerHostImpl failed.");
            return false;
        }
    }
#endif
    return true;
}

void BundleMgrService::CreateBmsServiceDir()
{
    auto ret = InstalldClient::GetInstance()->Mkdir(
        Constants::HAP_COPY_PATH, S_IRWXU | S_IXGRP | S_IRGRP | S_IROTH | S_IXOTH,
        Constants::FOUNDATION_UID, Constants::BMS_GID);
    if (!ret) {
        APP_LOGE("create dir failed");
    }
}

bool BundleMgrService::InitBundleResourceMgr()
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    if (bundleResourceHostImpl_ == nullptr) {
        bundleResourceHostImpl_ = new (std::nothrow) BundleResourceHostImpl();
        if (bundleResourceHostImpl_ == nullptr) {
            APP_LOGE("create bundleResourceHostImpl failed.");
            return false;
        }
    }
#endif
    return true;
}

sptr<BundleInstallerHost> BundleMgrService::GetBundleInstaller() const
{
    return installer_;
}

void BundleMgrService::RegisterDataMgr(std::shared_ptr<BundleDataMgr> dataMgrImpl)
{
    dataMgr_ = dataMgrImpl;
    if (dataMgr_ != nullptr) {
        dataMgr_->AddUserId(Constants::DEFAULT_USERID);
    }
}

const std::shared_ptr<BundleDataMgr> BundleMgrService::GetDataMgr() const
{
    return dataMgr_;
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
const std::shared_ptr<BundleAgingMgr> BundleMgrService::GetAgingMgr() const
{
    return agingMgr_;
}

const std::shared_ptr<BundleConnectAbilityMgr> BundleMgrService::GetConnectAbility() const
{
    return connectAbilityMgr_;
}

const std::shared_ptr<BundleDistributedManager> BundleMgrService::GetBundleDistributedManager() const
{
    return bundleDistributedManager_;
}
#endif

void BundleMgrService::SelfClean()
{
    if (ready_) {
        ready_ = false;
        if (registerToService_) {
            registerToService_ = false;
        }
    }
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
    agingMgr_.reset();
    connectAbilityMgr_.reset();
    bundleDistributedManager_.reset();
#endif
}

sptr<BundleUserMgrHostImpl> BundleMgrService::GetBundleUserMgr() const
{
    return userMgrHost_;
}

sptr<IVerifyManager> BundleMgrService::GetVerifyManager() const
{
    return verifyManager_;
}

sptr<IExtendResourceManager> BundleMgrService::GetExtendResourceManager() const
{
    return extendResourceManager_;
}

const std::shared_ptr<BmsParam> BundleMgrService::GetBmsParam() const
{
    return bmsParam_;
}

const std::shared_ptr<PreInstallExceptionMgr> BundleMgrService::GetPreInstallExceptionMgr() const
{
    return preInstallExceptionMgr_;
}

#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
sptr<IDefaultApp> BundleMgrService::GetDefaultAppProxy() const
{
    return defaultAppHostImpl_;
}
#endif

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
sptr<IAppControlMgr> BundleMgrService::GetAppControlProxy() const
{
    return appControlManagerHostImpl_;
}
#endif

#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
sptr<QuickFixManagerHostImpl> BundleMgrService::GetQuickFixManagerProxy() const
{
    return quickFixManagerHostImpl_;
}
#endif

#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
sptr<IOverlayManager> BundleMgrService::GetOverlayManagerProxy() const
{
    return overlayManagerHostImpl_;
}
#endif

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
sptr<IBundleResource> BundleMgrService::GetBundleResourceProxy() const
{
    return bundleResourceHostImpl_;
}
#endif

void BundleMgrService::RegisterChargeIdleListener()
{
    APP_LOGI("begin to register charge idle listener");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_CHARGE_IDLE_MODE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    chargeIdleListener_ = std::make_shared<ChargeIdleListener>(subscribeInfo);
    (void)EventFwk::CommonEventManager::SubscribeCommonEvent(chargeIdleListener_);
    APP_LOGI("register charge idle listener done");
}

void BundleMgrService::CheckAllUser()
{
    if (dataMgr_ == nullptr) {
        return;
    }

    APP_LOGI("Check all user start.");
    std::set<int32_t> userIds = dataMgr_->GetAllUser();
    for (auto userId : userIds) {
        if (userId == Constants::DEFAULT_USERID) {
            continue;
        }

        bool isExists = false;
        if (AccountHelper::IsOsAccountExists(userId, isExists) != ERR_OK) {
            APP_LOGW("Failed to query whether the user(%{public}d) exists.", userId);
            continue;
        }

        if (!isExists) {
            APP_LOGI("Query user(%{public}d) success but not complete and remove it", userId);
            userMgrHost_->RemoveUser(userId);
        }
    }
    APP_LOGI("Check all user end");
}

void BundleMgrService::RegisterService()
{
    if (!registerToService_) {
        if (!SystemAbilityHelper::AddSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, host_)) {
            APP_LOGE("fail to register to system ability manager");
            return;
        }
        APP_LOGI("BundleMgrService register to sam success");
        registerToService_ = true;
    }

    PerfProfile::GetInstance().SetBmsLoadEndTime(GetTickCount());
    PerfProfile::GetInstance().Dump();
}

void BundleMgrService::NotifyBundleScanStatus()
{
    APP_LOGI("PublishCommonEvent for bundle scan finished");
    AAFwk::Want want;
    want.SetAction(COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    EventFwk::CommonEventData commonEventData { want };
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonEventData)) {
        notifyBundleScanStatus = true;
        APP_LOGE("PublishCommonEvent for bundle scan finished failed.");
    } else {
        APP_LOGI("PublishCommonEvent for bundle scan finished succeed.");
    }
}

void BundleMgrService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    APP_LOGI("OnAddSystemAbility systemAbilityId:%{public}d added!", systemAbilityId);
    if (COMMON_EVENT_SERVICE_ID == systemAbilityId && notifyBundleScanStatus) {
        NotifyBundleScanStatus();
    }
    if (BUNDLE_BROKER_SERVICE_ABILITY_ID == systemAbilityId) {
        if (host_ != nullptr) {
            isBrokerServiceStarted_ = true;
            host_->SetBrokerServiceStatus(true);
        }
    }
}

bool BundleMgrService::Hidump(const std::vector<std::string> &args, std::string& result) const
{
    if (hidumpHelper_ && hidumpHelper_->Dump(args, result)) {
        return true;
    }

    APP_LOGD("HidumpHelper failed");
    return false;
}

bool BundleMgrService::IsBrokerServiceStarted() const
{
    return isBrokerServiceStarted_;
}
}  // namespace AppExecFwk
}  // namespace OHOS
