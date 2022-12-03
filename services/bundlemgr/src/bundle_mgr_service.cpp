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

#include "bundle_mgr_service.h"

#include "account_helper.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_distributed_manager.h"
#include "bundle_permission_mgr.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "datetime_ex.h"
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
#include "app_control_manager_host_impl.h"
#endif
#include "perf_profile.h"
#include "system_ability_definition.h"
#include "system_ability_helper.h"
#include "want.h"
#include "xcollie/watchdog.h"

namespace OHOS {
namespace AppExecFwk {
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
    if (runner_) {
        runner_.reset();
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

    bmsThreadPool_.Stop();

    APP_LOGI("instance is destroyed");
}

void BundleMgrService::OnStart()
{
    APP_LOGD("start is triggered");
    if (!Init()) {
        APP_LOGE("init fail");
        return;
    }

    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
#ifdef DEVICE_MANAGER_ENABLE
    AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
    AddSystemAbilityListener(DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
#endif
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

    APP_LOGI("Init begin");
    InitThreadPool();
    InitBmsParam();
    CHECK_INIT_RESULT(InitBundleMgrHost(), "Init bundleMgr fail");
    CHECK_INIT_RESULT(InitBundleInstaller(), "Init bundleInstaller fail");
    InitBundleDataMgr();
    CHECK_INIT_RESULT(InitBundleUserMgr(), "Init bundleUserMgr fail");
    CHECK_INIT_RESULT(InitBundleEventHandler(), "Init bundleEventHandler fail");
    InitDeviceManager();
    InitHidumpHelper();
    InitFreeInstall();
    CHECK_INIT_RESULT(InitDefaultApp(), "Init defaultApp fail");
    CHECK_INIT_RESULT(InitAppControl(), "Init appControl fail");
    CHECK_INIT_RESULT(InitQuickFixManager(), "Init quickFixManager fail");
    ready_ = true;
    APP_LOGI("Init success");
    return true;
}

void BundleMgrService::InitThreadPool()
{
    bmsThreadPool_.Start(THREAD_NUMBER);
    bmsThreadPool_.SetMaxTaskNum(Constants::MAX_TASK_NUMBER);
}

void BundleMgrService::InitBmsParam()
{
    bmsParam_ = std::make_shared<BmsParam>();
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

bool BundleMgrService::InitBundleEventHandler()
{
    if (runner_ == nullptr) {
        runner_ = EventRunner::Create(Constants::BMS_SERVICE_NAME);
        if (runner_ == nullptr) {
            APP_LOGE("create runner fail");
            return false;
        }
    }

    if (handler_ == nullptr) {
        handler_ = std::make_shared<BMSEventHandler>(runner_);
        int32_t timeout = 10 * 60 * 1000; // 10min
        if (HiviewDFX::Watchdog::GetInstance().AddThread(Constants::BMS_SERVICE_NAME, handler_, timeout) != 0) {
            APP_LOGE("watchdog addThread failed");
        }
    }

    handler_->SendEvent(BMSEventHandler::BMS_START);
    return true;
}

void BundleMgrService::InitDeviceManager()
{
#ifdef DEVICE_MANAGER_ENABLE
    if (deviceManager_ == nullptr) {
        APP_LOGI("Create device manager");
        deviceManager_ = std::make_shared<BmsDeviceManager>();
    }
#endif
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
        agingMgr_ = DelayedSingleton<BundleAgingMgr>::GetInstance();
        if (agingMgr_ != nullptr) {
            agingMgr_->InitAgingRunner();
            agingMgr_->InitAgingtTimer();
        }
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

sptr<IBundleInstaller> BundleMgrService::GetBundleInstaller() const
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

#ifdef DEVICE_MANAGER_ENABLE
const std::shared_ptr<BmsDeviceManager> BundleMgrService::GetDeviceManager() const
{
    return deviceManager_;
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
}

sptr<BundleUserMgrHostImpl> BundleMgrService::GetBundleUserMgr() const
{
    return userMgrHost_;
}

const std::shared_ptr<BmsParam> BundleMgrService::GetBmsParam() const
{
    return bmsParam_;
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

void BundleMgrService::CheckAllUser()
{
    if (dataMgr_ == nullptr) {
        return;
    }

    APP_LOGD("Check all user start.");
    std::set<int32_t> userIds = dataMgr_->GetAllUser();
    for (auto userId : userIds) {
        bool isExists = false;
        if (AccountHelper::IsOsAccountExists(userId, isExists) != ERR_OK) {
            APP_LOGE("Failed to query whether the user(%{public}d) exists.", userId);
            continue;
        }

        if (!isExists) {
            userMgrHost_->RemoveUser(userId);
        }
    }
    APP_LOGD("Check all user end");
}

void BundleMgrService::RegisterService()
{
    if (!registerToService_) {
        if (!SystemAbilityHelper::AddSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, host_)) {
            APP_LOGE("fail to register to system ability manager");
            return;
        }
        APP_LOGI("register to sam success");
        registerToService_ = true;
    }

    PerfProfile::GetInstance().SetBmsLoadEndTime(GetTickCount());
    PerfProfile::GetInstance().Dump();
}

void BundleMgrService::NotifyBundleScanStatus()
{
    APP_LOGD("PublishCommonEvent for bundle scan finished");
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    EventFwk::CommonEventData commonEventData { want };
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonEventData)) {
        notifyBundleScanStatus = true;
        APP_LOGE("PublishCommonEvent for bundle scan finished failed.");
    } else {
        APP_LOGD("PublishCommonEvent for bundle scan finished succeed.");
    }
}

void BundleMgrService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    APP_LOGD("OnAddSystemAbility systemAbilityId:%{public}d added!", systemAbilityId);
#ifdef DEVICE_MANAGER_ENABLE
    if (deviceManager_) {
        deviceManager_->OnAddSystemAbility(systemAbilityId, deviceId);
    }
#endif
    if (COMMON_EVENT_SERVICE_ID == systemAbilityId && notifyBundleScanStatus) {
        NotifyBundleScanStatus();
    }
}

void BundleMgrService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    APP_LOGD("OnRemoveSystemAbility systemAbilityId:%{public}d removed!", systemAbilityId);
#ifdef DEVICE_MANAGER_ENABLE
    if (deviceManager_) {
        deviceManager_->OnRemoveSystemAbility(systemAbilityId, deviceId);
    }
#endif
}

bool BundleMgrService::Hidump(const std::vector<std::string> &args, std::string& result) const
{
    if (hidumpHelper_ && hidumpHelper_->Dump(args, result)) {
        return true;
    }

    APP_LOGD("HidumpHelper failed");
    return false;
}

ThreadPool &BundleMgrService::GetThreadPool()
{
    return bmsThreadPool_;
}
}  // namespace AppExecFwk
}  // namespace OHOS
