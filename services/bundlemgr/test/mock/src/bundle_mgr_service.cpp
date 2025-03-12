/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifdef CODE_SIGNATURE_ENABLE
#include "aot/aot_sign_data_cache_mgr.h"
#endif
#include "aot/aot_device_idle_listener.h"
#include "bundle_common_event.h"
#include "bundle_memory_guard.h"
#include "bundle_resource_helper.h"
#include "datetime_ex.h"
#include "el5_filekey_callback.h"
#include "el5_filekey_manager_kit.h"
#include "installd_client.h"
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
#include "app_control_manager_host_impl.h"
#endif
#include "perf_profile.h"
#include "scope_guard.h"
#include "system_ability_definition.h"
#include "system_ability_helper.h"
#include "xcollie_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t BUNDLE_BROKER_SERVICE_ABILITY_ID = 0x00010500;
constexpr int16_t EL5_FILEKEY_SERVICE_ABILITY_ID = 8250;
constexpr const char* FUN_BMS_START = "BundleMgrService::Start";
constexpr unsigned int BMS_START_TIME_OUT_SECONDS = 60 * 4;
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
    APP_LOGI("BundleMgrService instance is destroyed");
}

void BundleMgrService::OnStart()
{
    APP_LOGI_NOFUNC("BundleMgrService OnStart start");
}

void BundleMgrService::OnStop()
{
    APP_LOGI("OnStop is called");
}

void BundleMgrService::OnDeviceLevelChanged(int32_t type, int32_t level, std::string& action)
{
    APP_LOGD("SystemAbility OnDeviceLevelChanged is called");
}

bool BundleMgrService::IsServiceReady() const
{
    return false;
}

bool BundleMgrService::Init()
{
    return false;
}

void BundleMgrService::InitBmsParam()
{
}

void BundleMgrService::InitPreInstallExceptionMgr()
{
}

bool BundleMgrService::InitBundleMgrHost()
{
    return false;
}

bool BundleMgrService::InitBundleInstaller()
{
    return false;
}

void BundleMgrService::InitBundleDataMgr()
{
}

bool BundleMgrService::InitBundleUserMgr()
{
    return false;
}

bool BundleMgrService::InitVerifyManager()
{
    return false;
}

bool BundleMgrService::InitExtendResourceManager()
{
    return false;
}

bool BundleMgrService::InitBundleEventHandler()
{
    return false;
}

void BundleMgrService::InitHidumpHelper()
{
}

void BundleMgrService::InitFreeInstall()
{
}

bool BundleMgrService::InitDefaultApp()
{
    return false;
}

bool BundleMgrService::InitAppControl()
{
    return false;
}

bool BundleMgrService::InitQuickFixManager()
{
    return false;
}

bool BundleMgrService::InitOverlayManager()
{
    return false;
}

void BundleMgrService::CreateBmsServiceDir()
{
}

bool BundleMgrService::InitBundleResourceMgr()
{
    return false;
}

sptr<BundleInstallerHost> BundleMgrService::GetBundleInstaller() const
{
    return nullptr;
}

void BundleMgrService::RegisterDataMgr(std::shared_ptr<BundleDataMgr> dataMgrImpl)
{
}

const std::shared_ptr<BundleDataMgr> BundleMgrService::GetDataMgr() const
{
    return nullptr;
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
const std::shared_ptr<BundleAgingMgr> BundleMgrService::GetAgingMgr() const
{
    return nullptr;
}

const std::shared_ptr<BundleConnectAbilityMgr> BundleMgrService::GetConnectAbility(int32_t userId)
{
    return nullptr;
}

const std::shared_ptr<BundleDistributedManager> BundleMgrService::GetBundleDistributedManager() const
{
    return nullptr;
}
#endif

void BundleMgrService::SelfClean()
{
}

sptr<BundleUserMgrHostImpl> BundleMgrService::GetBundleUserMgr() const
{
    return nullptr;
}

sptr<IVerifyManager> BundleMgrService::GetVerifyManager() const
{
    return nullptr;
}

sptr<IExtendResourceManager> BundleMgrService::GetExtendResourceManager() const
{
    return nullptr;
}

const std::shared_ptr<BmsParam> BundleMgrService::GetBmsParam() const
{
    return nullptr;
}

const std::shared_ptr<PreInstallExceptionMgr> BundleMgrService::GetPreInstallExceptionMgr() const
{
    return nullptr;
}

#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
sptr<IDefaultApp> BundleMgrService::GetDefaultAppProxy() const
{
    return nullptr;
}
#endif

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
sptr<IAppControlMgr> BundleMgrService::GetAppControlProxy() const
{
    return nullptr;
}
#endif

#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
sptr<QuickFixManagerHostImpl> BundleMgrService::GetQuickFixManagerProxy() const
{
    return nullptr;
}
#endif

#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
sptr<IOverlayManager> BundleMgrService::GetOverlayManagerProxy() const
{
    return nullptr;
}
#endif

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
sptr<IBundleResource> BundleMgrService::GetBundleResourceProxy() const
{
    return nullptr;
}
#endif

void BundleMgrService::CheckAllUser()
{
}

void BundleMgrService::RegisterService()
{
}

void BundleMgrService::NotifyBundleScanStatus()
{
}

void BundleMgrService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    APP_LOGI("OnAddSystemAbility systemAbilityId:%{public}d added", systemAbilityId);
}

bool BundleMgrService::Hidump(const std::vector<std::string> &args, std::string& result) const
{
    return false;
}

bool BundleMgrService::IsBrokerServiceStarted() const
{
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
