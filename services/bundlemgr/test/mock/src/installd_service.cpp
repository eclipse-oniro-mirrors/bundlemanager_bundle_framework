/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "installd/installd_service.h"

#include <chrono>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <thread>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "installd/installd_operator.h"
#include "system_ability_definition.h"
#include "system_ability_helper.h"

#ifdef DFX_SIGDUMP_HANDLER_ENABLE
#include "dfx_sigdump_handler.h"
#endif

using namespace std::chrono_literals;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr unsigned int INSTALLD_UMASK = 0000;
}
InstalldService::InstalldService() : SystemAbility(INSTALLD_SERVICE_ID, true)
{
    APP_LOGI("installd service instance is created");
}

InstalldService::~InstalldService()
{
    APP_LOGI("installd service instance is destroyed");
}

void InstalldService::OnStart()
{
    APP_LOGI("installd OnStart");
    Start();
    if (!Publish(hostImpl_)) {
        APP_LOGE("Publish failed");
    }
#ifdef DFX_SIGDUMP_HANDLER_ENABLE
    InitSigDumpHandler();
#endif
}

void InstalldService::OnStop()
{
    Stop();
#ifdef DFX_SIGDUMP_HANDLER_ENABLE
    DeinitSigDumpHandler();
#endif
    APP_LOGI("installd OnStop");
}

bool InstalldService::Init()
{
    if (isReady_) {
        APP_LOGW("the installd service is already ready");
        return false;
    }
    // installd service need mask 000
    umask(INSTALLD_UMASK);
    hostImpl_ = new (std::nothrow) InstalldHostImpl();
    if (hostImpl_ == nullptr) {
        APP_LOGE("InstalldHostImpl Init failed");
        return false;
    }
    if (!InitDir(ServiceConstants::HAP_COPY_PATH)) {
        APP_LOGI("HAP_COPY_PATH is already exists");
    }
    return true;
}

bool InstalldService::InitDir(const std::string &path)
{
    if (InstalldOperator::IsExistDir(path)) {
        APP_LOGI("Path already exists");
        return false;
    }
    if (!InstalldOperator::MkOwnerDir(path, true, Constants::FOUNDATION_UID, ServiceConstants::BMS_GID)) {
        APP_LOGE("create path failed, errno : %{public}d", errno);
        return false;
    }
    return true;
}

void InstalldService::Start()
{
    if (!(Init())) {
        APP_LOGE("init fail");
        return;
    }
    // add installd service to system ability manager.
    // need to retry some times due to installd start faster than system ability manager.
    if (!SystemAbilityHelper::AddSystemAbility(INSTALLD_SERVICE_ID, hostImpl_)) {
        APP_LOGE("installd service fail to register into system ability manager");
        return;
    }
    isReady_ = true;
    APP_LOGI("installd service start successfully");
}

void InstalldService::Stop()
{
    if (!isReady_) {
        APP_LOGW("the installd service is already stopped");
        return;
    }
    // remove installd service from system ability manager.
    // since we can't handle the fail case, just ignore the result.
    SystemAbilityHelper::RemoveSystemAbility(INSTALLD_SERVICE_ID);
    isReady_ = false;
    APP_LOGI("installd service stop successfully");
}

void InstalldService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    APP_LOGI("OnAddSystemAbility: %{public}d", systemAbilityId);
}

int32_t InstalldService::OnIdle(const SystemAbilityOnDemandReason& idleReason)
{
    APP_LOGI("OnIdle: %{public}s, %{public}s",
        idleReason.GetName().c_str(), idleReason.GetValue().c_str());
    return 0;
}
}  // namespace AppExecFwk
}  // namespace OHOS
