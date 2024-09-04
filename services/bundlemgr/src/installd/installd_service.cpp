/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <csignal>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <thread>

#include "app_log_tag_wrapper.h"
#include "bundle_constants.h"
#include "bundle_resource/bundle_resource_constants.h"
#include "bundle_service_constants.h"
#include "installd/installd_operator.h"
#include "system_ability_definition.h"
#include "system_ability_helper.h"

using namespace std::chrono_literals;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr unsigned int INSTALLD_UMASK = 0000;
constexpr int32_t DFX_SIGNAL = 35;
}
REGISTER_SYSTEM_ABILITY_BY_ID(InstalldService, INSTALLD_SERVICE_ID, true);

InstalldService::InstalldService(int32_t saId, bool runOnCreate) : SystemAbility(saId, runOnCreate)
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "installd service instance created");
}


InstalldService::InstalldService() : SystemAbility(INSTALLD_SERVICE_ID, true)
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "installd service instance created");
}

InstalldService::~InstalldService()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "installd service instance destroyed");
}

void InstalldService::OnStart()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "installd OnStart");
    Start();
    if (!Publish(hostImpl_)) {
        LOG_E(BMS_TAG_INSTALLD, "Publish failed");
    }
}

void InstalldService::OnStop()
{
    Stop();
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "installd OnStop");
}

bool InstalldService::Init()
{
    if (isReady_) {
        LOG_NOFUNC_W(BMS_TAG_INSTALLD, "the installd service is already ready");
        return false;
    }
    // installd service need mask 000
    umask(INSTALLD_UMASK);
    hostImpl_ = new (std::nothrow) InstalldHostImpl();
    if (hostImpl_ == nullptr) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLD, "InstalldHostImpl Init failed");
        return false;
    }
    if (!InitDir(ServiceConstants::HAP_COPY_PATH)) {
        LOG_NOFUNC_I(BMS_TAG_INSTALLD, "HAP_COPY_PATH is already exists");
    }
    if (!InitDir(BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH)) {
        LOG_NOFUNC_I(BMS_TAG_INSTALLD, "BUNDLE_RESOURCE_RDB_PATH is already exists");
    }
    return true;
}

bool InstalldService::InitDir(const std::string &path)
{
    if (InstalldOperator::IsExistDir(path)) {
        LOG_NOFUNC_I(BMS_TAG_INSTALLD, "Path already exists");
        return false;
    }
    if (!InstalldOperator::MkOwnerDir(path, true, Constants::FOUNDATION_UID, ServiceConstants::BMS_GID)) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLD, "create path failed errno:%{public}d", errno);
        return false;
    }
    return true;
}

void InstalldService::Start()
{
    if (!Init()) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLD, "init fail");
        return;
    }
    isReady_ = true;
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "installd service start successfully");
}

void InstalldService::Stop()
{
    if (!isReady_) {
        LOG_NOFUNC_W(BMS_TAG_INSTALLD, "the installd service is already stopped");
        return;
    }
    // remove installd service from system ability manager.
    // since we can't handle the fail case, just ignore the result.
    SystemAbilityHelper::UnloadSystemAbility(INSTALLD_SERVICE_ID);
    isReady_ = false;
    LOG_NOFUNC_I(BMS_TAG_INSTALLD, "installd service stop successfully");
}

__attribute__((constructor)) void InstalldService::DisableDfx()
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, DFX_SIGNAL);
    sigprocmask(SIG_BLOCK, &set, NULL);
}
}  // namespace AppExecFwk
}  // namespace OHOS