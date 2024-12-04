/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "bundle_app_spawn_client.h"

#include "app_log_tag_wrapper.h"
#include "bundle_constants.h"
#include "hitrace_meter.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t MAX_PROC_NAME_LEN = 256;
}

BundleAppSpawnClient& BundleAppSpawnClient::GetInstance()
{
    static BundleAppSpawnClient instance;
    return instance;
}

BundleAppSpawnClient::BundleAppSpawnClient()
    : serviceName_(APPSPAWN_SERVER_NAME),
      handle_(nullptr),
      state_(SpawnConnectionState::STATE_NOT_CONNECT) {}

BundleAppSpawnClient::~BundleAppSpawnClient()
{
    CloseConnection();
}

int32_t BundleAppSpawnClient::OpenConnection()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == SpawnConnectionState::STATE_CONNECTED) {
        return 0;
    }
    AppSpawnClientHandle handle = nullptr;
    int32_t ret = AppSpawnClientInit(serviceName_.c_str(), &handle);
    if (FAILED(ret)) {
        LOG_E(BMS_TAG_INSTALLER, "AppSpawnClientInit failed");
        state_ = SpawnConnectionState::STATE_CONNECT_FAILED;
        return ret;
    }
    handle_ = handle;
    state_ = SpawnConnectionState::STATE_CONNECTED;

    return ret;
}

void BundleAppSpawnClient::CloseConnection()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == SpawnConnectionState::STATE_CONNECTED) {
        AppSpawnClientDestroy(handle_);
        handle_ = nullptr;
    }
    state_ = SpawnConnectionState::STATE_NOT_CONNECT;
}


int32_t BundleAppSpawnClient::AppspawnCreateDefaultMsg(const AppSpawnRemoveSandboxDirMsg &removeSandboxDirMsg,
    AppSpawnReqMsgHandle reqHandle)
{
    int32_t ret = 0;
    do {
        ret = AppSpawnReqMsgSetBundleInfo(reqHandle, removeSandboxDirMsg.bundleIndex,
            removeSandboxDirMsg.bundleName.c_str());
        if (ret != 0) {
            LOG_E(BMS_TAG_INSTALLER, "AppSpawnReqMsgSetBundleInfo fail, ret: %{public}d", ret);
            break;
        }
        AppDacInfo appDacInfo = {0};
        appDacInfo.uid = removeSandboxDirMsg.uid;
        ret = AppSpawnReqMsgSetAppDacInfo(reqHandle, &appDacInfo);
        if (ret != 0) {
            LOG_E(BMS_TAG_INSTALLER, "AppSpawnReqMsgSetAppDacInfo fail, ret: %{public}d", ret);
            break;
        }
        ret = AppSpawnReqMsgSetAppFlag(reqHandle, removeSandboxDirMsg.flags);
        if (ret != 0) {
            LOG_E(BMS_TAG_INSTALLER, "AppSpawnReqMsgSetAppFlag fail, ret: %{public}d", ret);
            break;
        }
        return ret;
    } while (0);

    AppSpawnReqMsgFree(reqHandle);
    return ret;
}

bool BundleAppSpawnClient::VerifyMsg(const AppSpawnRemoveSandboxDirMsg &removeSandboxDirMsg)
{
    if (removeSandboxDirMsg.code == MSG_UNINSTALL_DEBUG_HAP) {
        if (removeSandboxDirMsg.bundleName.empty() || removeSandboxDirMsg.bundleName.size() >= MAX_PROC_NAME_LEN) {
            LOG_E(BMS_TAG_INSTALLER, "invalid bundleName! [%{public}s]", removeSandboxDirMsg.bundleName.c_str());
            return false;
        }
        if (removeSandboxDirMsg.bundleIndex < 0 ||
            removeSandboxDirMsg.bundleIndex > Constants::INITIAL_SANDBOX_APP_INDEX) {
            LOG_E(BMS_TAG_INSTALLER, "invalid bundleIndex! [%{public}d]", removeSandboxDirMsg.bundleIndex);
            return false;
        }
        if (removeSandboxDirMsg.uid < 0) {
            LOG_E(BMS_TAG_INSTALLER, "invalid uid! [%{public}d]", removeSandboxDirMsg.uid);
            return false;
        }
    } else {
        LOG_E(BMS_TAG_INSTALLER, "invalid code! [%{public}d]", removeSandboxDirMsg.code);
        return false;
    }
    return true;
}

int32_t BundleAppSpawnClient::RemoveSandboxDir(const AppSpawnRemoveSandboxDirMsg &removeSandboxDirMsg)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_INSTALLER, "call RemoveSandboxDir start");
    if (!VerifyMsg(removeSandboxDirMsg)) {
        LOG_E(BMS_TAG_INSTALLER, "invalid msg");
        return ERR_INVALID_VALUE;
    }

    int32_t ret = 0;
    AppSpawnReqMsgHandle reqHandle = nullptr;

    ret = OpenConnection();
    if (ret != 0) {
        LOG_E(BMS_TAG_INSTALLER, "BundleAppSpawnClient open connection fail");
        return ret;
    }

    ret = AppSpawnReqMsgCreate(static_cast<AppSpawnMsgType>(removeSandboxDirMsg.code),
        removeSandboxDirMsg.bundleName.c_str(), &reqHandle);
    if (ret != 0) {
        LOG_E(BMS_TAG_INSTALLER, "AppSpawnReqMsgCreate fail");
        return ret;
    }

    ret = AppspawnCreateDefaultMsg(removeSandboxDirMsg, reqHandle);
    if (ret != 0) {
        LOG_E(BMS_TAG_INSTALLER, "AppspawnCreateDefaultMsg fail");
        return ret; // create msg failed
    }

    AppSpawnResult result = {0};
    ret = AppSpawnClientSendMsg(handle_, reqHandle, &result);
    if (ret != 0) {
        LOG_E(BMS_TAG_INSTALLER, "BundleAppSpawnClient appspawn send msg fail");
    }
    LOG_D(BMS_TAG_INSTALLER, "call RemoveSandboxDir end");
    return ret;
}
}  // namespace AppExecFwk
}  // namespace OHOS