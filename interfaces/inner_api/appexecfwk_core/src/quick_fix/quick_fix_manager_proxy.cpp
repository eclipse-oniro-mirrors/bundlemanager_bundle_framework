/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "quick_fix_manager_proxy.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "hitrace_meter.h"
#include "ipc_types.h"

namespace OHOS {
namespace namespace AppExecFwk {
QuickFixManagerProxy::QuickFixManagerProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IDefaultApp>(object)
{
    APP_LOGD("create QuickFixManagerProxy.");
}

QuickFixManagerProxy::~QuickFixManagerProxy()
{
    APP_LOGD("destroy QuickFixManagerProxy.");
}

bool QuickFixManagerProxy::DeployQuickFix(const std::vector<string> &bundleFilePaths,
    const sptr<IQuickFixStatusCallBack> &statusCallBack)
{
    APP_LOGI("begin to call DeployQuickFix.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (bundleFilePaths.empty() || !statusCallBack) {
        APP_LOGE("DeployQuickFix failed due to params error.");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return false;
    }
    if (!data.WriteVectorString(bundleFilePaths)) {
        APP_LOGE("write bundleFilePaths failed.");
        return false;
    }
    if (!data.WriteObject<IRemoteObject>(statusCallBack->AsObject())) {
        APP_LOGE("write parcel failed.");
        return false;
    }

    MessageParcel reply;
    if (!SendRequest(IQuickFixManager::Message::DEPLOY_QUICK_FIX, data, reply)) {
        APP_LOGE("SendRequest failed.");
        return false;
    }

    return reply.ReadBool();
}

bool QuickFixManagerProxy::SwitchQuickFix(const std::string &bundleName,
    sptr<IQuickFixStatusCallBack> &statusCallBack)
{
    APP_LOGI("begin to call SwitchQuickFix.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (bundleName.empty() || !statusCallBack) {
        APP_LOGE("SwitchQuickFix failed due to params error.");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("write bundleName failed.");
        return false;
    }
    if (!data.WriteObject<IRemoteObject>(statusCallBack->AsObject())) {
        APP_LOGE("write parcel failed.");
        return false;
    }

    MessageParcel reply;
    if (!SendRequest(IQuickFixManager::Message::SWITCH_QUICK_FIX, data, reply)) {
        APP_LOGE("SendRequest failed.");
        return false;
    }

    return reply.ReadBool();
}

bool QuickFixManagerProxy::DeleteQuickFix(const std::string &bundleName,
    const sptr<IQuickFixStatusCallBack> &statusCallBack)
{
    APP_LOGI("begin to call DeleteQuickFix.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (bundleName.empty() || !statusCallBack) {
        APP_LOGE("DeleteQuickFix failed due to params error.");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("write bundleName failed.");
        return false;
    }
    if (!data.WriteObject<IRemoteObject>(statusCallBack->AsObject())) {
        APP_LOGE("write parcel failed.");
        return false;
    }

    MessageParcel reply;
    if (!SendRequest(IQuickFixManager::Message::DELETE_QUICK_FIX, data, reply)) {
        APP_LOGE("SendRequest failed.");
        return false;
    }

    return reply.ReadBool();
}

bool QuickFixManagerProxy::SendRequest(IDefaultApp::Message code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("failed to send request %{public}d due to remote object null.", code);
        return false;
    }
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error code %{public}d in transact %{public}d", result, code);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS