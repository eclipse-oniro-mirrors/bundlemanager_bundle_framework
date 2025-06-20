/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef INSTALLER_CALLBACK_H
#define INSTALLER_CALLBACK_H

#include <future>

#include "nocopyable.h"
#include "status_receiver_host.h"

namespace OHOS {
namespace AppExecFwk {
class InstallerCallback : public OHOS::AppExecFwk::StatusReceiverHost {
public:
    InstallerCallback() = default;
    ~InstallerCallback() override = default;

    void OnStatusNotify(const int32_t progress) override;
    void OnFinished(const int32_t resultCode, [[maybe_unused]] const std::string &resultMsg) override;
    void OnFinished(const int32_t resultCode, const std::string &resultMsg, const int32_t innerCode) override;
    int32_t GetResultCode();
    std::string GetResultMsg();
    int32_t GetInnerCode();

private:
    bool isSetValue_ = false;
    std::mutex setValueMutex_;
    std::promise<int32_t> resultCodeSignal_;
    std::promise<std::string> resultMsgSignal_;
    std::promise<int32_t> innerCodeSignal_;
    DISALLOW_COPY_AND_MOVE(InstallerCallback);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INSTALLER_CALLBACK_H