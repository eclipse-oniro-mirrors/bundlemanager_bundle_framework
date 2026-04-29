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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_XCOLLIE_HELPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_XCOLLIE_HELPER_H

#include <string>

namespace OHOS {
namespace AppExecFwk {
enum ActionTimerOp {
    ACT_TIMER_PAUSE_ALL = 0xbfac0004,
    ACT_TIMER_RESUME_ALL = 0xbfac0005,
};
class XCollieHelper {
public:
    // set timer
    // name : timer name
    // timeout : timeout, unit s
    // func : callback
    // arg : the callback's param
    // return: the timer id
    static int SetTimer(const std::string &name, unsigned int timeout, std::function<void (void *)> func, void *arg);

    // set timer
    // name : timer name
    // timeout : timeout, unit s
    static int SetRecoveryTimer(const std::string &methodName, unsigned int timeout = 60);

    // cancel timer
    // id: timer id
    static void CancelTimer(int id);

    // pause timer
    static void PauseFoundationWatchdog();
    
    // resume timer
    static void ResumeFoundationWatchdog();

    // set timer with flag XCOLLIE_FLAG_RECOVERY
    // name : timer name
    // timeout : timeout, unit s
    // return: the timer id
    static int32_t SetOTATimer(const std::string &name, unsigned int timeout);

private:
    static void ControlWatchdogInternal(ActionTimerOp op);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_XCOLLIE_HELPER_H
