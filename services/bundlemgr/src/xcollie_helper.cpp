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

#include "xcollie_helper.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cerrno>

#include "app_log_wrapper.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BOOT_DETECTOR_DEV_PATH = "/dev/bbox";
constexpr int8_t ACTION_NAME_LEN = 64;

struct ActionIoctlData {
    enum ActionTimerOp op = ACT_TIMER_PAUSE_ALL;
    char actionName[ACTION_NAME_LEN] = "";
    unsigned int timeout = 0;
};

#define ACTION_TIMER_CTL _IOW('B', 11, struct ActionIoctlData)
}
int XCollieHelper::SetTimer(const std::string &name, unsigned int timeout, std::function<void(void *)> func, void *arg)
{
#ifdef HICOLLIE_ENABLE
    return HiviewDFX::XCollie::GetInstance().SetTimer(name, timeout, func, arg, HiviewDFX::XCOLLIE_FLAG_LOG);
#else
    APP_LOGI("HICOLLIE_ENABLE is false");
    // HICOLLIE_ENABLE is false, do nothing and return -1.
    return -1;
#endif
}

int32_t XCollieHelper::SetOTATimer(const std::string &name, unsigned int timeout)
{
#ifdef HICOLLIE_ENABLE
    return HiviewDFX::XCollie::GetInstance().SetTimer(
        name, timeout, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_RECOVERY);
#else
    APP_LOGI_NOFUNC("HICOLLIE_ENABLE is false");
    return -1;
#endif
}

void XCollieHelper::CancelTimer(int id)
{
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(id);
#endif
}

int32_t XCollieHelper::SetRecoveryTimer(const std::string &methodName, unsigned int timeout)
{
    return SetTimer(methodName, timeout, nullptr, nullptr);
}

void XCollieHelper::PauseFoundationWatchdog()
{
    APP_LOGI_NOFUNC("start pause foundation watchdog");
    ControlWatchdogInternal(ActionTimerOp::ACT_TIMER_PAUSE_ALL);
}

void XCollieHelper::ResumeFoundationWatchdog()
{
    APP_LOGI_NOFUNC("start resume foundation watchdog");
    ControlWatchdogInternal(ActionTimerOp::ACT_TIMER_RESUME_ALL);
}

void XCollieHelper::ControlWatchdogInternal(ActionTimerOp op)
{
#ifdef HICOLLIE_ENABLE
    struct ActionIoctlData data = {
        .op = op,
    };
    int32_t fd = open(BOOT_DETECTOR_DEV_PATH, O_WRONLY);
    if (fd < 0) {
        APP_LOGE_NOFUNC("XCollie open failed, errno: %{public}d", errno);
        return;
    }
    fdsan_exchange_owner_tag(fd, 0, LOG_DOMAIN);
    int32_t ret = ioctl(fd, ACTION_TIMER_CTL, &data);
    if (ret < 0) {
        APP_LOGE_NOFUNC("XCollie ioctl failed, ret: %{public}d, errno: %{public}d", ret, errno);
    }
    fdsan_close_with_tag(fd, LOG_DOMAIN);
    return;
#else
    APP_LOGI_NOFUNC("HICOLLIE_ENABLE is false");
#endif
}
}  // namespace AppExecFwk
}  // namespace OHOS
