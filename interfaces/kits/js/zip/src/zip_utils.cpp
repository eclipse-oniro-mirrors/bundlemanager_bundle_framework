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
#include "zip_utils.h"

#include <regex.h>

#include "event_handler.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
namespace {
const std::string SEPARATOR = "/";
const char* FILE_PATH_PATTERN = ".*";
const std::string ZIP_THREAD = "ZipThread";
}  // namespace
using namespace OHOS::AppExecFwk;

std::shared_ptr<EventHandler> g_handler = nullptr;
std::mutex mutex;
void PostTask(const InnerEvent::Callback &callback)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (g_handler == nullptr) {
        auto runner = EventRunner::Create(ZIP_THREAD, ThreadMode::FFRT);
        g_handler = std::make_shared<EventHandler>(runner);
    }
    g_handler->PostTask(callback);
}

struct tm *GetCurrentSystemTime(void)
{
    auto tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    struct tm *time = localtime(&tt);
    return time;
}

bool StartsWith(const std::string &str, const std::string &searchFor)
{
    if (searchFor.size() > str.size()) {
        return false;
    }

    std::string source = str.substr(0, searchFor.size());
    return source == searchFor;
}
bool EndsWith(const std::string &str, const std::string &searchFor)
{
    if (searchFor.size() > str.size()) {
        return false;
    }

    std::string source = str.substr(str.size() - searchFor.size(), searchFor.size());
    return source == searchFor;
}

bool FilePathCheckValid(const std::string &str)
{
    if (str.empty()) {
        return false;
    }
    regex_t regex;
    if (regcomp(&regex, FILE_PATH_PATTERN, REG_EXTENDED | REG_NOSUB) != 0) {
        return false;
    }
    int32_t ret = regexec(&regex, str.c_str(), 0, NULL, 0);
    if (ret != 0) {
        regfree(&regex);
        return false;
    }
    regfree(&regex);
    return true;
}

}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
