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

#include <cstring>

#include "parameter.h"
#include "securec.h"
#include <string>

namespace OHOS {
namespace {
const char *DEVICE_TYPE_OF_PHONE = "phone";
const char *DEVICE_TYPE_OF_DEFAULT = "default";
const char *EMPTY_STRING = "";
const int DEFAULT_SDK_API = 9;
const int32_t MAX_LEN = 40;
} // namespace

char *g_testDeviceType = const_cast<char *>(EMPTY_STRING);

char *GetDeviceType()
{
    if (strcmp(g_testDeviceType, DEVICE_TYPE_OF_PHONE) == 0) {
        return const_cast<char *>(DEVICE_TYPE_OF_PHONE);
    }
    if (strcmp(g_testDeviceType, DEVICE_TYPE_OF_DEFAULT) == 0) {
        return const_cast<char *>(DEVICE_TYPE_OF_DEFAULT);
    }

    return const_cast<char *>(EMPTY_STRING);
}

int GetSdkApiVersion()
{
    return DEFAULT_SDK_API;
}

int GetParameter(const char *key, const char *def, char *value, int len)
{
    if ((key != nullptr) && (value != nullptr) &&
        (std::strcmp(key, "persist.bms.supportCompressNativeLibs") == 0)) {
        char tmp[MAX_LEN] = "true";
        if (strcpy_s(value, len, tmp) == 0) {
            return 1;
        }
    }
    return 0;
}

int GetIntParameter(const char *key, int def)
{
    return def;
}

const char *GetAbiList(void)
{
    return "arm64-v8a";
}

int SetParameter(const char *key, const char *value)
{
    return 0;
}

int GetDevUdid(char *udid, int size)
{
    return 0;
}
} // OHOS