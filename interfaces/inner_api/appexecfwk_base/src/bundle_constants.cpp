/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundle_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace Constants {
    const std::string PATH_SEPARATOR = "/";
    const std::string LIBS = "libs/";
    const std::string AN = "an/";
    const std::string RES_FILE_PATH = "resources/resfile/";
    const std::vector<std::string> BUNDLE_EL = {DIR_EL1, DIR_EL2, DIR_EL3, DIR_EL4};
    constexpr const char* X86 = "x86";
    constexpr const char* X86_64 = "x86_64";
    const std::map<std::string, std::string> ABI_MAP = {
        {ARM_EABI, "arm"},
        {ARM_EABI_V7A, "arm"},
        {ARM64_V8A, "arm64"},
        {X86, "x86"},
        {X86_64, "x86_64"},
    };
    const std::string CLONE_BUNDLE_PREFIX = "clone_";
}
}
}