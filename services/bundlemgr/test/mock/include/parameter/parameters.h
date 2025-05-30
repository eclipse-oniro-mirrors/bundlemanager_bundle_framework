/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_PARAMETERS_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_PARAMETERS_H

#include <string>

namespace OHOS {
namespace system {
std::string GetDeviceType();

bool GetBoolParameter(const std::string& key, bool def);

template<typename T>
T GetIntParameter(const std::string& key, T def);

std::string GetParameter(const std::string& key, const std::string& def);

bool SetParameter(const std::string& key, const std::string& val);

void RemoveParameter(const std::string& key);
} // namespace system
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_PARAMETERS_H