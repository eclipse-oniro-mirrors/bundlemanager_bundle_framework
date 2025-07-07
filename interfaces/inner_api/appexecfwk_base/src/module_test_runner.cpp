/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "module_test_runner.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "string_ex.h"
 
namespace OHOS {
namespace AppExecFwk {
bool ModuleTestRunner::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    srcPath = Str16ToStr8(parcel.ReadString16());
    arkTSMode = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool ModuleTestRunner::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(srcPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(arkTSMode));
    return true;
}

ModuleTestRunner *ModuleTestRunner::Unmarshalling(Parcel &parcel)
{
    ModuleTestRunner *testRunner = new (std::nothrow) ModuleTestRunner();
    if (testRunner && !testRunner->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete testRunner;
        testRunner = nullptr;
    }
    return testRunner;
}
 
std::string ModuleTestRunner::ToString() const
{
    return "[ name = " + name
            + ", srcPath = " + srcPath
            + ", arkTSMode = " + arkTSMode
            + "]";
}
}  // namespace AppExecFwk
}  // namespace OHOS