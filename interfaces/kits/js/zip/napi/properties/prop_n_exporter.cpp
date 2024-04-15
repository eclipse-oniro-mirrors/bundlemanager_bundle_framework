/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "prop_n_exporter.h"

#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <unistd.h>

#include "common/common_func.h"
#include "create_checksum.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using namespace std;

bool PropNExporter::Export()
{
    return exports_.AddProp({
        NapiValue::DeclareNapiFunction("createChecksum", CreateChecksum::Async),
        NapiValue::DeclareNapiFunction("createChecksumSync", CreateChecksum::Sync),
    });
}

string PropNExporter::GetClassName()
{
    return PropNExporter::className_;
}

PropNExporter::PropNExporter(napi_env env, napi_value exports) : NapiExporter(env, exports) {}
} // namespace LIBZIP
} // namespace AppExecFwk
} // namespace OHOS