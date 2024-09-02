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

#ifndef OHOS_CJ_ZIP_H
#define OHOS_CJ_ZIP_H

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {

int32_t Zip(const std::string &srcPath, const std::string &destPath, const OPTIONS &options);
int32_t UnZip(const std::string &srcFile, const std::string &destFile, OPTIONS options);

} // BundleManager
} // CJSystemapi
} // OHOS
#endif