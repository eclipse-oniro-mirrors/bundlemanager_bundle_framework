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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZLIB_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZLIB_H

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "enum_util.h"
#include "file_path.h"
#include "zip_utils.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
bool ANIParseOptions(ani_env* env, ani_object object, LIBZIP::OPTIONS& options);
ErrCode ANICompressFileImpl(const std::string& inFile, const std::string& outFile, const LIBZIP::OPTIONS& options);
ErrCode ANIDecompressFileImpl(const std::string& inFile, const std::string& outFile, const LIBZIP::OPTIONS& options);
} // namespace LIBZIP
} // namespace AppExecFwk
} // namespace OHOS

#endif