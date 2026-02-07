/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_IDLE_MANAGER_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_IDLE_MANAGER_RDB_H

#include "bundle_option.h"
#include "appexecfwk_errors.h"

namespace OHOS {
namespace AppExecFwk {

// Global test control functions for mock behavior
void SetGetAllBundleResultForTest(ErrCode ret);
void SetBundlesForTest(const std::vector<BundleOptionInfo> &bundles);
void SetAddBundlesResultForTest(ErrCode ret);
void SetAddBundleResultForTest(ErrCode ret);
void SetDeleteBundleResultForTest(ErrCode ret);
void ClearBundlesForTest();

} // namespace AppExecFwk
} // namespace OHOS

#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_IDLE_MANAGER_RDB_H
