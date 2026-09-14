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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_INCLUDE_MOCK_ENTERPRISE_CERT_RECORD_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_INCLUDE_MOCK_ENTERPRISE_CERT_RECORD_H

#include <cstdint>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
// InstalldClient mock records and failure injection for enterprise cert calls, defined
// in test/mock/src/mock_install_client.cpp; lets tests assert call args and order.
extern std::vector<std::string> g_addedCertPaths;
extern std::vector<std::string> g_addedCertContents;
extern std::vector<std::string> g_deletedCertPaths;
extern void ClearCertRecordForTest();
extern void SetAddCertRetListForTest(const std::vector<int32_t> &list);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_INCLUDE_MOCK_ENTERPRISE_CERT_RECORD_H
