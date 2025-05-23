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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_PARAMETER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_PARAMETER_H

namespace OHOS {
char *GetDeviceType();
int GetSdkApiVersion();
int GetParameter(const char *key, const char *def, char *value, int len);
int GetIntParameter(const char *key, int def);
int SetParameter(const char *key, const char *value);
const char *GetAbiList(void);
int GetDevUdid(char *udid, int size);
void SetBMSMockParameter(const char *param, int ret);
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_PARAMETER_H