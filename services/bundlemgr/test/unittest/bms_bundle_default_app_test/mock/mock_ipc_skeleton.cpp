/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "mock_ipc_skeleton.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
using namespace IPC_SINGLE;
#endif

int32_t uid_ = 20000001;
int32_t tokenId_ = 0;

int32_t IPCSkeleton::GetCallingUid()
{
    return uid_;
}

int32_t IPCSkeleton::GetCallingPid()
{
    return 1;
}

void IPCSkeleton::SetCallingUid(int32_t uid)
{
    uid_ = uid;
}

uint32_t IPCSkeleton::GetCallingTokenID()
{
    return tokenId_;
}

uint32_t IPCSkeleton::SetCallingTokenID(int32_t tokenId)
{
    return tokenId_ = tokenId;
}

uint32_t IPCSkeleton::GetCallingFullTokenID()
{
    return 0;
}

bool IPCSkeleton::SetCallingIdentity(std::string &identity, bool flag)
{
    return false;
}
} // namespace OHOS
