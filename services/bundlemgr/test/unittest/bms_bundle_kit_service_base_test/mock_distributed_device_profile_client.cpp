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
#include "distributed_device_profile_client.h"
namespace OHOS {
namespace DeviceProfile {
int32_t DistributedDeviceProfileClient::PutDeviceProfile(const ServiceCharacteristicProfile& profile)
{
    return 0;
}
int32_t DistributedDeviceProfileClient::GetDeviceProfile(const std::string& udid, const std::string& serviceId,
    ServiceCharacteristicProfile& profile)
{
    if (udid != "") {
        return 0;
    }
    return -1;
}
int32_t DistributedDeviceProfileClient::DeleteDeviceProfile(const std::string& serviceId)
{
    return 0;
}
int32_t DistributedDeviceProfileClient::SubscribeProfileEvent(const SubscribeInfo& subscribeInfo,
    const std::shared_ptr<IProfileEventCallback>& eventCb)
{
    return 0;
}
int32_t DistributedDeviceProfileClient::UnsubscribeProfileEvent(ProfileEvent profileEvent,
    const std::shared_ptr<IProfileEventCallback>& eventCb)
{
    return 0;
}
int32_t DistributedDeviceProfileClient::SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
    const std::shared_ptr<IProfileEventCallback>& eventCb,
    std::list<ProfileEvent>& failedEvents)
{
    return 0;
}
int32_t DistributedDeviceProfileClient::UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
    const std::shared_ptr<IProfileEventCallback>& eventCb,
    std::list<ProfileEvent>& failedEvents)
{
    return 0;
}
int32_t DistributedDeviceProfileClient::SyncDeviceProfile(const SyncOptions& syncOptions,
    const std::shared_ptr<IProfileEventCallback>& syncCb)
{
    return 0;
}

}
}