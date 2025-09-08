/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

import { Callback } from '@ohos.base';

export default namespace bundleMonitor {

  loadLibraryWithPermissionCheck("ani_bundle_monitor.z", "@ohos.bundle.bundleMonitor");

  export interface BundleChangedInfo {
    readonly bundleName: string;
    readonly userId: number;
    readonly appIndex: number;
  }
  
  export class BundleChangedInfoInner implements BundleChangedInfo {
    readonly bundleName: string;
    readonly userId: number;
    readonly appIndex: number;
  }

  type BundleChangedEvent = 'add' | 'update' | 'remove';

  export native function on(type: BundleChangedEvent, callback: Callback<BundleChangedInfo>): void;

  export native function off(type: BundleChangedEvent, callback?: Callback<BundleChangedInfo>): void;
}