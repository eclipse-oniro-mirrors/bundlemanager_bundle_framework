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
    readonly userId: int;
    readonly appIndex: int;
  }
  
  export class BundleChangedInfoInner implements BundleChangedInfo {
    readonly bundleName: string;
    readonly userId: int;
    readonly appIndex: int;

    constructor() { }
    constructor(bundleName: string,
      userId: int,
      appIndex: int) {
        this.bundleName = bundleName;
        this.userId = userId;
        this.appIndex = appIndex;
    }
  }

  type BundleChangedEvent = 'add' | 'update' | 'remove';

  native function on(type: BundleChangedEvent, callback: Callback<BundleChangedInfo>): void;

  native function off(type: BundleChangedEvent, callback?: Callback<BundleChangedInfo>): void;
}