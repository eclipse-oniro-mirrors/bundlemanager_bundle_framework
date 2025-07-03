/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import bundleManager from '@ohos.bundle.bundleManager';

export interface SharedBundleInfo {
  readonly name: string;
  readonly compatiblePolicy: bundleManager.CompatiblePolicy;
  readonly sharedModuleInfo: Array<SharedModuleInfo>;
}

export interface SharedModuleInfo {
  readonly name: string;
  readonly versionCode: number;
  readonly versionName: string;
  readonly description: string;
  readonly descriptionId: number;
}
