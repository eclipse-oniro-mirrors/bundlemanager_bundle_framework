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

import { Metadata } from 'bundleManager.Metadata';
import { Resource } from 'global.resource';
import bundleManager from '@ohos.bundle.bundleManager';
import { ApplicationInfo, ModuleMetadata, MultiAppMode, PreinstalledApplicationInfo } from 'bundleManager.ApplicationInfo';
import { ResourceInner } from 'global.resourceInner';

export class ApplicationInfoInner implements ApplicationInfo {
  readonly name: string = "";
  readonly description: string = "";
  readonly descriptionId: number;
  readonly enabled: boolean;
  readonly label: string = "";
  readonly labelId: number;
  readonly icon: string = "";
  readonly iconId: number;
  readonly process: string = "";
  readonly permissions: Array<string> = new Array<string>;
  readonly codePath: string = "";
  readonly metadataArray: Array<ModuleMetadata> = new Array<ModuleMetadata>;
  readonly removable: boolean;
  readonly accessTokenId: number;
  readonly uid: number;
  readonly iconResource: Resource = new ResourceInner;
  readonly labelResource: Resource = new ResourceInner;
  readonly descriptionResource: Resource = new ResourceInner;
  readonly appDistributionType: string = "";
  readonly appProvisionType: string = "";
  readonly systemApp: boolean;
  readonly bundleType: bundleManager.BundleType = bundleManager.BundleType.APP;
  readonly debug: boolean;
  readonly dataUnclearable: boolean;
  readonly nativeLibraryPath: string = "";
  readonly multiAppMode: MultiAppMode = new MultiAppModeInner;
  readonly appIndex: number;
  readonly installSource: string = "";
  readonly releaseType: string = "";
  readonly cloudFileSyncEnabled: boolean;
  readonly flags?: number|undefined;
}

export class ModuleMetadataInner implements ModuleMetadata {
  readonly moduleName: string = "";
  readonly metadata: Array<Metadata> = new Array<Metadata>;
}

export class MultiAppModeInner implements MultiAppMode {
  readonly multiAppModeType: bundleManager.MultiAppModeType = bundleManager.MultiAppModeType.UNSPECIFIED;
  readonly maxCount: number;
}

export class PreinstalledApplicationInfoInner implements PreinstalledApplicationInfo {
  readonly bundleName: string = "";
  readonly moduleName: string = "";
  readonly iconId: number;
  readonly labelId: number;
}
