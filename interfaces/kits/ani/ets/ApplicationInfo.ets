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

import { Metadata } from './Metadata';
import { Resource } from './resource';
import bundleManager from './@ohos.bundle.bundleManager';

import { ResourceInner } from './resource';

export interface ApplicationInfo {
  readonly name: string;
  readonly description: string;
  readonly descriptionId: int;
  readonly enabled: boolean;
  readonly label: string;
  readonly labelId: int;
  readonly icon: string;
  readonly iconId: int;
  readonly process: string;
  readonly permissions: Array<string>;
  readonly codePath: string;
  readonly metadata: Map<string, Array<Metadata>>;
  readonly metadataArray: Array<ModuleMetadata>;
  readonly removable: boolean;
  readonly accessTokenId: int;
  readonly uid: int;
  readonly iconResource: Resource;
  readonly labelResource: Resource;
  readonly descriptionResource: Resource;
  readonly appDistributionType: string;
  readonly appProvisionType: string;
  readonly systemApp: boolean;
  readonly bundleType: bundleManager.BundleType;
  readonly debug: boolean;
  readonly dataUnclearable: boolean;
  readonly nativeLibraryPath: string;
  readonly multiAppMode: MultiAppMode;
  readonly appIndex: int;
  readonly installSource: string;
  readonly releaseType: string;
  readonly cloudFileSyncEnabled: boolean;
  readonly flags?: int;
}

export interface ModuleMetadata {
  readonly moduleName: string;
  readonly metadata: Array<Metadata>;
}

export interface MultiAppMode {
  readonly multiAppModeType: bundleManager.MultiAppModeType;
  readonly maxCount: int;
}

export interface PreinstalledApplicationInfo {
  readonly bundleName: string;
  readonly moduleName: string;
  readonly iconId: int;
  readonly labelId: int;
}


export class ApplicationInfoInner implements ApplicationInfo {
  readonly name: string = "";
  readonly description: string = "";
  readonly descriptionId: int;
  readonly enabled: boolean;
  readonly label: string = "";
  readonly labelId: int;
  readonly icon: string = "";
  readonly iconId: int;
  readonly process: string = "";
  readonly permissions: Array<string> = new Array<string>;
  readonly codePath: string = "";
  readonly metadata: Map<string, Array<Metadata>> = new Map<string, Array<Metadata>>;
  readonly metadataArray: Array<ModuleMetadata> = new Array<ModuleMetadata>;
  readonly removable: boolean;
  readonly accessTokenId: int;
  readonly uid: int;
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
  readonly appIndex: int;
  readonly installSource: string = "";
  readonly releaseType: string = "";
  readonly cloudFileSyncEnabled: boolean;
  readonly flags?: int|undefined;
}

class ModuleMetadataInner implements ModuleMetadata {
  readonly moduleName: string = "";
  readonly metadata: Array<Metadata> = new Array<Metadata>;
}

class MultiAppModeInner implements MultiAppMode {
  readonly multiAppModeType: bundleManager.MultiAppModeType = bundleManager.MultiAppModeType.UNSPECIFIED;
  readonly maxCount: int;
}

class PreinstalledApplicationInfoInner implements PreinstalledApplicationInfo {
  readonly bundleName: string = "";
  readonly moduleName: string = "";
  readonly iconId: int;
  readonly labelId: int;
}
