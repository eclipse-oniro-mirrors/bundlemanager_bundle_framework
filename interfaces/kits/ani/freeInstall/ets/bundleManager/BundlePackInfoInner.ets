/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { BundlePackInfo, PackageConfig, PackageSummary, BundleConfigInfo, ExtensionAbility, ModuleConfigInfo,
  ModuleDistroInfo, ModuleAbilityInfo, AbilityFormInfo, Version, ApiVersion } from 'bundleManager.BundlePackInfo';

export class BundlePackInfoInner implements BundlePackInfo {
  public readonly packages: Array<PackageConfig> = new Array<PackageConfig>;
  public readonly summary: PackageSummary = new PackageSummaryInner;
}

export class PackageConfigInner implements PackageConfig {
  public readonly deviceTypes: Array<string> = new Array<string>;
  public readonly name: string = '';
  public readonly moduleType: string = '';
  public readonly deliveryWithInstall: boolean;
}

export class PackageSummaryInner implements PackageSummary {
  public readonly app: BundleConfigInfo = new BundleConfigInfoInner;
  public readonly modules: Array<ModuleConfigInfo> = new Array<ModuleConfigInfo>;
}

export class BundleConfigInfoInner implements BundleConfigInfo {
  public readonly bundleName: string = '';
  public readonly version: Version = new VersionInner;
}

export class ExtensionAbilityInner implements ExtensionAbility {
  public readonly name: string = '';
  public readonly forms: Array<AbilityFormInfo> = new Array<AbilityFormInfo>;
}

export class ModuleConfigInfoInner implements ModuleConfigInfo {
  public readonly mainAbility: string = '';
  public readonly apiVersion: ApiVersion = new ApiVersionInner;
  public readonly deviceTypes: Array<string> = new Array<string>;
  public readonly distro: ModuleDistroInfo = new ModuleDistroInfoInner;
  public readonly abilities: Array<ModuleAbilityInfo> = new Array<ModuleAbilityInfo>;
  public readonly extensionAbilities: Array<ExtensionAbility> = new Array<ExtensionAbility>;
}

export class ModuleDistroInfoInner implements ModuleDistroInfo {
  public readonly deliveryWithInstall: boolean;
  public readonly installationFree: boolean;
  public readonly moduleName: string = '';
  public readonly moduleType: string = '';
}

export class ModuleAbilityInfoInner implements ModuleAbilityInfo {
  public readonly name: string = '';
  public readonly label: string = '';
  public readonly exported: boolean;
  public readonly forms: Array<AbilityFormInfo> = new Array<AbilityFormInfo>;
}

export class AbilityFormInfoInner implements AbilityFormInfo {
  public readonly name: string = '';
  public readonly type: string = '';
  public readonly updateEnabled: boolean;
  public readonly scheduledUpdateTime: string = '';
  public readonly updateDuration: int;
  public readonly supportDimensions: Array<string> = new Array<string>;
  public readonly defaultDimension: string = '';
}

export class VersionInner implements Version {
  public readonly minCompatibleVersionCode: int;
  public readonly name: string = '';
  public readonly code: int;
}

export class ApiVersionInner implements ApiVersion {
  public readonly releaseType: string = '';
  public readonly compatible: int;
  public readonly target: int;
}