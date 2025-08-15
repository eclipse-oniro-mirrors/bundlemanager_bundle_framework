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

  constructor() { }
  constructor(packages: Array<PackageConfig>) {
      this.packages = packages;
  }
  constructor(summary: PackageSummary) {
      this.summary = summary;
  }
  constructor(packages: Array<PackageConfig>, summary: PackageSummary) {
      this.packages = packages;
      this.summary = summary;
  }
}

export class PackageConfigInner implements PackageConfig {
  public readonly deviceTypes: Array<string> = new Array<string>;
  public readonly name: string = '';
  public readonly moduleType: string = '';
  public readonly deliveryWithInstall: boolean;

  constructor() { }
  constructor(deviceTypes: Array<string>, name: string, moduleType: string, deliveryWithInstall: boolean) {
      this.deviceTypes = deviceTypes;
      this.name = name;
      this.moduleType = moduleType;
      this.deliveryWithInstall = deliveryWithInstall;
  }
}

export class PackageSummaryInner implements PackageSummary {
  public readonly app: BundleConfigInfo = new BundleConfigInfoInner;
  public readonly modules: Array<ModuleConfigInfo> = new Array<ModuleConfigInfo>;

  constructor() { }
  constructor(modules: Array<ModuleConfigInfo>) {
      this.modules = modules;
  }
  constructor(modules: Array<ModuleConfigInfo>, app: BundleConfigInfo) {
      this.modules = modules;
      this.app = app;
  }
}

export class BundleConfigInfoInner implements BundleConfigInfo {
  public readonly bundleName: string = '';
  public readonly version: Version = new VersionInner;

  constructor() { }
  constructor(bundleName: string, version: Version) {
      this.bundleName = bundleName;
      this.version = version;
  }
}

export class ExtensionAbilityInner implements ExtensionAbility {
  public readonly name: string = '';
  public readonly forms: Array<AbilityFormInfo> = new Array<AbilityFormInfo>;

  constructor() { }
  constructor(name: string, forms: Array<AbilityFormInfo>) {
      this.name = name;
      this.forms = forms;
  }
}

export class ModuleConfigInfoInner implements ModuleConfigInfo {
  public readonly mainAbility: string = '';
  public readonly apiVersion: ApiVersion = new ApiVersionInner;
  public readonly deviceTypes: Array<string> = new Array<string>;
  public readonly distro: ModuleDistroInfo = new ModuleDistroInfoInner;
  public readonly abilities: Array<ModuleAbilityInfo> = new Array<ModuleAbilityInfo>;
  public readonly extensionAbilities: Array<ExtensionAbility> = new Array<ExtensionAbility>;

  constructor() { }
  constructor(mainAbility: string,
    apiVersion: ApiVersion,
    deviceTypes: Array<string>,
    distro: ModuleDistroInfo,
    abilities: Array<ModuleAbilityInfo>,
    extensionAbilities: Array<ExtensionAbility>) {
      this.mainAbility = mainAbility;
      this.apiVersion = apiVersion;
      this.deviceTypes = deviceTypes;
      this.distro = distro;
      this.abilities = abilities;
      this.extensionAbilities = extensionAbilities;
  }
}

export class ModuleDistroInfoInner implements ModuleDistroInfo {
  public readonly deliveryWithInstall: boolean;
  public readonly installationFree: boolean;
  public readonly moduleName: string = '';
  public readonly moduleType: string = '';

  constructor() { }
  constructor(deliveryWithInstall: boolean, installationFree: boolean, moduleName: string, moduleType: string) {
      this.deliveryWithInstall = deliveryWithInstall;
      this.installationFree = installationFree;
      this.moduleName = moduleName;
      this.moduleType = moduleType;
  }
}

export class ModuleAbilityInfoInner implements ModuleAbilityInfo {
  public readonly name: string = '';
  public readonly label: string = '';
  public readonly exported: boolean;
  public readonly forms: Array<AbilityFormInfo> = new Array<AbilityFormInfo>;

  constructor() { }
  constructor(name: string, label: string, exported: boolean, forms: Array<AbilityFormInfo>) {
      this.name = name;
      this.label = label;
      this.exported = exported;
      this.forms = forms;
  }
}

export class AbilityFormInfoInner implements AbilityFormInfo {
  public readonly name: string = '';
  public readonly type: string = '';
  public readonly updateEnabled: boolean;
  public readonly scheduledUpdateTime: string = '';
  public readonly updateDuration: int;
  public readonly supportDimensions: Array<string> = new Array<string>;
  public readonly defaultDimension: string = '';

  constructor() { }
  constructor(name: string,
    type: string,
    updateEnabled: boolean,
    scheduledUpdateTime: string,
    updateDuration: int,
    supportDimensions: Array<string>,
    defaultDimension: string) {
      this.name = name;
      this.type = type;
      this.updateEnabled = updateEnabled;
      this.scheduledUpdateTime = scheduledUpdateTime;
      this.updateDuration = updateDuration;
      this.supportDimensions = supportDimensions;
      this.defaultDimension = defaultDimension;
  }
}

export class VersionInner implements Version {
  public readonly minCompatibleVersionCode: int;
  public readonly name: string = '';
  public readonly code: int;

  constructor() { }
  constructor(minCompatibleVersionCode: int, name: string, code: int) {
      this.minCompatibleVersionCode = minCompatibleVersionCode;
      this.name = name;
      this.code = code;
  }
}

export class ApiVersionInner implements ApiVersion {
  public readonly releaseType: string = '';
  public readonly compatible: int;
  public readonly target: int;

  constructor() { }
  constructor(releaseType: string, compatible: int, target: int) {
      this.releaseType = releaseType;
      this.compatible = compatible;
      this.target = target;
  }
}