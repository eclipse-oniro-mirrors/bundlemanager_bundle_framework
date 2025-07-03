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

export interface BundlePackInfo {
  readonly packages: Array<PackageConfig>;
  readonly summary: PackageSummary;
}

export interface PackageConfig {
  readonly deviceTypes: Array<string>;
  readonly name: string;
  readonly moduleType: string;
  readonly deliveryWithInstall: boolean;
}

export interface PackageSummary {
  readonly app: BundleConfigInfo;
  readonly modules: Array<ModuleConfigInfo>;
}

export interface BundleConfigInfo {
  readonly bundleName: string;
  readonly version: Version;
}

export interface ExtensionAbility {
  readonly name: string;
  readonly forms: Array<AbilityFormInfo>;
}

export interface ModuleConfigInfo {
  readonly mainAbility: string;
  readonly apiVersion: ApiVersion;
  readonly deviceTypes: Array<string>;
  readonly distro: ModuleDistroInfo;
  readonly abilities: Array<ModuleAbilityInfo>;
  readonly extensionAbilities: Array<ExtensionAbility>;
}

export interface ModuleDistroInfo {
  readonly deliveryWithInstall: boolean;
  readonly installationFree: boolean;
  readonly moduleName: string;
  readonly moduleType: string;
}

export interface ModuleAbilityInfo {
  readonly name: string;
  readonly label: string;
  readonly exported: boolean;
  readonly forms: Array<AbilityFormInfo>;
}

export interface AbilityFormInfo {
  readonly name: string;
  readonly type: string;
  readonly updateEnabled: boolean;
  readonly scheduledUpdateTime: string;
  readonly updateDuration: number;
  readonly supportDimensions: Array<string>;
  readonly defaultDimension: string;
}

export interface Version {
  readonly minCompatibleVersionCode: number;
  readonly name: string;
  readonly code: number;
}

export interface ApiVersion {
  readonly releaseType: string;
  readonly compatible: number;
  readonly target: number;
}