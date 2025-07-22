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
  readonly descriptionId: long;
  readonly enabled: boolean;
  readonly label: string = "";
  readonly labelId: long;
  readonly icon: string = "";
  readonly iconId: long;
  readonly process: string = "";
  readonly permissions: Array<string> = new Array<string>;
  readonly codePath: string = "";
  readonly metadataArray: Array<ModuleMetadata> = new Array<ModuleMetadata>;
  readonly removable: boolean;
  readonly accessTokenId: long;
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

  constructor() { }
  constructor(name: string,
    description: string,
    descriptionId: long,
    enabled: boolean,
    label: string,
    labelId: long,
    icon: string,
    iconId: long,
    process: string,
    permissions: Array<string>,
    codePath: string,
    metadataArray: Array<ModuleMetadata>,
    removable: boolean,
    accessTokenId: long,
    uid: int,
    iconResource: Resource,
    labelResource: Resource,
    descriptionResource: Resource,
    appDistributionType: string,
    appProvisionType: string,
    systemApp: boolean,
    bundleType: bundleManager.BundleType,
    debug: boolean,
    dataUnclearable: boolean,
    nativeLibraryPath: string,
    multiAppMode: MultiAppMode,
    appIndex: int,
    installSource: string,
    releaseType: string,
    cloudFileSyncEnabled: boolean,
    flags?: int) {
      this.name = name;
      this.description = description;
      this.descriptionId = descriptionId;
      this.enabled = enabled;
      this.label = label;
      this.labelId = labelId;
      this.icon = icon;
      this.iconId = iconId;
      this.process = process;
      this.permissions = permissions;
      this.codePath = codePath;
      this.metadataArray = metadataArray;
      this.removable = removable;
      this.accessTokenId = accessTokenId;
      this.uid = uid;
      this.iconResource = iconResource;
      this.labelResource = labelResource;
      this.descriptionResource = descriptionResource;
      this.appDistributionType = appDistributionType;
      this.appProvisionType = appProvisionType;
      this.systemApp = systemApp;
      this.bundleType = bundleType;
      this.debug = debug;
      this.dataUnclearable = dataUnclearable;
      this.nativeLibraryPath = nativeLibraryPath;
      this.multiAppMode = multiAppMode;
      this.appIndex = appIndex;
      this.installSource = installSource;
      this.releaseType = releaseType;
      this.cloudFileSyncEnabled = cloudFileSyncEnabled;
      this.flags = flags;
  }
}

export class ModuleMetadataInner implements ModuleMetadata {
  readonly moduleName: string = "";
  readonly metadata: Array<Metadata> = new Array<Metadata>;

  constructor() { }
  constructor(moduleName: string, metadata: Array<Metadata>) {
    this.moduleName = moduleName;
    this.metadata = metadata;
  }
}

export class MultiAppModeInner implements MultiAppMode {
  readonly multiAppModeType: bundleManager.MultiAppModeType = bundleManager.MultiAppModeType.UNSPECIFIED;
  readonly maxCount: int;

  constructor() { }
  constructor(multiAppModeType: bundleManager.MultiAppModeType, maxCount: int) {
    this.multiAppModeType = multiAppModeType;
    this.maxCount = maxCount;
  }
}

export class PreinstalledApplicationInfoInner implements PreinstalledApplicationInfo {
  readonly bundleName: string = "";
  readonly moduleName: string = "";
  readonly iconId: long;
  readonly labelId: long;
}
