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

import { PluginBundleInfo, PluginModuleInfo } from 'bundleManager.PluginBundleInfo';

export class PluginBundleInfoInner implements PluginBundleInfo {
  public readonly label: string = '';
  public readonly labelId: long;
  public readonly icon: string = '';
  public readonly iconId: long;
  public readonly pluginBundleName: string = '';
  public readonly versionCode: long;
  public readonly versionName: string = '';
  public readonly pluginModuleInfos: Array<PluginModuleInfo> = new Array<PluginModuleInfo>;

  constructor() { }
  constructor(label: string,
    labelId: long,
    icon: string,
    iconId: long,
    pluginBundleName: string,
    versionCode: long,
    versionName: string,
    pluginModuleInfos: Array<PluginModuleInfo>) {
      this.label = label;
      this.labelId = labelId;
      this.icon = icon;
      this.iconId = iconId;
      this.pluginBundleName = pluginBundleName;
      this.versionCode = versionCode;
      this.versionName = versionName;
      this.pluginModuleInfos = pluginModuleInfos;
  }
}

export class PluginModuleInfoInner implements PluginModuleInfo {
  public readonly moduleName: string = '';
  public readonly descriptionId: long;
  public readonly description: string = '';

  constructor() { }
  constructor(moduleName: string,
    descriptionId: long,
    description: string) {
      this.moduleName = moduleName;
      this.descriptionId = descriptionId;
      this.description = description;
  }
}
