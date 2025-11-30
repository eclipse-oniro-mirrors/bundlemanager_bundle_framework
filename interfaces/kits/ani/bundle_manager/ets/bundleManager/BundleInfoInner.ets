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

import { ApplicationInfo } from 'bundleManager.ApplicationInfo';
import { HapModuleInfo, RouterItem } from 'bundleManager.HapModuleInfo';
import bundleManager from '@ohos.bundle.bundleManager';
import { BundleInfo, ReqPermissionDetail, UsedScene, SignatureInfo, AppCloneIdentity, DynamicIconInfo,
  BundleOptions} from 'bundleManager.BundleInfo';
import { ApplicationInfoInner } from './ApplicationInfoInner';

export class BundleInfoInner implements BundleInfo {
  readonly name: string = "";
  readonly vendor: string = "";
  readonly versionCode: long;
  readonly versionName: string = "";
  readonly minCompatibleVersionCode: int;
  readonly targetVersion: int;
  readonly appInfo: ApplicationInfo | null = null;
  readonly hapModulesInfo: Array<HapModuleInfo> = new Array<HapModuleInfo>;
  readonly reqPermissionDetails: Array<ReqPermissionDetail> = new Array<ReqPermissionDetail>;
  readonly permissionGrantStates: Array<bundleManager.PermissionGrantState> = new Array<bundleManager.PermissionGrantState>;
  readonly signatureInfo: SignatureInfo | null = null;
  readonly installTime: long;
  readonly updateTime: long;
  readonly routerMap: Array<RouterItem> = new Array<RouterItem>;
  readonly appIndex: int;
  readonly firstInstallTime?: long;

  constructor() { }
  constructor(name: string,
    vendor: string,
    versionCode: long,
    versionName: string,
    minCompatibleVersionCode: int,
    targetVersion: int,
    appInfo: ApplicationInfo,
    hapModulesInfo: Array<HapModuleInfo>,
    reqPermissionDetails: Array<ReqPermissionDetail>,
    permissionGrantStates: Array<bundleManager.PermissionGrantState>,
    signatureInfo: SignatureInfo,
    installTime: long,
    updateTime: long,
    routerMap: Array<RouterItem>,
    appIndex: int,
    firstInstallTime?: long) {
      this.name = name;
      this.vendor = vendor;
      this.versionCode = versionCode;
      this.versionName = versionName;
      this.minCompatibleVersionCode = minCompatibleVersionCode;
      this.targetVersion = targetVersion;
      this.appInfo = appInfo;
      this.hapModulesInfo = hapModulesInfo;
      this.reqPermissionDetails = reqPermissionDetails;
      this.permissionGrantStates = permissionGrantStates;
      this.signatureInfo = signatureInfo;
      this.installTime = installTime;
      this.updateTime = updateTime;
      this.routerMap = routerMap;
      this.appIndex = appIndex;
      this.firstInstallTime = firstInstallTime;
  }
  constructor(name: string, hapModulesInfo: Array<HapModuleInfo>) {
      this.name = name;
      this.hapModulesInfo = hapModulesInfo;
  }
}

export class ReqPermissionDetailInner implements ReqPermissionDetail {
  name: string = "";
  moduleName: string = "";
  reason: string = "";
  reasonId: long;
  usedScene: UsedScene = new UsedSceneInner;

  constructor() { }
  constructor(name: string, moduleName: string, reason: string, reasonId: long, usedScene: UsedScene) {
    this.name = name;
    this.moduleName = moduleName;
    this.reason = reason;
    this.reasonId = reasonId;
    this.usedScene = usedScene;
  }
}

export class UsedSceneInner implements UsedScene {
  abilities: Array<string> = new Array<string>;
  when: string = "";

  constructor() { }
  constructor(abilities: Array<string>, when: string) {
    this.abilities = abilities;
    this.when = when;
  }
}

export class SignatureInfoInner implements SignatureInfo {
  readonly appId: string = "";
  readonly fingerprint: string = "";
  readonly appIdentifier: string = "";
  readonly certificate?: string | undefined;

  constructor() { }
  constructor(appId: string, fingerprint: string, appIdentifier: string, certificate?: string) {
    this.appId = appId;
    this.fingerprint = fingerprint;
    this.appIdentifier = appIdentifier;
    this.certificate = certificate;
  }
}

export class AppCloneIdentityInner implements AppCloneIdentity {
  readonly bundleName: string = "";
  readonly appIndex: int;

  constructor() { }
  constructor(bundleName: string, appIndex: int) {
    this.bundleName = bundleName;
    this.appIndex = appIndex;
  }
}

export class DynamicIconInfoInner implements DynamicIconInfo {
  public readonly bundleName: string = '';
  public readonly moduleName: string = '';
  public readonly userId: int;
  public readonly appIndex: int;

  constructor() { }
  constructor(bundleName: string, moduleName: string, userId: int, appIndex: int) {
    this.bundleName = bundleName;
    this.moduleName = moduleName;
    this.userId = userId;
    this.appIndex = appIndex;
  }
}

export class BundleOptionsInner implements BundleOptions {
  public userId?: int | undefined;
  public appIndex?: int | undefined;
  public bundleName?: string | undefined;
  public moduleName?: string | undefined;
  public abilityName?: string | undefined;
}