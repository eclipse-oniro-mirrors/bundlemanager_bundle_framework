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

/**
 * @file
 * @kit AbilityKit
 */

import { AsyncCallback, BusinessError } from '@ohos.base';
import { ElementName } from 'bundleManager.ElementName';
import Want from '@ohos.app.ability.Want';

export default namespace appControl {
  loadLibraryWithPermissionCheck("ani_app_control.z", "@ohos.bundle.appControl");

  export enum ComponentType {
    UI_ABILITY = 1,
    UI_EXTENSION = 2
  }

  export enum UninstallComponentType {
    EXTENSION = 1,
  }

  export enum DisposedType {
    BLOCK_APPLICATION = 1,
    BLOCK_ABILITY = 2,
    NON_BLOCK = 3
  }

  export enum ControlType {
    ALLOWED_LIST = 1,
    DISALLOWED_LIST = 2
  }

  export interface DisposedRule {
    want: Want;
    componentType: ComponentType;
    disposedType: DisposedType;
    controlType: ControlType;
    elementList: Array<ElementName>;
    priority: int;
  }

  export interface UninstallDisposedRule {
    want: Want;
    uninstallComponentType: UninstallComponentType;
    priority: int;
  }

  export interface DisposedRuleConfiguration {
    appId: string;
    appIndex: int;
    disposedRule: DisposedRule;
  }

  export class DisposedRuleInner implements DisposedRule {
    public want: Want = {};
    public componentType: ComponentType = ComponentType.UI_ABILITY;
    public disposedType: DisposedType = DisposedType.BLOCK_APPLICATION;
    public controlType: ControlType = ControlType.ALLOWED_LIST;
    public elementList: Array<ElementName>;
    public priority: int;

    constructor() { }
    constructor(componentType: ComponentType,
      disposedType: DisposedType,
      controlType: ControlType,
      elementList: Array<ElementName>,
      priority: int) {
        this.componentType = componentType;
        this.disposedType = disposedType;
        this.controlType = controlType;
        this.elementList = elementList;
        this.priority = priority;
    }
    constructor(componentType: ComponentType,
      disposedType: DisposedType,
      controlType: ControlType,
      elementList: Array<ElementName>,
      priority: int,
      want: Want) {
        this.componentType = componentType;
        this.disposedType = disposedType;
        this.controlType = controlType;
        this.elementList = elementList;
        this.priority = priority;
        this.want = want;
    }
  }

  export class UninstallDisposedRuleInner implements UninstallDisposedRule {
    public want: Want = {};
    public uninstallComponentType: UninstallComponentType = UninstallComponentType.EXTENSION;
    public priority: int;

    constructor() { }
    constructor(uninstallComponentType: UninstallComponentType, priority: int) {
        this.uninstallComponentType = uninstallComponentType;
        this.priority = priority;
    }
    constructor(uninstallComponentType: UninstallComponentType, priority: int, want: Want) {
        this.uninstallComponentType = uninstallComponentType;
        this.priority = priority;
        this.want = want;
    }
  }

  export class DisposedRuleConfigurationInner implements DisposedRuleConfiguration {
    public appId: string = '';
    public appIndex: int;
    public disposedRule: DisposedRule = new DisposedRuleInner;
  }

  native function setDisposedStatusNative(appId: string, disposedWant: Want, isSync: boolean): void;
  native function getDisposedStatusNative(appId: string, isSync: boolean): Want;
  native function deleteDisposedStatusNative(appId: string, appIndex: int, isSync: boolean): void;
  native function getDisposedRuleNative(appId: string, appIndex: int): DisposedRule;
  native function setDisposedRuleNative(appId: string, rule: DisposedRule, appIndex: int): void;
  native function setUninstallDisposedRuleNative(appIdentifier: string, rule: UninstallDisposedRule, appIndex: int): void;
  native function getUninstallDisposedRuleNative(appIdentifier: string, appIndex: int): UninstallDisposedRule;
  native function deleteUninstallDisposedRuleNative(appIdentifier: string, appIndex: int): void;
  native function setDisposedRules(disposedRuleConfigurations: Array<DisposedRuleConfiguration>): void;


  function setDisposedStatus(appId: string, disposedWant: Want, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return setDisposedStatusNative(appId, disposedWant, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setDisposedStatus(appId: string, disposedWant: Want): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let cb = (): void => {
        return setDisposedStatusNative(appId, disposedWant, false);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setDisposedStatusSync(appId: string, disposedWant: Want): void {
    return setDisposedStatusNative(appId, disposedWant, true);
  }

  function getDisposedStatus(appId: string, callback: AsyncCallback<Want>): void {
    let cb = (): Want => {
      return getDisposedStatusNative(appId, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: Any) => {
      let result: Want = e as Want;
      callback(null, result);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getDisposedStatus(appId: string): Promise<Want> {
    let p = new Promise<Want>((resolve: (want: Want) => void, reject: (error: BusinessError) => void) => {
      let cb = (): Want => {
        return getDisposedStatusNative(appId, false);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
        let result: Want = e as Want;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getDisposedStatusSync(appId: string): Want {
    return getDisposedStatusNative(appId, true);
  }

  function deleteDisposedStatus(appId: string, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return deleteDisposedStatusNative(appId, 0, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function deleteDisposedStatus(appId: string): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let cb = (): void => {
        return deleteDisposedStatusNative(appId, 0, false);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function deleteDisposedStatusSync(appId: string, appIndex?: int): void
  {
    let appIndexInfo = appIndex ?? 0;
    return deleteDisposedStatusNative(appId, appIndexInfo, true);
  }

  function getDisposedRule(appId: string, appIndex?: int): DisposedRule
  {
    let appIndexInfo = appIndex ?? 0;
    return getDisposedRuleNative(appId, appIndexInfo);
  }

  function setDisposedRule(appId: string, rule: DisposedRule, appIndex?: int): void
  {
    let appIndexInfo = appIndex ?? 0;
    setDisposedRuleNative(appId, rule, appIndexInfo);
  }

  function setUninstallDisposedRule(appIdentifier: string, rule: UninstallDisposedRule, appIndex?: int): void
  {
    let appIndexInfo = appIndex ?? 0;
    setUninstallDisposedRuleNative(appIdentifier, rule, appIndexInfo);
  }

  function getUninstallDisposedRule(appIdentifier: string, appIndex?: int): UninstallDisposedRule
  {
    let appIndexInfo = appIndex ?? 0;
    return getUninstallDisposedRuleNative(appIdentifier, appIndexInfo);
  }

  function deleteUninstallDisposedRule(appIdentifier: string, appIndex?: int): void
  {
    let appIndexInfo = appIndex ?? 0;
    deleteUninstallDisposedRuleNative(appIdentifier, appIndexInfo);
  }
}
