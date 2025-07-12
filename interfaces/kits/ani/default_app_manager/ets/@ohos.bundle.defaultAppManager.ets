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
import { BundleInfo } from 'bundleManager.BundleInfo';
import { ElementName } from 'bundleManager.ElementName';

export default namespace defaultAppManager {

  loadLibrary("ani_default_app_manager.z");

  const EMPTY_USER_ID: int = -500;

  export enum ApplicationType {
    BROWSER = 'Web Browser',
    IMAGE = 'Image Gallery',
    AUDIO = 'Audio Player',
    VIDEO = 'Video Player',
    PDF = 'PDF Viewer',
    WORD = 'Word Viewer',
    EXCEL = 'Excel Viewer',
    PPT = 'PPT Viewer',
    EMAIL = 'Email'
  }

  export native function isDefaultApplicationNative(type: string, isSync: boolean): boolean;
  export native function getDefaultApplicationNative(type: string, userId: int, isSync: boolean): BundleInfo;
  export native function setDefaultApplicationNative(type: string, elementName: ElementName, userId: int, isSync: boolean): void;
  export native function resetDefaultApplicationNative(type: string, userId: int, isSync: boolean): void;

  function isDefaultApplication(type: string, callback: AsyncCallback<boolean>): void {
    let cb = (): boolean => {
      return defaultAppManager.isDefaultApplicationNative(type, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let result: boolean = e as boolean;
      callback(null, result);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });

  }

  function isDefaultApplication(type: string): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isDefaultApp: boolean) => void, reject: (error: Error) => void) => {
      let cb = (): boolean => {
        return defaultAppManager.isDefaultApplicationNative(type, false);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let result: boolean = e as boolean;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function isDefaultApplicationSync(type: string): boolean {
    return defaultAppManager.isDefaultApplicationNative(type, true);
  }

  function getDefaultApplication(type: string, userId: int, callback: AsyncCallback<BundleInfo>): void {
    let cb = (): BundleInfo => {
      return defaultAppManager.getDefaultApplicationNative(type, userId, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let result: BundleInfo = e as BundleInfo;
      callback(null, result);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getDefaultApplication(type: string, callback: AsyncCallback<BundleInfo>): void {
    let cb = (): BundleInfo => {
      return defaultAppManager.getDefaultApplicationNative(type, EMPTY_USER_ID, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let result: BundleInfo = e as BundleInfo;
      callback(null, result);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getDefaultApplication(type: string, userId?: int): Promise<BundleInfo> {
    let userIdInfo: int = userId ?? EMPTY_USER_ID;
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void, reject: (error: Error) => void) => {
      let cb = (): BundleInfo => {
        return defaultAppManager.getDefaultApplicationNative(type, userIdInfo, false);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let result: BundleInfo = e as BundleInfo;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getDefaultApplicationSync(type: string, userId?: int): BundleInfo {
    let userIdInfo: int = userId ?? EMPTY_USER_ID;
    return defaultAppManager.getDefaultApplicationNative(type, userIdInfo, true);
  }

  function setDefaultApplication(type: string, elementName: ElementName, userId: int, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return defaultAppManager.setDefaultApplicationNative(type, elementName, userId, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setDefaultApplication(type: string, elementName: ElementName, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return defaultAppManager.setDefaultApplicationNative(type, elementName, EMPTY_USER_ID, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setDefaultApplication(type: string, elementName: ElementName, userId?: int): Promise<void> {
    let userIdInfo: int = userId ?? EMPTY_USER_ID;
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: Error) => void) : void => {
      let cb = (): void => {
        return defaultAppManager.setDefaultApplicationNative(type, elementName, userIdInfo, false);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setDefaultApplicationSync(type: string, elementName: ElementName, userId?: int): void {
    let userIdInfo: int = userId ?? EMPTY_USER_ID;
    return defaultAppManager.setDefaultApplicationNative(type, elementName, userIdInfo, true);
  }

  function resetDefaultApplication(type: string, userId: int, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return defaultAppManager.resetDefaultApplicationNative(type, userId, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function resetDefaultApplication(type: string, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return defaultAppManager.resetDefaultApplicationNative(type, EMPTY_USER_ID, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function resetDefaultApplication(type: string, userId?: int): Promise<void> {
    let userIdInfo: int = userId ?? EMPTY_USER_ID;
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: Error) => void) : void => {
      let cb = (): void => {
        return defaultAppManager.resetDefaultApplicationNative(type, userIdInfo, false);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function resetDefaultApplicationSync(type: string, userId?: int): void {
    let userIdInfo: int = userId ?? EMPTY_USER_ID;
    return defaultAppManager.resetDefaultApplicationNative(type, userIdInfo, true);
  }
}
