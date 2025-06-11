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
import { BundleInfoInner } from 'bundleManager.BundleInfoInner';
import { ElementName } from 'bundleManager.ElementName';

export default namespace defaultAppManager {

  loadLibrary("ani_default_app_manager.z");

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

  export native function isDefaultApplicationSync(type: string): boolean;
  export native function getDefaultApplicationSyncNative(type: string, userId: number): BundleInfo;
  export native function setDefaultApplicationSyncNative(type: string, elementName: ElementName, userId: number): void;
  export native function resetDefaultApplicationSyncNative(type: string, userId: number): void;

  function isDefaultApplication(type: string, callback: AsyncCallback<boolean>): void {
    let cb = (): boolean => {
      return defaultAppManager.isDefaultApplicationSync(type);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let result: boolean = e as boolean;
      let br = new BusinessError();
      callback(br, result);
    }, (err: BusinessError): void => {
      callback(err, false);
    });

  }

  function isDefaultApplication(type: string): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isDefaultApp: boolean) => void, reject: (error: BusinessError) => void) => {
      let cb = (): boolean => {
        return defaultAppManager.isDefaultApplicationSync(type);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let result: boolean = e as boolean;
        resolve(result);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function getDefaultApplication(type: string, userId: number, callback: AsyncCallback<BundleInfo>): void {
    let cb = (): BundleInfo => {
      return defaultAppManager.getDefaultApplicationSyncNative(type, userId);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let result: BundleInfo = e as BundleInfo;
      let br: BusinessError = new BusinessError();
      callback(br, result);
    }, (err: BusinessError): void => {
      let result: BundleInfo = new BundleInfoInner;
      callback(err, result);
    });
  }

  function getDefaultApplication(type: string, callback: AsyncCallback<BundleInfo>): void {
    let cb = (): BundleInfo => {
      return defaultAppManager.getDefaultApplicationSyncNative(type, -500);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let result: BundleInfo = e as BundleInfo;
      let br: BusinessError = new BusinessError();
      callback(br, result);
    }, (err: BusinessError): void => {
      let result: BundleInfo = new BundleInfoInner;
      callback(err, result);
    });
  }

  function getDefaultApplication(type: string, userId?: number): Promise<BundleInfo> {
    let userIdInfo: number = userId ?? -500;
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void, reject: (error: BusinessError) => void) => {
      let cb = (): BundleInfo => {
        return defaultAppManager.getDefaultApplicationSyncNative(type, userIdInfo);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let result: BundleInfo = e as BundleInfo;
        resolve(result);
      }, (err: BusinessError): void => {
        reject(err);
      });
    });
    return p;
  }

  function getDefaultApplicationSync(type: string, userId?: number): BundleInfo {
    let userIdInfo: number = userId ?? -500;
    return defaultAppManager.getDefaultApplicationSyncNative(type, userIdInfo);
  }

  function setDefaultApplication(type: string, elementName: ElementName, userId: number, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return defaultAppManager.setDefaultApplicationSyncNative(type, elementName, userId);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      let br: BusinessError = new BusinessError();
      callback(br, undefined);
    }, (err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  function setDefaultApplication(type: string, elementName: ElementName, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return defaultAppManager.setDefaultApplicationSyncNative(type, elementName, -500);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      let br: BusinessError = new BusinessError();
      callback(br, undefined);
    }, (err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  function setDefaultApplication(type: string, elementName: ElementName, userId?: number): Promise<void> {
    let userIdInfo: number = userId ?? -500;
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void) : void => {
      let cb = (): void => {
        return defaultAppManager.setDefaultApplicationSyncNative(type, elementName, userIdInfo);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(undefined);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function setDefaultApplicationSync(type: string, elementName: ElementName, userId?: number): void {
    let userIdInfo: number = userId ?? -500;
    return defaultAppManager.setDefaultApplicationSyncNative(type, elementName, userIdInfo);
  }

  function resetDefaultApplication(type: string, userId: number, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return defaultAppManager.resetDefaultApplicationSyncNative(type, userId);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      let br: BusinessError = new BusinessError();
      callback(br, undefined);
    }, (err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  function resetDefaultApplication(type: string, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return defaultAppManager.resetDefaultApplicationSyncNative(type, -500);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      let br: BusinessError = new BusinessError();
      callback(br, undefined);
    }, (err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  function resetDefaultApplication(type: string, userId?: number): Promise<void> {
    let userIdInfo: number = userId ?? -500;
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void) : void => {
      let cb = (): void => {
        return defaultAppManager.resetDefaultApplicationSyncNative(type, userIdInfo);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(undefined);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function resetDefaultApplicationSync(type: string, userId?: number): void {
    let userIdInfo: number = userId ?? -500;
    return defaultAppManager.resetDefaultApplicationSyncNative(type, userIdInfo);
  }
}
