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

import { ShortcutInfo as _ShortcutInfo, ShortcutWant as _ShortcutWant, ParameterItem as _ParameterItem } from 'bundleManager.ShortcutInfo';
import { BusinessError } from '@ohos.base';

namespace shortcutManager {

  loadLibraryWithPermissionCheck("ani_shortcut_manager.z", "@ohos.bundle.shortcutManager");

  function createBusinessError(code: int, message: string) {
    let err = new BusinessError();
    err.code = code;
    err.name = 'Error';
    err.message = message;
    return err;
  }
  
  const ERROR_SOURCETYPE : int = -1;
  const MAIN_APP_INDEX: int = 0;
  const CLONE_APP_INDEX_MAX: int = 5;
  const ERROR_PARAM_CHECK_ERROR: int = 401;
  const MAX_SHORTCUT_INFO_SIZE: int = 100;
  const ERROR_SHORTCUT_ID_ILLEGAL_ERROR: int = 17700070;
  const DEFAULT_SHORTCUT: int = 0;
  const DYNAMIC_SHORTCUT: int = 2;
  const ERROR_BUNDLENAME_APPINDEX_NOT_UNIQUE: int = 18100001;
  const ERROR_INVALID_APPINDEX_CODE: int = 17700061;
  const ERROR_INVALID_APPINDEX_MSG: string = "BusinessError 17700061: The specified app index is invalid.";
  const INVALID_SHORTCUT_INFO_ERROR: string = "invalid ShortcutInfo: parameter type error, or appIndex is less than 0";
  const SHORTCUT_INFO_LENGTH_ERROR: string = "shortcutInfo length invalid";
  const SHORTCUT_IDS_LENGTH_ERROR: string = "shortcut Ids length invalid";
  const SHORTCUT_ID_ILLEGAL: string = "BusinessError 17700070: The specified shortcut id is illegal.";
  const PARAM_TYPE_CHECK_ERROR: string = "param type check error";
  const BUNDLENAME_APPINDEX_NOT_UNIQUE: string =
    "BusinessError 18100001: A combination of bundleName and appIndex in the shortcutInfo list is different from the others.";

  native function addDesktopShortcutInfoNative(shortcutInfo: ShortcutInfo, userId: int): void;
  native function deleteDesktopShortcutInfoNative(shortcutInfo: ShortcutInfo, userId: int): void;
  native function getAllDesktopShortcutInfoNative(userId: int): Array<ShortcutInfo>;
  native function setShortcutVisibleForSelfNative(id: string, visible: boolean): void;
  native function getAllShortcutInfoForSelfNative(): Array<ShortcutInfo>;
  native function addDynamicShortcutInfosNative(shortcutInfo: Array<ShortcutInfo>, userId: int): void;
  native function deleteDynamicShortcutInfosNative(bundleName: string, appIndex: int, userId: int, ids: Array<string>): void;

  function addDesktopShortcutInfo(shortcutInfo: ShortcutInfo, userId: int): Promise<void> {
    if (shortcutInfo.appIndex < MAIN_APP_INDEX || shortcutInfo.sourceType === ERROR_SOURCETYPE) {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, INVALID_SHORTCUT_INFO_ERROR);
    }
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void): void => {
      let cb = (): Any => {
        return addDesktopShortcutInfoNative(shortcutInfo, userId);
      }
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function deleteDesktopShortcutInfo(shortcutInfo: ShortcutInfo, userId: int): Promise<void> {
    if (shortcutInfo.appIndex < MAIN_APP_INDEX || shortcutInfo.sourceType === ERROR_SOURCETYPE) {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, INVALID_SHORTCUT_INFO_ERROR);
    }
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void): void => {
      let cb = (): Any => {
        return deleteDesktopShortcutInfoNative(shortcutInfo, userId)
      }
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getAllDesktopShortcutInfo(userId: int): Promise<Array<ShortcutInfo>> {
    let p = new Promise<Array<ShortcutInfo>>((resolve: (arrShortcutInfo: Array<ShortcutInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<ShortcutInfo>) => {
        return getAllDesktopShortcutInfoNative(userId);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
        let result: Array<ShortcutInfo> = e as Array<ShortcutInfo>;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function setShortcutVisibleForSelf(id: string, visible: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void): void => {
      let cb = (): Any => {
        return setShortcutVisibleForSelfNative(id, visible);
      }
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getAllShortcutInfoForSelf(): Promise<Array<ShortcutInfo>> {
    let p = new Promise<Array<ShortcutInfo>>((resolve: (arrShortcutInfo: Array<ShortcutInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<ShortcutInfo>) => {
        return getAllShortcutInfoForSelfNative();
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
        let result: Array<ShortcutInfo> = e as Array<ShortcutInfo>;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function addDynamicShortcutInfos(shortcutInfo: Array<ShortcutInfo>, userId: int): Promise<void> {
    if (shortcutInfo.length <= 0 || shortcutInfo.length > MAX_SHORTCUT_INFO_SIZE) {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, SHORTCUT_INFO_LENGTH_ERROR);
    }
    const idSet = new Set<string>();
    let referenceBundleName: string = "";
    let referenceAppIndex: int = -1;
    for (let i = 0; i < shortcutInfo.length; ++i) {
      if (shortcutInfo[i].id === "" || idSet.has(shortcutInfo[i].id)) {
        throw createBusinessError(ERROR_SHORTCUT_ID_ILLEGAL_ERROR, SHORTCUT_ID_ILLEGAL);
      }
      if (shortcutInfo[i].appIndex < MAIN_APP_INDEX || shortcutInfo[i].appIndex > CLONE_APP_INDEX_MAX) {
        throw createBusinessError(ERROR_INVALID_APPINDEX_CODE, ERROR_INVALID_APPINDEX_MSG);
      }
      if (shortcutInfo[i].sourceType < DEFAULT_SHORTCUT ||
          shortcutInfo[i].sourceType > DYNAMIC_SHORTCUT) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
      }
      if (shortcutInfo[i].sourceType !== DYNAMIC_SHORTCUT) {
        shortcutInfo[i].sourceType = DYNAMIC_SHORTCUT;
      }
      if (i === 0) {
        referenceBundleName = shortcutInfo[i].bundleName;
        referenceAppIndex = shortcutInfo[i].appIndex;
      }
      if (shortcutInfo[i].bundleName !== referenceBundleName || shortcutInfo[i].appIndex !== referenceAppIndex) {
        throw createBusinessError(ERROR_BUNDLENAME_APPINDEX_NOT_UNIQUE, BUNDLENAME_APPINDEX_NOT_UNIQUE);
      }
      idSet.add(shortcutInfo[i].id);
    }
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void): void => {
      let cb = (): Any => {
        return addDynamicShortcutInfosNative(shortcutInfo, userId);
      }
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function deleteDynamicShortcutInfos(bundleName: string, appIndex: int, userId: int, ids?: Array<string>): Promise<void> {
    if (appIndex < MAIN_APP_INDEX || appIndex > CLONE_APP_INDEX_MAX) {
      throw createBusinessError(ERROR_INVALID_APPINDEX_CODE, ERROR_INVALID_APPINDEX_MSG);
    }
    const idsValue: Array<string> = ids ?? [];
    if (idsValue.length > MAX_SHORTCUT_INFO_SIZE) {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, SHORTCUT_IDS_LENGTH_ERROR);
    }
    if (idsValue.length !== 0) {
      const idSet = new Set<string>();
      for (const id of idsValue) {
        if (id === "" || idSet.has(id)) {
          throw createBusinessError(ERROR_SHORTCUT_ID_ILLEGAL_ERROR, SHORTCUT_ID_ILLEGAL);
        }
        idSet.add(id);
      }
    }
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void): void => {
      let cb = (): Any => {
        return deleteDynamicShortcutInfosNative(bundleName, appIndex, userId, idsValue);
      }
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  export type ShortcutInfo = _ShortcutInfo;
  export type ShortcutWant = _ShortcutWant;
  export type ParameterItem = _ParameterItem;
}

export default shortcutManager;
