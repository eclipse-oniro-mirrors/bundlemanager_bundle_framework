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

import { BundleInfo } from './BundleInfo';
export type MyFun = (e: int) => void;
export class BusinessError<T = void> {
    code: number;
    data: T;
}
type AsyncCallback<T, E = void> = (err: BusinessError<E>, data: T) => void;
export class BundleManager {
    static {
        loadLibrary("anibundlemanager.z")
    }
    native IsApplicationEnabledSync(bundleName: string): boolean;
    native GetBundleInfoForSelfSync(bundleFlags: int): BundleInfo;
    static GetBundleInfoForSelfSyncProc(bundleFlags: int, instance: BundleManager): BundleInfo
    {
        return instance.GetBundleInfoForSelfSync(bundleFlags);
    }
    GetBundleInfoForSelf(bundleFlags: int, callback: AsyncCallback<BundleInfo, void>):void {
        let p1 = taskpool.execute(BundleManager.GetBundleInfoForSelfSyncProc, bundleFlags, this);
        p1.then((e: NullishType) => {
            let resultBundleInfo = e as BundleInfo;
            let r: BusinessError = { code: 0, data: undefined };
            callback(r, resultBundleInfo);
        }, (err: Object): void => {
        });
    }
    GetBundleInfoForSelf(bundleFlags: int):Promise<BundleInfo> {
        let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void, reject: (error: Object) => void) => {
            let p1 = taskpool.execute(BundleManager.GetBundleInfoForSelfSyncProc, bundleFlags, this);
            p1.then((e: NullishType) => {
                let resultBundleInfo = e as BundleInfo;
                resolve(resultBundleInfo);
            }, (err: Object): void => {
            });
        });
        return p;
    }
}