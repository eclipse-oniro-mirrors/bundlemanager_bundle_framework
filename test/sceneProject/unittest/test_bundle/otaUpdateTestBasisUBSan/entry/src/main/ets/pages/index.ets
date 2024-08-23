/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
import file from '@system.file';

import {Core, ExpectExtend, InstrumentLog, ReportExtend} from "deccjsunit/index.ets"
import testsuite from "../../test/List.test.ets"
import installer from '@ohos.bundle.installer';
import { BusinessError } from '@ohos.base';


@Entry
@Component
struct Index {
  @State message: string = 'Default App Test'

  build() {
    Row() {
      Column() {
        Text(this.message)
          .fontSize(50)
          .fontWeight(FontWeight.Bold)
        Button() { Text('InstallStage').fontSize(20).fontWeight(FontWeight.Bold)}.type(ButtonType.Capsule).margin({ top: 20 }).backgroundColor('#0D9FFB').onClick(() => {
          try {
            let hapFilePaths = ['/data/storage/el2/base/files/entry-default-signed.hap'];
            let installParam: installer.InstallParam = {
              userId: 100,
              isKeepData: false,
              installFlag: 1,
            };
            installer.getBundleInstaller().then((data: installer.BundleInstaller) => {
              data.install(hapFilePaths, installParam, (err: BusinessError) => {
                if (err) {
                  this.message = err.message
                  console.error('install failed:' + err.message);
                } else {
                  this.message = "install ok"
                  console.info('install successfully.');
                }
              });
            }).catch((error: BusinessError) => {
              console.error('getBundleInstaller failed. Cause: ' + error.message);
            });
          } catch (error) {
            console.error('getBundleInstaller failed. Cause: ' + error.message);
          }
        })
      }
      .width('100%')
    }
    .height('100%')
  }
}