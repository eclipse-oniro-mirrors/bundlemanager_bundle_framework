/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import promptAction from '@ohos.promptAction';
import router from '@ohos.router';
import { tsHello, nativeHello, UIComponent } from 'liba'
import { ImageAnimatorTest } from './ImageAnimatorTest'

@Entry
@Component
struct Index {
  @State message: string = 'Result'

  build() {
    Column() {
      Row() {
        Text("Host1_v10001")
          .fontSize(50)
          .fontWeight(FontWeight.Bold).width('100%')
      }.width('100%')

      Row() {
        UIComponent()
      }
      .width('100%').borderWidth(1).borderColor(0xff0000)

      Row() {
        Button('接口调用测试').onClick(e => {
          this.log("nativeHello()=" + nativeHello() + "\ntsHello('hsp')=" + tsHello('hsp'))
        })
        Button('页面跳转测试').onClick(e => {
          promptAction.showToast({
            message: "image clicked"
          })
          router.pushUrl({
            url: "@bundle:com.example.liba/liba/ets/pages/sdk_page"
          })
        })
      }

      Row() {
        Text(this.message)
      }
    }
    .height('100%')
  }

  log(msg: string) {
    this.message = msg
    console.log(msg)
  }
}