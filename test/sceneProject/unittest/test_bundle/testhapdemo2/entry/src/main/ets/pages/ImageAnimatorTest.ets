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

@Entry
@Component
struct ImageAnimatorTest {
  @State state: AnimationStatus = AnimationStatus.Initial

  build() {
    Column() {
      ImageAnimator()
        .images([
          {
            src: $r('app.media.libA_v10001'),
            duration: 500,
            width: 170,
            height: 120,
            top: 0,
            left: 0
          },
          {
            src: $r('app.media.libB_v10001'),
            duration: 500,
            width: 170,
            height: 120,
            top: 0,
            left: 170
          },
          {
            src: $r('app.media.libA_v10002'),
            duration: 500,
            width: 170,
            height: 120,
            top: 120,
            left: 170
          },
          {
            src: $r('app.media.libA_v10000'),
            duration: 500,
            width: 170,
            height: 120,
            top: 120,
            left: 0
          },
        ])
        .state(this.state)
        .margin({ top: 100 })
        .fillMode(FillMode.None)
        .iterations(2)
        .width(340)
        .height(240)
        .onStart(() => {
          this.log('on start')
        })
        .onPause(() => {
          this.log('on pause')
        })
        .onRepeat(() => {
          this.log('on repeat')
        })
        .onCancel(() => {
          this.log('on cancel')
        })
        .onFinish(() => {
          this.log('on finish')
          this.state = AnimationStatus.Stopped
        })
        .onClick(e => {
          this.state = AnimationStatus.Running
        })
      Button('start').onClick(e => {
        this.state = AnimationStatus.Running
      })
    }.padding(8).width('100%')
  }

  log(txt: string) {
    promptAction.showToast({
      message: txt
    })
  }
}

export { ImageAnimatorTest };