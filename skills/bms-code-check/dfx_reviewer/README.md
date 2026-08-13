# DFX Review Skill - Bundle Framework 专用

**版本**: v3.1 (Bundle Framework)
**更新日期**: 2026-06-22
**状态**: ✅ 已适配 bundle_framework 仓

---

## 📚 文件说明

本目录包含 DFX (Design for X) 代码审查的完整工具链：

| 文件 | 用途 | 适用对象 |
|------|------|----------|
| `SKILL.md` | **bundle_framework 专用 DFX skill 文档** | bundle_framework 团队 |
| `dfx_reviewer_universal.md` | 通用 DFX skill 文档（参考） | 所有代码仓 |
| `DFX_Adaptation_Guide.md` | 适配指南（如何切换到其他代码仓） | 需要定制的团队 |
| `dfx_skill_config_template.yaml` | 配置文件模板 | 需要定制的团队 |
| `hilog_general_rules.md` | HiLog 通用规范 | 所有 OpenHarmony 代码仓 |

---

## 🚀 快速开始

### 对于通用用户

如果你想要了解 DFX 最佳实践：

```bash
# 1. 阅读通用 DFX skill
cat dfx_reviewer_universal.md

# 2. 了解架构规则（客户端禁止打点）
grep -A 50 "Architecture Principle" dfx_reviewer_universal.md

# 3. 查看代码质量检查清单
grep -A 30 "Code Quality Checklist" dfx_reviewer_universal.md
```

### 对于想要定制的团队

如果要将 DFX skill 适配到你的代码仓：

**步骤 1**: 阅读适配指南
```bash
cat DFX_Adaptation_Guide.md
```

**步骤 2**: 复制配置模板
```bash
cp dfx_skill_config_template.yaml my_dfx_config.yaml
```

**步骤 3**: 编辑配置文件
```yaml
# 替换 {placeholders} 为你的实际值
codebase:
  name: "Your Module Name"
  abbreviation: "YOUR_MODULE"
```

**步骤 4**: 生成你的 DFX skill
```bash
# 使用配置文件生成定制版本
python3 generate_dfx_skill.py my_dfx_config.yaml my_dfx_skill.md
```

---

## 📖 核心规则

### 🔴 架构规则：客户端禁止直接打点

**核心原则**: 客户端代码不允许直接进行 HiSysEvent 打点

| 代码位置 | 允许打点 | 说明 |
|----------|----------|------|
| `services/bundlemgr/src/` | ✅ YES | BMS 服务端实现 |
| `services/bundlemgr/include/` | ✅ YES | 服务端接口 |
| `services/bundlemgr/src/event_report.cpp` | ✅ YES | DFX 实现本身 |
| `interfaces/inner_api/appexecfwk_core/` | ❌ NO | Inner API 客户端 |
| `interfaces/kits/appkit/` | ❌ NO | 应用侧 Kit 客户端 |
| `interfaces/kits/js/`、`ndk/`、`cj/` | ❌ NO | JS/NDK/CJ 接口客户端 |

**原因**：
1. ✅ 统一管理
2. ✅ 避免重复
3. ✅ 权限控制
4. ✅ 数据一致性
5. ✅ 性能优化
6. ✅ 安全性

### ⚠️ 业务场景区分

**必须**：同一操作在不同场景下使用不同的 EventInfo 字段（`preBundleScene`、`BundleEventType`、`BMSEventType`）

**组合方式**: `BundleEventType` + `InstallScene` + `BMSEventType`

**示例**:
- `BundleEventType::INSTALL` + `InstallScene::BOOT` - 开机扫描预装
- `BundleEventType::INSTALL` + `InstallScene::NORMAL` - 用户主动安装
- `BundleEventType::UPDATE` + `InstallScene::REBOOT` - OTA 升级
- `BMSEventType::BUNDLE_INSTALL_EXCEPTION` - 安装失败（故障事件）

---

## 🛠️ 自动化工具

### 客户端打点检查脚本

检查客户端代码是否违规进行 HiSysEvent 打点：

```bash
./.refdocs/scripts/check_client_hisysevent.sh
```

**输出**:
- ✅ 未发现违规
- ❌ 发现违规（详细列表）

### DFX 覆盖率检查脚本

检查整体 DFX 实现质量：

```bash
./.refdocs/scripts/check_dfx_coverage.sh [服务目录]
```

### 敏感数据检查脚本

检查是否有敏感数据泄漏：

```bash
./.refdocs/scripts/check_sensitive_data.sh [服务目录]
```

---

## 📋 适配流程

### 快速适配（15 分钟）

1. **确定目录结构**
   ```bash
   # 识别你的服务端和客户端目录
   find . -name "*service*.cpp"  # 服务端
   find . -name "*client*.cpp"   # 客户端
   ```

2. **定义操作常量**
   ```cpp
   namespace Constants {
       const char YOUR_MODULE_OPT_CREATE[] = "create";
       const char YOUR_MODULE_OPT_DELETE[] = "delete";
   }
   ```

3. **运行检查脚本**
   ```bash
   ./check_client_hisysevent.sh
   ```

### 完整适配（2 小时）

参考 `DFX_Adaptation_Guide.md` 进行完整的适配。

---

## 🎯 适用场景

### 适合的团队

- ✅ 使用 HiSysEvent/HiTrace 的任何代码仓
- ✅ 需要统一 DFX 标准的中大型项目
- ✅ 关注代码质量和可维护性的团队
- ✅ 进行代码审查的团队

### 核心收益

1. **统一标准**: 团队使用一致的 DFX 实践
2. **自动化检查**: 快速发现违规代码
3. **知识传承**: 新人快速了解 DFX 要求
4. **持续改进**: 可衡量的 DFX 质量提升

---

## 📊 版本对比

| 特性 | OS Account 旧版 | bundle_framework 版本 |
|------|------------------|----------|
| **适用范围** | OS Account 模块 | bundle_framework 仓 |
| **文件路径** | services/accountmgr/ | services/bundlemgr/ |
| **DFX 入口** | account_hisysevent_adapter | EventReport 类 |
| **业务场景** | 账户场景 | bundle install/uninstall/update |
| **示例代码** | OS Account 实际代码 | bundle_framework 实际代码 |
| **打点 API** | REPORT_*_FAIL 宏 | EventReport::Send* |
| **学习曲线** | 低 | 低 |

---

## 🔧 定制示例

### 示例 1: 网络模块

**配置** (`network_dfx_config.yaml`):
```yaml
codebase:
  name: "Network Manager"
  abbreviation: "NETWORK"

operations:
  - name: "connect"
    constant: "NETWORK_OPT_CONNECT"
  - name: "disconnect"
    constant: "NETWORK_OPT_DISCONNECT"
```

**生成**:
```bash
python3 generate_dfx_skill.py network_dfx_config.yaml network_dfx_skill.md
```

### 示例 2: 存储模块

**配置** (`storage_dfx_config.yaml`):
```yaml
codebase:
  name: "Storage Manager"
  abbreviation: "STORAGE"

operations:
  - name: "read"
    constant: "STORAGE_OPT_READ"
  - name: "write"
    constant: "STORAGE_OPT_WRITE"
```

**生成**:
```bash
python3 generate_dfx_skill.py storage_dfx_config.yaml storage_dfx_skill.md
```

---

## 📚 相关资源

### 内部文档

**DFX 相关**:
- **通用 DFX Skill**: `dfx_reviewer_universal.md`
- **适配指南**: `DFX_Adaptation_Guide.md`
- **配置模板**: `dfx_skill_config_template.yaml`

### 外部参考

- [OpenHarmony HiSysEvent 文档](https://docs.openharmony.cn/)
- [OpenHarmony HiTrace 文档](https://docs.openharmony.cn/)

### 工具脚本

- **客户端检查**: `.refdocs/scripts/check_client_hisysevent.sh`
- **覆盖率检查**: `.refdocs/scripts/check_dfx_coverage.sh`
- **敏感数据检查**: `.refdocs/scripts/check_sensitive_data.sh`

---

## 🤝 贡献指南

### 改进通用版本

如果你发现通用版本需要改进：

1. **Fork** 这个文件
2. **修改** 为更通用的版本
3. **提交** PR 到上游

### 分享你的定制版本

如果你为特定模块创建了定制版本：

1. **保持结构**: 与通用版本保持一致的结构
2. **标记差异**: 明确说明你的定制内容
3. **分享经验**: 在团队间分享最佳实践

---

## 💡 使用建议

### 对于团队 Leader

1. **分配 DFX 负责人**: 指定专人负责 DFX 质量维护
2. **集成 CI/CD**: 将检查脚本加入 CI 流程
3. **定期评审**: 每月评审 DFX 质量报告
4. **持续改进**: 根据反馈更新 skill

### 对于开发者

1. **阅读指南**: 熟悉 DFX 最佳实践
2. **使用检查**: 提交 PR 前运行检查脚本
3. **参考示例**: 查看文档中的代码示例
4. **反馈问题**: 及时报告遇到的问题

### 对于代码审查者

1. **使用检查清单**: 系统性地检查每个项目
2. **关注架构规则**: 特别是客户端禁止打点
3. **要求改进**: 对不符合要求的代码要求改进
4. **记录问题**: 记录常见问题供团队学习

---

## 📈 质量指标

### 目标指标

适配 DFX skill 后，预期达到：

| 指标 | 当前 | 目标 | 改进 |
|------|------|------|------|
| HiSysEvent 覆盖率 | ? | 70%+ | +? |
| HiTrace 使用率 | ? | 60%+ | +? |
| 数据隐私保护 | ? | 90%+ | +? |
| 架构规则遵守 | ? | 100% | +? |

### 测量方法

```bash
# 1. 运行覆盖率检查
./check_dfx_coverage.sh services/your_module

# 2. 查看评分
# 输出会显示总体评分和等级

# 3. 生成报告
# 根据输出生成详细的质量报告
```

---

## 🎓 学习路径

### 新手（第 1 周）

1. 阅读 `dfx_reviewer_universal.md` 前 3 章
2. 理解架构规则（客户端禁止打点）
3. 运行检查脚本查看当前状态
4. 修复 1-2 个简单问题

### 进阶（第 2-4 周）

1. 深入阅读完整文档
2. 为你的模块定制 DFX skill
3. 在代码审查中应用规则
4. 改进代码库的 DFX 质量

### 专家（第 2-3 月）

1. 成为团队的 DFX 负责人
2. 优化检查脚本和工具
3. 分享最佳实践
4. 持续改进 DFX skill

---

## ❓ 常见问题

### Q1: 通用版本是否完全替代特定版本？

**A**: 不是。通用版本提供了框架和最佳实践，特定版本提供了具体示例。建议：
- 使用通用版本学习原则
- 参考特定版本看实际代码
- 根据你的需求定制

### Q2: 如何判断代码是服务端还是客户端？

**A**: 看目录位置和代码类型：
- 服务端: `services/`, 实现 System Ability
- 客户端: `frameworks/`, `sdk/`, 包装类，Proxy 类

### Q3: 底层工具类能否打点？

**A**: 可以，但需要满足条件：
1. 被多个模块使用
2. 只记录基础操作
3. 不包含业务语义
4. 经过架构批准

### Q4: 如何添加新的操作类型？

**A**:
1. 在 `Constants` 命名空间添加常量
2. 更新配置文件
3. 在文档中添加说明
4. 通知团队成员

### Q5: 检查脚本误报怎么办？

**A**:
1. 确认是否真的是客户端代码
2. 检查是否符合例外情况
3. 如果是例外，更新文档说明
4. 如果脚本问题，修复脚本

---

## 📞 支持和反馈

### 获取帮助

- **文档问题**: 查看 DFX_Adaptation_Guide.md
- **技术问题**: 咨询架构团队或 DFX 负责人
- **Bug 报告**: 提交 Issue 到代码仓

### 提供反馈

如果你有改进建议：

1. **小改进**: 直接提交 PR
2. **大改进**: 先提 Issue 讨论
3. **定制版本**: 分享你的定制经验

---

## 📝 更新日志

### v3.1 (2026-06-22) - Bundle Framework 适配

**变更**:
- ✅ SKILL.md 重写为 bundle_framework 专用版本
- ✅ 使用 EventReport 类替代 REPORT_*_FAIL 宏
- ✅ 文件路径替换为 services/bundlemgr/
- ✅ 业务场景替换为 InstallScene/BundleEventType/BMSEventType
- ✅ 代码示例替换为 base_bundle_installer.cpp / bundle_mgr_service.cpp

### v3.0 (2026-03-23) - Universal Release

**新增**:
- ✅ 通用版本，适配任何代码仓
- ✅ 配置文件模板
- ✅ 适配指南
- ✅ 自动化生成工具

### v2.1 (2026-03-23) - OS Account Specific

**内容**:
- OS Account 特定实现
- 客户端禁止打点规则
- 业务场景区分指南

---

**最后更新**: 2026-06-22
**维护**: Bundle Framework DFX Working Group
**许可**: 开源，可自由使用和修改
**版本**: v3.1 Bundle Framework
