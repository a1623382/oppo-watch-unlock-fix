# OPPO Watch 解锁修复 - LSPosed模块

## 功能
绕过OPPO Watch X3手机解锁手表功能的root检测和加密解密失败问题。

## 问题分析

通过日志分析发现两个关键问题：

### 问题1：TEESimulator模式（密钥不匹配）
- `TEESimulator`生成的密钥与手表端不匹配
- 导致 `EncryptionUtils.decrypt` 抛出 `BadPaddingException`
- 错误：`OPENSSL_internal:BAD_DECRYPT`

### 问题2：真实TEE模式（完整性校验失败）
- `sysIntegrity: false` — 设备完整性校验失败
- `errorCode = 13` — 服务端拒绝解锁请求
- Bootloader解锁/root状态被检测到

## Hook策略

本模块hook以下关键点：

### 1. Cipher解密层
- `javax.crypto.Cipher.doFinal()` — 拦截BadPaddingException
- 无论使用TEESimulator还是真实TEE，都能处理解密错误

### 2. EncryptionUtils
- `com.oplus.linker`中的解密工具类
- 捕获并忽略解密失败异常

### 3. 连接Socket
- `ConnectionSocket.processLockEventResponse` — 处理手表回复
- 清除解密错误

### 4. 完整性校验
- `com.heytap.htms:sysintegrity`进程
- 强制所有完整性检查返回true
- 伪造设备完整性状态

### 5. SRP密钥协商
- `stdsrp`安全远程协议
- 伪造attestation结果

## 使用方法

### 1. 编译APK
在Android Studio中打开此项目，编译生成APK。

### 2. 安装APK
将编译好的APK安装到手机上。

### 3. 在LSPosed中启用模块
- 打开LSPosed管理器
- 进入「模块」页面
- 找到「OPPO Watch解锁修复」
- 启用该模块
- 将作用域设置为：
  - **com.oplus.linker** (设备互联服务)
  - **com.heytap.htms** (移动服务/系统完整性服务)
  - **com.heytap.health** (欢太健康)
  - **android** (Android系统) — *重要！sysintegrity进程是system_server子进程*

### 4. 强制停止「移动服务」（关键步骤！）
**必须执行此步骤**，否则模块无法hook到sysintegrity进程：
1. 设置 → 应用管理 → 搜索「移动服务」→ 强制停止
2. 或者：LSPosed → 模块 → 作用域中点击 `com.heytap.htms` → 强制停止

### 5. 重启手机
重启手机使hook生效。

### 6. 测试
- 佩戴手表
- 锁定手机
- 解锁手机看手表是否自动解锁

## 注意事项

1. **需要LSPosed (Zygisk) 框架**
2. **需要KernelSU root**
3. **作用域必须包含 `android`（Android系统）**，否则无法hook sysintegrity进程
4. **升级APK后必须重新强制停止「移动服务」并重启**，否则新的hook代码不会加载
4. **如果仍然失败**，可能需要：
   - 确认已强制停止 `com.heytap.htms`
   - 检查KernelSU的Zygisk设置
   - 尝试Shamiko

## 技术说明

OPPO Watch解锁流程：
1. 手机解锁 → 发送解锁命令到手表
2. 手表收到命令 → 回复加密数据
3. 手机解密回复 → 验证设备完整性
4. 服务端验证 → 返回解锁结果

本模块通过hook多个层级，绕过root检测和解密失败问题。
