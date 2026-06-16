# OPPO Watch 解锁修复 - LSPosed模块

## 功能
绕过OPPO Watch X3手机解锁手表功能的root检测和加密解密失败问题。

## 当前状态：未解决 ⚠️

本项目经过大量尝试，找到了问题的根本原因，但尚未找到可行的解决方案。以下记录了所有尝试和发现，供后续研究者参考。

---

## 已确认的根本原因

### 解锁流程（完全本地验证，不经过OPPO服务器）

1. 手机解锁 → `OnetScreenUnlockReceiver` 触发
2. `ConnectionManager` 发送 `lock inquiry` 到手表（162字节）
3. 手表回复 `processLockInquiryResponse`（128字节）→ `errorCode=0, tokenStatus=3`
4. `ConnectionManager.checkSrp` → 触发 stdsrp 生成 SRP token
5. `Cipher.doFinal` 加密解锁数据 → 我们在此 hook 修改 `sysIntegrity:false` → `true`
6. `ConnectionManager.secureSendData("unlock watch")` → 发送 4434字节到手表
7. 手表验证 attestation → **拒绝** → 返回 `processLockEventResponse`（16字节加密数据）
8. `processLockEventResponse` 解密 → `errorCode=5` → 转换为 `errorCode=2` → `processFailLockEventResult(2)`

### 为什么飞行模式也失败？

飞行模式下无法生成SRP token（需要访问 `omes-sec-stdsrp-cn.heytapmobi.com`），但更重要的是：**手表本身没有网络连接**，它通过手机的蓝牙转发请求。如果手机无网络，SRP token请求失败，无法完成token注册流程。

### 飞行模式下手表如何验证？

手表在之前的token注册时已经存储了设备的attestation数据（包含TEE证书链）。每次解锁时，手表用存储的attestation验证手机。所以**飞行模式不影响手表的验证逻辑**——手表用的是之前注册时存储的数据。

---

## 已确认的技术细节

### 1. 解锁数据是加密的protobuf格式，不是JSON

```
[SEND-UNLOCK] hex=28 07 31 8d d8 b8 d0 5f 6a 73 86 39 b6 cf 61 72
```
- 4434字节的二进制加密数据
- JSON中的 `sysIntegrity` 字段是加密前的明文，加密后不存在于二进制数据中
- `ProtoDataGenerator.getLockInquiryProtoData(Byte, byte[32], byte[8], byte[64], byte[32])` — 第二个参数byte[32]可能是密钥

### 2. 手表返回的16字节响应是加密的

```
[RESP] processLockEventResponse: 0d 8b 0c 84 c7 ec 10 48 e4 8b 5a c3 7a 28 0c b6
```
- error code byte 13 (0x0D) 在 offset 0
- 每次尝试的响应完全不同（加密）
- app内部转换: byte[0]=13 → `errorCode=5` → `processFailLockEventResult(2)`

### 3. processFailLockEventResult 是唯一的失败处理路径

```
processLockEventResponse(byte[16]) → processFailLockEventResult(Integer=2)
```
- 没有 `processSuccessLockEventResult` 方法（在未patch时）
- 当byte[0]从38改为0后，app调用了 `processSuccessLockEventResult(Integer=0, byte[0], byte[0])`
- 但 `EncryptionUtils.encrypt: pbSequence/key/iv=null` — 加密密钥为null

### 4. 密钥协商流程正常但密钥未传递给加密方法

```
unregisterToken → token.isNullOrEmpty=true
key agreement → success
register token → success, errorCode=0, tokenStatus=0
processSuccessLockEventResult → EncryptionUtils encrypt: pbSequence/key/iv=null ← 密钥为空！
```
- 密钥协商和token注册都成功了
- 但 `EncryptionUtils` 找不到密钥
- `EncryptionUtils` 类名被混淆，无法通过名称hook

### 5. com.heytap.htms:sysintegrity 进程

- **默认状态**：由 system_server (PID 1985) 直接启动，LSPosed无法注入
- **杀死后重启**：`am force-stop com.heytap.htms` 后，LSPosed可以成功注入该进程
- **hook结果**：成功hook到 `SystemProperties.get()` 和 `Build` 字段
- **但仍然无效**：TEE证明在native层(`processCmdV2`)生成，Java层的SystemProperties hook无法影响native代码读取的设备状态
- **结论**：即使hook到sysintegrity进程，也无法从Java层修改TEE证明。native层的设备状态读取绕过了Java hook

### 6. JSON patch 只修改了显示层

- `Cipher.doFinal` hook 在加密前修改明文中的 `sysIntegrity:false` → `true`
- 但手表验证的是TEE证书链中的加密证明，不是JSON字段
- 服务器/手表返回的 `sysIntegrity:false` 是基于TEE证明的判断

---

## 已尝试的方案

### 方案1：Hook Cipher.doFinal 修改加密前的明文
- ✅ 成功找到 `sysIntegrity:false` 在offset ~1950
- ✅ 成功修改为 `sysIntegrity:true`
- ❌ 手表仍返回errorCode=5（签名校验失败）
- **结论**：手表验证TEE证明签名，不是JSON字段

### 方案2：Hook processFailLockEventResult 覆盖error code
- ✅ 找到error code=2作为Integer参数传入
- ✅ 成功修改为0
- ❌ 手机认为解锁成功，但手表未解锁
- **结论**：只改变了手机端认知，手表端仍拒绝

### 方案3：Hook processLockEventResponse 修改byte[0]
- ✅ 找到error byte在offset 0
- ✅ 从38/13改为0
- ✅ 触发了 `processSuccessLockEventResult`（成功路径）
- ❌ `EncryptionUtils.encrypt: pbSequence/key/iv=null` — 密钥为空
- ❌ 手机卡在"正在解锁"状态

### 方案4：KernelSU模块修改系统属性 + 隐藏root
- ✅ `resetprop ro.boot.verifiedbootstate green` — 属性补丁成功
- ✅ `resetprop ro.boot.flash.locked 1` — 属性补丁成功
- ✅ `resetprop ro.boot.selinux 1` — 属性补丁成功
- ✅ 杀死 `com.heytap.htms:sysintegrity` 进程后重启，LSPosed成功hook到该进程
- ✅ hook到 `SystemProperties.get()` 和 `Build` 字段
- ❌ TEE证明是硬件级的，系统属性修改对TEE证明无效
- ❌ 激进的属性修改（如修改Build.TYPE、Build.TAGS等）导致卡开机（已修复为只修改3个属性）
- **结论**：系统属性补丁对TEE证明无效，但对部分Java层检查可能有效

### 方案5：Hook所有ConnectionSocket方法 + dump字段
- ✅ 找到 `processFailLockEventResult(Integer)` 方法
- ✅ 找到 `processSuccessLockEventResult(Integer, byte[], byte[])` 方法
- ✅ 理解了完整的调用链

### 方案6：Hook EncryptionUtils / ConnectionManager key方法
- ❌ EncryptionUtils类名被混淆，无法找到
- ✅ 找到 `ProtoDataGenerator` 在 `com.oplus.linker.unlock.utils`
- ❌ 密钥协商成功但密钥未传递给EncryptionUtils

---

## 未尝试的方案

### 1. 使用jadx反编译linker APK
- 找到 `EncryptionUtils` 的真实类名
- 理解密钥存储和传递机制
- 找到 `processSuccessLockEventResult` 的完整逻辑

### 2. 使用KernelSU模块 + native hook
- Hook `stdsrp` native库的 `processCmdV2` 函数
- 在native层面修改TEE证明数据
- 需要ARM64交叉编译

### 3. 修改system分区
- 替换 `stdsrp` 库文件
- 修改TEE客户端代码
- 风险较高，可能影响其他功能

### 4. 使用Shamiko + 更多Magisk模块
- 尝试隐藏root状态的不同方法
- 可能需要多个模块配合

---

## 项目结构

```
oppo-watch-unlock-fix/
├── app/src/main/java/com/opporootfix/
│   ├── MainActivity.java          # 模块状态显示
│   └── hook/
│       └── OppoWatchUnlockFix.java # Xposed hook主文件
├── ksu-module/                    # KernelSU模块
│   ├── module.prop
│   ├── service.sh
│   ├── post-fs-data.sh
│   └── customize.sh
├── artifacts/                     # 构建产物
├── logcat_*.log                   # 各次调试的日志
└── README.md
```

## 关键类和方法（linker进程）

| 类名 | 方法 | 作用 |
|------|------|------|
| `com.oplus.linker.unlock.connect.ConnectionSocket` | `processLockEventResponse(byte[])` | 处理手表16字节响应 |
| `com.oplus.linker.unlock.connect.ConnectionSocket` | `processFailLockEventResult(Integer)` | 失败处理（error code=2） |
| `com.oplus.linker.unlock.connect.ConnectionSocket` | `processSuccessLockEventResult(Integer, byte[], byte[])` | 成功处理（byte[0]=0时触发） |
| `com.oplus.linker.unlock.connect.ConnectionManager` | `secureSendData(String, byte[])` | 发送加密数据到手表 |
| `com.oplus.linker.unlock.utils.ProtoDataGenerator` | `getLockInquiryProtoData(Byte, byte[32], byte[8], byte[64], byte[32])` | 生成proto数据 |
| `com.oplus.linker.unlock.connect.UnlockDataCache` | `updateConKeyAndAlgorithmNum(byte[64], byte[32])` | 更新连接密钥 |
| `javax.crypto.Cipher` | `doFinal(byte[])` | 加密/解密 |

## 关键时序（单次解锁尝试）

```
T+0ms    lock inquiry sent (162B)
T+250ms  onReceive(130B) → processLockInquiryResponse(128B) → errorCode=0, tokenStatus=3
T+280ms  Cipher.doFinal → [CIPHER-PATCH] sysIntegrity:false → true
T+280ms  sendSecureData("unlock watch", 4434B)
T+380ms  onReceive(18B) → processLockEventResponse(16B)
         → [EVT-PATCH] byte[0] 38→0
         → errorCode=0, operationType=0
         → processSuccessLockEventResult(0, byte[0], byte[0])
T+400ms  EncryptionUtils.encrypt: pbSequence/key/iv=null ← 失败！
T+10s    reset isUnlocking flag (超时)
```

## 给后续研究者的建议

1. **首要任务**：用jadx反编译 `com.oplus.linker` APK，找到：
   - `EncryptionUtils` 的真实类名（已被ProGuard混淆）
   - `processSuccessLockEventResult` 的完整逻辑
   - 密钥存储位置和传递机制

2. **sysintegrity进程**：该进程无法被LSPosed hook。如需修改TEE证明数据，需要：
   - KernelSU模块 + native hook
   - 或修改system分区

3. **验证方式**：手表的验证是本地的，基于之前token注册时存储的attestation数据。要让手表解锁，必须在**token注册阶段**就修改attestation数据。

4. **关键约束**：
   - TEE证明是硬件级签名，无法从Java层修改
   - 加密数据是protobuf格式，不是JSON
   - `EncryptionUtils` 类名被混淆
   - `processCmdV2` 是native函数

## 已知的环境信息

- 设备：OPPO Watch X3 (OWW261) + OPPO手机 (PJZ110)
- 系统：ColorOS 16.1 (Android 15)
- Root：KernelSU
- LSPosed：Zygisk版本

## 项目声明

本项目使用 AI（MiMo Code，基于 mimo-auto 模型）辅助开发。所有代码、日志分析、方案设计均由 AI 完成。
