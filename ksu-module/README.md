# OPPO Watch Unlock Fix - KernelSU Module

## 功能
通过 KernelSU 模块修改系统属性和文件系统，帮助绕过 root 检测。

## 安装方法
1. 将 `ksu-module` 目录打包为 zip 文件
2. 在 KernelSU 管理器中安装 zip
3. 重启手机

## 工作原理
1. **系统属性补丁**：修改 `ro.boot.verifiedbootstate`、`ro.boot.flash.locked` 等属性
2. **文件系统隐藏**：隐藏 su、KernelSU、Magisk 等文件
3. **持续监控**：定期检查属性是否被重置

## 注意事项
1. 此模块需要 KernelSU root
2. 此模块单独使用可能不足以解锁手表
3. 需要配合 LSPosed 模块一起使用
4. 重启后模块自动生效

## 与 LSPosed 模块的配合
1. 安装 KernelSU 模块 → 重启
2. 安装 LSPosed 模块 → 在 LSPosed 中启用
3. 强制停止「移动服务」→ 重启
4. 测试解锁
