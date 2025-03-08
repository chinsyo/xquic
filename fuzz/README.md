# XQUIC 模糊测试框架

## 简介

本目录包含XQUIC的模糊测试框架，用于发现协议实现中的潜在漏洞和错误。模糊测试通过向XQUIC库提供异常或随机输入，测试其处理边界情况和异常输入的能力。

## 模糊测试的重要性

对于网络协议实现，特别是像QUIC这样的安全传输协议，模糊测试是非常重要的安全保障措施：

1. 发现内存安全问题：缓冲区溢出、释放后使用等
2. 识别协议状态机错误：不正确的状态转换处理
3. 测试边界条件：特殊长度、格式的数据包处理
4. 验证错误处理：确保实现能够优雅地处理错误情况

## 目录结构

```
fuzz/
├── README.md                 # 本文档
├── CMakeLists.txt            # 构建配置
├── common/                   # 通用工具和辅助函数
├── corpus/                   # 测试语料库
│   ├── initial/              # 初始连接语料
│   ├── handshake/            # 握手阶段语料
│   ├── transport/            # 传输阶段语料
│   └── h3/                   # HTTP/3语料
├── packet_fuzzer/            # 数据包模糊测试
├── frame_fuzzer/             # 帧模糊测试
├── stream_fuzzer/            # 流模糊测试
├── state_fuzzer/             # 状态转换模糊测试
└── h3_fuzzer/                # HTTP/3模糊测试
```

## 模糊测试方法

本框架采用多种模糊测试方法，确保全面覆盖XQUIC的各个组件：

1. **基于状态的模糊测试**：跟踪QUIC连接状态机，确保在每个状态下都进行适当的测试
2. **基于语法的模糊测试**：根据QUIC协议规范生成有效但边界的输入
3. **基于覆盖率的模糊测试**：使用代码覆盖率信息指导测试用例生成

## 避免无效测试场景

为确保测试有效性，本框架特别注意：

1. 不会跳过握手阶段直接发送应用数据
2. 不会持续发送明显无效的请求
3. 遵循QUIC协议状态转换逻辑
4. 确保测试用例能够覆盖协议的各个阶段

## 使用方法

### 构建

```bash
# 在XQUIC根目录下执行
cmake -DENABLE_FUZZING=ON .
make fuzz
```

### 运行测试

```bash
# 运行数据包模糊测试
./fuzz/packet_fuzzer/xqc_packet_fuzzer ./fuzz/corpus/packet/

# 运行帧模糊测试
./fuzz/frame_fuzzer/xqc_frame_fuzzer ./fuzz/corpus/frame/
```

## 参考资料

- [QUIC协议规范 (RFC 9000)](https://datatracker.ietf.org/doc/html/rfc9000)
- [HTTP/3规范 (RFC 9114)](https://datatracker.ietf.org/doc/html/rfc9114)
- [QUIC-TLS (RFC 9001)](https://datatracker.ietf.org/doc/html/rfc9001)
- [LibFuzzer文档](https://llvm.org/docs/LibFuzzer.html)
- [Google OSS-Fuzz项目](https://github.com/google/oss-fuzz)