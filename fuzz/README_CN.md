# XQUIC 模糊测试使用指南

## 前提条件

在运行XQUIC的模糊测试之前，请确保满足以下条件：

1. 已安装必要的开发工具：
   - CMake (版本 3.5 或更高)
   - C编译器 (支持C11标准)
   - Clang 编译器 (推荐用于模糊测试)

2. 已安装BabaSSL或BoringSSL：
   - 默认情况下，XQUIC使用BabaSSL
   - 如果BabaSSL未安装在默认位置(/usr/local/babassl)，需要指定SSL_PATH

## 编译步骤

1. 在XQUIC根目录下创建构建目录并进入：

```bash
mkdir -p build && cd build
```

2. 使用CMake配置项目，启用模糊测试：

```bash
cmake -DENABLE_FUZZING=ON ..
```

如果需要指定SSL库路径，可以添加SSL_PATH参数：

```bash
cmake -DENABLE_FUZZING=ON -DSSL_PATH=/path/to/babassl ..
```

3. 编译XQUIC库和模糊测试目标：

```bash
make -j$(nproc)
```

4. 编译所有模糊测试器：

```bash
make fuzz
```

## 运行模糊测试

所有模糊测试器都会被编译到`build/fuzz/`目录下，语料库目录位于`build/fuzz/corpus/`。

### 运行单个模糊测试器

在XQUIC的构建目录(build)中执行以下命令：

```bash
# 运行数据包模糊测试
./fuzz/xqc_packet_fuzzer -max_len=4096 -timeout=10 ./fuzz/corpus/packet/

# 运行帧模糊测试
./fuzz/xqc_frame_fuzzer -max_len=4096 -timeout=10 ./fuzz/corpus/frame/

# 运行流模糊测试
./fuzz/xqc_stream_fuzzer -max_len=4096 -timeout=10 ./fuzz/corpus/stream/

# 运行状态模糊测试
./fuzz/xqc_state_fuzzer -max_len=4096 -timeout=10 ./fuzz/corpus/state/

# 运行HTTP/3模糊测试
./fuzz/xqc_h3_fuzzer -max_len=4096 -timeout=10 ./fuzz/corpus/h3/
```

### 使用CMake目标运行模糊测试

也可以使用CMake定义的目标来运行模糊测试：

```bash
# 运行单个模糊测试器
make run_packet_fuzzer
make run_frame_fuzzer
make run_stream_fuzzer
make run_state_fuzzer
make run_h3_fuzzer

# 运行所有模糊测试器
make run_fuzz
```

## 模糊测试参数说明

模糊测试器支持多种参数来控制测试行为：

- `-max_len=N`：设置最大输入长度
- `-timeout=N`：设置每个测试用例的超时时间（秒）
- `-runs=N`：设置运行测试用例的次数
- `-seed=N`：设置随机种子
- `-dict=DICT`：指定字典文件

更多参数请参考[LibFuzzer文档](https://llvm.org/docs/LibFuzzer.html)。

## 故障排除

1. 如果遇到编译错误，请确保已安装所有必要的依赖项。

2. 如果模糊测试器崩溃，会生成崩溃报告和测试用例。请保存这些文件并报告问题。

3. 如果遇到"Sanitizer"相关错误，这通常表示发现了内存安全问题，应该被视为需要修复的漏洞。

## 注意事项

- 模糊测试可能会消耗大量CPU和内存资源。
- 长时间运行模糊测试可能会导致系统负载增加。
- 建议在专用环境中运行模糊测试。