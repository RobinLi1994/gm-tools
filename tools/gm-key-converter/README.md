# 国密密钥格式转换

直接用现代浏览器打开 `gm-key-converter.html`。这是完整的离线单文件，可单独复制给他人使用；运行时不需要 Java、Node.js、网络、后端或 CDN。

## 使用

1. SM2 选择 GM0016 或 GM0009；RSA 自动使用 GM0016 项目兼容格式，禁用 GM0009。GM0016 固定为小端序。
2. 分别选择、拖入或粘贴签名证书、加密证书、加密私钥。
3. 点击「生成密钥文件」，查看并复制 Base64，或下载 `.key` 文件。
4. 使用结束后点击「清空全部」。修改任何输入或目标格式都会使旧结果失效。

签名证书用于保护随机会话密钥，解封时需要该签名证书对应的私钥。加密证书必须和输入的加密私钥匹配。

输入支持单张 PEM/DER 证书和未加密的 PKCS#8/SEC1/PKCS#1 PEM 私钥，单文件上限 256 KiB。接受 SM2 命名曲线（sm2p256v1）和 RSA 2048/3072/4096 位；两张证书和私钥必须为同一种算法。SEC1 文件需要携带 SM2 曲线信息。RSA 仅接受通用 rsaEncryption、两素数私钥，检查模数、公钥指数、私钥指数与 CRT 关系；不支持 RSA-PSS 受限密钥或多素数 RSA。不支持带密码的私钥、P12/PFX、证书链或显式曲线参数。

输入仅保留在当前页面内存中，不写入浏览器存储，不发起网络请求。页面清空、关闭后不保留应用状态，但 JavaScript 无法保证已经分配的字符串立即从内存抹除。只检查格式、曲线、密钥对匹配，不验证证书信任链、有效期和用途。

## 编码与兼容

SM2 采用以下密钥保护结构：

- 使用浏览器安全随机数生成 16 字节 SM4 会话密钥，由签名证书的 SM2 公钥以 C1C3C2 模式封装。
- 加密私钥标量编码为 32 字节，以 SM4/ECB/NoPadding 加密。
- GM0016：388 字节 `EnvelopedKeyBlob`，版本 1，算法 0x401，密钥位数 256。32 位整数字段为小端；公钥、临时点坐标及私钥密文按现有实现左补零到 64 字节。
- GM0009：DER `SM2EnvelopedKey`，SM4-ECB 算法 OID 为 `1.2.156.10197.1.104.1`，算法参数省略；公钥 BIT STRING 为 `04 || X || Y`，私钥密文 BIT STRING 为 32 字节。
- 输出为单行 Base64，无 PEM 包装；每次转换使用随机数，不能通过比较两次 Base64 是否相等验证正确性。

RSA 采用现有项目兼容结构，界面标为「GM0016 RSA · 现有项目兼容格式」：

- 使用浏览器 CSPRNG 生成 16 字节会话密钥，签名证书 RSA 公钥按 PKCS#1 v1.5 加密；填充随机字节也来自同一安全随机源。
- PKCS#1 私钥统一包装为 PKCS#8 DER；PKCS#8 输入归一化为无属性的 rsaEncryption + NULL 包装。
- 会话密钥按 K1-K2-K1 扩展为 24 字节，使用 3DES-CBC 加密私钥，填充等价于 Java `DESede/CBC/PKCS5Padding`，固定 IV 为 `0001020304050607`。
- 输出布局：`uint32LE(0x2002) || uint32LE(wrappedKey.length) || wrappedKey || encryptedPkcs8`。
- `0x2002` 为现有项目的龙脉 3DES-CBC 标识，接收端按长度拆分后调用 `SKF_ImportRSAKeyPair`。这些参数用于既有项目兼容，不声称所有 SKF 厂商都支持，也不用于新协议设计。
- GM0009 专用于 SM2，RSA 输入不能生成 GM0009。RSA 文件名为 `GM0016_RSA_enveloped_key.key`。

已通过 Java/BouncyCastle 独立解析与交叉解密，尚未做特定厂商设备的实机导入验证。

## 维护与验证

文件职责：`src/core.js` 负责输入解析、校验及分发，`src/rsa.js` 负责 RSA 兼容封装，`src/ui.js` 负责本地交互，`src/page.html` 为页面模板；`build.mjs` 内嵌脚本、许可证和对应 CSP 哈希，生成最终 HTML。不要直接编辑生成文件。

开发环境需要 Node.js 20+、Python 3、Java 17；用户打开 HTML 不需要这些环境。

```sh
cd tools/gm-key-converter
npm ci --ignore-scripts
npm test
npm run build
```

`npm test` 自动生成临时 SM2/P-256/RSA 自签名测试材料到被忽略的 `build/fixtures/`，不会读取用户真实私钥。BC 依赖固定为 1.80 的三个运行库，优先复用本机 Gradle 缓存，缺少时从 Maven Central 下载到 `build/bc/`；两种来源均校验固定 SHA-256。不依赖其他业务项目或 Gradle 构建。

测试覆盖 PEM/DER、PKCS#8/SEC1/PKCS#1、密钥匹配、错误曲线、加密私钥拒绝、DER 边界、随机性以及 Java/BouncyCastle 独立解析和交叉解密。RSA 测试覆盖三种位数、CRT 损坏、混用拒绝、随机性、不同签名证书位数，以及恢复私钥的签名验签。Java 验证代码在 `tests/GmInterop.java`，仅参与开发测试，不被打包到 HTML。

运行库固定为 [sm-crypto-v2 1.15.1](https://github.com/Cubelrti/sm-crypto-v2) 和 [crypto-js 4.2.0](https://github.com/brix/crypto-js)，传递依赖版本及校验值由 `package-lock.json` 锁定。SM2 使用基于 noble-curves 的实现，RSA 按 RFC 8017 进行编码并使用 noble 的公钥模幂运算，3DES 使用 CryptoJS；随机数来自 `crypto.getRandomValues`，不退回 `Math.random`。内嵌库的许可证可在页面「格式说明与开源组件」查看。

CryptoJS 已停止维护，本工具仅为既有 3DES 设备协议固定使用其 4.2.0 的分组加密实现，不使用其口令派生或随机数 API。RSA 编码依据 [RFC 8017 §7.2.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-7.2.1)，只执行公钥加密，不实现私钥解密或签名。
