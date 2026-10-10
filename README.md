# GM 工具箱

一个页面，三个密码与证书工具。提供统一导航、表单样式和一键清空，所有脚本和依赖均打包在一个 HTML 中。

- **在线使用**：[RobinLi1994.github.io/gm-tools](https://RobinLi1994.github.io/gm-tools/)
- **离线使用**：在线页点击「下载离线版」，或下载仓库的 [`index.html`](https://github.com/RobinLi1994/gm-tools/raw/refs/heads/main/index.html)，用现代浏览器打开。单独保存这一个文件即可。
- **源码维护**：修改源码后重新构建 `index.html`，不要手工修改生成文件。

## 工具用途

| 工具 | 输入 | 输出及用途 | 运行条件 |
| --- | --- | --- | --- |
| 国密密钥转换 | SM2 签名证书、加密证书和匹配的未加密 PEM 私钥 | GM0016 小端序 / GM0009 DER 的 Base64，支持复制与下载 `.key`，用于加密密钥对的保护与导入 | 浏览器本地计算，离线可用 |
| UKey 证书 SQL | 本地 wekey-skf 设备信息、签名证书、管理员名称、角色 ID | 为既有 `sms_admin`、`sms_admin_cert` 表生成 PostgreSQL 导入脚本，支持复制与下载 `.sql` | 本地 wekey-skf 服务、UKey 及对应数据库表结构 |
| Jasypt 加解密 | 加密口令与明文/密文，或含主口令和 ENC 值的简单 YAML 配置 | 手动加密生成 `ENC(...)`，手动/批量解密并复制明文 | 支持 Web Crypto 的现代浏览器，使用 HTTPS、localhost 或本地文件 |

切换页签保留当前输入及结果。刷新、关闭或「清空所有工具」会清除应用状态；不使用 localStorage、IndexedDB 或统计脚本。下载离线版只包含工具源码，不包含当前输入和结果。清空不会删除已经下载的文件或系统剪贴板内容，JavaScript 也无法保证旧字符串立即从内存抹除。

## 1. 国密密钥格式转换

1. 选择 GM0016 或 GM0009。
2. 选择文件、拖拽或粘贴签名证书、加密证书和加密私钥。
3. 点击「生成密钥文件」，复制 Base64 或下载 `.key`。

证书支持单张 PEM/DER，私钥支持未加密 PKCS#8/SEC1 PEM。只支持 SM2 命名曲线，单个输入不超过 256 KiB；加密证书与私钥必须匹配。不支持加密私钥、P12/PFX 和 GM0019。

GM0016 为 388 字节结构，32 位整数字段使用小端序；GM0009 为 ASN.1 DER。每次使用新的随机 SM4 会话密钥与 SM2 加密随机数，输出不同是正常现象。解封需要签名证书对应的私钥。工具不验证证书信任链、有效期或用途，也未做特定厂商设备实机导入验证。

更详细的格式、源码和测试说明见 [转换工具 README](tools/gm-key-converter/README.md)。

## 2. UKey 管理员证书 SQL

1. 启动 wekey-skf（默认 `http://localhost:9001`），插入 UKey，点击「枚举设备」并选择设备。
2. 导出签名证书，或手动粘贴 PEM 证书作为兜底。手动模式仍需要选择设备以取得 UKey 序列号。
3. 确认管理员名称、密钥类型及角色 ID（默认 1001，必须与目标库 `sms_role.id` 对应）。
4. 生成并审阅 SQL，然后复制或下载；工具不会连接数据库或执行 SQL。

服务需提供 `GET /api/v1/enum-dev`、`GET /api/v1/export-cert?serialNumber=...`，并返回 `{code: 0, data: ...}`。导出优先选择 `certType=0` 的签名证书，没有时使用第一张。

该脚本适用于原工具对应的表结构及 `sms_admin_id_seq`、`sms_admin_cert_id_seq` 序列，并非通用数据库迁移工具。按 UKey 序列号更新/插入管理员，按证书序列号更新/插入证书，再关联签名证书。更新会启用管理员并恢复删除标志；插入采用 `MAX(id)+1`，请避免并发执行。确认 SQL 的事务和后续序列推进语句均完成。

在线页连接本地服务可能被浏览器本地网络权限、跨域或混合内容策略限制。优先下载离线版；仍需服务允许对应来源的 CORS。服务地址可修改，请确认填写的是你信任的服务。工具不会自动请求设备，只有点击相关按钮才会访问服务。

## 3. Jasypt 加密与解密

手动填写 `jasypt.encryptor.password` 后，可解密 `ENC(...)` 或纯 Base64，也可把明文加密为 `ENC(...)`。YAML 文件支持选择或拖拽多个文件，自动查找主口令和各行 ENC 值。

算法参数固定为 PBKDF2-HMAC-SHA512、1000 次迭代和 AES-256-CBC；新密文采用随机 16 字节盐和 16 字节 IV，按 `salt || IV || ciphertext` 编码。解密尝试 16/8 字节盐布局，不代表兼容所有 Jasypt 算法、版本或自定义配置。AES-CBC 不带认证，解密成功不等于密文真实性得到验证。

YAML 提取采用缩进扫描，不是完整 YAML 解析器。请使用普通嵌套 `jasypt: / encryptor: / password:` 结构和字面量口令，不支持环境变量解析、多行标量等复杂语法；点号形式 `.properties` 的主口令不会自动提取。批量结果会显示主口令与明文，使用后可点击顶部「清空所有工具」。

## 开发与测试

构建需要 Node.js 20+；国密交叉解密测试还需要 Python 3、Java 17。最终 HTML 的用户无需安装这些环境。

```sh
npm --prefix tools/gm-key-converter ci --ignore-scripts
npm run check
npm test
npm run build
# 可选本地预览
python3 -m http.server 8080 --bind 127.0.0.1
```

测试生成合成 SM2/P-256 证书和私钥到被忽略的 `build/`，不会读取真实私钥。BouncyCastle 固定 1.80，优先复用本机缓存，否则从 Maven Central 下载并校验 SHA-256。测试覆盖输入解析、曲线/密钥匹配校验、随机性、GM0016/GM0009 解封以及 Java/BouncyCastle 独立交叉解密。

```text
index.html                      # 生成的统一单文件入口，供 Pages 和离线使用
src/index.html                  # 工具箱外壳及页签
src/app.js                      # 切换、保留状态、全部清空、离线下载
src/tool-theme.css              # 共享视觉样式
build.mjs                      # 内嵌三个工具及主题，生成 index.html
tools/admin-cert-sql.html       # UKey SQL 工具源码，可独立使用
tools/jasypt-decrypt.html       # Jasypt 工具源码，可独立使用
tools/gm-key-converter/         # 国密转换源码、构建与测试
```

三个工具通过内嵌文档隔离同名字段和脚本，共享统一主题。页签切换保留文档；全部清空销毁已打开的工具文档，旧异步操作不能回填到新界面。维护时同时验证页签保留、全部清空、离线下载及三项工具功能。

GitHub Pages 使用 `main` 分支根目录，直接提供已提交的 `index.html`。发布前运行构建并提交生成文件。仓库不包含真实证书、私钥、配置密码、依赖目录或测试生成物；第三方组件的许可证随转换工具一同内嵌。
