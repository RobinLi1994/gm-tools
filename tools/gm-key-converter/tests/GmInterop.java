import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * 生成临时测试密钥，并用独立的 BouncyCastle 解封逻辑验证浏览器输出。
 *
 * @author robin.li
 * @version 1.0
 * @date 2026-10-10 20:03:46
 */
class GmInterop {
    /**
     * 执行测试材料生成或两种格式的交叉解密验证，不读取用户真实密钥。
     *
     * @param args 操作名（generate、verify 或 verify-rsa）及临时测试目录
     * @throws Exception 测试材料生成失败、格式不符或解密结果不一致时抛出
     */
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Path directory = Path.of(args[1]);
        if ("generate".equals(args[0])) {
            Files.createDirectories(directory);
            createFixture(directory, "sign", "sm2p256v1");
            createFixture(directory, "enc", "sm2p256v1");
            createFixture(directory, "p256", "secp256r1");
            createRsaFixture(directory, "rsa-sign", 2048);
            for (int bits : new int[]{2048, 3072, 4096}) {
                createRsaFixture(directory, "rsa-enc-" + bits, bits);
            }
            System.out.println("临时测试证书及密钥已生成");
        } else if ("verify".equals(args[0])) {
            verify(directory, "0016");
            verify(directory, "0009");
            System.out.println("GM0016 和 GM0009 交叉解密验证通过");
        } else if ("verify-rsa".equals(args[0])) {
            for (int bits : new int[]{2048, 3072, 4096}) {
                for (String encoding : new String[]{"key", "pkcs1.key"}) {
                    verifyRsa(directory, "rsa-output-" + bits + "-" + encoding, "rsa-sign", "rsa-enc-" + bits);
                }
            }
            verifyRsa(directory, "rsa-output-large-sign", "rsa-enc-4096", "rsa-enc-2048");
            System.out.println("RSA GM0016 交叉解密验证通过");
        } else {
            throw new IllegalArgumentException("未知测试操作");
        }
    }

    /**
     * 创建指定曲线的自签名测试证书及 PKCS#8、SEC1 私钥。
     *
     * @param directory 仅用于测试的输出目录
     * @param name      文件名前缀与证书通用名
     * @param curve     BouncyCastle 支持的命名曲线
     * @throws Exception 密钥生成、证书签名或文件写入失败时抛出
     */
    private static void createFixture(Path directory, String name, String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(new ECGenParameterSpec(curve));
        KeyPair pair = generator.generateKeyPair();
        X500Name subject = new X500Name("CN=Offline test " + name);
        Instant now = Instant.now();
        X509CertificateHolder certificate = new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(86400)), subject, pair.getPublic())
                .build(new JcaContentSignerBuilder("sm2p256v1".equals(curve) ? "SM3withSM2" : "SHA256withECDSA")
                        .setProvider("BC").build(pair.getPrivate()));
        Files.write(directory.resolve(name + ".der"), certificate.getEncoded());
        writePem(directory.resolve(name + ".pem"), "CERTIFICATE", certificate.getEncoded());
        writePem(directory.resolve(name + ".key"), "PRIVATE KEY", pair.getPrivate().getEncoded());
        Files.write(directory.resolve(name + "-pkcs8.der"), pair.getPrivate().getEncoded());
        byte[] sec1 = PrivateKeyInfo.getInstance(pair.getPrivate().getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded();
        writePem(directory.resolve(name + "-sec1.key"), "EC PRIVATE KEY", sec1);
    }

    /**
     * 生成 RSA 自签名证书及两种未加密私钥编码，供解析与独立解封测试使用。
     *
     * @param directory 合成测试材料目录
     * @param name      文件名前缀
     * @param bits      RSA 模数位数
     * @throws Exception 密钥生成、证书签名或文件写入失败时抛出
     */
    private static void createRsaFixture(Path directory, String name, int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(bits);
        KeyPair pair = generator.generateKeyPair();
        X500Name subject = new X500Name("CN=RSA offline test " + name);
        Instant now = Instant.now();
        X509CertificateHolder certificate = new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(86400)), subject, pair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate()));
        Files.write(directory.resolve(name + ".der"), certificate.getEncoded());
        writePem(directory.resolve(name + ".pem"), "CERTIFICATE", certificate.getEncoded());
        byte[] pkcs8 = pair.getPrivate().getEncoded();
        writePem(directory.resolve(name + ".key"), "PRIVATE KEY", pkcs8);
        Files.write(directory.resolve(name + "-pkcs8.der"), pkcs8);
        byte[] pkcs1 = PrivateKeyInfo.getInstance(pkcs8).parsePrivateKey().toASN1Primitive().getEncoded();
        writePem(directory.resolve(name + "-pkcs1.key"), "RSA PRIVATE KEY", pkcs1);
    }

    /**
     * 将测试数据写为 PEM，内容不输出到日志。
     *
     * @param path  目标文件路径
     * @param type  PEM 类型标签
     * @param bytes DER 数据
     * @throws Exception 编码或文件写入失败时抛出
     */
    private static void writePem(Path path, String type, byte[] bytes) throws Exception {
        StringWriter text = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(text)) {
            writer.writeObject(new PemObject(type, bytes));
        }
        Files.writeString(path, text.toString());
    }

    /**
     * 按独立结构定义解封会话密钥和加密私钥，并核对对应公钥。
     *
     * @param directory 包含临时密钥、证书和待校验结果的目录
     * @param format    0016 或 0009
     * @throws Exception 结构、算法、填充、公钥或解密后的私钥不符合预期时抛出
     */
    private static void verify(Path directory, String format) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(Files.readString(directory.resolve("output-" + format + ".key")).trim());
        byte[] sm2Cipher;
        byte[] encryptedPrivate;
        byte[] publicKey;
        if ("0016".equals(format)) {
            ByteBuffer buffer = ByteBuffer.wrap(encoded).order(ByteOrder.LITTLE_ENDIAN);
            check(encoded.length == 388 && buffer.getInt(0) == 1 && buffer.getInt(4) == 0x401
                    && buffer.getInt(8) == 256 && buffer.getInt(76) == 256 && buffer.getInt(368) == 16, "GM0016 头部错误");
            for (int start : new int[]{12, 80, 144, 208, 272}) {
                check(Arrays.equals(Arrays.copyOfRange(encoded, start, start + 32), new byte[32]), "GM0016 填充错误");
            }
            publicKey = join(new byte[]{4}, Arrays.copyOfRange(encoded, 112, 144), Arrays.copyOfRange(encoded, 176, 208));
            sm2Cipher = join(new byte[]{4}, Arrays.copyOfRange(encoded, 240, 272), Arrays.copyOfRange(encoded, 304, 336),
                    Arrays.copyOfRange(encoded, 336, 368), Arrays.copyOfRange(encoded, 372, 388));
            encryptedPrivate = Arrays.copyOfRange(encoded, 44, 76);
        } else {
            ASN1Sequence envelope = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoded));
            check(envelope.size() == 4, "GM0009 字段数错误");
            AlgorithmIdentifier algorithm = AlgorithmIdentifier.getInstance(envelope.getObjectAt(0));
            check(algorithm.getAlgorithm().equals(GMObjectIdentifiers.sms4_ecb) && algorithm.getParameters() == null, "GM0009 算法错误");
            ASN1Sequence encryptedKey = ASN1Sequence.getInstance(envelope.getObjectAt(1));
            check(encryptedKey.size() == 4, "SM2 密文字段数错误");
            byte[] x = BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(encryptedKey.getObjectAt(0)).getPositiveValue());
            byte[] y = BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(encryptedKey.getObjectAt(1)).getPositiveValue());
            sm2Cipher = join(new byte[]{4}, x, y, ASN1OctetString.getInstance(encryptedKey.getObjectAt(2)).getOctets(),
                    ASN1OctetString.getInstance(encryptedKey.getObjectAt(3)).getOctets());
            publicKey = ASN1BitString.getInstance(envelope.getObjectAt(2)).getOctets();
            encryptedPrivate = ASN1BitString.getInstance(envelope.getObjectAt(3)).getOctets();
            check(Arrays.equals(encoded, envelope.getEncoded("DER")), "GM0009 非规范 DER");
        }
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        var signKey = converter.getPrivateKey(PrivateKeyInfo.getInstance(Files.readAllBytes(directory.resolve("sign-pkcs8.der"))));
        var expectedKey = (ECPrivateKey) converter.getPrivateKey(PrivateKeyInfo.getInstance(Files.readAllBytes(directory.resolve("enc-pkcs8.der"))));
        byte[] expectedPublic = new X509CertificateHolder(Files.readAllBytes(directory.resolve("enc.der")))
                .getSubjectPublicKeyInfo().getPublicKeyData().getOctets();
        check(Arrays.equals(publicKey, expectedPublic), "加密证书公钥不一致");
        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        engine.init(false, ECUtil.generatePrivateKeyParameter(signKey));
        byte[] sessionKey = engine.processBlock(sm2Cipher, 0, sm2Cipher.length);
        check(sessionKey.length == 16 && encryptedPrivate.length == 32, "密钥长度错误");
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "SM4"));
        check(Arrays.equals(cipher.doFinal(encryptedPrivate), BigIntegers.asUnsignedByteArray(32, expectedKey.getS())), "私钥解密不一致");
    }

    /**
     * 按现有项目兼容协议解封 RSA Blob，并以证书验签证明恢复出的私钥可用。
     *
     * @param directory 测试材料目录
     * @param output    待解封 Base64 文件名
     * @param signer    签名密钥材料名前缀
     * @param recipient 加密密钥材料名前缀
     * @throws Exception 结构、算法、填充、解封内容或签名验证不符合预期时抛出
     */
    private static void verifyRsa(Path directory, String output, String signer, String recipient) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(Files.readString(directory.resolve(output)).trim());
        ByteBuffer buffer = ByteBuffer.wrap(encoded).order(ByteOrder.LITTLE_ENDIAN);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        var signKey = converter.getPrivateKey(PrivateKeyInfo.getInstance(Files.readAllBytes(directory.resolve(signer + "-pkcs8.der"))));
        var signPublic = (RSAPublicKey) converter.getPublicKey(new X509CertificateHolder(
                Files.readAllBytes(directory.resolve(signer + ".der"))).getSubjectPublicKeyInfo());
        check(buffer.getInt() == 0x2002, "RSA 对称算法标识错误");
        int wrappedLength = buffer.getInt();
        check(wrappedLength == (signPublic.getModulus().bitLength() + 7) / 8, "RSA 会话密钥密文长度错误");
        byte[] wrapped = new byte[wrappedLength];
        buffer.get(wrapped);
        byte[] encrypted = new byte[buffer.remaining()];
        buffer.get(encrypted);
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        rsa.init(Cipher.DECRYPT_MODE, signKey);
        byte[] session = rsa.doFinal(wrapped);
        check(session.length == 16, "RSA 会话密钥应为 16 字节");
        byte[] expanded = Arrays.copyOf(session, 24);
        System.arraycopy(session, 0, expanded, 16, 8);
        Cipher des = Cipher.getInstance("DESede/CBC/PKCS5Padding", "BC");
        des.init(Cipher.DECRYPT_MODE, new SecretKeySpec(expanded, "DESede"),
                new IvParameterSpec(new byte[]{0, 1, 2, 3, 4, 5, 6, 7}));
        byte[] decrypted = des.doFinal(encrypted);
        check(Arrays.equals(decrypted, Files.readAllBytes(directory.resolve(recipient + "-pkcs8.der"))), "RSA 私钥解封不一致");
        var recovered = converter.getPrivateKey(PrivateKeyInfo.getInstance(decrypted));
        var publicKey = converter.getPublicKey(new X509CertificateHolder(
                Files.readAllBytes(directory.resolve(recipient + ".der"))).getSubjectPublicKeyInfo());
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        byte[] challenge = new byte[]{10, 11, 12, 13};
        signature.initSign(recovered);
        signature.update(challenge);
        byte[] signed = signature.sign();
        signature.initVerify(publicKey);
        signature.update(challenge);
        check(signature.verify(signed), "恢复的 RSA 私钥不能通过证书公钥验签");
    }

    /**
     * 拼接测试用二进制字段。
     *
     * @param parts 按顺序拼接的字节数组
     * @return 拼接后的新数组
     */
    private static byte[] join(byte[]... parts) {
        int length = Arrays.stream(parts).mapToInt(part -> part.length).sum();
        ByteBuffer buffer = ByteBuffer.allocate(length);
        for (byte[] part : parts) {
            buffer.put(part);
        }
        return buffer.array();
    }

    /**
     * 将测试约束转换为明确的断言失败。
     *
     * @param condition 必须满足的测试条件
     * @param message   失败原因，不包含私钥内容
     * @throws AssertionError 条件不满足时抛出
     */
    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
