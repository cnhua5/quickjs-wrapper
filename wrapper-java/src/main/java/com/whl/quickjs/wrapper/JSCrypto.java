package com.whl.quickjs.wrapper;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * JS代码加密工具
 * 加密流程: 原始JS -> 压缩 -> XOR加密 -> Base64变体编码
 * 解密在Native层VMP中执行
 */
public class JSCrypto {
    
    // 魔数标识加密的JS
    private static final byte[] MAGIC = {(byte)0xE5, (byte)0x5C, (byte)0x52, (byte)0x59};
    
    // 版本号
    private static final byte VERSION = 0x01;
    
    // 加密标志
    public static final int FLAG_COMPRESSED = 0x01;
    public static final int FLAG_XOR = 0x02;
    public static final int FLAG_SHUFFLE = 0x04;
    
    /**
     * 加密JS代码
     * @param jsCode 原始JS代码
     * @param key 加密密钥 (建议16-32字节)
     * @return 加密后的字节数组
     */
    public static byte[] encrypt(String jsCode, byte[] key) {
        try {
            byte[] data = jsCode.getBytes(StandardCharsets.UTF_8);
            
            // 1. 压缩
            byte[] compressed = compress(data);
            
            // 2. XOR加密
            byte[] encrypted = xorEncrypt(compressed, key);
            
            // 3. 字节混淆
            byte[] shuffled = shuffle(encrypted, key);
            
            // 4. 构建最终数据包
            // 格式: MAGIC(4) + VERSION(1) + FLAGS(1) + KEY_HASH(4) + ORIG_LEN(4) + DATA
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(MAGIC);
            bos.write(VERSION);
            bos.write(FLAG_COMPRESSED | FLAG_XOR | FLAG_SHUFFLE);
            bos.write(intToBytes(hashKey(key)));
            bos.write(intToBytes(data.length));
            bos.write(shuffled);
            
            return bos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Encrypt failed", e);
        }
    }
    
    /**
     * 加密JS代码（使用默认密钥）
     */
    public static byte[] encrypt(String jsCode) {
        return encrypt(jsCode, getDefaultKey());
    }
    
    /**
     * 生成随机密钥
     */
    public static byte[] generateKey(int length) {
        byte[] key = new byte[length];
        new SecureRandom().nextBytes(key);
        return key;
    }
    
    /**
     * 获取默认密钥（实际使用时应该替换为你自己的密钥）
     */
    public static byte[] getDefaultKey() {
        // 这个密钥会被编译进native层，修改时需要同步修改native代码
        return new byte[] {
            (byte)0x51, (byte)0x4A, (byte)0x53, (byte)0x5F,
            (byte)0x56, (byte)0x4D, (byte)0x50, (byte)0x5F,
            (byte)0x4B, (byte)0x45, (byte)0x59, (byte)0x5F,
            (byte)0x32, (byte)0x30, (byte)0x32, (byte)0x34
        };
    }
    
    // ============== 内部方法 ==============
    
    private static byte[] compress(byte[] data) throws Exception {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(data);
        deflater.finish();
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            bos.write(buffer, 0, count);
        }
        deflater.end();
        return bos.toByteArray();
    }
    
    private static byte[] xorEncrypt(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            // 多层XOR增加复杂度
            result[i] = (byte)(data[i] ^ key[i % key.length] ^ (i & 0xFF) ^ ((i >> 8) & 0xFF));
        }
        return result;
    }
    
    private static byte[] shuffle(byte[] data, byte[] key) {
        byte[] result = data.clone();
        int seed = hashKey(key);
        
        // Fisher-Yates shuffle变体
        for (int i = result.length - 1; i > 0; i--) {
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
            int j = seed % (i + 1);
            byte temp = result[i];
            result[i] = result[j];
            result[j] = temp;
        }
        return result;
    }
    
    private static int hashKey(byte[] key) {
        int hash = 0x811C9DC5;
        for (byte b : key) {
            hash ^= b;
            hash *= 0x01000193;
        }
        return hash;
    }
    
    private static byte[] intToBytes(int value) {
        return new byte[] {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        };
    }
}
