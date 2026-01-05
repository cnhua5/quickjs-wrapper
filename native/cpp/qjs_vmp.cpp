#include "qjs_vmp.h"
#include <cstdlib>
#include <cstring>
#include <zlib.h>

// ============================================================
// VMP保护标记 - 将关键函数放入VMP保护段
// 使用时根据你的VMP工具调整标记方式
// ============================================================

// 方式1: 使用section属性（需要VMP工具支持）
#if defined(__GNUC__) || defined(__clang__)
#define VMP_PROTECT __attribute__((section(".vmp")))
#define VMP_BEGIN 
#define VMP_END
#else
#define VMP_PROTECT
#define VMP_BEGIN
#define VMP_END
#endif

// 方式2: 使用特殊标记（某些VMP工具识别）
// #define VMP_BEGIN __asm__("VMP_BEGIN")
// #define VMP_END __asm__("VMP_END")

// ============================================================
// 默认密钥 - 与Java端保持一致
// 实际使用时应该修改这个密钥
// ============================================================
static const uint8_t DEFAULT_KEY[] = {
    0x51, 0x4A, 0x53, 0x5F,  // QJS_
    0x56, 0x4D, 0x50, 0x5F,  // VMP_
    0x4B, 0x45, 0x59, 0x5F,  // KEY_
    0x32, 0x30, 0x32, 0x34   // 2024
};
static const size_t KEY_LEN = sizeof(DEFAULT_KEY);

// ============================================================
// 内部辅助函数
// ============================================================

// 计算密钥哈希 (FNV-1a)
VMP_PROTECT
static uint32_t calc_key_hash(const uint8_t *key, size_t len) {
    VMP_BEGIN;
    uint32_t hash = 0x811C9DC5;
    for (size_t i = 0; i < len; i++) {
        hash ^= key[i];
        hash *= 0x01000193;
    }
    VMP_END;
    return hash;
}

// 字节反混淆 (shuffle的逆操作)
VMP_PROTECT
static void unshuffle(uint8_t *data, size_t len, const uint8_t *key, size_t keyLen) {
    VMP_BEGIN;
    
    // 计算seed
    uint32_t seed = calc_key_hash(key, keyLen);
    
    // 记录shuffle顺序
    uint32_t *indices = (uint32_t*)malloc(len * sizeof(uint32_t));
    uint32_t tempSeed = seed;
    
    for (size_t i = len - 1; i > 0; i--) {
        tempSeed = (tempSeed * 1103515245 + 12345) & 0x7FFFFFFF;
        indices[len - 1 - i] = tempSeed % (i + 1);
    }
    
    // 逆向还原
    for (size_t i = 1; i < len; i++) {
        size_t j = indices[len - 1 - i];
        uint8_t temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
    
    free(indices);
    VMP_END;
}

// XOR解密
VMP_PROTECT
static void xor_decrypt(uint8_t *data, size_t len, const uint8_t *key, size_t keyLen) {
    VMP_BEGIN;
    for (size_t i = 0; i < len; i++) {
        // 与加密时相同的多层XOR
        data[i] ^= key[i % keyLen] ^ (i & 0xFF) ^ ((i >> 8) & 0xFF);
    }
    VMP_END;
}

// zlib解压缩
static uint8_t* decompress(const uint8_t *data, size_t len, size_t origLen, size_t *outLen) {
    uint8_t *output = (uint8_t*)malloc(origLen + 1);
    if (!output) return nullptr;
    
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in = (Bytef*)data;
    strm.avail_in = len;
    strm.next_out = output;
    strm.avail_out = origLen;
    
    if (inflateInit(&strm) != Z_OK) {
        free(output);
        return nullptr;
    }
    
    int ret = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);
    
    if (ret != Z_STREAM_END) {
        free(output);
        return nullptr;
    }
    
    *outLen = strm.total_out;
    output[*outLen] = '\0';
    return output;
}

// ============================================================
// 公开API
// ============================================================

int vmp_is_encrypted(const uint8_t *data, size_t len) {
    if (len < sizeof(VmpHeader)) return 0;
    
    // 检查魔数 (0xEJ实际上是非法的，这里用0xE5代替)
    if (data[0] != 0xE5 || data[1] != 0x5C || 
        data[2] != 0x52 || data[3] != 0x59) {
        return 0;
    }
    
    return 1;
}

// 核心解密函数 - 放入VMP保护
VMP_PROTECT
char* vmp_decrypt_internal(const uint8_t *encrypted, size_t encLen, size_t *outLen) {
    VMP_BEGIN;
    
    if (encLen < sizeof(VmpHeader)) {
        return nullptr;
    }
    
    // 解析头部
    const VmpHeader *header = (const VmpHeader*)encrypted;
    
    // 验证魔数
    if (header->magic[0] != 0xE5 || header->magic[1] != 0x5C ||
        header->magic[2] != 0x52 || header->magic[3] != 0x59) {
        return nullptr;
    }
    
    // 验证版本
    if (header->version != VMP_VERSION) {
        return nullptr;
    }
    
    // 验证密钥哈希
    uint32_t keyHash = calc_key_hash(DEFAULT_KEY, KEY_LEN);
    uint32_t storedHash = (header->keyHash >> 24) | 
                          ((header->keyHash >> 8) & 0xFF00) |
                          ((header->keyHash << 8) & 0xFF0000) |
                          (header->keyHash << 24);
    
    if (storedHash != keyHash) {
        // 密钥不匹配
        return nullptr;
    }
    
    // 获取原始长度
    uint32_t origLen = (header->origLen >> 24) |
                       ((header->origLen >> 8) & 0xFF00) |
                       ((header->origLen << 8) & 0xFF0000) |
                       (header->origLen << 24);
    
    // 获取加密数据
    size_t dataLen = encLen - sizeof(VmpHeader);
    uint8_t *data = (uint8_t*)malloc(dataLen);
    if (!data) return nullptr;
    
    memcpy(data, encrypted + sizeof(VmpHeader), dataLen);
    
    // 根据标志位逆向解密
    uint8_t flags = header->flags;
    
    // 1. 反混淆
    if (flags & VMP_FLAG_SHUFFLE) {
        unshuffle(data, dataLen, DEFAULT_KEY, KEY_LEN);
    }
    
    // 2. XOR解密
    if (flags & VMP_FLAG_XOR) {
        xor_decrypt(data, dataLen, DEFAULT_KEY, KEY_LEN);
    }
    
    // 3. 解压缩
    char *result = nullptr;
    if (flags & VMP_FLAG_COMPRESSED) {
        size_t decompLen;
        result = (char*)decompress(data, dataLen, origLen, &decompLen);
        if (outLen) *outLen = decompLen;
    } else {
        result = (char*)malloc(dataLen + 1);
        if (result) {
            memcpy(result, data, dataLen);
            result[dataLen] = '\0';
            if (outLen) *outLen = dataLen;
        }
    }
    
    free(data);
    
    VMP_END;
    return result;
}

char* vmp_decrypt(const uint8_t *encrypted, size_t encLen, size_t *outLen) {
    return vmp_decrypt_internal(encrypted, encLen, outLen);
}
