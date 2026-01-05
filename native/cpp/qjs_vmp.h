#ifndef QJS_VMP_H
#define QJS_VMP_H

#include <cstdint>
#include <cstddef>

// 魔数标识
#define VMP_MAGIC_0 0xE5
#define VMP_MAGIC_1 0x5C
#define VMP_MAGIC_2 0x52
#define VMP_MAGIC_3 0x59

// 版本号
#define VMP_VERSION 0x01

// 加密标志
#define VMP_FLAG_COMPRESSED 0x01
#define VMP_FLAG_XOR        0x02
#define VMP_FLAG_SHUFFLE    0x04

// 数据包头结构
#pragma pack(push, 1)
struct VmpHeader {
    uint8_t magic[4];
    uint8_t version;
    uint8_t flags;
    uint32_t keyHash;
    uint32_t origLen;
};
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 检查是否是加密的JS数据
 * @param data 数据指针
 * @param len 数据长度
 * @return 1=是加密数据, 0=普通文本
 */
int vmp_is_encrypted(const uint8_t *data, size_t len);

/**
 * VMP解密JS代码
 * @param encrypted 加密数据
 * @param encLen 加密数据长度
 * @param outLen 输出解密后长度
 * @return 解密后的JS代码(需要free), NULL表示失败
 */
char* vmp_decrypt(const uint8_t *encrypted, size_t encLen, size_t *outLen);

/**
 * 解密并执行JS (内部使用，放入VMP保护区)
 */
char* vmp_decrypt_internal(const uint8_t *encrypted, size_t encLen, size_t *outLen);

#ifdef __cplusplus
}
#endif

#endif // QJS_VMP_H
