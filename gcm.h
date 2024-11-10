#include <wmmintrin.h> // For AES-NI instructions
#include <emmintrin.h>
#include <smmintrin.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// typedef long long unsigned int u64;
// typedef unsigned int u32;
// typedef unsigned char u8;

__m128i AES_128_ASSIST (__m128i temp1, __m128i temp2)
{
__m128i temp3;
temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
temp3 = _mm_slli_si128 (temp1, 0x4);
temp1 = _mm_xor_si128 (temp1, temp3);
temp3 = _mm_slli_si128 (temp3, 0x4);
temp1 = _mm_xor_si128 (temp1, temp3);
temp3 = _mm_slli_si128 (temp3, 0x4);
temp1 = _mm_xor_si128 (temp1, temp3);
temp1 = _mm_xor_si128 (temp1, temp2);
return temp1;
}
void AES_128_Key_Expansion (u8 *userkey,
u8 *key)
{
    __m128i temp1, temp2;
    __m128i *Key_Schedule = (__m128i*)key;
    temp1 = _mm_loadu_si128((__m128i*)userkey);
    Key_Schedule[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[10] = temp1;
}

// Perform AES encryption using AES-NI
__m128i encrypt(__m128i input, u8* ExpandedKey) {
    __m128i tmp = input;
    tmp = _mm_xor_si128 (tmp,((__m128i*)ExpandedKey)[0]);
    
    for(int j=1; j < 10; j++)
        tmp = _mm_aesenc_si128 (tmp,((__m128i*)ExpandedKey)[j]);
    
    tmp = _mm_aesenclast_si128 (tmp,((__m128i*)ExpandedKey)[10]);
    return tmp;
}


// Perform AES-CTR encryption (encrypting plaintext block with counter and AES)
void aes_ctr_encrypt(u8 *expkey, u8 *counter, u8 *plaintext, u8 *ciphertext, u64 length) {
    __m128i countr = _mm_loadu_si128((__m128i *)counter);
    __m128i temp, pt_block;
    
    u64 i;
    for (i = 0; i + 16 <= length; i += 16) {
        temp = encrypt(countr, expkey);
        pt_block = _mm_loadu_si128((__m128i *)(plaintext + i));
        temp = _mm_xor_si128(temp, pt_block);
        _mm_storeu_si128((__m128i *)(ciphertext + i), temp);
        countr = _mm_add_epi64(countr, _mm_set_epi64x(0, 1));
    }
    
    // Handle the final block if it is less than 16 bytes
    if (i < length) {
        u8 buffer[16] = {0};
        u64 remaining_bytes = length - i;
        temp = encrypt(countr, expkey);
        memcpy(buffer, plaintext + i, remaining_bytes);
        pt_block = _mm_loadu_si128((__m128i *)buffer);
        temp = _mm_xor_si128(temp, pt_block);
        memcpy(ciphertext + i, &temp, remaining_bytes);
    }
}


// Galois field multiplication (GF(2^128)) using AES-NI
void gfmul (__m128i a, __m128i b, __m128i *res){
    __m128i tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);
    tmp7 = _mm_srli_epi32(tmp3, 31);
    tmp8 = _mm_srli_epi32(tmp6, 31);
    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);
    tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);
    tmp7 = _mm_slli_epi32(tmp3, 31);
    tmp8 = _mm_slli_epi32(tmp3, 30);
    tmp9 = _mm_slli_epi32(tmp3, 25);
    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);
    tmp8 = _mm_srli_si128(tmp7, 4);
    tmp7 = _mm_slli_si128(tmp7, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp7);
    tmp2 = _mm_srli_epi32(tmp3, 1);
    tmp4 = _mm_srli_epi32(tmp3, 2);
    tmp5 = _mm_srli_epi32(tmp3, 7);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp8);
    tmp3 = _mm_xor_si128(tmp3, tmp2);
    tmp6 = _mm_xor_si128(tmp6, tmp3);
    *res = tmp6;
}

// Perform GHASH (Galois hash) for GCM mode
void ghash(__m128i H, u8 *input, u64 length, u8 *output) {
    __m128i result = _mm_setzero_si128();

    for (u64 i = 0; i < length; i += 16) {
        __m128i block = _mm_loadu_si128((__m128i *)&input[i]);
        result = _mm_xor_si128(result, block);
        gfmul(result, H, &result);
    }

    _mm_storeu_si128((__m128i *)output, result);
}

// Perform AES-GCM encryption
char* aes_gcm_encrypt(u8 *expkey, u8 *counter, u8 *plaintext, u64 length, u8 *aad, u64 aad_len) {
    u8 tag[16] = {0};
    __m128i H;
    __m128i hash_subkey = _mm_setzero_si128();;

    // 1. Generate hash subkey H = AES_k(0^128)
    H = encrypt(hash_subkey, expkey);

    // 2. Encrypt plaintext using AES-CTR mode
    u64 len = (((length - 1)/16)+1)*16;
    u8* ciphertext = malloc(length * sizeof(u8));
    aes_ctr_encrypt(expkey, counter, plaintext, ciphertext, length);

    // 3. Compute GHASH(AAD || ciphertext || lengths)
    u64 a_len = (((aad_len - 1)/16)+1)*16;
    u64 ghash_input_len = a_len + len + 16 + 16;
    u8 *ghash_input = malloc(ghash_input_len);
    memset(ghash_input, 0, ghash_input_len);
    
    // Copy AAD to the beginning of the GHASH input
    memcpy(ghash_input, aad, aad_len);

    // Copy ciphertext after AAD in the GHASH input
    memcpy(ghash_input + a_len, ciphertext, length);

    // Append lengths (in bits) at the end: len(AAD in bits) || len(ciphertext in bits)
    u64 aad_bits = aad_len * 8;
    u64 ciphertext_bits = length * 8;
    
    // Reading each byte and shifting it into the 64-bit integer
    for (int i = 0; i < 8 ; i++){
        ghash_input[i+len+a_len] = aad_bits >> (8 * (7-i));
        ghash_input[i+len+a_len+8] = ciphertext_bits >> (8 * (7-i));
    }

    // 4. Compute GHASH(AAD || ciphertext || lengths)
    ghash(H, ghash_input, ghash_input_len-16, tag);

    // 5. Append the tag to the ghash input
    memcpy(ghash_input+ ghash_input_len - 16, tag, 16);

    char* hexStr = (char*)malloc(ghash_input_len* 2 + 1);
    memset(hexStr, 0, ghash_input_len* 2 + 1);
    
    for (size_t i = 0; i < ghash_input_len; i++)
        sprintf(&hexStr[i * 2], "%02X", ghash_input[i]);
    hexStr[ghash_input_len * 2] = '\0'; // Null-terminate the string
    
    // Clean up allocated memory
    free(ciphertext);
    free(ghash_input);
    // Authentication Tag is now in 'tag'
    return hexStr;
}

u8* aes_gcm_verify_and_decrypt(u8 *expkey, u8 *counter, char *input) {
    __m128i H;
    __m128i hash_subkey = _mm_setzero_si128();
    u8 computed_tag[16], tag[16];
    u64 len=0, a_len=0;
    u64 length = strlen(input)/2 - 16;
    // 1. Generate hash subkey H = AES_k(0^128)
    H = encrypt(hash_subkey, expkey);

    u8* ghash_input = (u8*)malloc(length + 16);
    for (int i = 0; i < length+16; i++)
        sscanf(&input[i * 2], "%2hhx", &ghash_input[i]);

    // Extract the tag
    memcpy( tag, ghash_input + length, 16);

    // Reading each byte and shifting it into the 64-bit integer
    for (int i = 0; i < 8 ; i++){
        a_len ^= (u64)ghash_input[i+length-16] << (8 * (7-i));
        len ^= (u64)ghash_input[i+length-8] << (8 * (7-i));
    }

    // 3. Compute GHASH(AAD || ciphertext || lengths)
    ghash(H, ghash_input, length, computed_tag);  // Compute the tag

    // 4. Verify the provided tag with the computed tag
    if (memcmp(computed_tag, tag, 16) != 0) {
        perror("couldn't validate");
        exit(EXIT_FAILURE);
    }

    // 5. If tag is valid, decrypt the ciphertext using AES-CTR mode
    u8* plaintext = malloc((len+a_len)/8 + 1);
    u64 ad_len = ((a_len/8 - 1)/16 + 1)*16;
    memcpy(plaintext, ghash_input, a_len/8);
    aes_ctr_encrypt(expkey, counter, ghash_input+ad_len, plaintext + a_len/8, len/8);
    plaintext[(len+a_len)/8] = 0;
    free(ghash_input);
    return plaintext;
}
