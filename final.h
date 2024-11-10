//E92E40AD6F281C8A082AFDC49E1372659455BEC8CEEA043A614C835B7FE9EFF5
#include"ecc.h"
#include "sha256.h"
#include "gcm.h"
#include <openssl/rand.h>  // For RAND_bytes

ECPoint Base;

// Function to convert a hexadecimal string to an array of u32
u64 hextoint(char hex) {
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    } else if (hex >= 'a' && hex <= 'f') {
        return hex - 'a' + 10;
    } else if (hex >= 'A' && hex <= 'F') {
        return hex - 'A' + 10;
    }
	perror("Invalid hex char");
	exit(EXIT_FAILURE);
}

void parse_to_int(char* hex, u64* bignum){
	bignum[0] =   hextoint(hex[5])      ^ hextoint(hex[4])<<4
				^ hextoint(hex[3])<<8   ^ hextoint(hex[2])<<12
				^ hextoint(hex[1])<<16  ^ hextoint(hex[0])<<20;
    bignum[1] =   hextoint(hex[13])>>3  ^ hextoint(hex[12])<<1
			    ^ hextoint(hex[11])<<5  ^ hextoint(hex[10])<<9
				^ hextoint(hex[9])<<13  ^ hextoint(hex[8])<<17
				^ hextoint(hex[7])<<21  ^ (hextoint(hex[6])& 0xf)<<25;
    bignum[2] =   hextoint(hex[20])>>2  ^ hextoint(hex[19])<<2
			    ^ hextoint(hex[18])<<6  ^ hextoint(hex[17])<<10
				^ hextoint(hex[16])<<14 ^ hextoint(hex[15])<<18
				^ hextoint(hex[14])<<22 ^ (hextoint(hex[13])& 0x7)<<26;
    bignum[3] =   hextoint(hex[27])>>1  ^ hextoint(hex[26])<<3
			    ^ hextoint(hex[25])<<7  ^ hextoint(hex[24])<<11
				^ hextoint(hex[23])<<15 ^ hextoint(hex[22])<<19
				^ hextoint(hex[21])<<23 ^ (hextoint(hex[20])& 0x3)<<27;
    bignum[4] =   hextoint(hex[34])     ^ hextoint(hex[33])<<4
			    ^ hextoint(hex[32])<<8  ^ hextoint(hex[31])<<12
				^ hextoint(hex[30])<<16 ^ hextoint(hex[29])<<20
				^ hextoint(hex[28])<<24 ^ (hextoint(hex[27])& 0x1)<<28;
    bignum[5] =   hextoint(hex[42])>>3  ^ hextoint(hex[41])<<1
			    ^ hextoint(hex[40])<<5  ^ hextoint(hex[39])<<9
				^ hextoint(hex[38])<<13 ^ hextoint(hex[37])<<17
				^ hextoint(hex[36])<<21 ^ (hextoint(hex[35])& 0xf)<<25;
    bignum[6] =   hextoint(hex[49])>>2  ^ hextoint(hex[48])<<2
			    ^ hextoint(hex[47])<<6  ^ hextoint(hex[46])<<10
				^ hextoint(hex[45])<<14 ^ hextoint(hex[44])<<18
				^ hextoint(hex[43])<<22 ^ (hextoint(hex[42])& 0x7)<<26;
    bignum[7] =   hextoint(hex[56])>>1  ^ hextoint(hex[55])<<3
			    ^ hextoint(hex[54])<<7  ^ hextoint(hex[53])<<11
				^ hextoint(hex[52])<<15 ^ hextoint(hex[51])<<19
				^ hextoint(hex[50])<<23 ^ (hextoint(hex[49])& 0x3)<<27;
    bignum[8] =   hextoint(hex[63])     ^ hextoint(hex[62])<<4
			    ^ hextoint(hex[61])<<8  ^ hextoint(hex[60])<<12
				^ hextoint(hex[59])<<16 ^ hextoint(hex[58])<<20
				^ hextoint(hex[57])<<24 ^ (hextoint(hex[56])& 0x1)<<28;
}


void parse_to_hex(u64* bignum, char* hex){
    u64 temp[4];
    temp[0] = bignum[2]>>18 ^ bignum[1]<<11 ^ bignum[0]<<40;
	temp[1] = bignum[4]>>12 ^ bignum[3]<<17 ^ bignum[2]<<46;
	temp[2] = bignum[6]>>6  ^ bignum[5]<<23 ^ bignum[4]<<52;
	temp[3] = bignum[8]     ^ bignum[7]<<29 ^ bignum[6]<<58;
	for (u8 i=0; i<4; i++)
		sprintf(hex + (i * 16), "%016llx", temp[i]);
	hex[64] = '\0';
}

void print_point(ECPoint A){
    char pub_x[65], pub_y[65];
    parse_to_hex(A.x ,pub_x);
    parse_to_hex(A.y ,pub_y);
    pub_x[64] =pub_y[64] = '\0';
    printf("\nPOINT COORDINATES: %s\n\t\t   %s\n", pub_x, pub_y);
}

void rand_str(char* output) {
    // Length in bytes (since 1 byte = 2 hex characters, divide by 2)
    unsigned char random_bytes[32];

    // Generate random bytes using OpenSSL RAND_bytes
    if (RAND_bytes(random_bytes, 32) != 1) {
        fprintf(stderr, "Error generating random bytes\n");
        exit(EXIT_FAILURE);
    }
    //Make the integer less than the prime
    random_bytes[0] %= 105;
    random_bytes[0] |= 0x80;

    // Convert each byte to its hex representation
    for (size_t i = 0; i < 32; i++) 
        sprintf(output + (i * 2), "%02x", random_bytes[i]);

    output[64] = '\0';    // Null-terminate the string
}


void pub_point_generation(char* s_key, char* p_point){
    for(u8 i=0; i<9; i++) {
        Base.x[i] = 0;
        Base.y[i] = 0;
        Base.z[i] = 0;
    }
    Base.y[8] = Base.z[8] = 1;
    
    u64 scalar[9] = {0};
    rand_str(s_key);
    parse_to_int(s_key, scalar);

    ECPoint result;
    ECPoint* result1 = NULL;
    point_mult(Base, scalar, &result1);
    PtoA(*result1, &result);
    parse_to_hex(result.x ,p_point);
    parse_to_hex(result.y ,p_point + 64);
    p_point[128] = '\0';

    printf("SECRET KEY: %s\n",s_key);
    print_point(result);
}

void shared_key_generation(char* s_key, char* p_key, u8* aes_key){
    u64 scalar[9] = {0};
    parse_to_int(s_key, scalar);

    ECPoint pub_point, shared_affine, *shared_point;
    parse_to_int(p_key, pub_point.x);
    parse_to_int(p_key+64, pub_point.y);
    for (int i=0; i<8; i++) pub_point.z[i] = 0;
    pub_point.z[8] = 1;

    point_mult(pub_point, scalar, &shared_point);
    char shared_secret[129];
    PtoA(*shared_point, &shared_affine);
    parse_to_hex(shared_affine.x ,shared_secret);
    parse_to_hex(shared_affine.y ,shared_secret + 64);
    print_point(shared_affine);
    
    sha256((u8 *)shared_secret, strlen(shared_secret), aes_key);
    printf("SESSION KEY: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", aes_key[i]);
    printf("\n");
}