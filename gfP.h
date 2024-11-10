#include<stdio.h>
#include<stdlib.h>
#include <string.h>

typedef long long unsigned int u64;
typedef unsigned int u32;
typedef unsigned char u8;

//The chosen prime "0xE92E40AD6F281C8A082AFDC49E1372659455BEC8CEEA043A614C835B7FE9EFF5"
const u64 m[9]		= {0xe92e40, 0x15ade503, 0x122820ab, 0x1ee24f09, 0x17265945, 0xb7d919d, 0x1a810e98, 0xa641adb, 0x1fe9eff5};
const u64 mu[10]	= {0x23, 0x435b5a4, 0x1777172, 0x696b212, 0x12508c04, 0x115a5eea, 0x1812b7cb, 0x171d776b, 0x1d398149, 0x1ae00018};
const u64 g[9]		= {0, 0, 0, 0, 0, 0, 0, 0, 2};

const u64 m_2[9]	= {0xe92e40, 0x15ade503, 0x122820ab, 0x1ee24f09, 0x17265945, 0xb7d919d, 0x1a810e98, 0xa641adb, 0x1fe9eff3}; // (m-2) {Required for mod_inv}

//Multiplication of 10 word(29bit) long integers
void mult10(const u64* a, const u64* b, u64* p){
	p[18] = a[9]*b[9];
	p[17] = a[8]*b[9] + a[9]*b[8];
	p[16] = a[7]*b[9] + a[8]*b[8] + a[9]*b[7];
	p[15] = a[6]*b[9] + a[7]*b[8] + a[8]*b[7] + a[9]*b[6];
	p[14] = a[5]*b[9] + a[6]*b[8] + a[7]*b[7] + a[8]*b[6] + a[9]*b[5];
	p[13] = a[4]*b[9] + a[5]*b[8] + a[6]*b[7] + a[7]*b[6] + a[8]*b[5] + a[9]*b[4];
	p[12] = a[3]*b[9] + a[4]*b[8] + a[5]*b[7] + a[6]*b[6] + a[7]*b[5] + a[8]*b[4] + a[9]*b[3];
	p[11] = a[2]*b[9] + a[3]*b[8] + a[4]*b[7] + a[5]*b[6] + a[6]*b[5] + a[7]*b[4] + a[8]*b[3] + a[9]*b[2];
	p[10] = a[1]*b[9] + a[2]*b[8] + a[3]*b[7] + a[4]*b[6] + a[5]*b[5] + a[6]*b[4] + a[7]*b[3] + a[8]*b[2] + a[9]*b[1];
	p[9]  = a[0]*b[9] + a[1]*b[8] + a[2]*b[7] + a[3]*b[6] + a[4]*b[5] + a[5]*b[4] + a[6]*b[3] + a[7]*b[2] + a[8]*b[1] + a[9]*b[0];
	p[8]  = a[0]*b[8] + a[1]*b[7] + a[2]*b[6] + a[3]*b[5] + a[4]*b[4] + a[5]*b[3] + a[6]*b[2] + a[7]*b[1] + a[8]*b[0];
	p[7]  = a[0]*b[7] + a[1]*b[6] + a[2]*b[5] + a[3]*b[4] + a[4]*b[3] + a[5]*b[2] + a[6]*b[1] + a[7]*b[0];
	p[6]  = a[0]*b[6] + a[1]*b[5] + a[2]*b[4] + a[3]*b[3] + a[4]*b[2] + a[5]*b[1] + a[6]*b[0];
	p[5]  = a[0]*b[5] + a[1]*b[4] + a[2]*b[3] + a[3]*b[2] + a[4]*b[1] + a[5]*b[0];
	p[4]  = a[0]*b[4] + a[1]*b[3] + a[2]*b[2] + a[3]*b[1] + a[4]*b[0];
	p[3]  = a[0]*b[3] + a[1]*b[2] + a[2]*b[1] + a[3]*b[0];
	p[2]  = a[0]*b[2] + a[1]*b[1] + a[2]*b[0];
	p[1]  = a[0]*b[1] + a[1]*b[0];
	p[0]  = a[0]*b[0];
	
	u64 carry = 0;
	for(int i=18; i>=0; i--){
		p[i] += carry;
		carry = p[i] >> 29;
		p[i] &= 0x1fffffff;
	}
}

//Multiplication of 9 word(29bit) long integers
void mult9(const u64* a, const u64* b, u64* p){
	p[17] = a[8]*b[8];
	p[16] = a[7]*b[8] + a[8]*b[7];
	p[15] = a[6]*b[8] + a[7]*b[7] + a[8]*b[6];
	p[14] = a[5]*b[8] + a[6]*b[7] + a[7]*b[6] + a[8]*b[5];
	p[13] = a[4]*b[8] + a[5]*b[7] + a[6]*b[6] + a[7]*b[5] + a[8]*b[4];
	p[12] = a[3]*b[8] + a[4]*b[7] + a[5]*b[6] + a[6]*b[5] + a[7]*b[4] + a[8]*b[3];
	p[11] = a[2]*b[8] + a[3]*b[7] + a[4]*b[6] + a[5]*b[5] + a[6]*b[4] + a[7]*b[3] + a[8]*b[2];
	p[10] = a[1]*b[8] + a[2]*b[7] + a[3]*b[6] + a[4]*b[5] + a[5]*b[4] + a[6]*b[3] + a[7]*b[2] + a[8]*b[1];
	p[9]  = a[0]*b[8] + a[1]*b[7] + a[2]*b[6] + a[3]*b[5] + a[4]*b[4] + a[5]*b[3] + a[6]*b[2] + a[7]*b[1] + a[8]*b[0];
	p[8]  = a[0]*b[7] + a[1]*b[6] + a[2]*b[5] + a[3]*b[4] + a[4]*b[3] + a[5]*b[2] + a[6]*b[1] + a[7]*b[0];
	p[7]  = a[0]*b[6] + a[1]*b[5] + a[2]*b[4] + a[3]*b[3] + a[4]*b[2] + a[5]*b[1] + a[6]*b[0];
	p[6]  = a[0]*b[5] + a[1]*b[4] + a[2]*b[3] + a[3]*b[2] + a[4]*b[1] + a[5]*b[0];
	p[5]  = a[0]*b[4] + a[1]*b[3] + a[2]*b[2] + a[3]*b[1] + a[4]*b[0];
	p[4]  = a[0]*b[3] + a[1]*b[2] + a[2]*b[1] + a[3]*b[0];
	p[3]  = a[0]*b[2] + a[1]*b[1] + a[2]*b[0];
	p[2]  = a[0]*b[1] + a[1]*b[0];
	p[1]  = a[0]*b[0];
	p[0]  = 0;
	
	u64 carry = 0;
	for(int i=17; i>=0; i--){
		p[i] += carry;
		carry = p[i] >> 29;
		p[i] &= 0x1fffffff;
	}
}

//Subtraction using 2's complement
u8 sub(const u64* a, const u64* b, u64* result){
	u8 carry = 1;
	for (int i=8; i>=0; i--){
		result[i] = a[i] + (b[i]^0x1fffffff) + carry;
		carry = result[i] >> 29;
		result[i] &= 0x1fffffff;
	}
	return carry;
}

//Addition modulo "m"
void add(const u64* a, const u64* b, u64* result){
	u8 carry = 0;
	for (int i=8; i>=0; i--){
		result[i] = a[i] + b[i] + carry;
		carry = result[i] >> 29;
		result[i] &= 0x1fffffff;
	}
	u64 temp[9] = {0};
	u64 mask = -sub(result,m,temp);
	for (int j = 0; j < 9; j++)
        result[j] = (temp[j] & mask) | (result[j] & ~mask);
}

//Subtraction modulo "m"
void mod_sub(const u64* a, const u64* b, u64* result){
	u64 temp[9];
	u64 mask = -sub(a,b,result);
	u8 carry = 0;
	for (int i=8; i>=0; i--){
		temp[i] = result[i] + m[i] + carry;
		carry = temp[i] >> 29;
		temp[i] &= 0x1fffffff;
	}
	for (u8 i = 0; i < 9; i++)
        result[i] = (temp[i] & ~mask) | (result[i] & mask);
}

// Barrett Modular Reduction
void barrett(const u64* a, u64* result){
	u64 temp[9],q2[19],q3[18],r[9];
    u64 mask;

	mult10(a, mu, q2);
	mult9(q2, m, q3);
	sub(a + 9, q3 + 9, result);

    // Perform the first subtraction unconditionally and calculate the mask
    mask = -sub(result, m, temp);
    for (u8 i = 0; i < 9; i++)
        result[i] = (temp[i] & mask) | (result[i] & ~mask); 

	//Repeat to ensure reduction
    mask = -sub(result, m, temp);
    for (u8 i = 0; i < 9; i++)
    	result[i] = (temp[i] & mask) | (result[i] & ~mask);
}

//Square and reduction
void square(const u64* a, u64* result){
	u64 p[18];
	p[17] = a[8]*a[8];
	p[16] = (a[7]*a[8]) << 1;
	p[15] = ((a[6]*a[8]) << 1) + a[7]*a[7];
	p[14] = ((a[5]*a[8]) << 1) + ((a[6]*a[7]) << 1);
	p[13] = ((a[4]*a[8]) << 1) + ((a[5]*a[7]) << 1) + a[6]*a[6];
	p[12] = ((a[3]*a[8]) << 1) + ((a[4]*a[7]) << 1) + ((a[5]*a[6]) << 1);
	p[11] = ((a[2]*a[8]) << 1) + ((a[3]*a[7]) << 1) + ((a[4]*a[6]) << 1) + a[5]*a[5];
	p[10] = ((a[1]*a[8]) << 1) + ((a[2]*a[7]) << 1) + ((a[3]*a[6]) << 1) + ((a[4]*a[5]) << 1);
	p[9]  = ((a[0]*a[8]) << 1) + ((a[1]*a[7]) << 1) + ((a[2]*a[6]) << 1) + ((a[3]*a[5]) << 1) + a[4]*a[4];
	p[8]  = ((a[0]*a[7]) << 1) + ((a[1]*a[6]) << 1) + ((a[2]*a[5]) << 1) + ((a[3]*a[4]) << 1);
	p[7]  = ((a[0]*a[6]) << 1) + ((a[1]*a[5]) << 1) + ((a[2]*a[4]) << 1) + a[3]*a[3];
	p[6]  = ((a[0]*a[5]) << 1) + ((a[1]*a[4]) << 1) + ((a[2]*a[3]) << 1);
	p[5]  = ((a[0]*a[4]) << 1) + ((a[1]*a[3]) << 1) + a[2]*a[2];
	p[4]  = ((a[0]*a[3]) << 1) + ((a[1]*a[2]) << 1);
	p[3]  = ((a[0]*a[2]) << 1) + a[1]*a[1];
	p[2]  = ((a[0]*a[1]) << 1);
	p[1]  = a[0]*a[0];
	p[0]  = 0;
	
	u64 carry = 0;
	for(int i=17; i>=0; i--){
		p[i] += carry;
		carry = p[i] >> 29;
		p[i] &= 0x1fffffff;
	}
	barrett(p,result);
}

// Multiplication along with reduction
void mult(const u64* inputA, const u64* inputB, u64* result){
    u64 temp[18];
    mult9(inputA, inputB, temp);
    barrett(temp,result);
}

// Modular Exponentiation (Right to left)
void modexp_rtl(const u64* b, const u64* exp, u64* result){
    u64 temp[18], result_copy[9], base[9];
	memset(result, 0, 72); memcpy(base, b, 72);
	result[8] = 1;
    // Fixed maximum number of iterations (assume exp has a fixed bit size, 256 bits)
    for (int i = 0; i < 256; i++) {
        // Prepare to check the corresponding significant bit of exp
        u8 p = i%29;
		u8 sb = (exp[8- (i/29)] >> p) & 0x1;
        u64 mask = -sb; // mask is 0xFFFFFFFFFFFFFFFF if lsb is 1, otherwise 0x0
		
        // Perform multiplication and reduction unconditionally
        mult9(result, base, temp);
        barrett(temp, result_copy);

        // Apply the result of multiplication conditionally based on the least significant bit of exp
        for (int j = 0; j < 9; j++)
            result[j] = (result_copy[j] & mask) | (result[j] & ~mask); // Update result conditionally

        // Perform the squaring and modular reduction unconditionally
        mult9(base, base, temp);
        barrett(temp, base);
    }
}

//Modular Exponentiation (Left to right)
void modexp_ltr(const u64* base, const u64* exp, u64* result){
    u64 temp[18], result_copy[9];
	memset(result, 0, 72);
	result[8] = 1;
    for (int i = 255; i>=0; i--) {
        u8 p = i%29;
		u8 sb = (exp[8- (i/29)] >> p) & 0x1;
        u64 mask = -sb;
		mult9(result, result, temp);
        barrett(temp, result);
        mult9(result, base, temp);
        barrett(temp, result_copy);
        for (int j = 0; j < 9; j++)
            result[j] = (result_copy[j] & mask) | (result[j] & ~mask);
    }
}

//Inverse in F_m
void mod_inv(const u64* a, u64* result){
	modexp_ltr(a,m_2,result);
}