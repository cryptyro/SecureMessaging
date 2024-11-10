#include "gfP.h"

// Elliptic curve parameters: y^2 = x^3 + ax + b over the finite field F(E92E40AD6F281C8A082AFDC49E1372659455BEC8CEEA043A614C835B7FE9EFF5)
const u64 a[9] = {0xe92e40, 0x15ade503, 0x122820ab, 0x1ee24f09, 0x17265945, 0xb7d919d, 0x1a810e98, 0xa641adb, 0x1fe9eff2};   // Curve parameter a
const u64 b[9] = {0, 0, 0, 0, 0, 0, 0, 0, 1};   // Curve parameter b
const u64 order[9] = {0xe92e4, 0x15ade503, 0x122820ab, 0x1ee24f09, 0x17265b6a, 0xfb615de, 0x188614a3, 0xb240987, 0x54ba426}; //This is (order of the ECgroup)-1, which we need for key_validation

// Elliptic Curve Point structure
typedef struct {
    u64 x[9];
    u64 y[9];
    u64 z[9];
} ECPoint;

// Function to convert projective form to affine form
void PtoA(const ECPoint P, ECPoint* A){
    u64 temp[9], zinv[9];
    square(P.z, temp); mod_inv(temp, zinv); mult(zinv, P.x, A->x);
    mult(P.z, temp, temp); mod_inv(temp, zinv); mult(zinv, P.y, A->y);
    for (u8 i = 0; i<8 ; i++) A->z[i] =0;
    A->z[8] = 1;
}

//Function to check if two integer(256bit) are equal (return 0 if true)
u64 are_equal(const u64* arr1, const u64* arr2) {
    u64 flag = 0;
    for (int i = 0; i < 9; i++) 
        flag += arr1[i] ^ arr2[i];
    return flag;
}

//Function to check if a point is negative of other(return 0 if true)
u64 are_negative(ECPoint P, ECPoint Q) {
    ECPoint A, B;
    PtoA(P, &A); PtoA(Q, &B);
    u64 temp[9] = {0};
    u64 flag = 0;
    mod_sub(m, Q.y, temp);
    flag = are_equal(A.x, B.x) + are_equal(A.y, temp) + are_equal(A.z, B.z);
    return flag;
}

//Point doubling (y 2 = x 3 − 3x + b, Jacobian coordinates)
void point_double(const ECPoint P, ECPoint* result){
    u64 t1[9], t2[9], t3[9];
    square(P.z, t1);
    mod_sub(P.x, t1, t2);
    add(P.x, t1, t1);
    mult(t2, t1, t2);
    add(t2, t2, t1); add(t1, t2, t2);
    add(P.y, P.y, result->y);
    mult(result->y, P.z, result->z);
    square(result->y, result->y);
    mult(result->y, P.x, t3);
    square(result->y, result->y);
    mod_inv(g, t1);
    mult(t1, result->y, result->y);
    square(t2, result->x);
    add(t3, t3, t1);
    mod_sub(result->x, t1, result->x);
    mod_sub(t3, result->x, t1);
    mult(t1, t2, t1);
    mod_sub(t1, result->y, result->y);
}

void point_add(const ECPoint P, const ECPoint Q, ECPoint* result){
    u64 t1[9], t2[9], t3[9], t4[9];
    square(P.z, t1);
    mult(P.z, t1, t2);
    mult(Q.x, t1, t1);
    mult(Q.y, t2, t2);
    mod_sub(t1, P.x, t1);
    mod_sub(t2, P.y, t2);
    mult(P.z, t1, result->z);
    square(t1, t3);
    mult(t3, t1, t4);
    mult(t3, P.x, t3);
    add(t3, t3, t1);
    square(t2, result->x);
    mod_sub(result->x, t1, result->x);
    mod_sub(result->x, t4, result->x);
    mod_sub(t3, result->x, t3);
    mult(t3, t2, t3);
    mult(t4, P.y, t4);
    mod_sub(t3, t4, result->y);
}

void point_mult(ECPoint P, const u64* a, ECPoint** result){
    u64 temp[18], result_copy[9];
    *result = &P;
    ECPoint inter[2];
    for (int i = 254; i>=0; i--) {
        u8 p = i%29;
		u8 sb = (a[8- (i/29)] >> p) & 0x1;
		point_double(**result, inter);
        point_add(inter[0], P, inter+1);
        *result = inter+sb ;
    }
}

// ACCEPT or REJECT A as an affine point on Wa,b of order n.
void key_validation(ECPoint A){
    u64 temp[9], temp1[9];
    if (sub(A.x, m, temp) || sub(A.y, m, temp)) {
        perror("The point co-ordinates don't belong to the field F(p) \n");
        exit(EXIT_FAILURE);
    }
    square(A.x, temp); mult(A.x, temp, temp);
    mult(a, A.x, temp1);
    add(temp1, temp, temp);
    add(temp, b, temp);
    square(A.y, temp1);
    if (are_equal(temp, temp1)){
        perror("It is not a point on the curve \n");
        exit(EXIT_FAILURE);
    }
    // In particular, this step won't be necessary for our curve
    ECPoint* B = NULL;
    point_mult(A, order, &B);
    if (are_negative(A, *B)){
        perror("The point does not have the desired order \n");
        exit(EXIT_FAILURE);
    }
}