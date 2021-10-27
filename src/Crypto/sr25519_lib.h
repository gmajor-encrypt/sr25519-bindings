#define FFI_LIB "src/Crypto/sr25519.so"


typedef long int ptrdiff_t;
typedef long unsigned int size_t;
typedef int wchar_t;
typedef long double max_align_t;

typedef struct { const char *p; ptrdiff_t n; } _GoString_;


typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef long unsigned int GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;



typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];


typedef _GoString_ GoString;

typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;
struct NewKeypairFromSeed_return {
 char* r0;
 char* r1;
};


extern struct NewKeypairFromSeed_return NewKeypairFromSeed(GoString hexSeed);

extern GoUint8 VerifySign(GoString publicKey, GoString msg, GoString sig);

extern char* Sign(GoString hexSeed, GoString msg);
