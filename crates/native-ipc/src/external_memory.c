#include <stddef.h>

#if defined(_WIN32)
#define NIPC_HIDDEN
#else
#define NIPC_HIDDEN __attribute__((visibility("hidden")))
#endif

NIPC_HIDDEN void native_ipc_0_4_0_vnext_v1_external_read(
    const volatile unsigned char *source,
    unsigned char *destination,
    size_t length
) {
    for (size_t index = 0; index < length; ++index) {
        destination[index] = source[index];
    }
}

NIPC_HIDDEN void native_ipc_0_4_0_vnext_v1_external_write(
    volatile unsigned char *destination,
    const unsigned char *source,
    size_t length
) {
    for (size_t index = 0; index < length; ++index) {
        destination[index] = source[index];
    }
}

NIPC_HIDDEN void native_ipc_0_4_0_vnext_v1_external_fill(
    volatile unsigned char *destination,
    unsigned char value,
    size_t length
) {
    for (size_t index = 0; index < length; ++index) {
        destination[index] = value;
    }
}

NIPC_HIDDEN void native_ipc_0_4_0_vnext_v1_external_touch_read(
    const volatile unsigned char *address
) {
    (void)*address;
}

NIPC_HIDDEN void native_ipc_0_4_0_vnext_v1_external_touch_write(
    volatile unsigned char *address
) {
    unsigned char value = *address;
    *address = value;
}
