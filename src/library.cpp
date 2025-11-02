//
// Created by mrjar on 10/10/2025.
//
#include "mem.h"
#include "memscan.h"
#include "inlinehook.h"
#include <vector>
#include <dlfcn.h>
#include <jni.h>

#define NOEXPORT __attribute__((visibility("hidden")))

struct Data
{
    const char *a1;
    int a2;
    int a3;
    void *a4;
    int a5;
    std::vector<void *> a6;
    int a7 = 0;
    double a8 = 0.0;
    double a9 = 0.0;
    double a10 = 0.0;
    double a11 = 0.0;
};

static void (*original_funcz)(void *a1, Data* scopedData, void* threadId);
NOEXPORT void hooked_funcz(void *a1, Data* scopedData, void* threadId) {

    scopedData->a1 = "Minecraft";
    scopedData->a2 = 0;
    scopedData->a3 = 0;
    scopedData->a5 = 0;
    scopedData->a7 = 0;

    scopedData->a4 = nullptr;
    scopedData->a6.clear();

    scopedData->a8 = 0.0;
    scopedData->a9 = 0.0;
    scopedData->a10 = 0.0;
    scopedData->a11 = 0.0;

    original_funcz(a1, scopedData, threadId);
}

extern "C" NOEXPORT void patch_libs() {
    void* dlhandle = dlopen("libmaesdk.so", RTLD_NOLOAD);
    if(!dlhandle) return;
    void *libmae_fun = dlsym(dlhandle,
        "_ZN9Microsoft12Applications6Events19TelemetrySystemBase5startEv");
    if(libmae_fun) {
#if defined(__x86_64__) || defined(__amd64__)
        unsigned char retop = 0xC3;
#elif defined(__i386__) || defined(__i686__) || defined (__x86__)
        unsigned char retop = 0xC3;
#elif defined(__aarch64__)
        uint32_t retop = 0xD65F03C0;
#elif defined(__arm__)
        uint32_t retop = 0xE1A0F00E;
#endif
        write_mem(libmae_fun, &retop, sizeof(retop));
    }
    dlclose(dlhandle);
#ifdef __aarch64__
    sigscan_handle *scanner = sigscan_setup(
        "?? ?? ?? D1 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9"
        " ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? 91 ?? ?? ?? D5 ?? ?? ?? F0"
        " F4 03 02 AA", "libminecraftpe.so", GPWN_SIGSCAN_XMEM);
    if(!scanner) return;
    void *funcz = get_sigscan_result(scanner);
    if(funcz != (void*) -1) {
        // hook function
        hook_addr(funcz, (void*) hooked_funcz,
            (void**) &original_funcz, GPWN_AARCH64_MICROHOOK);
    }
    sigscan_cleanup(scanner);
#endif
}

extern "C" jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    patch_libs();
    return JNI_VERSION_1_6;
}

extern "C" void ExecuteProgram() {
    return;
}
