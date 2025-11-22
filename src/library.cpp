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

static Data* defaultData = new Data{};
static void (*original_funcz)(void *a1, Data* scopedData, void* threadId);

NOEXPORT void hooked_funcz(void *a1, Data* scopedData, void* threadId) {
    defaultData->a1 = "Minecraft";
    defaultData->a2 = 0;
    defaultData->a3 = 0;
    defaultData->a5 = 0;
    defaultData->a7 = 0;
    defaultData->a4 = nullptr;
    defaultData->a6.clear();
    defaultData->a8 = 0.0;
    defaultData->a9 = 0.0;
    defaultData->a10 = 0.0;
    defaultData->a11 = 0.0;
    original_funcz(a1, defaultData, threadId);
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
        "?? ?? ?? 96 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? 94",
        "libminecraftpe.so", GPWN_SIGSCAN_XMEM);


    if(!scanner) {
        scanner = sigscan_setup(
            "?? ?? ?? 97 ?? ?? ?? F9 ?? ?? ?? BD ?? ?? ?? 94 E0 03 00 91",
            "libminecraftpe.so", GPWN_SIGSCAN_XMEM);
    }

    if(!scanner) return;

    void *code_addr = get_sigscan_result(scanner);
    if(code_addr != (void*) -1) {

        const uint32_t bl_insn = *reinterpret_cast<const uint32_t*>(code_addr);


        if ((bl_insn & 0xFC000000) == 0x94000000) {
            const uint32_t imm26 = bl_insn & 0x03FFFFFF;
            int32_t signed_imm26 = static_cast<int32_t>(imm26);


            if (signed_imm26 & (1 << 25)) {
                signed_imm26 -= (1 << 26);
            }

            uintptr_t funcz = reinterpret_cast<uintptr_t>(code_addr) + (signed_imm26 << 2);

            hook_addr((void*)funcz, (void*) hooked_funcz,
                (void**) &original_funcz, GPWN_AARCH64_MICROHOOK);
        }
    }
    sigscan_cleanup(scanner);
#endif
}

extern "C" jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    patch_libs();
    return JNI_VERSION_1_6;
}

extern "C" void ExecuteProgram() {
}