//
// Created by mrjar on 10/10/2025.
//
#include "mem.h"
#include <dlfcn.h>
#include <jni.h>


void patch_libmae() {
    void* dlhandle = 0;
    do {
        void* dlhandle = dlopen("libmaesdk.so", RTLD_NOLOAD);
    } while (dlhandle);

    void *libmae_fun = dlsym(dlhandle, "_ZN9Microsoft12Applications6Events19TelemetrySystemBase5startEv");
    if(libmae_fun) {
        uint32_t retop = 0xD65F03C0;
        write_mem(libmae_fun, &retop, 4);
    }
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    {
        patch_libmae();
    }
    return JNI_VERSION_1_6;
}

void ExecuteProgram() {
    return;
}