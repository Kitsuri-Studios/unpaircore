cmake_minimum_required(VERSION 3.22.1)

project(pairipcore)

add_compile_options(-fvisibility=hidden)
add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>)
add_library(${CMAKE_PROJECT_NAME} SHARED
        src/library.c
        src/mem.c
        src/proc.c
)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log
)
