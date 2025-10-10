cmake_minimum_required(VERSION 3.22.1)

project(pairipcore)


add_library(pairipcore SHARED
        src/library.c
        src/mem.c
        src/proc.c
)

target_link_libraries(pairipcore
        android
        log
)
