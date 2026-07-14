include(FetchContent)

FetchContent_Declare(
    cmocka
    GIT_REPOSITORY https://git.cryptomilk.org/projects/cmocka.git
    GIT_TAG        cmocka-1.1.7
    GIT_SHALLOW    TRUE
)

set(WITH_STATIC_LIB ON  CACHE BOOL "" FORCE)
set(WITH_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(WITH_CMOCKERY_SUPPORT OFF CACHE BOOL "" FORCE)
set(WITH_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(cmocka)
