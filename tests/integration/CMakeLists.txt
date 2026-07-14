add_executable(test_core_integration
    test_core_integration.c
)

target_include_directories(test_core_integration PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${cmocka_SOURCE_DIR}/include
    ${cmocka_BINARY_DIR}/include
)

target_link_libraries(test_core_integration PRIVATE
    tinyev
    cmocka
    pthread
    rt
)

add_test(NAME core_integration COMMAND test_core_integration)

add_executable(test_buf_integration
    test_buf_integration.c
)

target_include_directories(test_buf_integration PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${cmocka_SOURCE_DIR}/include
    ${cmocka_BINARY_DIR}/include
)

target_link_libraries(test_buf_integration PRIVATE
    tinyev
    cmocka
    pthread
    rt
)

add_test(NAME buf_integration COMMAND test_buf_integration)

add_executable(test_rpc_integration
    test_rpc_integration.c
)

target_include_directories(test_rpc_integration PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${cmocka_SOURCE_DIR}/include
    ${cmocka_BINARY_DIR}/include
)

target_link_libraries(test_rpc_integration PRIVATE
    tinyev
    cmocka
    pthread
    rt
)

add_test(NAME rpc_integration COMMAND test_rpc_integration)

add_executable(test_helpers_integration
    test_helpers_integration.c
)

target_include_directories(test_helpers_integration PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${cmocka_SOURCE_DIR}/include
    ${cmocka_BINARY_DIR}/include
)

target_link_libraries(test_helpers_integration PRIVATE
    tinyev
    cmocka
    pthread
    rt
)

add_test(NAME helpers_integration COMMAND test_helpers_integration)
