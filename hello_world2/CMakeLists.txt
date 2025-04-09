project (optee_example_hello_world2 C)

set (SRC host/main.c)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include
			   PUBLIC ../../libp11-0.4.12/src
			   PUBLIC ../../p11-kit-0.25.3/
			   PUBLIC ../../libopenssl-3.3.1/include)

target_link_libraries (${PROJECT_NAME} 
PRIVATE 
teec 
${CMAKE_CURRENT_SOURCE_DIR}/../../libp11-0.4.12/src/.libs/libp11.so
${CMAKE_CURRENT_SOURCE_DIR}/../../libp11-0.4.12/src/.libs/pkcs11.so
${CMAKE_CURRENT_SOURCE_DIR}/../../p11-kit-0.25.3/.libs/libp11-kit.so
${CMAKE_CURRENT_SOURCE_DIR}/../../libopenssl-3.3.1/libssl.so
${CMAKE_CURRENT_SOURCE_DIR}/../../libopenssl-3.3.1/libcrypto.so
) 

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
