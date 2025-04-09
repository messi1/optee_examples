cmake_minimum_required(VERSION 3.16)
project(optee_example_aes_securestorage LANGUAGES CXX)

# Nur moderne C++ Features
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Executable definieren
add_executable(${PROJECT_NAME})

# Quellen hinzufügen
target_sources(${PROJECT_NAME}
    PRIVATE
        host/main.cpp  # Falls du einen main hast – sonst weglassen oder anpassen
        host/src/OpTeeContextManager.cpp
        host/src/KeyManager.cpp
        host/src/AesFileEncryptor.cpp
        host/src/FileUtils.cpp
        host/src/HexConverter.cpp
        host/src/AesSecureStorageFacade.cpp

        host/include/OpTeeContextManager.h
        host/include/KeyManager.h
        host/include/AesFileEncryptor.h
        host/include/FileUtils.h
        host/include/HexConverter.h
        host/include/AesSecureStorageFacade.h
		host/include/OpTeeException.h
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
	include
	host/include
        ta/include
)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
