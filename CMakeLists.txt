#-------------------------------------------------------------------------------
# Copyright (c) 2022-2023, Arm Limited. All rights reserved.
# Copyright (c) 2024-2026, Laurence Lundblade. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# See BSD-3-Clause license in README.md
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

project(t_cose
    DESCRIPTION "t_cose"
    LANGUAGES C
    VERSION 1.1.3)


# =========================================================================
#    General Configuration
# =========================================================================

option(BUILD_T_COSE_WARN  "Compile with the warning flags used in the t_cose release process" OFF)
option(BUILD_TESTS "Build tests" OFF)
option(BUILD_EXAMPLES "Build examples" OFF)
option(BUILD_SHARED_LIBS  "Build shared libraries instead of static ones" OFF)

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "No build type selected, defaulting to Release")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

option(T_COSE_DISABLE_CONTENT_TYPE        "" OFF)
option(T_COSE_DISABLE_ES384               "" OFF)
option(T_COSE_DISABLE_ES512               "" OFF)
option(T_COSE_DISABLE_PS256               "" OFF)
option(T_COSE_DISABLE_PS384               "" OFF)
option(T_COSE_DISABLE_PS512               "" OFF)
option(T_COSE_DISABLE_EDDSA               "" OFF)
option(T_COSE_DISABLE_SHORT_CIRCUIT_SIGN  "" OFF)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# =========================================================================
#    Crypto provider configuration
# =========================================================================
set(CRYPTO_PROVIDERS "OpenSSL" "MbedTLS" "Test")

set(CRYPTO_PROVIDER "OpenSSL" CACHE STRING "The crypto provider to use: ${CRYPTO_PROVIDERS}")

if (NOT CRYPTO_PROVIDER IN_LIST CRYPTO_PROVIDERS)
    message(FATAL_ERROR "CRYPTO_PROVIDER must be one of ${CRYPTO_PROVIDERS}")
endif()

if(CRYPTO_PROVIDER STREQUAL "MbedTLS")

    set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)
    find_package(MbedTLS CONFIG REQUIRED)
    set(CRYPTO_LIBRARY MbedTLS::mbedcrypto)
    set(T_COSE_CRYPTO_BACKEND "mbedTLS")
    set(CRYPTO_COMPILE_DEFS -DT_COSE_USE_PSA_CRYPTO=1 ${CC_DEFINES})
    set(CRYPTO_ADAPTER_SRC crypto_adapters/t_cose_psa_crypto.c)

elseif(CRYPTO_PROVIDER STREQUAL "OpenSSL")

    find_package(OpenSSL REQUIRED)
    set(CRYPTO_LIBRARY OpenSSL::Crypto)
    set(T_COSE_CRYPTO_BACKEND "OpenSSL")
    set(CRYPTO_COMPILE_DEFS -DT_COSE_USE_OPENSSL_CRYPTO=1)
    set(CRYPTO_ADAPTER_SRC crypto_adapters/t_cose_openssl_crypto.c)

elseif(CRYPTO_PROVIDER STREQUAL "Test")

    message(FATAL_ERROR "Use 'Makefile.test' to build for Test crypto")

    # Decided not to support Test crypto via CMake for t_cose 1.x
    # because it requires some refactoring of the tests and little
    # further development on 1.x is planed The refactoring was done
    # for t_cose 2.x because it is the main branch going forward and
    # uses a lot more crypto

else()
    message(FATAL_ERROR "Bug!")
endif()


# =========================================================================
#    Build the t_cose library
# =========================================================================

set(T_COSE_SRC_COMMON
    src/t_cose_sign1_sign.c
    src/t_cose_parameters.c
    src/t_cose_sign1_verify.c
    src/t_cose_util.c
    src/t_cose_short_circuit.c
)

# Some functions in QCBOR require the math library, -lm, but t_cose
# doesn't use any of them so there is nothing here in the manual
# configuration for the math library. If QCBOR was installed as 
# a cmake package, then the math library dependency will
# be brought through, even though it is unnecessary because
# t_cose doesn't use and math-related CBOR functionality.

if(NOT QCBOR_LIBRARY OR NOT QCBOR_INCLUDE_DIR)
    # The caller didn't specify the QCBOR locations manually.
    # Try to find it as a cmake package.
    find_package(qcbor QUIET)
endif()

if(NOT qcbor_FOUND)
    # Allow user to specify these via -DQCBOR_LIBRARY=... and -DQCBOR_INCLUDE_DIR=...
    if(QCBOR_LIBRARY AND QCBOR_INCLUDE_DIR)
        # Create an imported target to match what find_package would create
        add_library(qcbor::qcbor UNKNOWN IMPORTED)
        set_target_properties(qcbor::qcbor PROPERTIES
            IMPORTED_LOCATION "${QCBOR_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${QCBOR_INCLUDE_DIR}"
        )
        # So the config file can access these variables
        set(QCBOR_FOUND_AS_PACKAGE FALSE)
        set(QCBOR_LIBRARY_PATH "${QCBOR_LIBRARY}")
        set(QCBOR_INCLUDE_PATH "${QCBOR_INCLUDE_DIR}")
        message(STATUS "Using manually specified qcbor: ${QCBOR_LIBRARY}")
    else()
        message(FATAL_ERROR "qcbor not found. Either install it as a CMake package or specify QCBOR_LIBRARY and QCBOR_INCLUDE_DIR")
    endif()
else()
    set(QCBOR_FOUND_AS_PACKAGE TRUE)
endif()


add_library(t_cose ${T_COSE_SRC_COMMON} ${CRYPTO_ADAPTER_SRC})

add_library(t_cose::t_cose ALIAS t_cose)

set_target_properties(
    t_cose PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 99
)

target_compile_definitions(t_cose PRIVATE ${CRYPTO_COMPILE_DEFS})
target_compile_definitions(t_cose
    PUBLIC
        $<$<BOOL:${T_COSE_DISABLE_CONTENT_TYPE}>:T_COSE_DISABLE_CONTENT_TYPE>
        $<$<BOOL:${T_COSE_DISABLE_ES384}>:T_COSE_DISABLE_ES384>
        $<$<BOOL:${T_COSE_DISABLE_ES512}>:T_COSE_DISABLE_ES512>
        $<$<BOOL:${T_COSE_DISABLE_PS256}>:T_COSE_DISABLE_PS256>
        $<$<BOOL:${T_COSE_DISABLE_PS384}>:T_COSE_DISABLE_PS384>
        $<$<BOOL:${T_COSE_DISABLE_PS512}>:T_COSE_DISABLE_PS512>
        $<$<BOOL:${T_COSE_DISABLE_EDDSA}>:T_COSE_DISABLE_EDDSA>
        $<$<BOOL:${T_COSE_DISABLE_SHORT_CIRCUIT_SIGN}>:T_COSE_DISABLE_SHORT_CIRCUIT_SIGN>
)


target_include_directories(t_cose
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${EXTRA_INC}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
        $<INSTALL_INTERFACE:include>
        ${QCBOR_INCLUDE_DIR}
)

target_link_libraries(t_cose PUBLIC qcbor::qcbor)
target_link_libraries(t_cose PUBLIC ${CRYPTO_LIBRARY})

# Global compile options applying to all targets
if (BUILD_T_COSE_WARN)
    target_compile_options(t_cose PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wcast-qual)
    
    # Tell MSVC not to warn about padded structures
    if (MSVC)
        target_compile_options(t_cose PRIVATE /wd4820)
    endif()
endif()




# =========================================================================
#    Install the t_cose library
# =========================================================================

include(GNUInstallDirs)

install(TARGETS t_cose
    EXPORT t_coseTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY
        inc/t_cose
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(
    EXPORT t_coseTargets
    NAMESPACE t_cose::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/t_cose
)



# =========================================================================
#    install cmake package info
# =========================================================================

include(CMakePackageConfigHelpers)

configure_package_config_file(
    cmake/t_coseConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/t_coseConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/t_cose
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/t_coseConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/t_coseConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/t_coseConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/t_cose
) 


# =========================================================================
#    Build the example code
# =========================================================================

if (BUILD_EXAMPLES)

    if (CRYPTO_PROVIDER STREQUAL "MbedTLS")
        add_executable(t_cose_examples examples/t_cose_basic_example_psa.c test/t_cose_make_psa_test_key.c)
    elseif(CRYPTO_PROVIDER STREQUAL "OpenSSL")
        add_executable(t_cose_examples examples/t_cose_basic_example_ossl.c test/t_cose_make_openssl_test_key.c)
    endif()

    target_include_directories(t_cose_examples PRIVATE examples)
    target_link_libraries(t_cose_examples PRIVATE t_cose ${CRYPTO_LIBRARY})
    # Crypto defs are needed because the tests include headers from src/
    target_compile_definitions(t_cose_examples PRIVATE ${CRYPTO_COMPILE_DEFS} ${EXAMPLE_EXTRA_DEFS})

endif()


# =========================================================================
#    Build the test app 
# =========================================================================

if (BUILD_TESTS)

    enable_testing()

    set(TEST_SRC_COMMON
        main.c
        test/run_tests.c
        test/t_cose_make_test_messages.c
        test/t_cose_test.c
    )

    if (NOT CRYPTO_PROVIDER STREQUAL "Test")
        list(APPEND TEST_SRC_COMMON test/t_cose_sign_verify_test.c)
    endif()

    if (CRYPTO_PROVIDER STREQUAL "MbedTLS")
        set(TEST_SRC_EXTRA test/t_cose_make_psa_test_key.c)
        set(TEST_EXTRA_DEFS)
    elseif(CRYPTO_PROVIDER STREQUAL "OpenSSL")
        set(TEST_SRC_EXTRA test/t_cose_make_openssl_test_key.c)
        set(TEST_EXTRA_DEFS)
    else()
        message(FATAL_ERROR "Bug!")
    endif()

    add_executable(t_cose_test ${TEST_SRC_COMMON} ${TEST_SRC_EXTRA})
    target_include_directories(t_cose_test PRIVATE src test examples)
    target_link_libraries(t_cose_test PRIVATE t_cose ${CRYPTO_LIBRARY})
    # Crypto defs are needed because the tests include headers from src/
    target_compile_definitions(t_cose_test PRIVATE ${CRYPTO_COMPILE_DEFS} ${TEST_EXTRA_DEFS})

    add_test(NAME t_cose_test COMMAND t_cose_test)

endif()
