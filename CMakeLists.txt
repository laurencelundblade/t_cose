cmake_minimum_required(VERSION 3.10.2)
project(t_cose
	DESCRIPTION "t_cose"
	LANGUAGES C
	VERSION 1.0.1)

set(CMAKE_C_FLAGS "-pedantic -Wall -O3")

#set(CMAKE_INSTALL_NAME_DIR ${CMAKE_INSTALL_FULL_LIBDIR}/lib)

include_directories(inc)
include_directories(src)

set(T_COSE_SOURCE crypto_adapters/t_cose_psa_crypto.c src/t_cose_sign1_sign.c src/t_cose_parameters.c src/t_cose_sign1_verify.c src/t_cose_util.c)

add_definitions(-DT_COSE_USE_PSA_CRYPTO=1)

add_library(t_cose ${T_COSE_SOURCE})
