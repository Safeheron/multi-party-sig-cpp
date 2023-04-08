find_package(GTest REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(
        ${GTEST_INCLUDE_DIRS}
        "../src"
        /usr/local/include
)

link_directories(
        /usr/local/lib
)

link_libraries(
        ${CMAKE_PROJECT_NAME}
        ${GTEST_BOTH_LIBRARIES}
        pthread
)

option(NO_MPC_GG18 "NO_MPC_GG18" OFF)
option(NO_MPC_GG20 "NO_MPC_GG20" OFF)
option(NO_MPC_CMP "NO_MPC_CMP" OFF)

if (NOT ${NO_MPC_GG18})
    # gg18
    add_executable(gg18.key_gen_test gg18/key_gen_test.cpp CTimer.cpp)
    add_test(NAME gg18.key_gen_test COMMAND gg18.key_gen_test)

    add_executable(gg18.key_refresh_test gg18/key_refresh_test.cpp)
    add_test(NAME gg18.key_refresh_test COMMAND gg18.key_refresh_test)

    add_executable(gg18.sign_test gg18/sign_test.cpp)
    add_test(NAME gg18.sign_test COMMAND gg18.sign_test)

    # multi-thread
    add_executable(gg18.key_gen_mt_test gg18/key_gen_mt_test.cpp)
    add_test(NAME gg18.key_gen_mt_test COMMAND gg18.key_gen_mt_test)

    add_executable(gg18.sign_n_n_mt_test gg18/sign_n_n_mt_test.cpp)
    add_test(NAME gg18.sign_n_n_mt_test COMMAND gg18.sign_n_n_mt_test)

    add_executable(gg18.sign_t_n_mt_test gg18/sign_t_n_mt_test.cpp)
    add_test(NAME gg18.sign_t_n_mt_test COMMAND gg18.sign_t_n_mt_test)

    add_executable(gg18.key_refresh_mt_test gg18/key_refresh_mt_test.cpp)
    add_test(NAME gg18.key_refresh_mt_test COMMAND gg18.key_refresh_mt_test)
endif()

if (NOT ${NO_MPC_GG20})
    # gg20
    add_executable(gg20.sign_test gg20/sign_test.cpp)
    add_test(NAME gg20.sign_test COMMAND gg20.sign_test)
    # multi-thread
    add_executable(gg20.sign_n_n_mt_test gg20/sign_n_n_mt_test.cpp)
    add_test(NAME gg20.sign_n_n_mt_test COMMAND gg20.sign_n_n_mt_test)
endif()

if (NOT ${NO_MPC_GG20_HD})
    ## gg20_hd_v0
    add_executable(gg20_hd_v0.sign_test gg20_hd_v0/sign_test.cpp)
    add_test(NAME gg20_hd_v0.sign_test COMMAND gg20_hd_v0.sign_test)
endif()

if (NOT ${NO_MPC_CMP})
    # cmp
    add_executable(cmp.minimal_key_gen_test cmp/minimal_key_gen_test.cpp CTimer.cpp)
    add_test(NAME cmp.minimal_key_gen_test COMMAND cmp.minimal_key_gen_test)

    add_executable(cmp.aux_info_key_refresh_test cmp/aux_info_key_refresh_test.cpp CTimer.cpp)
    add_test(NAME cmp.aux_info_key_refresh_test COMMAND cmp.aux_info_key_refresh_test)

    add_executable(cmp.sign_test cmp/sign_test.cpp CTimer.cpp)
    add_test(NAME cmp.sign_test COMMAND cmp.sign_test)
    # multi-thread
    add_executable(gg20.sign_t_n_mt_test gg20/sign_t_n_mt_test.cpp)
    add_test(NAME gg20.sign_t_n_mt_test COMMAND gg20.sign_t_n_mt_test)

    add_executable(cmp.minimal_key_gen_mt_test cmp/minimal_key_gen_mt_test.cpp)
    add_test(NAME cmp.minimal_key_gen_mt_test COMMAND cmp.minimal_key_gen_mt_test)

    add_executable(cmp.aux_info_key_refresh_mt_test cmp/aux_info_key_refresh_mt_test.cpp)
    add_test(NAME cmp.aux_info_key_refresh_mt_test COMMAND cmp.aux_info_key_refresh_mt_test)

    add_executable(cmp.sign_n_n_mt_test cmp/sign_n_n_mt_test.cpp)
    add_test(NAME cmp.sign_n_n_test COMMAND cmp.sign_n_n_mt_test)

    add_executable(cmp.sign_t_n_mt_test cmp/sign_t_n_mt_test.cpp)
    add_test(NAME cmp.sign_t_n_test COMMAND cmp.sign_t_n_mt_test)
endif()



