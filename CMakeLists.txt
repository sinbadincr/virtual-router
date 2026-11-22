cmake_minimum_required(VERSION 3.25)
project(minivr C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON) # GNU extensions: _GNU_SOURCE APIs (recvmmsg, signalfd)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_definitions(_GNU_SOURCE)
add_compile_options(-Wall -Wextra -Werror -Wshadow -Wconversion -fno-omit-frame-pointer)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions(MINIVR_DEBUG=1)
endif()

include_directories(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/pio)

file(GLOB DP_SRC CONFIGURE_DEPENDS src/common/*.c src/dp/*.c)
set(DP_SRC ${DP_SRC} src/ctl/cmd.c src/ctl/frame.c)
add_library(minivr_dp STATIC ${DP_SRC})

file(GLOB DAEMON_SRC CONFIGURE_DEPENDS src/daemon/*.c src/pio/pio_afpacket.c
     src/ctl/config.c src/ctl/ctl_server.c src/ctl/fdcheck.c)
add_executable(minivrd ${DAEMON_SRC})
target_link_libraries(minivrd minivr_dp)
target_link_options(minivrd PRIVATE -rdynamic) # symbol names in crash backtraces

file(GLOB VRCTL_SRC CONFIGURE_DEPENDS src/vrctl/*.c)
add_executable(vrctl ${VRCTL_SRC})
target_link_libraries(vrctl minivr_dp)

enable_testing()
add_subdirectory(tests/unit)
