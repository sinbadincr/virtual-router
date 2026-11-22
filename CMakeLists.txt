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
# Phase 3 code that does I/O or belongs to libminivr_ctrl stays out of the data-plane library.
list(FILTER DP_SRC EXCLUDE REGEX "/(nodestate|json_in|tcp|unixsock)\\.c$")
set(DP_SRC ${DP_SRC} src/ctl/cmd.c src/ctl/frame.c)
add_library(minivr_dp STATIC ${DP_SRC})

# Pure control-plane library (phase 3): protocol codec, node-state sets, controller model/compute,
# agent reconcile. No I/O, no syscalls, no heap (scripts/check-fastpath.sh enforces it).
file(GLOB CTRL_SRC CONFIGURE_DEPENDS src/proto/*.c)
set(CTRL_SRC ${CTRL_SRC} src/common/nodestate.c src/controller/model.c src/controller/compute.c
    src/controller/alloc.c src/controller/grammar.c src/agent/reconcile.c)
add_library(minivr_ctrl STATIC ${CTRL_SRC})
target_link_libraries(minivr_ctrl minivr_dp)

file(GLOB DAEMON_SRC CONFIGURE_DEPENDS src/daemon/*.c src/pio/pio_afpacket.c
     src/ctl/config.c src/ctl/ctl_server.c src/ctl/fdcheck.c)
add_executable(minivrd ${DAEMON_SRC})
target_link_libraries(minivrd minivr_dp)
target_link_options(minivrd PRIVATE -rdynamic) # symbol names in crash backtraces

file(GLOB VRCTL_SRC CONFIGURE_DEPENDS src/vrctl/*.c)
add_executable(vrctl ${VRCTL_SRC} src/common/json_in.c)
target_link_libraries(vrctl minivr_dp)

# Controller and agent (phase 3). Sources are added as they are written (tasks T032-T043).
set(CTL_COMMON src/common/tcp.c src/common/unixsock.c src/common/json_in.c src/daemon/privdrop.c
    src/daemon/evloop.c)
file(GLOB CTLD_SRC CONFIGURE_DEPENDS src/controller/session.c src/controller/store.c
     src/controller/localctl.c src/controller/main.c)
if(EXISTS ${CMAKE_SOURCE_DIR}/src/controller/main.c)
  add_executable(minivr-ctld ${CTLD_SRC} ${CTL_COMMON})
  target_link_libraries(minivr-ctld minivr_ctrl minivr_dp)
endif()
file(GLOB AGENT_SRC CONFIGURE_DEPENDS src/agent/fwd.c src/agent/bindings.c src/agent/session.c
     src/agent/localctl.c src/agent/main.c)
if(EXISTS ${CMAKE_SOURCE_DIR}/src/agent/main.c)
  add_executable(minivr-agent ${AGENT_SRC} ${CTL_COMMON}
                 src/pio/pio_afpacket.c)
  target_link_libraries(minivr-agent minivr_ctrl minivr_dp)
endif()

enable_testing()
add_subdirectory(tests/unit)
