file(GLOB UNIT_TESTS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/test_*.c)

# In-memory pio backend, linked only into unit tests.
add_library(pio_fake STATIC ${CMAKE_SOURCE_DIR}/src/pio/pio_fake.c)
target_link_libraries(pio_fake minivr_dp)

# Daemon/CLI code with parsers that must be testable without sockets, root or a running daemon.
add_library(unit_extras STATIC
  ${CMAKE_SOURCE_DIR}/src/common/json_in.c
  ${CMAKE_SOURCE_DIR}/src/daemon/linkmon_parse.c
  ${CMAKE_SOURCE_DIR}/src/daemon/privdrop.c
  ${CMAKE_SOURCE_DIR}/src/ctl/config.c
  ${CMAKE_SOURCE_DIR}/src/ctl/fdcheck.c)
target_include_directories(unit_extras PUBLIC ${CMAKE_SOURCE_DIR}/src/daemon)
target_link_libraries(unit_extras minivr_ctrl minivr_dp)

foreach(src ${UNIT_TESTS})
  get_filename_component(name ${src} NAME_WE)
  add_executable(${name} ${src})
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_definitions(${name} PRIVATE MINIVR_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
  target_link_libraries(${name} unit_extras pio_fake minivr_dp)
  add_test(NAME ${name} COMMAND ${name})
endforeach()
