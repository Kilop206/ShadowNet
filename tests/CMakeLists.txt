add_executable(shadow-unit unit/foundation.cpp unit/tunnel.cpp unit/proxy.cpp unit/reliability.cpp)
target_link_libraries(shadow-unit PRIVATE shadow_protocol shadow_configuration shadow_observability Catch2::Catch2WithMain)
target_compile_definitions(shadow-unit PRIVATE SHADOW_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
add_test(NAME unit.foundation COMMAND shadow-unit)
set_tests_properties(unit.foundation PROPERTIES TIMEOUT 30)

find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
find_program(SHADOW_OPENSSL_EXECUTABLE NAMES openssl REQUIRED)
add_test(NAME integration.local_transport
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/integration/local_transport.py"
    --agent $<TARGET_FILE:shadow-agent> --gateway $<TARGET_FILE:shadow-gateway>
    --cli $<TARGET_FILE:shadow> --source "${PROJECT_SOURCE_DIR}")
set_tests_properties(integration.local_transport PROPERTIES TIMEOUT 60)
add_test(NAME integration.secure_transport
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/integration/secure_transport.py"
    --agent $<TARGET_FILE:shadow-agent> --gateway $<TARGET_FILE:shadow-gateway>
    --cli $<TARGET_FILE:shadow> --source "${PROJECT_SOURCE_DIR}" --openssl "${SHADOW_OPENSSL_EXECUTABLE}")
set_tests_properties(integration.secure_transport PROPERTIES TIMEOUT 120)
add_test(NAME e2e.reverse_proxy
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/e2e/reverse_proxy.py"
    --agent $<TARGET_FILE:shadow-agent> --gateway $<TARGET_FILE:shadow-gateway>
    --cli $<TARGET_FILE:shadow> --source "${PROJECT_SOURCE_DIR}" --openssl "${SHADOW_OPENSSL_EXECUTABLE}")
set_tests_properties(e2e.reverse_proxy PROPERTIES TIMEOUT 180)
add_test(NAME e2e.reliability
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/e2e/reliability.py"
    --agent $<TARGET_FILE:shadow-agent> --gateway $<TARGET_FILE:shadow-gateway>
    --cli $<TARGET_FILE:shadow> --source "${PROJECT_SOURCE_DIR}" --openssl "${SHADOW_OPENSSL_EXECUTABLE}"
    --load-report "${CMAKE_CURRENT_BINARY_DIR}/reliability-load.json")
set_tests_properties(e2e.reliability PROPERTIES TIMEOUT 420)
