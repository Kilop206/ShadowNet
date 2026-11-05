add_library(shadow_core INTERFACE)
target_include_directories(shadow_core INTERFACE core/include)
target_compile_definitions(shadow_core INTERFACE SHADOW_VERSION="${PROJECT_VERSION}")
target_link_libraries(shadow_core INTERFACE shadow_options)

add_library(shadow_security security/src/validation.cpp security/src/tls.cpp)
target_include_directories(shadow_security PUBLIC security/include)
target_link_libraries(shadow_security PUBLIC shadow_core shadow_boost OpenSSL::SSL OpenSSL::Crypto)

add_library(shadow_observability observability/src/log.cpp)
target_include_directories(shadow_observability PUBLIC observability/include)
target_link_libraries(shadow_observability PUBLIC shadow_core Threads::Threads)

add_library(shadow_protocol protocol/src/message.cpp protocol/src/tunnel.cpp)
target_include_directories(shadow_protocol PUBLIC protocol/include)
target_link_libraries(shadow_protocol PUBLIC shadow_security)

add_library(shadow_configuration configuration/src/config.cpp)
target_include_directories(shadow_configuration PUBLIC configuration/include)
target_link_libraries(shadow_configuration PUBLIC shadow_security PRIVATE yaml-cpp::yaml-cpp)

add_library(shadow_networking networking/src/local_transport.cpp networking/src/secure_session.cpp networking/src/secure_transport.cpp)
target_include_directories(shadow_networking PUBLIC networking/include)
target_link_libraries(shadow_networking PUBLIC shadow_configuration shadow_boost PRIVATE shadow_protocol shadow_observability Threads::Threads)
target_compile_definitions(shadow_boost INTERFACE BOOST_ASIO_NO_DEPRECATED BOOST_ALL_NO_LIB)
if(WIN32)
  target_compile_definitions(shadow_boost INTERFACE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN NOMINMAX)
  target_link_libraries(shadow_boost INTERFACE ws2_32 mswsock)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # Beast/SSL async templates generate very large DWARF on MinGW.
    set_source_files_properties(networking/src/secure_session.cpp PROPERTIES
      COMPILE_OPTIONS "-Wa,-mbig-obj;$<$<CONFIG:Debug>:-g1>;$<$<CONFIG:Debug>:-O1>")
  endif()
endif()
