include(FetchContent)
add_library(shadow_boost INTERFACE)

if(SHADOW_FETCH_DEPENDENCIES)
  # Prefer verified local archives, otherwise download the same pinned releases.
  function(shadow_archive name url output)
    if(EXISTS "${PROJECT_SOURCE_DIR}/.deps/${name}.tar.gz")
      set(url "${PROJECT_SOURCE_DIR}/.deps/${name}.tar.gz")
    endif()
    set(${output} "${url}" PARENT_SCOPE)
  endfunction()
  shadow_archive(boost-1.90.0-cmake
    https://github.com/boostorg/boost/releases/download/boost-1.90.0/boost-1.90.0-cmake.tar.gz
    SHADOW_BOOST_URL)
  set(BOOST_INCLUDE_LIBRARIES "asio;beast")
  set(BOOST_ENABLE_CMAKE ON CACHE BOOL "Enable Boost CMake")
  FetchContent_Declare(boost URL "${SHADOW_BOOST_URL}"
    URL_HASH SHA256=913ca43d49e93d1b158c9862009add1518a4c665e7853b349a6492d158b036d4
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(boost)
  # Modular sources need Asio's transitive include directories, not the
  # aggregate Boost::headers target intended for installed distributions.
  target_link_libraries(shadow_boost INTERFACE Boost::asio Boost::beast)
  shadow_archive(yaml-cpp-0.9.0 https://codeload.github.com/jbeder/yaml-cpp/tar.gz/refs/tags/yaml-cpp-0.9.0 SHADOW_YAML_URL)
  set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "")
  set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "")
  set(YAML_CPP_INSTALL OFF CACHE BOOL "")
  FetchContent_Declare(yaml-cpp URL "${SHADOW_YAML_URL}"
    URL_HASH SHA256=25cb043240f828a8c51beb830569634bc7ac603978e0f69d6b63558dadefd49a
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  # Keep the pinned upstream's CMake 3.5 compatibility working on CMake 4.
  set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
  FetchContent_MakeAvailable(yaml-cpp)
  if(BUILD_TESTING)
    shadow_archive(Catch2-3.8.1 https://codeload.github.com/catchorg/Catch2/tar.gz/refs/tags/v3.8.1 SHADOW_CATCH_URL)
    FetchContent_Declare(Catch2 URL "${SHADOW_CATCH_URL}"
      URL_HASH SHA256=18b3f70ac80fccc340d8c6ff0f339b2ae64944782f8d2fca2bd705cf47cadb79
      DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(Catch2)
  endif()
else()
  find_package(Boost 1.74 REQUIRED CONFIG)
  target_link_libraries(shadow_boost INTERFACE Boost::headers)
  find_package(yaml-cpp 0.7 REQUIRED CONFIG)
  if(NOT TARGET yaml-cpp::yaml-cpp)
    add_library(yaml-cpp::yaml-cpp ALIAS yaml-cpp)
  endif()
  if(BUILD_TESTING)
    find_package(Catch2 3 REQUIRED CONFIG)
  endif()
endif()
