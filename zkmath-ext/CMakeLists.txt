cmake_minimum_required (VERSION 3.0)
project (emp-zk)
set(NAME "emp-zk")

# ZKMath's own CMakeLists forces a Debug (-O0) build; all numbers here use Release (-O3).
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})
set(sources
  emp-zk/emp-zk-bool/emp-zk-bool.cpp
  emp-zk/emp-zk-arith/emp-zk-arith.cpp
  emp-zk/emp-zk-math/ZKmath-functions.cpp
  emp-zk/emp-zk-math/ZKmath-global.cpp
  emp-zk/emp-zk-math/ZKmath-ext.cpp
)
add_library(${NAME} SHARED ${sources})

# Hao et al.'s original tests (calibration against their Tables 4-5)
foreach(t exp div rsqrt sigmoid gelu softmax msnzb positiveTruncation)
	add_executable(hao_${t} "test/math/${t}.cpp")
	target_link_libraries(hao_${t} ${EMP-OT_LIBRARIES} emp-zk)
endforeach()

# Our benchmark driver: v2 protocols (LUT) vs no-LUT baselines vs plaintext
add_executable(bench_ext "test/math/bench_ext.cpp")
target_link_libraries(bench_ext ${EMP-OT_LIBRARIES} emp-zk)
