# Add google benchmark
include(FetchContent)

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  benchmark
  GIT_REPOSITORY https://github.com/google/benchmark.git
  GIT_TAG v1.9.4
)
FetchContent_MakeAvailable(benchmark)

add_executable(custom_benchmark custom_benchmark.cu)
target_link_libraries(custom_benchmark PRIVATE Phantom benchmark::benchmark)
target_include_directories(custom_benchmark PUBLIC ${CMAKE_SOURCE_DIR}/include)