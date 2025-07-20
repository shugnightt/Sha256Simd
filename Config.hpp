#pragma once

#include <intrin.h>
#include <emmintrin.h>

#include <array>
#include <chrono>
#include <vector>
#include <memory>
#include <random>
#include <sstream>
#include <fstream>
#include <numeric>
#include <iostream>
#include <algorithm>
#include <filesystem>

#include "utils/Allocator.hpp"

#define DEBUG_MODE 0
#define BENCHMARK 1

constexpr size_t H_count = 8;
constexpr size_t bitsInByte = 8;
constexpr size_t sheduleSize = 64;						// in words
constexpr size_t sha256BlockSize = 64;					// in bytes
constexpr size_t hashSHA256Length = 256;                // digest length in bits