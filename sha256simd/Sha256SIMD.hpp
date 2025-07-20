#pragma once

#include "../Config.hpp"


class alignas(16) SHA256SIMD
{
public:
	using byte = uint8_t;
	using word32 = uint32_t;

	SHA256SIMD();
	~SHA256SIMD() = default;

	constexpr std::string_view algName() { return std::string_view("Sha256Simd"); }

	void shaReset();
	void shaUpdate(byte* msg, size_t length);
	void shaFinal(byte* msg, size_t length);
	size_t shaProcess(byte* data, size_t length);

private:
	std::array<word32, 8> _state;
	std::array<byte, sha256BlockSize> _shedule;
	size_t _offsShedule, _recvBitLen;
};