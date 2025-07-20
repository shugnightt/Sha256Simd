#pragma once

#include "../Config.hpp"


// Используется внутри функций shaUpdate семейства SHA
// Возвращает указатель на W_0.
// Стандартная реализация (Без SIMD)
template<typename T>
T* bytesToWords(uint8_t* seq)
{
	size_t wSize = sizeof(T);
	for (size_t i = 0; i < 16; ++i)
		for (size_t j = 0; j < wSize / 2; ++j)
			std::swap(seq[(i + 1) * wSize - 1 - j], seq[i * wSize + j]);

	return reinterpret_cast<T*>(seq);
}


// Идентификатор алгоритма
enum class ShaType {
	SHA256,
	SHA384,
	SHA512
};


/*	Шаблонный класс предоставляющий набор логических операций
	Используемый семейством алгоритмов хэшрования SHA. В зависимости
	От типа алгоритма предоставляет функции для манипуляции с переменными
	типа uint32_t (SHA256) и uint64_t (SHA384, SHA512) */
template<typename T> requires
std::is_same<T, uint32_t>::value ||
std::is_same<T, uint64_t>::value
class shaLogicalOps
{
public:
	const size_t bitsInType = sizeof(T) * bitsInByte;

	explicit shaLogicalOps(ShaType id) : _shaId(id) {}
	~shaLogicalOps() = default;

	T RotateR(T x, size_t n) { return (x >> n) | (x << (bitsInType - n)); }
	T RotateL(T x, size_t n) { return (x << n) | (x >> (bitsInType - n)); }

	T Ch(T x, T y, T z) { return (x & y) xor ((~x) & z); }
	T Maj(T x, T y, T z) { return (x & y) xor (x & z) xor (y & z); }


	T Sigma0(T x) {
		if (_shaId == ShaType::SHA256)
			return RotateR(x, 2) xor RotateR(x, 13) xor RotateR(x, 22);
		else
			return RotateR(x, 28) xor RotateR(x, 34) xor RotateR(x, 39);
	}
	T Sigma1(T x) {
		if (_shaId == ShaType::SHA256)
			return RotateR(x, 6) xor RotateR(x, 11) xor RotateR(x, 25);
		else
			return RotateR(x, 14) xor RotateR(x, 18) xor RotateR(x, 41);
	}
	T sigma0(T x) {
		if (_shaId == ShaType::SHA256)
			return RotateR(x, 7) xor RotateR(x, 18) xor (x >> 3);
		else
			return RotateR(x, 1) xor RotateR(x, 8) xor (x >> 7);
	}
	T sigma1(T x) {
		if (_shaId == ShaType::SHA256)
			return RotateR(x, 17) xor RotateR(x, 19) xor (x >> 10);
		else
			return RotateR(x, 19) xor RotateR(x, 61) xor (x >> 6);
	}
private:
	// Поля класса
	ShaType _shaId;
};


class SHA256
{
public:
	using word = uint32_t;
	using byte = uint8_t;

	SHA256();
	~SHA256() = default;

	constexpr std::string_view algName() { return std::string_view("Sha256"); }

	void shaReset();
	void shaUpdate(byte* msg, size_t size);
	std::string_view shaFinal(byte* msg, size_t size);
	void processBlock();

private:
	// Используются при формировании первых 16 блоков message shedule
	size_t offsShedule{}, recvBitLength{};
	std::array<byte, hashSHA256Length> shedule{};			// W_i
	std::array<word, H_count> H{};							// H_i

	shaLogicalOps<word> ops{ ShaType::SHA256 };
};