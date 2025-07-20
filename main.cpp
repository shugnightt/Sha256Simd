#include "Config.hpp"
#include "sha256/Sha256.hpp"
#include "sha256simd/Sha256SIMD.hpp"


void fillByRandBytes(std::vector<uint8_t>& vec, const uint64_t& caseSize)
{
	std::random_device rd;
	std::uniform_int_distribution<uint32_t> distribution(0x00, 0xff);

	vec.reserve(caseSize);

	for (size_t i = vec.size(); i < vec.capacity(); ++i)
		vec.push_back(distribution(rd));
}


void bench()
{
	uint64_t roof{ 0xf0000000ull };
	size_t count{ 0x32 };
	std::fstream fmeasure("sha256comp.txt", std::ios_base::out);
	std::vector<uint8_t> msg;
	std::vector<uint64_t> simdMean, stdMean;
	simdMean.resize(count); stdMean.resize(count);

	SHA256 processorNoSimd;
	SHA256SIMD processorWithSimd;

	std::chrono::time_point<std::chrono::steady_clock> sttSimd, endSimd, sttNoSimd, endNoSimd;

	for (size_t caseSize = 1; caseSize <= roof + 1; caseSize <<= 1)
	{
		fillByRandBytes(msg, caseSize);

		for (size_t i = 0; i < count; ++i)
		{
			// Sha256 no simd
			sttNoSimd = std::chrono::steady_clock::now();
			processorNoSimd.shaFinal(msg.data(), msg.size());
			endNoSimd = std::chrono::steady_clock::now();
			stdMean[i] = static_cast<uint64_t>(
				std::chrono::duration_cast<std::chrono::microseconds>(endNoSimd - sttNoSimd).count());


			// sha256 with simd
			sttSimd = std::chrono::steady_clock::now();
			processorWithSimd.shaFinal(msg.data(), msg.size());
			endSimd = std::chrono::steady_clock::now();
			simdMean[i] = static_cast<uint64_t>(
				std::chrono::duration_cast<std::chrono::microseconds>(endSimd - sttSimd).count());
		}

		auto tmp1{ std::accumulate(stdMean.begin(), stdMean.end(), static_cast<uint64_t>(0)) / count };
		auto tmp2{ std::accumulate(simdMean.begin(), simdMean.end(), static_cast<uint64_t>(0)) / count };

		fmeasure << caseSize << " " << tmp1 << " " << tmp2 << std::endl; // count, stnd, simd
	}

	fmeasure.close();
}


int main()
{
	#if BENCHMARK
	bench();
	#else // ѕростой пример использовани€ и демонстраци€ превосходства SIMD реализации
	size_t bytes = 0x40000000ull;
	std::vector<uint8_t, AlignedAllocator<uint8_t, 16>> msg(bytes, 'a');

	SHA256SIMD processorWithSimd;
	std::cout << "Duration with simd:" << std::endl;
	auto start = std::chrono::high_resolution_clock::now();
	processorWithSimd.shaFinal(msg.data(), msg.size());
	auto end = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	std::cout << "time: " << duration.count() << " milliseconds\n";

	SHA256 processorWithoutSimd;

	std::cout << "Duration without simd:" << std::endl;
	auto startNoSimd = std::chrono::high_resolution_clock::now();
	processorWithoutSimd.shaFinal(msg.data(), msg.size());
	auto endNoSimd = std::chrono::high_resolution_clock::now();

	auto durationNoSimd = std::chrono::duration_cast<std::chrono::milliseconds>(endNoSimd - startNoSimd);
	std::cout << "time: " << durationNoSimd.count() << " milliseconds\n";
	#endif
}