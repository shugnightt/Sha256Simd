#include "Sha256.hpp"

extern uint32_t initH[8];


uint32_t K_64[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


SHA256::SHA256()
{
	shaReset();
}


void SHA256::shaReset()
{
	H[0] = initH[0];
	H[1] = initH[1];
	H[2] = initH[2];
	H[3] = initH[3];
	H[4] = initH[4];
	H[5] = initH[5];
	H[6] = initH[6];
	H[7] = initH[7];

	shedule.fill(0);
	offsShedule = recvBitLength = 0;
}


void SHA256::shaUpdate(byte* msg, size_t size)
{
	size_t cpLength = size;
	size_t tailLength = 64 - offsShedule;
	byte* msgPtr = msg;

	if (tailLength <= cpLength)
	{
		// «аполнение хвоста и обработка блока
		std::memcpy(shedule.data() + offsShedule, msgPtr, tailLength);
		processBlock();
		msgPtr += tailLength; cpLength -= tailLength; offsShedule = tailLength = 0;

		//  опирование и обработка блоков, пока позвол€ет длина
		while (cpLength > 64)
		{
			std::memcpy(shedule.data(), msgPtr, 64);
			processBlock();
			cpLength -= 64; msgPtr += 64;
		}
	}

	// «аполнение остатка
	std::memcpy(shedule.data() + offsShedule, msgPtr, cpLength);
	offsShedule += cpLength; recvBitLength += size * bitsInByte;
}


std::string_view SHA256::shaFinal(byte* msg, size_t size)
{
	// Updating
	shaUpdate(msg, size);

	// Padding последнего блока 

	// Ѕлижайший байт к последнему заполненному - 0x80
	// ќстальные - нули. ѕоследние 8 байт зарезервированы под длину сообщени€.
	// ≈сли в блок не умещаетс€ длина сообщени€, формируетс€ дополнительный блок из нулей.

	if (offsShedule < 64 - sizeof(uint64_t))
	{
		shedule[offsShedule++] = 0x80;
		for (; offsShedule < 64 - sizeof(uint64_t); ++offsShedule)
			shedule[offsShedule] = 0;
	}
	else
	{
		bool wasPadded = false;
		if (offsShedule < 64)
		{
			shedule[offsShedule++] = 0x80;
			for (; offsShedule < 64; ++offsShedule)
				shedule[offsShedule] = 0;

			wasPadded = true;
		}

		processBlock();

		shedule.fill(0);
		shedule[0] = wasPadded ? 0x00 : 0x80;
	}

	byte* mlen = reinterpret_cast<byte*>(&recvBitLength);
	for (size_t i = 0; i < sizeof(uint64_t); ++i)
		shedule[64 - 1 - i] = mlen[i];

	processBlock();

	std::ostringstream s;
	s << std::hex << std::showbase << std::setfill('0') << std::setw(10) << H[0] << std::noshowbase
		<< std::setfill('0') << std::setw(8) << H[1]
		<< std::setfill('0') << std::setw(8) << H[2]
		<< std::setfill('0') << std::setw(8) << H[3]
		<< std::setfill('0') << std::setw(8) << H[4]
		<< std::setfill('0') << std::setw(8) << H[5]
		<< std::setfill('0') << std::setw(8) << H[6]
		<< std::setfill('0') << std::setw(8) << H[7] << std::endl;

#if DEBUG_MODE
	// DEBUG info
	std::cout << s.str();
#endif

	shaReset();

	auto hex = std::string_view(s.str());
	return hex;
}


void SHA256::processBlock()
{
	word* pShedule = bytesToWords<word>(shedule.data());

	// ќкончательное формирование message shedule
	for (size_t i = 16; i < 64; ++i)
	{
		pShedule[i] = ops.sigma1(pShedule[i - 2]) + pShedule[i - 7]
			+ ops.sigma0(pShedule[i - 15]) + pShedule[i - 16];
	}

	word a{ H[0] };
	word b{ H[1] };
	word c{ H[2] };
	word d{ H[3] };
	word e{ H[4] };
	word f{ H[5] };
	word g{ H[6] };
	word h{ H[7] };

	word T1{}, T2{};

	for (size_t i = 0; i < 64; ++i)
	{
		T1 = h + ops.Sigma1(e) + ops.Ch(e, f, g) + K_64[i] + pShedule[i];
		T2 = ops.Sigma0(a) + ops.Maj(a, b, c);

		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	// H_{i} = H_{i + 1}
	H[0] = a + H[0];
	H[1] = b + H[1];
	H[2] = c + H[2];
	H[3] = d + H[3];
	H[4] = e + H[4];
	H[5] = f + H[5];
	H[6] = g + H[6];
	H[7] = h + H[7];
}
