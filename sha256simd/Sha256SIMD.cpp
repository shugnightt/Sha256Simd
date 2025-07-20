#include "Sha256SIMD.hpp"


alignas(16) uint32_t initH[8]
{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
};


alignas(16) uint64_t K_SIMD_64[32] = {
	0x71374491428a2f98, 0xe9b5dba5b5c0fbcf, 0x59f111f13956c25b, 0xab1c5ed5923f82a4,
	0x12835b01d807aa98, 0x550c7dc3243185be, 0x80deb1fe72be5d74, 0xc19bf1749bdc06a7,
	0xefbe4786e49b69c1, 0x240ca1cc0fc19dc6, 0x4a7484aa2de92c6f, 0x76f988da5cb0a9dc,
	0xa831c66d983e5152, 0xbf597fc7b00327c8, 0xd5a79147c6e00bf3, 0x1429296706ca6351,
	0x2e1b213827b70a85, 0x53380d134d2c6dfc, 0x766a0abb650a7354, 0x92722c8581c2c92e,
	0xa81a664ba2bfe8a1, 0xc76c51a3c24b8b70, 0xd6990624d192e819, 0x106aa070f40e3585,
	0x1e376c0819a4c116, 0x34b0bcb52748774c, 0x4ed8aa4a391c0cb3, 0x682e6ff35b9cca4f,
	0x78a5636f748f82ee, 0x8cc7020884c87814, 0xa4506ceb90befffa, 0xc67178f2bef9a3f7
};


SHA256SIMD::SHA256SIMD()
{
	shaReset();
}


void SHA256SIMD::shaReset()
{
	_shedule.fill(0);
	_offsShedule = _recvBitLen = 0;

	memcpy(_state.data(), initH, _state.size() * sizeof(word32));
}


void SHA256SIMD::shaUpdate(byte* msg, size_t length)
{
	size_t newTailLength{}, tmp{};
	_recvBitLen += length * bitsInByte;

	// Если на обработку поступила достаточная для формирования хотябы одного блока часть
	if (_offsShedule + length >= sha256BlockSize)
	{		
		// Если с прошлой обработки остался хвост -> дополняем до блока буффер _shedule
		// и отправляем его в обработку. Обновляем переменные.
		if (_offsShedule > 0)
		{
			tmp = sha256BlockSize - _offsShedule;
			memcpy(_shedule.data(), msg, tmp);
			shaProcess(&(*_shedule.data()), sha256BlockSize);
			msg += tmp; length -= tmp;
		}

		newTailLength = shaProcess(msg, length);
		if (newTailLength != 0)
			memcpy(_shedule.data(), msg, newTailLength);
		_offsShedule = newTailLength;
		return;
	}

	// Иначе дополняем _shedule и обновляем _offsShedule.
	_offsShedule += length;
	memcpy(_shedule.data(), msg, length);

	return;
}


void SHA256SIMD::shaFinal(byte* msg, size_t length)
{
	size_t paddedMsgLen, msgPaddingLen;

	// Дообработка полноценных блоков
	shaUpdate(msg, length);

	// Подсчет финальной длины хешируемого сообщения в битах.
	// Рассчитывается длина дополнения и суммируется с длиной сообщения.
	msgPaddingLen = (512 - (_recvBitLen % 512) - 1) >= 64 ?
		512 - (_recvBitLen % 512) - 1 - 64 : 512 + (512 - (_recvBitLen % 512) - 1);
	paddedMsgLen = msgPaddingLen + _recvBitLen + 1 + 64;

	// Обработка блока(ов) с дополнением.
	_shedule[_offsShedule++] = 0x80;
	if (msgPaddingLen >= 512)
	{
		std::fill(_shedule.begin() + _offsShedule, _shedule.end(), 0x00);
		shaProcess(&_shedule[0], sha256BlockSize);
		std::fill(_shedule.begin(), _shedule.end() - sizeof(uint64_t), 0x00);
	}
	else
		std::fill(_shedule.begin() + _offsShedule, _shedule.end() - sizeof(uint64_t), 0x00);
	
	byte* mlen = reinterpret_cast<byte*>(&_recvBitLen);
	for (size_t i = 0; i < sizeof(uint64_t); ++i)
		_shedule[64 - 1 - i] = mlen[i];

	shaProcess(&_shedule[0], sha256BlockSize);


	std::ostringstream s;
	s << std::hex << std::showbase << std::setfill('0') << std::setw(10) << _state[0] << std::noshowbase
		<< std::setfill('0') << std::setw(8) << _state[1]
		<< std::setfill('0') << std::setw(8) << _state[2]
		<< std::setfill('0') << std::setw(8) << _state[3]
		<< std::setfill('0') << std::setw(8) << _state[4]
		<< std::setfill('0') << std::setw(8) << _state[5]
		<< std::setfill('0') << std::setw(8) << _state[6]
		<< std::setfill('0') << std::setw(8) << _state[7] << std::endl;

#if DEBUG_MODE
	std::cout << s.str();
#endif

	// Очищаем контекст
	shaReset();
}


size_t SHA256SIMD::shaProcess(byte* data, size_t length)
{
	if (length < sha256BlockSize or data == nullptr)
		throw std::invalid_argument("Bad arguments in shaProcess function!");

	const __m128i* pData = reinterpret_cast<const __m128i*>(data);
	const __m128i* pConsts = reinterpret_cast<const __m128i*>(K_SIMD_64);

	__m128i ABEF_SAVE, CDGH_SAVE;
	__m128i STATE0, STATE1, MASK, MSG;
	__m128i TMP, TMP1, TMP2, TMPM0, TMPM1, TMPM2, TMPM3;

	TMP1 = _mm_load_si128(
		reinterpret_cast<const __m128i*>(_state.data()));
	TMP2 = _mm_load_si128(
		reinterpret_cast<const __m128i*>(_state.data() + 4));

	STATE0 = _mm_blend_epi32(TMP1, TMP2, 0b1100);  // ABGH
	STATE1 = _mm_blend_epi32(TMP1, TMP2, 0b0011);  // EFCD

	TMP1 = _mm_shuffle_epi32(STATE0, _MM_SHUFFLE(0, 1, 2, 3)); // HGBA
	TMP2 = _mm_shuffle_epi32(STATE1, _MM_SHUFFLE(2, 3, 0, 1)); // FEDC

	STATE0 = _mm_blend_epi32(TMP2, TMP1, 0b1100);  // FEBA
	STATE1 = _mm_blend_epi32(TMP2, TMP1, 0b0011);  // HGDC
	
	MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bull, 0x0405060700010203ull);

	while (length >= sha256BlockSize)
	{
		ABEF_SAVE = STATE0; CDGH_SAVE = STATE1;

		// 0-3 rounds
		MSG = _mm_loadu_si128(pData);
		MSG = _mm_shuffle_epi8(MSG, MASK);
		TMPM0 = MSG;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

		// 4-7 rounds
		MSG = _mm_loadu_si128(pData + 1);
		MSG = _mm_shuffle_epi8(MSG, MASK);
		TMPM1 = MSG;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 1));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM0 = _mm_sha256msg1_epu32(TMPM0, TMPM1);

		// 8-11 rounds
		MSG = _mm_loadu_si128(pData + 2);
		MSG = _mm_shuffle_epi8(MSG, MASK);
		TMPM2 = MSG;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 2));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM1 = _mm_sha256msg1_epu32(TMPM1, TMPM2);

		// 12-15 rounds
		MSG = _mm_loadu_si128(pData + 3);
		MSG = _mm_shuffle_epi8(MSG, MASK);
		TMPM3 = MSG;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 3));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM3;
		TMP = _mm_alignr_epi8(TMP, TMPM2, 4);
		TMPM0 = _mm_add_epi32(TMP, TMPM0);
		TMPM0 = _mm_sha256msg2_epu32(TMPM0, TMPM3);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM2 = _mm_sha256msg1_epu32(TMPM2, TMPM3);

		// 16-19 rounds
		MSG = TMPM0;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 4));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM0;
		TMP = _mm_alignr_epi8(TMP, TMPM3, 4);
		TMPM1 = _mm_add_epi32(TMP, TMPM1);
		TMPM1 = _mm_sha256msg2_epu32(TMPM1, TMPM0);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM3 = _mm_sha256msg1_epu32(TMPM3, TMPM0);

		// 20-23 rounds
		MSG = TMPM1;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 5));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM1;
		TMP = _mm_alignr_epi8(TMP, TMPM0, 4);
		TMPM2 = _mm_add_epi32(TMP, TMPM2);
		TMPM2 = _mm_sha256msg2_epu32(TMPM2, TMPM1);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM0 = _mm_sha256msg1_epu32(TMPM0, TMPM1);

		// 24-27 rounds
		MSG = TMPM2;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 6));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM2;
		TMP = _mm_alignr_epi8(TMP, TMPM1, 4);
		TMPM3 = _mm_add_epi32(TMP, TMPM3);
		TMPM3 = _mm_sha256msg2_epu32(TMPM3, TMPM2);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM1 = _mm_sha256msg1_epu32(TMPM1, TMPM2);

		// 28-31 rounds
		MSG = TMPM3;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 7));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM3;
		TMP = _mm_alignr_epi8(TMP, TMPM2, 4);
		TMPM0 = _mm_add_epi32(TMP, TMPM0);
		TMPM0 = _mm_sha256msg2_epu32(TMPM0, TMPM3);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM2 = _mm_sha256msg1_epu32(TMPM2, TMPM3);

		// 32-35 rounds
		MSG = TMPM0;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 8));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM0;
		TMP = _mm_alignr_epi8(TMP, TMPM3, 4);
		TMPM1 = _mm_add_epi32(TMP, TMPM1);
		TMPM1 = _mm_sha256msg2_epu32(TMPM1, TMPM0);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM3 = _mm_sha256msg1_epu32(TMPM3, TMPM0);

		// 36-39 rounds
		MSG = TMPM1;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 9));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM1;
		TMP = _mm_alignr_epi8(TMP, TMPM0, 4);
		TMPM2 = _mm_add_epi32(TMP, TMPM2);
		TMPM2 = _mm_sha256msg2_epu32(TMPM2, TMPM1);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM0 = _mm_sha256msg1_epu32(TMPM0, TMPM1);

		// 40-43 rounds
		MSG = TMPM2;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 10));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM2;
		TMP = _mm_alignr_epi8(TMP, TMPM1, 4);
		TMPM3 = _mm_add_epi32(TMP, TMPM3);
		TMPM3 = _mm_sha256msg2_epu32(TMPM3, TMPM2);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM1 = _mm_sha256msg1_epu32(TMPM1, TMPM2);

		// 44-47 rounds
		MSG = TMPM3;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 11));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM3;
		TMP = _mm_alignr_epi8(TMP, TMPM2, 4);
		TMPM0 = _mm_add_epi32(TMP, TMPM0);
		TMPM0 = _mm_sha256msg2_epu32(TMPM0, TMPM3);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM2 = _mm_sha256msg1_epu32(TMPM2, TMPM3);

		// 48-51 rounds
		MSG = TMPM0;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 12));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM0;
		TMP = _mm_alignr_epi8(TMP, TMPM3, 4);
		TMPM1 = _mm_add_epi32(TMP, TMPM1);
		TMPM1 = _mm_sha256msg2_epu32(TMPM1, TMPM0);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
		TMPM3 = _mm_sha256msg1_epu32(TMPM3, TMPM0);

		// 52-55 rounds
		MSG = TMPM1;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 13));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM1;
		TMP = _mm_alignr_epi8(TMP, TMPM0, 4);
		TMPM2 = _mm_add_epi32(TMP, TMPM2);
		TMPM2 = _mm_sha256msg2_epu32(TMPM2, TMPM1);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

		// 56-59 rounds
		MSG = TMPM2;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 14));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		TMP = TMPM2;
		TMP = _mm_alignr_epi8(TMP, TMPM1, 4);
		TMPM3 = _mm_add_epi32(TMP, TMPM3);
		TMPM3 = _mm_sha256msg2_epu32(TMPM3, TMPM2);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

		// 60-63 rounds
		MSG = TMPM3;
		MSG = _mm_add_epi32(MSG, _mm_load_si128(pConsts + 15));
		STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

		STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
		STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

		length -= sha256BlockSize; data += sha256BlockSize;
	}

	ABEF_SAVE = _mm_shuffle_epi32(STATE0, _MM_SHUFFLE(0, 1, 2, 3));
	CDGH_SAVE = _mm_shuffle_epi32(STATE1, _MM_SHUFFLE(2, 3, 0, 1));

	TMP1 = _mm_blend_epi32(ABEF_SAVE, CDGH_SAVE, 0b1100);
	_mm_store_si128(reinterpret_cast<__m128i*>(_state.data()), TMP1);

	ABEF_SAVE = _mm_srli_si128(ABEF_SAVE, 8);
	CDGH_SAVE = _mm_slli_si128(CDGH_SAVE, 8);

	TMP2 = _mm_or_si128(ABEF_SAVE, CDGH_SAVE);
	_mm_store_si128(reinterpret_cast<__m128i*>(_state.data() + 4), TMP2);

	return length;
}
