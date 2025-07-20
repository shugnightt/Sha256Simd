#pragma once

#include <malloc.h>
#include <iostream>


// Аллокация памяти с выравниванием
inline void* alignedMalloc(size_t size, size_t alignment)
{
#ifdef _MSC_VER
	return _aligned_malloc(size, alignment);
#else
	return aligned_alloc(alignment, size);
#endif
}

// Освобождение выделенной памяти
inline void alignedFree(void* ptr)
{
#ifdef _MSC_VER
	_aligned_free(ptr);
#else
	free(ptr);
#endif
}

template <typename T, size_t align = alignof (T)>
class AlignedAllocator
{
public:
	using value_type = T;
	using size_type = std::size_t;
	using propagate_on_container_move_assignment = std::true_type;

	template<class U>
	struct rebind { using other = AlignedAllocator<U, align>; };

	AlignedAllocator() noexcept {};

	AlignedAllocator(const AlignedAllocator&) noexcept {};

	template <typename U, size_t a>
	AlignedAllocator(const AlignedAllocator<U, a>&) noexcept {};

	AlignedAllocator(AlignedAllocator&& other) noexcept {}

	AlignedAllocator& operator = (const AlignedAllocator&) noexcept
	{
		return *this;
	}

	AlignedAllocator& operator = (AlignedAllocator&& other) noexcept
	{
		return *this;
	}

	~AlignedAllocator() noexcept = default;

	T* allocate(size_type n)
	{
		void* const pArray = alignedMalloc(n * sizeof(T), align);
		if (nullptr == pArray)
			throw std::bad_alloc();
		return static_cast<T*>(pArray);
	}

	void deallocate(T* ptr, size_type n) noexcept
	{
		alignedFree(ptr);
	}
};
