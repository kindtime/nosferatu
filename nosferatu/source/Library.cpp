#include "pch.h"
#include "nosferatu.h"

namespace RAII
{
	Library::Library(std::wstring input)
	{
		_libraryHandle = ::LoadLibraryW(input.c_str());
	}

	Library::~Library()
	{
		::FreeLibrary(_libraryHandle);
	}

	HMODULE Library::GetHandle()
	{
		return _libraryHandle;
	}
}