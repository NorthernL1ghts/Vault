#include <iostream>
#include <Windows.h>
#include <bcrypt.h>
#include <array>
#include <format>

#pragma comment(lib, "bcrypt.lib")

BCRYPT_ALG_HANDLE h_Algorithm = nullptr;

bool Initialize() {
	// Open an algorithm handle for AES
	NTSTATUS status = BCryptOpenAlgorithmProvider(&h_Algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
	if (status != 0) {
		std::cerr << "Failed to open algorithm provider, error code: " << status << std::endl;
		return false;
	}
	return true;
}

void GenerateAES256Keys(std::array<unsigned char, 32>& aes256Key1, std::array<unsigned char, 32>& aes256Key2) {
	NTSTATUS status;

	// Generate first key
	status = BCryptGenRandom(nullptr, aes256Key1.data(), static_cast<ULONG>(aes256Key1.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (status != 0)
		std::cerr << "Failed to generate first AES-256 key, error code: " << status << std::endl;

	// Generate second key
	status = BCryptGenRandom(nullptr, aes256Key2.data(), static_cast<ULONG>(aes256Key2.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (status != 0)
		std::cerr << "Failed to generate second AES-256 key, error code: " << status << std::endl;
}

int main() {
	if (!Initialize()) {
		std::cerr << "Failed to initialize BCrypt." << std::endl;
		return -1;
	}

	std::array<unsigned char, 32> aes256Key1;
	std::array<unsigned char, 32> aes256Key2;

	GenerateAES256Keys(aes256Key1, aes256Key2);

	std::cout << "AES-256 Key 1: ";
	for (const auto& byte : aes256Key1)
		std::cout << std::format("{:02x}", byte);

	std::cout << "\nAES-256 Key 2: ";
	for (const auto& byte : aes256Key2)
		std::cout << std::format("{:02x}", byte);

	std::cout << std::endl;

	// Clean up
	if (h_Algorithm)
		BCryptCloseAlgorithmProvider(h_Algorithm, 0);

	return 0;
}
