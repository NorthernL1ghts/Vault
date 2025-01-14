#include <iostream>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

void GenerateAES256Keys(unsigned char* key1, unsigned char* key2) {
	NTSTATUS status;

	// Define key size (256 bits = 32 bytes)
	const size_t keySize = 32;

	// Generate first key
	status = BCryptGenRandom(nullptr, key1, keySize, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (status != 0) {
		std::cerr << "Failed to generate key1, error code: " << status << std::endl;
	}

	// Generate second key
	status = BCryptGenRandom(nullptr, key2, keySize, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (status != 0) {
		std::cerr << "Failed to generate key2, error code: " << status << std::endl;
	}
}

int main() {
	unsigned char key1[32];
	unsigned char key2[32];

	GenerateAES256Keys(key1, key2);

	std::cout << "Key1: ";
	for (int i = 0; i < 32; i++) {
		std::cout << std::hex << (int)key1[i];
	}
	std::cout << "\nKey2: ";
	for (int i = 0; i < 32; i++) {
		std::cout << std::hex << (int)key2[i];
	}
	std::cout << std::endl;

	return 0;
}
