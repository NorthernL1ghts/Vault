#include <iostream>
#include <Windows.h>
#include <bcrypt.h>
#include <array>
#include <format>

#pragma comment(lib, "bcrypt.lib")

BCRYPT_ALG_HANDLE h_Algorithm = nullptr;
bool g_ApplicationRunning = true;

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

void Run() {
	if (!Initialize()) {
		std::cerr << "Failed to initialize BCrypt." << std::endl;
		return;
	}

	std::cout << "Application is running...\n";

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

	while (g_ApplicationRunning) {
		// Application running logic
		// For demonstration, we will stop the application after one iteration
		g_ApplicationRunning = false;
	}
}

void Shutdown() {
	// Perform shutdown tasks
	g_ApplicationRunning = false;
	std::cout << "Shutting down application...\n";

	// Clean up BCrypt resources
	if (h_Algorithm)
		BCryptCloseAlgorithmProvider(h_Algorithm, 0);

	// Exit the application
	exit(0);
}

int main() {
	Run();
	Shutdown();

	return 0;
}
