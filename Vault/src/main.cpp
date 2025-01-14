#include <iostream>
#include <Windows.h>
#include <bcrypt.h>
#include <array>
#include <format>
#include <atomic>

#pragma comment(lib, "bcrypt.lib")

BCRYPT_ALG_HANDLE h_Algorithm = nullptr;
std::atomic<bool> g_ApplicationRunning(true);

bool Initialize()
{
	NTSTATUS status = BCryptOpenAlgorithmProvider(&h_Algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
	if (status != 0)
	{
		std::cerr << "Failed to open algorithm provider, error code: " << status << '\n';
		return false;
	}
	return true;
}

void GenerateAES256Keys(std::array<unsigned char, 32>& aes256Key1, std::array<unsigned char, 32>& aes256Key2)
{
	NTSTATUS status;

	status = BCryptGenRandom(nullptr, aes256Key1.data(), static_cast<ULONG>(aes256Key1.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (status != 0)
		std::cerr << "Failed to generate first AES-256 key, error code: " << status << '\n';

	status = BCryptGenRandom(nullptr, aes256Key2.data(), static_cast<ULONG>(aes256Key2.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (status != 0)
		std::cerr << "Failed to generate second AES-256 key, error code: " << status << '\n';
}

void ConcatenateKeys(const std::array<unsigned char, 32>& aes256Key1, const std::array<unsigned char, 32>& aes256Key2, std::array<unsigned char, 64>& aes512Key)
{
	std::copy(aes256Key1.begin(), aes256Key1.end(), aes512Key.begin());
	std::copy(aes256Key2.begin(), aes256Key2.end(), aes512Key.begin() + 32);
}

void Run()
{
	if (!Initialize())
	{
		std::cerr << "Failed to initialize BCrypt." << '\n';
		return;
	}

	std::cout << "Application is running...\n";

	std::array<unsigned char, 32> aes256Key1;
	std::array<unsigned char, 32> aes256Key2;
	std::array<unsigned char, 64> aes512Key;

	GenerateAES256Keys(aes256Key1, aes256Key2);
	ConcatenateKeys(aes256Key1, aes256Key2, aes512Key);

	std::cout << "Generated AES-256 Key 1: ";
	for (const auto& byte : aes256Key1)
		std::cout << std::format("{:02x}", byte);

	std::cout << "\nGenerated AES-256 Key 2: ";
	for (const auto& byte : aes256Key2)
		std::cout << std::format("{:02x}", byte);

	std::cout << "\nGenerated AES-512 Key: ";
	for (const auto& byte : aes512Key)
		std::cout << std::format("{:02x}", byte);

	std::cout << '\n';

	while (g_ApplicationRunning)
	{
	}

	Shutdown();  // Call Shutdown here
}

void Shutdown()
{
	g_ApplicationRunning = false;
	std::cout << "Shutting down application...\n";

	if (h_Algorithm)
		BCryptCloseAlgorithmProvider(h_Algorithm, 0);
}

int main()
{
	Run();
	return 0;
}
