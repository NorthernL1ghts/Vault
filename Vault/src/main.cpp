#include <iostream>
#include <Windows.h>
#include <bcrypt.h>
#include <array>
#include <format>
#include <atomic>
#include <thread>
#include <vector>
#include <functional>
#include <mutex>
#include <csignal>

constexpr const char* ROOT_DIR = "C:\\Dev\\Vault";

#pragma comment(lib, "bcrypt.lib")

using ByteArray32 = std::array<unsigned char, 32>;
using ByteArray64 = std::array<unsigned char, 64>;
using FunctionQueue = std::vector<std::function<void()>>;
using MutexLock = std::scoped_lock<std::mutex>;

BCRYPT_ALG_HANDLE h_Algorithm = nullptr;
std::atomic<bool> g_ApplicationRunning(true);
static std::thread s_MainThread;
static std::thread s_KeyThread;
static std::thread::id s_MainThreadID;
FunctionQueue m_MainThreadQueue;
std::mutex m_MainThreadQueueMutex;

static bool Initialize();
static void GenerateAES256Keys(ByteArray32& aes256Key1, ByteArray32& aes256Key2);
static void ConcatenateKeys(const ByteArray32& aes256Key1, const ByteArray32& aes256Key2, ByteArray64& aes512Key);
static void SubmitToMainThread(const std::function<void()>& function);
static void ExecuteMainThreadQueue();
static void Shutdown();
static void KeyMonitor();
static void Run();

void SignalHandler(int signal)
{
	if (signal == SIGINT)
	{
		std::cout << "SIGINT received. Initiating shutdown...\n";
		SubmitToMainThread(Shutdown);
	}
}

static bool Initialize()
{
	NTSTATUS status = BCryptOpenAlgorithmProvider(&h_Algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
	if (status != 0)
	{
		std::cerr << "Failed to open algorithm provider, error code: " << status << '\n';
		return false;
	}
	return true;
}

static void GenerateAES256Keys(ByteArray32& aes256Key1, ByteArray32& aes256Key2)
{
	NTSTATUS status;

	status = BCryptGenRandom(nullptr, aes256Key1.data(), static_cast<ULONG>(aes256Key1.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (status != 0)
		std::cerr << "Failed to generate first AES-256 key, error code: " << status << '\n';

	status = BCryptGenRandom(nullptr, aes256Key2.data(), static_cast<ULONG>(aes256Key2.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (status != 0)
		std::cerr << "Failed to generate second AES-256 key, error code: " << status << '\n';
}

static void ConcatenateKeys(const ByteArray32& aes256Key1, const ByteArray32& aes256Key2, ByteArray64& aes512Key)
{
	std::copy(aes256Key1.begin(), aes256Key1.end(), aes512Key.begin());
	std::copy(aes256Key2.begin(), aes256Key2.end(), aes512Key.begin() + 32);
}

static void SubmitToMainThread(const std::function<void()>& function)
{
	MutexLock lock(m_MainThreadQueueMutex);
	m_MainThreadQueue.emplace_back(function);
}

static void ExecuteMainThreadQueue()
{
	FunctionQueue queueCopy;
	{
		MutexLock lock(m_MainThreadQueueMutex);
		queueCopy.swap(m_MainThreadQueue);
	}

	for (auto& func : queueCopy)
		func();
}

static void Shutdown()
{
	g_ApplicationRunning = false;
	std::cout << "Shutting down application...\n";

	if (h_Algorithm)
		BCryptCloseAlgorithmProvider(h_Algorithm, 0);

	if (s_MainThread.joinable())
		s_MainThread.join();

	if (s_KeyThread.joinable())
		s_KeyThread.join();
}

static void KeyMonitor()
{
	while (g_ApplicationRunning)
	{
		if ((GetAsyncKeyState('Q') & 0x8000) || (GetAsyncKeyState('q') & 0x8000))
		{
			std::cout << "Termination key (q/Q) pressed. Initiating shutdown...\n";
			SubmitToMainThread(Shutdown);
			return;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

static void Run()
{
	s_MainThreadID = std::this_thread::get_id();
	std::cout << "Main thread ID: " << s_MainThreadID << '\n';

	if (!Initialize())
	{
		std::cerr << "Failed to initialize BCrypt.\n";
		return;
	}

	std::cout << "Application is running...\n";

	ByteArray32 aes256Key1;
	ByteArray32 aes256Key2;
	ByteArray64 aes512Key;

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

	s_KeyThread = std::thread(KeyMonitor);

	while (g_ApplicationRunning)
		ExecuteMainThreadQueue();

	Shutdown();
}

int main()
{
	signal(SIGINT, SignalHandler);
	s_MainThread = std::thread(Run);
	if (s_MainThread.joinable())
		s_MainThread.join();
	return 0;
}
