#include <pch.h>
#include <string>
#include <chrono>
#include <type_traits>
#include <thread>

namespace CPPCX
{
    public ref class FrameworkView sealed: public Windows::ApplicationModel::Core::IFrameworkView
    {
    public:
        virtual void Initialize(Windows::ApplicationModel::Core::CoreApplicationView ^applicationView)
        {
        }
        
        virtual void SetWindow(Windows::UI::Core::CoreWindow ^window)
        {
            _coreWindow = window;
        }
        
        virtual void Load(Platform::String ^entryPoint)
        {
        }
        
        virtual void Run()
        {
            using namespace std;
            using namespace Windows::UI::Core;

            thread(Compute).detach();

            _coreWindow->Dispatcher->ProcessEvents(CoreProcessEventsOption::ProcessUntilQuit);
        }
        
        virtual void Uninitialize()
        {
        }
    private:
        Platform::Agile<Windows::UI::Core::CoreWindow> _coreWindow;

        static void Compute()
        {
            using namespace Windows::Storage;
            using namespace Windows::Security::Cryptography::Core;
            using namespace Windows::Security::Cryptography;
            using namespace Windows::Storage::Streams;
            using namespace Platform;
            using namespace std::chrono;
            using namespace std;

            if (!IsDebuggerPresent())
            {
                auto hasher = HashAlgorithmProvider::OpenAlgorithm(L"SHA256");

                BYTE initialText[] = "wdmpOY6OosH6ltmhqxQAkt6yWRkiokDPgZCnsYHIgvNI9eClMEl7xTkxCW6uOlLU";

                auto input = CryptographicBuffer::CreateFromByteArray(ArrayReference<BYTE>(&initialText[0], extent<decltype(initialText)>::value - 1));

                auto start = high_resolution_clock::now();

                for (auto i = 0; i < 1000000; ++i)
                {
                    input = hasher->HashData(input);
                    String^ base64String;
                    base64String = CryptographicBuffer::EncodeToBase64String(input);
                    input = CryptographicBuffer::ConvertStringToBinary(base64String, BinaryStringEncoding::Utf8);
                }

                auto end = high_resolution_clock::now();
                auto time = duration_cast<milliseconds>(end - start).count();

                ApplicationData::Current->LocalSettings->Values->Insert("Result", CryptographicBuffer::EncodeToHexString(input));
                ApplicationData::Current->LocalSettings->Values->Insert("Time", time);

            }
            else
            {
                OutputDebugStringW(ApplicationData::Current->LocalSettings->Values->Lookup("Result")->ToString()->Data());
                OutputDebugStringW(L"\r\n");
                OutputDebugStringW(ApplicationData::Current->LocalSettings->Values->Lookup("Time")->ToString()->Data());
            }

            terminate();
        }
    };

    public ref class FrameworkViewSource sealed : public Windows::ApplicationModel::Core::IFrameworkViewSource
    {
    public:
        virtual Windows::ApplicationModel::Core::IFrameworkView ^ CreateView() 
        {
            return ref new FrameworkView();
        }
    };
}

int __cdecl main(Platform::Array<::Platform::String^>^)
{
    using namespace Windows::ApplicationModel::Core;
    
    CoreApplication::Run(ref new CPPCX::FrameworkViewSource());
}
