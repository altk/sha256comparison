#include <pch.h>
#include <string>
#include <chrono>
#include <type_traits>
#include <wrl.h>
#include <windows.security.cryptography.core.h>
#include <windows.security.cryptography.h>
#include <windows.storage.streams.h>
#include <thread>

class FrameworkView sealed : public Microsoft::WRL::RuntimeClass<ABI::Windows::ApplicationModel::Core::IFrameworkView>
{
    InspectableClass(L"FrameworkView", BaseTrust);

public:
    HRESULT __stdcall Initialize(ABI::Windows::ApplicationModel::Core::ICoreApplicationView *) override
    {
        return S_OK;
    }

    HRESULT __stdcall SetWindow(ABI::Windows::UI::Core::ICoreWindow *coreWindow) override
    {
        _coreWindow = coreWindow;
        return S_OK;
    }

    HRESULT __stdcall Load(HSTRING) override
    {
        return S_OK;
    }

    HRESULT __stdcall Run() override
    {
        using namespace Microsoft::WRL;
        using namespace ABI::Windows::UI::Core;
        using namespace std;

        ComPtr<ICoreDispatcher> dispatcher;

        _coreWindow->Activate();

        _coreWindow->get_Dispatcher(&dispatcher);

        thread(Compute).detach();

        dispatcher->ProcessEvents(CoreProcessEventsOption_ProcessUntilQuit);
        
        return S_OK;
    }

    HRESULT __stdcall Uninitialize() override
    {
        return S_OK;
    }

private:

    ABI::Windows::UI::Core::ICoreWindow *_coreWindow;

    static void Compute() noexcept
    {
        using namespace Microsoft::WRL::Wrappers;
        using namespace Microsoft::WRL;
        using namespace ABI::Windows::UI::Core;
        using namespace ABI::Windows::Security::Cryptography::Core;
        using namespace ABI::Windows::Security::Cryptography;
        using namespace ABI::Windows::Storage::Streams;
        using namespace ABI::Windows::Storage;
        using namespace ABI::Windows::Foundation::Collections;
        using namespace ABI::Windows::Foundation;
        using namespace std::chrono;
        using namespace std;

        ComPtr<IApplicationDataStatics> applicationDataStatics;
        ComPtr<IApplicationData> applicationData;
        ComPtr<IApplicationDataContainer> localSettings;
        ComPtr<IPropertySet> values;
        ComPtr<IMap<HSTRING, IInspectable*>> map;

        GetActivationFactory(HStringReference(RuntimeClass_Windows_Storage_ApplicationData).Get(),
                             &applicationDataStatics);

        applicationDataStatics->get_Current(applicationData.GetAddressOf());

        applicationData->get_LocalSettings(localSettings.GetAddressOf());

        localSettings->get_Values(values.GetAddressOf());

        values.As(&map);

        if (IsDebuggerPresent())
        {
            ComPtr<IInspectable> result;
            ComPtr<IInspectable> time;
            ComPtr<IPropertyValue> resultValue;
            ComPtr<IPropertyValue> timeValue;
            HString resultString;
            INT64 timeInt64;
            UINT32 length;

            map->Lookup(HStringReference(L"Result").Get(), result.GetAddressOf());

            result.As(&resultValue);

            resultValue->GetString(resultString.GetAddressOf());

            map->Lookup(HStringReference(L"Time").Get(), time.GetAddressOf());

            time.As(&timeValue);

            timeValue->GetInt64(&timeInt64);

            OutputDebugStringW(resultString.GetRawBuffer(&length));
            OutputDebugStringW(L"\r\n");
            OutputDebugStringW(to_wstring(timeInt64).data());
        }
        else
        {
            const char initialText[] = "wdmpOY6OosH6ltmhqxQAkt6yWRkiokDPgZCnsYHIgvNI9eClMEl7xTkxCW6uOlLU";

            ComPtr<ICryptographicBufferStatics> cryptoBufferStatics;
            ComPtr<IHashAlgorithmProviderStatics> providerStatics;
            ComPtr<IHashAlgorithmProvider> hasher;
            ComPtr<IActivationFactory> dataWriterActivationFactory;
            ComPtr<IDataWriter> dataWriter;
            ComPtr<IBuffer> input;
            HString hexString;
            ComPtr<IPropertyValueStatics> propertyValueStatics;
            ComPtr<IPropertyValue> resultValue;
            ComPtr<IPropertyValue> timeValue;
            BOOLEAN replaced;

            GetActivationFactory(HStringReference(RuntimeClass_Windows_Security_Cryptography_Core_HashAlgorithmProvider).Get(),
                                 &providerStatics);

            GetActivationFactory(HStringReference(RuntimeClass_Windows_Storage_Streams_DataWriter).Get(),
                                 &dataWriterActivationFactory);

            GetActivationFactory(HStringReference(RuntimeClass_Windows_Security_Cryptography_CryptographicBuffer).Get(),
                                 &cryptoBufferStatics);

            GetActivationFactory(HStringReference(RuntimeClass_Windows_Foundation_PropertyValue).Get(),
                                 &propertyValueStatics);

            dataWriterActivationFactory->ActivateInstance(&dataWriter);

            providerStatics->OpenAlgorithm(HStringReference(L"SHA256").Get(),
                                           &hasher);

            cryptoBufferStatics->CreateFromByteArray(extent<decltype(initialText)>::value - 1,
                                                     (BYTE*)initialText,
                                                     input.ReleaseAndGetAddressOf());

            auto start = high_resolution_clock::now();

            for (auto i = 0; i < 1000000; ++i)
            {
                auto temp = input;
                HString base64String;

                hasher->HashData(temp.Get(), input.ReleaseAndGetAddressOf());

                cryptoBufferStatics->EncodeToBase64String(input.Get(), base64String.GetAddressOf());

                cryptoBufferStatics->ConvertStringToBinary(base64String.Get(),
                                                           BinaryStringEncoding_Utf8,
                                                           input.ReleaseAndGetAddressOf());
            }

            auto end = high_resolution_clock::now();
            auto time = duration_cast<milliseconds>(end - start).count();

            cryptoBufferStatics->EncodeToHexString(input.Get(), hexString.GetAddressOf());

            propertyValueStatics->CreateString(hexString.Get(), &resultValue);

            propertyValueStatics->CreateInt64(time, &timeValue);

            map->Insert(HStringReference(L"Result").Get(), resultValue.Get(), &replaced);

            map->Insert(HStringReference(L"Time").Get(), timeValue.Get(), &replaced);
        }

        terminate();
    }
};

class FrameworkViewSource sealed : public Microsoft::WRL::RuntimeClass<ABI::Windows::ApplicationModel::Core::IFrameworkViewSource>
{
public:
    InspectableClass(L"FrameworkViewSource", BaseTrust);

    HRESULT __stdcall CreateView(ABI::Windows::ApplicationModel::Core::IFrameworkView **viewProvider) override
    {
        *viewProvider = Microsoft::WRL::Make<FrameworkView>().Detach();
        return S_OK;
    }
};

void CALLBACK WinMain(HINSTANCE,
                      HINSTANCE,
                      LPSTR,
                      int)
{
    using namespace Microsoft::WRL::Wrappers;
    using namespace Microsoft::WRL;
    using namespace ABI::Windows::ApplicationModel::Core;
    using namespace ABI::Windows::Foundation;

    RoInitialize(RO_INIT_MULTITHREADED);

    ComPtr<ICoreApplication> coreApplication;
    GetActivationFactory(HStringReference(RuntimeClass_Windows_ApplicationModel_Core_CoreApplication).Get(),
                         &coreApplication);

    coreApplication->Run(Make<FrameworkViewSource>().Get());
}
