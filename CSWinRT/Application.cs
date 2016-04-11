#define DEBUG
using System;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Core;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.UI.Core;

namespace CSWinRT
{
    internal sealed class FrameworkView : IFrameworkView
    {
        private static void Compute()
        {
            if (Debugger.IsAttached)
            {
                Debug.WriteLine(ApplicationData.Current.LocalSettings.Values["Result"]);
                Debug.Write(ApplicationData.Current.LocalSettings.Values["Time"]);
            }
            else
            {
                var hasher = HashAlgorithmProvider.OpenAlgorithm("SHA256");

                const String initialText = "wdmpOY6OosH6ltmhqxQAkt6yWRkiokDPgZCnsYHIgvNI9eClMEl7xTkxCW6uOlLU";
                var input = Encoding.ASCII.GetBytes(initialText).AsBuffer();

                var sw = Stopwatch.StartNew();

                for (var i = 0; i < 1000000; i++)
                {
                    input = hasher.HashData(input);
                    input = CryptographicBuffer.ConvertStringToBinary(CryptographicBuffer.EncodeToBase64String(input), BinaryStringEncoding.Utf8);
                }

                GC.Collect(2, GCCollectionMode.Forced, true);

                sw.Stop();

                ApplicationData.Current.LocalSettings.Values["Result"] = CryptographicBuffer.EncodeToHexString(input);
                ApplicationData.Current.LocalSettings.Values["Time"] = sw.ElapsedMilliseconds;

                CoreApplication.Exit();
            }
        }

        private CoreWindow _coreWindow;

        public void Initialize(CoreApplicationView applicationView) { }

        public void Load(String entryPoint) { }

        public void Run()
        {
            Task.Run(() => Compute());

            _coreWindow.Activate();

            _coreWindow.Dispatcher.ProcessEvents(CoreProcessEventsOption.ProcessUntilQuit);
        }

        public void SetWindow(CoreWindow window)
        {
            _coreWindow = window;
        }

        public void Uninitialize() { }
    }

    internal sealed class FrameworkViewSource : IFrameworkViewSource
    {
        public IFrameworkView CreateView()
        {
            return new FrameworkView();
        }
    }

    internal static class Application
    {
        [MTAThread]
        public static void Main()
        {
            CoreApplication.Run(new FrameworkViewSource());
        }
    }
}