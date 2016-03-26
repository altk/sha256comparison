#define DEBUG
using System;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Core;
using Windows.Security.Cryptography;
using Windows.Storage;
using Windows.UI.Core;

namespace CS
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
                const String initialText = "wdmpOY6OosH6ltmhqxQAkt6yWRkiokDPgZCnsYHIgvNI9eClMEl7xTkxCW6uOlLU";
                var input = Encoding.ASCII.GetBytes(initialText);

                var sw = Stopwatch.StartNew();

                for (var i = 0; i < 1000000; i++)
                {
                    var hasher = new Sha256();
                    hasher.AddData(input, 0, (UInt32) input.Length);
                    var hash = hasher.GetHash();
                    input = new Byte[hash.Length * 4];
                    for (var j = 0; j < hash.Length; j++)
                    {
                        var temp = BitConverter.GetBytes(hash[j]);
                        input[4 * j + 0] = temp[3];
                        input[4 * j + 1] = temp[2];
                        input[4 * j + 2] = temp[1];
                        input[4 * j + 3] = temp[0];
                    }
                    input = Encoding.ASCII.GetBytes(Convert.ToBase64String(input));
                    input = Encoding.ASCII.GetBytes(Convert.ToBase64String(input));
                }

                GC.Collect(2, GCCollectionMode.Forced, true);

                sw.Stop();

                ApplicationData.Current.LocalSettings.Values["Result"] = CryptographicBuffer.EncodeToHexString(input.AsBuffer());
                ApplicationData.Current.LocalSettings.Values["Time"] = sw.ElapsedMilliseconds;
            }

            throw new Exception();
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

    public static class Application
    {
        [MTAThread]
        public static void Main()
        {
            CoreApplication.Run(new FrameworkViewSource());
        }
    }
}