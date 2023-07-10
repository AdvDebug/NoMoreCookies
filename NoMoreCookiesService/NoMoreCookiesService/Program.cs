using System.ServiceProcess;
using System.Threading;

namespace NoMoreCookiesService
{
    internal static class Program
    {
        static void Main()
        {
            Thread.Sleep(10000);
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new MainService()
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}
