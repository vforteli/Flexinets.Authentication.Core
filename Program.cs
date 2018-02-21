using log4net;
using log4net.Config;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using System.IO;
using System.Reflection;

namespace FlexinetsAuthentication.Core
{
    public class Program
    {
        public static void Main(string[] args)
        {
            XmlConfigurator.Configure(LogManager.GetRepository(Assembly.GetEntryAssembly()), new FileInfo("log4net.config"));

            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                //.UseSetting("detailedErrors", "true")
                //.CaptureStartupErrors(true)
                .Build();
    }
}

