using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NoMoreCookiesInstaller
{
    internal class Settings
    {
        public enum InstallationOptions
        {
            MiniMode = 1,
            NormalMode = 2,
            XMode = 3
        };
        public static bool CheckUpdates = true;
        public static bool ShowWarnings = true;
        public static bool DirectInstall = false;
        public static bool DirectUninstall = false;
        public static InstallationOptions Option;
        public static bool ShowBrowsers = false;
        public static bool ShowOutput = true;
        public static bool Debug = false;
    }
}
