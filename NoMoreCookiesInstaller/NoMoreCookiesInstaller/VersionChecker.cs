using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Windows.Forms;

public class VersionChecker
{

    public static void CheckVersion(double currentVersion)
    {
        try
        {
            WebClient webClient = new WebClient();
            byte[] Version = webClient.DownloadData("https://raw.githubusercontent.com/AdvDebug/NoMoreCookies/main/version");
            double latestVersion = Convert.ToDouble(Encoding.UTF8.GetString(Version));
            ConsoleColor Color = Console.BackgroundColor;
            if (latestVersion == currentVersion)
            {
                Console.BackgroundColor = ConsoleColor.DarkGreen;
                Console.Write("You are using the latest version.\n\n");
                Console.BackgroundColor = Color;
            }
            else if (latestVersion < currentVersion)
            {
                Console.BackgroundColor = ConsoleColor.DarkYellow;
                Console.Write($"Your version {currentVersion} is... overdated? please use the version {latestVersion} from NoMoreCookies Official Repo if you have an unofficial version.\n\n");
                Console.BackgroundColor = Color;
            }
            else
            {
                Console.BackgroundColor = ConsoleColor.DarkYellow;
                Console.Write($"Your version {currentVersion} is outdated. update to the version {latestVersion} from NoMoreCookies Repo.\n\n");
                Console.BackgroundColor = Color;
            }
        }
        catch
        {
            Console.WriteLine($"Couldn't check for the latest version.\n\n");
        }
    }
}
