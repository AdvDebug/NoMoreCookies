using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Windows.Forms;

public class VersionChecker
{

    public static void CheckVersion(string currentVersion)
    {
        try
        {
            WebClient webClient = new WebClient();
            byte[] Version = webClient.DownloadData("https://raw.githubusercontent.com/AdvDebug/NoMoreCookies/main/version");
            string latestVersion = Encoding.UTF8.GetString(Version);
            if (latestVersion == currentVersion)
            {
                Console.Write("You are using the latest version.\n\n");
            }
            else
            {
                Console.Write($"Your version {currentVersion} is outdated. update to the version {latestVersion} from NoMoreCookies Repo.\n\n");
            }
        }
        catch
        {
            Console.WriteLine($"Couldn't check for the latest version.\n\n");
        }
    }
}
