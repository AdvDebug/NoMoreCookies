using System;
using System.Net.Http;

public class VersionChecker
{
    private HttpClient client;

    public VersionChecker()
    {
        client = new HttpClient();
    }

    public void CheckVersion(string currentVersion)
    {
        try
        {
            HttpResponseMessage response = client.GetAsync("https://raw.githubusercontent.com/AdvDebug/NoMoreCookies/main/version").Result;
            response.EnsureSuccessStatusCode();
            string responseContent = response.Content.ReadAsStringAsync().Result;
            string latestVersion = responseContent.Trim();

            if (latestVersion == currentVersion)
            {
                Console.WriteLine("You are using the latest version.");
            }
            else
            {
                Console.WriteLine($"Your version {currentVersion} is outdated. Please update to version {latestVersion} | https://github.com/AdvDebug/NoMoreCookies/releases");
                Console.Read();
                Environment.Exit(0);
            }
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine($"Error occurred while checking the version: {e.Message}");
        }
    }
}
