# NoMoreCookies
<p align="center">
<a href="#"><img src="https://github.com/AdvDebug/NoMoreCookies/blob/main/NoMoreCookiesNew.jpg" height="200"></a>
</p>
<div>
Browser Protector against various stealers, written in C# & C/C++. (Just a small note, please don't use this protection in a SecureBoot-Enabled environment yet as this protection doesn't fully support SecureBoot yet and may cause problems, also this protection is in UM which means it can be bypassed but it's still a pretty good enough solution)
</div>

<div>
Works by hooking NtCreateFile & NtOpenFile and prevent accessing browser files, and also protections the browser memory if you choosed the "X Mode", in addition to prevent some types of unhooking. compatible with various games and software. (contributions are very welcomed)
</div>
#### Stealers/RATs Tested
* <a href="https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp">AsyncRAT</a>
* <a href="https://github.com/quasar/Quasar">Quasar RAT</a>
* <a href="https://github.com/swagkarna/StormKitty">StormKitty</a>
* <a href="https://github.com/moonD4rk/HackBrowserData">HackBrowserData</a>
* <a href="https://github.com/LimerBoy/FireFox-Thief">FireFox-Thief</a>
* <a href="https://github.com/qwqdanchun/DcRat">DcRat</a>
* <a href="https://github.com/Blank-c/Umbral-Stealer">Umbral Stealer</a>
* <a href="https://github.com/Blank-c/Blank-Grabber">Blank Grabber</a>
* <a href="https://venomcontrol.com">Venom RAT</a>
* XWorm RAT
* Raccoon Stealer
* EdgeGuard
* Vidar
* RedLine

and it should work against other popular stealers. and please note that this protection doesn't only work with these listed above, it will work with future stealers as well as this protection is universal and not targeted against a specific kind/family of stealers.

Supported Browsers:

* <a href="https://www.mozilla.org/en-US/firefox/browsers">Firefox</a>
* <a href="https://brave.com">Brave<a/>
* <a href="https://www.google.com/chrome">Chrome</a>
* <a href="https://www.microsoft.com/en-us/edge">Microsoft Edge</a>
* <a href="https://browser.yandex.com">Yandex</a>
* <a href="https://www.opera.com">Opera</a>
* <a href="https://www.waterfox.net">Waterfox</a>
* <a href="https://vivaldi.com">Vivaldi</a>
#### Installation 
you can find the release <a href="https://github.com/AdvDebug/NoMoreCookies/releases/tag/NoMoreCookies_2.2">here</a>, after you extract the files execute NoMoreCookiesInstaller.exe which will give you the option to both install and uninstall NoMoreCookies.

<a href="#installation"><img src="https://github.com/AdvDebug/NoMoreCookies/blob/main/NoMoreCookiesInstallerr.PNG?raw=true"></img></a>

in the installer you can see all options and what each one does so you can choose whatever suits you, and after installation/uninstallation it's recommended to restart your system so that the protection are fully activated/gone.

#### Showcase
if any Stealer/RAT tried to access your browser files you would get a notification, preventing the Stealer/RAT from accessing it and warning you about it.


![NoMoreCookies](https://github.com/AdvDebug/NoMoreCookies/assets/90452585/ad4d07bf-2b84-488f-8bad-cf8241c89d84)

### Contribution

if you are a C#/C++ developer and want to contribute, make a fork and make a pull request with the mentioning of the changes you have made and why do you think this change is a good idea.

you can find <a href="https://github.com/AdvDebug/NoMoreCookies/blob/main/CONTRIBUTORS.md">here</a> all the contributors that contributed to this project.

### Disclaimer

This Project is for educational purposes only. me, the developer, are not responsible for any kind of misuse.

### Donation
if you liked my work, feel free to donate!

BTC: bc1qt4959hf9t6k940u8l4x3khw8gfrrp5znwu29yw

ETH: 0x2dD43a77034361C1Dd702343BF6f4a42BF741b2F

# License
The Program, Libraries, etc. are licensed under MIT License.
