rule exec_macros
{
    meta:
        name = "exec_macros"
        severity = 9
        type = "vba"
        description = "exec macros"
        author = "mmpi"
        date = "2020-12-20"

    strings:
        $exec_1 = "Shell"
        $exec_2 = "vbNormal"
        $exec_3 = "vbNormalFocus"
        $exec_4 = "vbHide"
        $exec_5 = "WScript.Shell"
        $exec_6 = "Run"
        $exec_7 = "ShellExecute"
        $exec_8 = "winmgmts"
        $exec_9 = "vbMinimizedFocus"
        $exec_10 = "vbMaximizedFocus"
        $exec_11 = "vbNormalNoFocus"
        $exec_12 = "vbMinimizedNoFocus"
        $exec_13 = "Win32_Process"

    condition:
        (any of ($exec*))
}

rule obfuscate_macros
{
    meta:
        name = "obfuscate_macros"
        severity = 6
        type = "vba"
        author = "mmpi"
        date = "2020-12-20"
        description = "obfuscate macros"

    strings:
        $obfuscate_1 = "Chr"
        $obfuscate_2 = "Xor"
        $obfuscate_3 = "StrReverse"

    condition:
        (any of ($obfuscate*))
}

rule downloader_macros
{
    meta:
        name = "downloader_macros"
        severity = 9
        type = "vba"
        author = "mmpi"
        date = "2020-12-20"
        description = "downloader macros"

    strings:
        $download_1 = "InternetOpen" 
        $download_2 = "InternetOpenUrl" 
        $download_3 = "InternetReadFile" 
        $download_4 = "URLDownloadToFile" 
        $download_5 = "Net.WebClient"
        $download_6 = "DownloadFile"
        $download_7 = "DownloadString"
        $download_8 = "XMLHTTP"
        $download_9 = "User-Agent"

    condition:
        (any of ($download*))
}
