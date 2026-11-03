// procwatch built-in content rules (YARA subset). Written for procwatch;
// add your own under the config folder's yara/ directory.

rule PW_UPX_Packed_Executable : packer
{
  meta:
    description = "Executable packed with UPX (common for commodity malware, also some legitimate tools)"
    severity = "low"
  strings:
    $u0 = "UPX0"
    $u1 = "UPX1"
    $u2 = "UPX!"
  condition:
    (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA) and 2 of them
}

rule PW_Credential_Dumper_Strings : credential_access
{
  meta:
    description = "Command strings of a well-known credential dumping tool"
    severity = "high"
  strings:
    $a = "sekurlsa::logonpasswords" nocase ascii wide
    $b = "lsadump::sam" nocase ascii wide
    $c = "privilege::debug" nocase ascii wide
    $d = "gentilkiwi" nocase ascii wide
  condition:
    2 of them
}

rule PW_PHP_Web_Shell : webshell
{
  meta:
    description = "PHP code that evaluates request data or decoded payloads"
    severity = "high"
  strings:
    $php = "<?php" nocase
    $e1 = "eval(base64_decode(" nocase
    $e2 = "eval($_POST[" nocase
    $e3 = "eval($_REQUEST[" nocase
    $e4 = "assert($_REQUEST" nocase
    $e5 = "system($_GET[" nocase
  condition:
    $php and any of ($e*)
}

rule PW_Reverse_Shell_Script : execution
{
  meta:
    description = "Script that connects an interactive shell to a network socket"
    severity = "high"
  strings:
    $tcp = "/dev/tcp/"
    $i1 = "bash -i"
    $i2 = "sh -i"
    $nc = "nc -e" fullword
  condition:
    ($tcp and any of ($i*)) or $nc
}

rule PW_PowerShell_Download_Cradle : execution
{
  meta:
    description = "PowerShell that downloads and immediately runs code"
    severity = "medium"
  strings:
    $d1 = "DownloadString(" nocase ascii wide
    $d2 = "Invoke-WebRequest" nocase ascii wide
    $x1 = "IEX" fullword nocase ascii wide
    $x2 = "Invoke-Expression" nocase ascii wide
  condition:
    any of ($d*) and any of ($x*)
}

rule PW_Scripted_Admin_Prompt : credential_access
{
  meta:
    description = "AppleScript that asks for administrator privileges — used by installers and by password-phishing malware"
    severity = "low"
    confidence = "low"
  strings:
    $a = "do shell script" nocase
    $b = "with administrator privileges" nocase
  condition:
    all of them
}
