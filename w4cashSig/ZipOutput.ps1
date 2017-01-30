Add-Type -assembly "system.io.compression.filesystem"
$PSScriptRoot
if(Test-Path "$PSScriptRoot\bin\w4cashSig.zip")
{
    Remove-Item -Force "$PSScriptRoot\bin\w4cashSig.zip"
}
$source = "$PSScriptRoot\bin\x86\Debug\"
$dest = "$PSScriptRoot\bin\w4cashSig.zip"
[io.compression.zipfile]::CreateFromDirectory($source, $dest)

