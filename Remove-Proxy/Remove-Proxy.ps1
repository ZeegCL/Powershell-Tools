function Remove-RegistryKey ([string]$path, [string]$prop)
{
    if (Test-Path $path)
    {
        if ((Get-ItemProperty -Path $path -Name $prop -ErrorAction SilentlyContinue) -ne $null) {
            Remove-ItemProperty -Path $path -Name $prop
        } else {
            Write-Host "Property $prop not found, skipping..."
        }
        
    }
}

# x86
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value 0
Remove-RegistryKey -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -prop "ProxyOverride"
Remove-RegistryKey -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -prop "ProxyServer"
Remove-RegistryKey -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -prop "DefaultConnectionSettings"
Remove-RegistryKey -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -prop "SavedLegacySettings"

# x64
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value 0
Remove-RegistryKey -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings" -prop "ProxyOverride"
Remove-RegistryKey -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings" -prop "ProxyServer"
Remove-RegistryKey -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -prop "DefaultConnectionSettings"
Remove-RegistryKey -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -prop "SavedLegacySettings"


Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet\ManualProxies" -Name "Default" -Value ""