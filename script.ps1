<#
    MIT License

    Copyright (c) 2018 José González (0xe62207@gmail.com)

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
#>

$TARGET_USER = "JohnDoe";

function Set-RegistryForUser
{ 
    <# 
        .SYNOPSIS 
        Funcion para modificar los registros del usuario $TARGET_USER
        
        .EXAMPLE 
        PS> Set-RegistryForUser -RegistryInstance @{'Name' = 'Propiedad'; 'Type' = 'String'; 'Value' = 'Hola Mundo'; 'Path' = 'SOFTWARE\Microsoft\Windows\Something'} 
    #> 
    [CmdletBinding()] 
    param ( 
        [Parameter(Mandatory=$true)]
        [hashtable[]]$RegistryInstance 
    ) 
    try
    { 
        ## Si el usuario es el actual escribir en HKEY_CURRENT_USER, si no en HKU:\UserHive (temp)
        if ($env:UserName -eq $TARGET_USER)
        {
            $path = "HKCU:\";
        }
        else
        {
            $path = "HKU:\UserHive\";
            reg load HKU\UserHive "C:\Users\$TARGET_USER\NTUSER.DAT";
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS;
        }
        Write-Host "`n"
        Write-Host "# Cargado perfil de $TARGET_USER"  -ForegroundColor black -BackgroundColor green

        foreach ($instance in $RegistryInstance)
        {

            $path = $path + $instance.Path;
            if (!(Test-Path $path)) { New-Item -Path $path -Force > $null; }
            New-ItemProperty -Path $path -Name $instance.Name -PropertyType $instance.Type -Value $instance.Value -Force > $null;
            Write-Host "... $($instance.Description)";
        }

        Write-Host "* Modificados registros en perfil $TARGET_USER";

        if ($env:UserName -eq $TARGET_USER) {
            Remove-PSDrive -Name HKU;
            reg unload HKU\UserHive;
            [GC]::Collect();
        }
        
    } catch { 
        Write-Warning -Message $_.Exception.Message;
    }
}

$ShowMenu = {
    cls
    Write-Host "================ MENU DE CONFIGURACION ================"
    Write-Host "="
    Write-Host "="
    Write-Host "~   1: Presione '1' para crear los accesos directos en escritorio."
    Write-Host "~   2: Presione '2' para crear las reglas del Firewall de Windows."
    Write-Host "~   3: Presione '3' para bloquear el usuario."
    Write-Host "~   4: Presione '4' para desbloquear el usuario."
    Write-Host "~   Q: Presione 'Q' para finalizar."
    Write-Host "`n"
}

$LockUser = {

    $registryKeys = @(
        @{ 'Path' = 'Control Panel\PowerCfg';                                           'Name' = 'CurrentPowerPolicy';      'Type' = 'String'; 'Value' = '3'; 'Description' = 'Cambiado perfil de energía: Always On (3)' },
        @{ 'Path' = 'Control Panel\Accessibility\StickyKeys';                           'Name' = 'Flags';                   'Type' = 'String'; 'Value' = '506'; 'Description' = 'Desactivado: StickyKeys' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Siuf\Rules';                                    'Name' = 'PeriodInNanoSeconds';     'Type' = 'DWord'; 'Value' = 0x00000000; 'Description' = '' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Siuf\Rules';                                    'Name' = 'NumberOfSIUFInPeriod';    'Type' = 'DWord'; 'Value' = 0x00000000; 'Description' = 'Desactivado: System Initiated User Feedback' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';      'Name' = 'NoDriveTypeAutoRun';      'Type' = 'DWord'; 'Value' = 0x000000ff; 'Description' = 'Desactivado: Autorun en unidades removibles' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';      'Name' = 'NoCDBurning';             'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Grabacion de CD desde Explorer' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';      'Name' = 'NoClose';                 'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Opcion Apagar en menu Inicio' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';      'Name' = 'NoTrayItemsDisplay';      'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = '' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        'Name' = 'NoTrayItemsDisplay';      'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Iconos en la bandeja de la barra de tareas' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';      'Name' = 'NoWinKeys';               'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Accesos directos con la tecla Windows' },
        @{ 'Path' = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';      'Name' = 'NoViewOnDrive';           'Type' = 'DWord'; 'Value' = 0x67108863; 'Description' = 'Desactivado: (Sin confirmar?) Listado de unidades' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\WAU';  'Name' = 'Disabled';                'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Windows Anytime Upgrade' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        'Name' = 'DisableChangePassword';   'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Cambio de contraseña' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        'Name' = 'DisableLockWorkstation';  'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Bloquear equipo' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        'Name' = 'DisableTaskMgr';          'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Administrador de tareas' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        'Name' = 'NoDevMgrPage';            'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Administrador de dispositivos' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        'Name' = 'HideFastUserSwitching';   'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Cambio rapido de usuario Win10' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                    'Name' = 'MBFFLT';                  'Type' = 'String'; 'Value' = 'C:\My\Custom\Program.exe'; 'Description' = 'Agregado programa en autorun' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows Script Host\Settings';                  'Name' = 'Enabled';                 'Type' = 'DWord'; 'Value' = 0x00000000; 'Description' = '' },
        @{ 'Path' = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell';                   'Name' = 'EnableScripts';           'Type' = 'DWord'; 'Value' = 0x00000000; 'Description' = 'Desactivado: Scripting' },
        @{ 'Path' = 'SOFTWARE\Policies\Microsoft\Windows\System';                       'Name' = 'DisableCMD';              'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: CMD' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';      'Name' = 'NoControlPanel';          'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Panel de Control' },
        @{ 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        'Name' = 'DisableRegistryTools';    'Type' = 'DWord'; 'Value' = 0x00000001; 'Description' = 'Desactivado: Registro del sistema' }
    );


    Write-Host "# Aplicando bloqueos generales a nivel de MAQUINA..." -ForegroundColor white -BackgroundColor blue;

    $reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    if (!(Test-Path $reg)) { New-Item -Path $reg -Force > $null }
    New-ItemProperty -Path $reg -Name dontdisplaylastusername -PropertyType DWORD -Value 00000001 -Force > $null;
    Write-Host "... Desactivado: Listado de usuarios en el login";

    $reg = "HKLM:\SYSTEM\CurrentControlSet\Control\Power";
    if (!(Test-Path $reg)) { New-Item -Path $reg -Force > $null }
    New-ItemProperty -Path $reg -Name HibernateEnabled -PropertyType DWORD -Value 00000000 -Force > $null;
    New-ItemProperty -Path $reg -Name HiberFileSizePercent -PropertyType DWORD -Value 00000000 -Force > $null;
    Write-Host "... Desactivado: Modo Hibernacion";


    ## Modificaciones al perfil liquidacion
    
    Write-Host "`n"
    Write-Host "# Aplicando bloqueos al perfil de usuario $TARGET_USER"  -ForegroundColor white -BackgroundColor blue;

    Set-RegistryForUser -RegistryInstance $registryKeys;

    $appDataUsuario = "C:\Users\$TARGET_USER\AppData";
    if (Test-Path -Path $appDataUsuario)
    {
        Remove-Item -Recurse -Force "$appDataUsuario\Roaming\Microsoft\Windows\Start Menu\*";
        Write-Host "... Eliminados links del menu Inicio (perfil usuario)";
    }
    else
    {
        Write-Host "... No se encontró la carpeta AppData para el usuario $TARGET_USER ! Omitida la eliminación de accesos directos en el menú Inicio"  -ForegroundColor white -BackgroundColor red;
    }
}

$UnlockUser = {
    Write-Host "# Desbloqueando funcionalidades..." -BackgroundColor blue -ForegroundColor white;
    Write-Host "`n";

    $registryUnlocks = @(
        @{'Description' = 'Activado Registro de Windows'; 'Name' = 'DisableRegistryTools'; 'Type' = 'Dword'; 'Value' = '0x00000000'; 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'},
        @{ 'Description' = 'Activando Panel de Control'; 'Name' = 'NoControlPanel'; 'Type' = 'Dword'; 'Value' = '0x00000000'; 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'},
        @{ 'Description' = 'Activando Simbolo de Sistema (CMD)'; 'Name' = 'DisableCMD'; 'Type' = 'Dword'; 'Value' = '0x00000000'; 'Path' = 'SOFTWARE\Policies\Microsoft\Windows\System'},
        @{ 'Description' = 'Activando Atajos de la tecla Windows'; 'Name' = 'NoWinKeys'; 'Type' = 'Dword'; 'Value' = '0x00000000'; 'Path' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'}
    );

    Set-RegistryForUser -RegistryInstance $registryUnlocks;
}

$CreateShortcuts = {

        $shortcuts = @(
                @{ "LinkName" = "MyLink1"; "TargetPath" = "C:\My\Path\To\The\Target\file.exe"; "Description" = "My Awesome Shortcut" },
                @{ "LinkName" = "MyLink2"; "TargetPath" = "C:\My\Path\To\The\Target\file.exe"; "Description" = "My Awesome Shortcut" }
            );

        Write-Host "# Creando accesos directos en el escritorio del usuario $TARGET_USER ..." -BackgroundColor blue -ForegroundColor white;
        Write-Host "`n";

        foreach ($lnk in $shortcuts)
        {
            try {
                $Shell = New-Object -ComObject ("WScript.Shell")
                $ShortCut = $Shell.CreateShortcut("C:\Users\$TARGET_USER\Desktop\$($lnk.LinkName).lnk")
                $ShortCut.TargetPath = $lnk.TargetPath
                $ShortCut.WorkingDirectory = Split-Path -parent $lnk.TargetPath;
                $ShortCut.WindowStyle = 1;
                $ShortCut.Description = $lnk.Description;

                if ($lnk.Icon -eq '')
                {
                    $ShortCut.IconLocation = "$($lnk.TargetPath), 0";
                } else {
                    $ShortCut.IconLocation = "$($lnk.Icon), 0";
                }

                $ShortCut.Save();
                Write-Host "... Creado link $($lnk.LinkName)";
                Write-Host "`n";
            } catch { 
                Write-Warning -Message $_.Exception.Message 
            }
        }
}

$CreateFirewallRules = {

    $firewallRules = @(
            @{ "DisplayName" = "My Firewall Rule 1"; "Direction" = "Inbound"; "Action" = "Allow"; "RemoteAddress" = "192.168.100.0/24" },
            @{ "DisplayName" = "My Firewall Rule 2"; "Direction" = "Inbound"; "Action" = "Allow"; "RemoteAddress" = "192.168.100.0/24" }
        );

    Write-Host "# Creando reglas en el Firewall de Windows..." -BackgroundColor blue -ForegroundColor white;
    Write-Host "`n";

    foreach ($rule in $firewallRules)
    {
        Write-Host "Creando regla '$($rule.DisplayName)' para red $($rule.RemoteAddress) ..." -Foreground black -Background green;
        New-NetFirewallRule -DisplayName $rule.DisplayName -Direction $rule.Direction -Action $rule.Action -RemoteAddress $rule.RemoteAddress;
        Write-Host "`n";
    }
}

<#
    MAIN
#>

$userExists = $false;

do
{
    Write-Host "Indique el nombre de usuario de Windows que desea configurar.";
    $TARGET_USER = Read-Host "USUARIO";

    try
    {
        if (Test-Path -Path "C:\Users\$TARGET_USER")
        {
            $userExists = $true;
            Write-Host "Usuario encontrado!" -ForegroundColor black -BackgroundColor green
        } else {
            Write-Host "El usuario indicado no existe, verifique que ha escrito el nombre correctamente." -ForegroundColor black -BackgroundColor red
        }
    } catch {
        Write-Warning -Message $_.Exception.Message;
    }

    pause
} until ($userExists -eq $true)

do
{
    &$ShowMenu
    $input = Read-Host "Seleccione una opción"
    try{
        switch ($input)
        {
            '1' {
                cls
                
                &$CreateShortcuts
            }
            '2' {
                cls
                &$CreateFirewallRules
            }
            '3' {
                cls
                &$LockUser
            }
            '4' {
                cls
                &$UnlockUser
            }
            'q' {
                Write-Host "`n";
                Write-Host -NoNewLine '[Presione una tecla para finalizar]' -BackgroundColor yellow -ForegroundColor black;
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
                return
            }
        }
    } catch {
        Write-Warning -Message $_.Exception.Message;
    }

    pause
}
until ($input -eq 'q')

