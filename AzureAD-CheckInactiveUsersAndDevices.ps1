# Checks for inactive users and devices in AzureAD

# Note: This script previously required AzureAD Premium license (P1 or P2) for AuditSignInLogs in Preview version of AzureAD
# However the script has since been converted to utilise the Microsoft.Graph module rather than AzureADPreview/AzureAD.
# I don't know if Microsoft Graph REST API requires specific licensing.

#========#
# ^^^^^^ #
# README #
#========#

########################################################################################################################################################################################################################

# Creates function for checking admin status as it's used twice in modules and dependencies section
function Get-AdminStatus
{
    # Detects if the script is run in admin context, if it is not, the script will exit after letting the user know.
    # This is nested within the module actions as it's not needed for anything else
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false)
    {
        clear-host
        write-warning "Script needs to be run as admin."
        pause
        break
    }
}

#==========================#
# Modules and dependencies #
# VVVVVVVVVVVVVVVVVVVVVVVV #
#==========================#

# QoL setting, prevents the shells progressbar from blocking text
$ProgressPreference = "SilentlyContinue"

#Installs MSGraph module if not installed

if (-not(Get-Module -ListAvailable -Name MSGraph))
{
    Get-AdminStatus
    install-module MSGraph
}
# Creates dependency folder if nonexistant
$folderexist = test-path C:\Parceu
if ($folderexist -eq $false)
{
    New-Item -Path C:\ -Name "Parceu" -ItemType "directory"
}

#==========================#
# ^^^^^^^^^^^^^^^^^^^^^^^^ #
# Modules and dependencies #
#==========================#
#==================#
# Custom functions #
# VVVVVVVVVVVVVVVV #
#==================#


function Get-InactiveDevices
{
    # Deletes and re-creates content file for a fresh start
    $file2exist = test-path C:\Parceu\2_InactiveDevices.txt
    if ($file2exist -eq $true)
    {
        Remove-Item -Path C:\Parceu\2_InactiveDevices.txt -Force
        New-Item -Path C:\Parceu\2_InactiveDevices.txt
    }
    clear-host
    # Sets timespan to 30 days
    $30days = new-timespan -days 30

    # Gets all devices in AD and filters out any non-Windows devices. 
    # Selects the Displayname and ApproximateLastLogonTimeStamp objects
    $Devices = Get-MgDevice | Select-Object DisplayName,OperatingSystem,ApproximateLastSignInDateTime
    
    # Checks each device timestamp
    Foreach ($Device in $Devices)
    {
        # If no timestamp exists the device will be considered unknown
        if ($Device.ApproximateLastSignInDateTime -ne $null)
        {
            # If timestamp exceeds 30 days, the device will be considered inactive
            if (((get-date) - $Device.ApproximateLastSignInDateTime) -gt $30days) 
            {
                $Device.Displayname+" | "+$Device.OperatingSystem+" | "+$Device.ApproximateLastSignInDateTime | Out-File -Encoding UTF8 -append C:\Parceu\2_InactiveDevices.txt
            }
            # If timestamp is below 30 days, the device will be considered active
            if (((get-date) - $Device.ApproximateLastSignInDateTime) -lt $30days) 
            {
                $Device.Displayname+" | "+$Device.OperatingSystem+" | "+$Device.ApproximateLastSignInDateTime | Out-File -Encoding UTF8 -append C:\Parceu\2_ActiveDevices.txt
            }
        }
        # If timestamp can't be found, the device will be considered unknown
        else
        {
            $Device.Displayname+" | "+$Device.OperatingSystem+" | Unknown timestamp" | Out-File -Encoding UTF8 -append C:\Parceu\2_UnknownDevices.txt
        }
    }
}


function Get-InactiveUsers 
{
    # Deletes and re-creates content file for a fresh start
    $file1exist = test-path C:\Parceu\1_InactiveUsers.txt
    if ($file1exist -eq $true)
    {
        Remove-Item -Path C:\Parceu\1_InactiveUsers.txt -Force
        New-Item -Path C:\Parceu\1_InactiveUsers.txt
    }
    clear-host
    write-host "Please wait..."
    # Indexes all logins (inherently 30 days or newer)
    $ActiveUsers = $null
    $UserSignIns = get-MgAuditlogSignIn | select-object UserPrincipalName 
    Foreach ($UserSignIn in $UserSignIns)
    {
        if (-not ($ActiveUsers -match $UserSignIn.UserPrincipalname))
        {
            # Puts them into variable
            $ActiveUsers += $UserSignIn.UserPrincipalname+"`r`n"
        }
    }
    # Indexes all users in AAD
    $AllUsers = Get-MgUser | Select-Object UserPrincipalname
    
    # Exports both active and all users into temporary files for comparing
    $ActiveUsers | Out-File -Encoding UTF8 C:\Parceu\1_Temp_ActiveUsers.txt
    $AllUsers.UserPrincipalname | Out-File -Encoding UTF8 C:\Parceu\1_Temp_AllUsers.txt
    
    # Creates function to get results that only exists in "AllUsers"
    filter inactive{
    param(
            [Parameter(Position=0, Mandatory=$true,ValueFromPipeline = $true)]
            [ValidateNotNullOrEmpty()]
            [PSCustomObject]
            $obj
        )

        $obj|?{$_.sideindicator -eq '<='}

    }

    # Compares all users against active users and filters out active users, leaving only inactive users
    $InactiveUsersCollection = $null
    $InactiveUsers = Compare-Object -ReferenceObject (Get-Content -Path C:\Parceu\1_Temp_AllUsers.txt) -DifferenceObject (Get-Content -Path C:\Parceu\1_Temp_ActiveUsers.txt) | inactive | Select-Object InputObject
    #Takes each inactive account and checks if it is enabled
    foreach ($InactiveUser in $InactiveUsers)
    {
        $InactiveUserUPN = $InactiveUser.InputObject
        $InactiveUserStatus = Get-MgUser -Filter "userPrincipalName eq '$InactiveUserUPN'" | Select-Object AccountEnabled
        if ($InactiveUserStatus.AccountEnabled -eq $True)
        {
            $IsAccountEnabled = "Enabled"
        }
        if ($InactiveUserStatus.AccountEnabled -eq $False)
        {
            $IsAccountEnabled = "Disabled"
        }
        # Puts them into variable
        $InactiveUsersCollection += $InactiveUserUPN+" | "+$IsAccountEnabled+"`r`n"     
    }

    # Removes temporary files
    Remove-Item -Path C:\Parceu\1_Temp_ActiveUsers.txt -Force
    Remove-Item -Path C:\Parceu\1_Temp_AllUsers.txt -Force

    # Exports list of inactive users to file
    $InactiveUsersCollection | Out-File -Encoding UTF8 C:\Parceu\1_InactiveUsers.txt
}

#==================#
# ^^^^^^^^^^^^^^^^ #
# Custom functions #
#==================#

# Connects to AzureAD interactively
# (If running within ISE or any other method that maintains session, it's redundant to log in for each run
# so you can in theory just run this once and then comment it out)
start-sleep 1
clear-host 
write-host "+-------------------------+" -BackGroundColor Black
write-host "| Please login to AzureAD |" -BackGroundColor Black
write-host "| with your admin account |" -BackGroundColor Black
write-host "+-------------------------+" -BackGroundColor Black
Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All","Device.Read.All","AuditLog.Read.All","Directory.Read.All"

#Shows the startup banner main menu.
$MainMenu01 = 
{
    start-sleep 1
    clear-host
    write-host "+---FUNCTIONS------------------------+" -BackGroundColor Black -NoNewLine; write-host "---README-------------------------------------+" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|1. Check for inactive users         |" -BackGroundColor Black -NoNewLine; write-host "                                              |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|                                    |" -BackGroundColor Black -NoNewLine; write-host " Extracts audit data about Azure devices and  |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|------------------------------------|" -BackGroundColor Black -NoNewLine; write-host " users from the AzureAD to determine stale    |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|2. Check for inactive devices       |" -BackGroundColor Black -NoNewLine; write-host " entities, and present them in an             |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|                                    |" -BackGroundColor Black -NoNewLine; write-host " user-friendly format                         |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "+------------------------------------+" -BackGroundColor Black -NoNewLine; write-host "                                              |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|3. Check for both inactive          |" -BackGroundColor Black -NoNewLine; write-host "                                              |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|   users and devices                |" -BackGroundColor Black -NoNewLine; write-host "                             (CTRL+C to exit) |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "+------------------------------------+" -BackGroundColor Black -NoNewLine; write-host "----------------------------------------------+" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host ""
    $MainMenuFunction01 = read-host "Select function (1/2/3)"
    
    #If neither function 1 or function 2 is selected, the user is returned to the main menu. This forces the user to make a valid choice.
    if ($MainMenuFunction01 -ne "1" -and $MainMenuFunction01 -ne "2" -and $MainMenuFunction01 -ne "3")
    {
        &@MainMenu01
    }

    #============#
    # Function 2 #
    # VVVVVVVVVV #
    #============#

    if ($MainMenuFunction01 -eq "2")
    {
        clear-host

        Get-InactiveDevices

        clear-host
        write-host "The following devices have not been active within the last 30 days and are considered inactive:"
        write-host ""
        Get-Content -Path C:\Parceu\2_InactiveDevices.txt | write-host
        write-host ""
        write-host "This list can also be found at C:\Parceu\2_InactiveDevices.txt"
        write-host ""
        pause
        exit
    }

    #============#
    # ^^^^^^^^^^ #
    # Function 2 #
    #============#

    #============#
    # Function 3 #
    # VVVVVVVVVV #
    #============#

    if ($MainMenuFunction01 -eq "3")
    {
        clear-host

        Get-InactiveUsers
        Get-InactiveDevices

        # Tells user to manually check files, in theory they can be sent to console but it creates a lot of scrolling
        # Alternatively copy-paste the console output code from function 1 and 2 with a pause inbetween for a more controlled output rate.
        clear-host
        write-host "Please check files manually."
        write-host "They are located at C:\Parceu\1_InactiveUsers.txt and C:\Parceu\2_InactiveDevices.txt"
        write-host ""
        pause
        exit
    }

    #============#
    # ^^^^^^^^^^ #
    # Function 3 #
    #============#

#If function 1 is selected, the code breaks out of the main menu and will continue from the below point.
}
&@MainMenu01

clear-host
#============#
# Function 1 #
# VVVVVVVVVV #
#============#

clear-host

Get-InactiveUsers

clear-host
write-host "The following users have not been active within the last 30 days and are considered inactive:"
write-host ""
Get-Content -Path C:\Parceu\1_InactiveUsers.txt | write-host
write-host ""
write-host "This list can also be found at C:\Parceu\1_InactiveUsers.txt"
write-host ""
pause
exit

#============#
# ^^^^^^^^^^ #
# Function 1 #
#============#
########################################################################################################################################################################################################################
#=========#
# The end #
#=========#
