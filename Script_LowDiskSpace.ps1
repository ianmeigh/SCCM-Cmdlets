<#PSScriptInfo

.VERSION 1.0
.AUTHOR Ian Meigh
.COMPANYNAME UOD
.EXTERNALSCRIPTDEPENDENCIES @(Invoke-NXQL)
.RELEASEDATE 08/05/19
.RELEASENOTES

This Script queries Nexthink to return all PC's with less than 15GB remaining (GB or Gigabyte = 1073741824 bytes).
A ticket is then created and a log of the event made, if a ticket is still open the next time the script runs it with add a comment to chase.
If the ticket is solved it will ignore it and if it has been closed and appears again a followup will be created.

Fix when  Invoke-RestMethod, reloading of the powershell runspace until it can't.
https://stackoverflow.com/questions/41897114/unexpected-error-occurred-running-a-simple-unauthorized-rest-query?rq=1
#>

$code = @"
public class SSLHandler
{
    public static System.Net.Security.RemoteCertificateValidationCallback GetSSLHandler()
    {

        return new System.Net.Security.RemoteCertificateValidationCallback((sender, certificate, chain, policyErrors) => { return true; });
    }

}
"@
#compile the class
Add-Type -TypeDefinition $code

#Array to hold Log custom objects
$customLog = @()

#Array to hold Exception custome objects
$ExceptionLog = @()

Add-Type -AssemblyName System.Web
Function Invoke-NXQL {
    <#
	.SYNOPSIS
	Sends an NXQL query to a Nexthink engine.

	.DESCRIPTION
	 Sends an NXQL query to the Web API of Nexthink Engine as HTTP GET using HTTPS.
	 
	.PARAMETER ServerName
	 Nexthink Engine name or IP address.

	.PARAMETER PortNumber
	Port number of the Web API (default 1671).

	.PARAMETER UserName
	User name of the Finder account under which the query is executed.

	.PARAMETER UserPassword
	User password of the Finder account under which the query is executed.

	.PARAMETER NxqlQuery
	NXQL query.

	.PARAMETER FirstParamter
	Value of %1 in the NXQL query.

	.PARAMETER SecondParamter
	Value of %2 in the NXQL query.

	.PARAMETER OuputFormat
	NXQL query output format i.e. csv, xml, html, json (default csv).

	.PARAMETER Platforms
	Platforms on which the query applies i.e. windows, mac_os, mobile (default windows).
	
	.EXAMPLE
	Invoke-Nxql -ServerName 176.31.63.200 -UserName "admin" -UserPassword "admin" 
	-Platforms=windows,mac_os -NxqlQuery "(select (name) (from device))"
	#>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        [Parameter(Mandatory = $true)]
        [string]$UserName,
        [Parameter(Mandatory = $true)]
        [string]$UserPassword,
        [Parameter(Mandatory = $true)]
        [string]$Query,
        [Parameter(Mandatory = $false)]
        [int]$PortNumber = 1671,
        [Parameter(Mandatory = $false)]
        [string]$OuputFormat = "csv",
        [Parameter(Mandatory = $false)]
        [string[]]$Platforms = "windows",
        [Parameter(Mandatory = $false)]
        [string]$FirstParameter,
        [Parameter(Mandatory = $false)]
        [string]$SecondParameter
    )
    $PlaformsString = ""
    Foreach ($platform in $Platforms) {
        $PlaformsString += "&platform={0}" -f $platform
    }
    $EncodedNxqlQuery = [System.Web.HttpUtility]::UrlEncode($Query)
    $Url = "https://{0}:{1}/2/query?query={2}&format={3}{4}" -f $ServerName, $PortNumber, $EncodedNxqlQuery, $OuputFormat, $PlaformsString
    if ($FirstParameter) { 
        $EncodedFirstParameter = [System.Web.HttpUtility]::UrlEncode($FirstParameter)
        $Url = "{0}&p1={1}" -f $Url, $EncodedFirstParameter
    }
    if ($SecondParameter) { 
        $EncodedSecondParameter = [System.Web.HttpUtility]::UrlEncode($SecondParameter)
        $Url = "{0}&p2={1}" -f $Url, $EncodedSecondParameter
    }
    #echo $Url
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } 
        $webclient = New-Object system.net.webclient
        $webclient.Credentials = New-Object System.Net.NetworkCredential($UserName, $UserPassword)
        $webclient.DownloadString($Url)
    }
    catch {
        Write-Host $Error[0].Exception.Message
    }
}; Set-Alias inxql Invoke-Nxql  

Function Read-Ticket ($ID) {

    #-------------------------------------------DECLERATIONS-------------------------------------------#
    #Force the use of TLS 1.2 for API calls
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    #Create the authorisation header to be used in all Invoke-RestMethod for authentication and what format the results should be returned in.
    
    #Email address of agent (MUST BE EQUIVILENT OF AGENT IN LIVE/SANDBOX)
    $email = ""

    #Live API Token
    $APIToken = ""
    #SandBox API Token
    #$APIToken = ""
    
    $ZendeskAuthToken = $email + $APIToken
    $ZendeskAuthTokenEncoded = [Convert]::ToBase64String( [System.Text.Encoding]::ASCII.GetBytes( $ZendeskAuthToken ) )
    $Headers = @{ Authorization = ("Basic " + $ZendeskAuthTokenEncoded); Accept = "application/json" }
    
    #Live URI
    $URI = "https://LIVE_URI.zendesk.com/api/v2/tickets/" + $ID + ".json"
    #Sandbox URI
    #$URI = "https://SANDBOX_URI.zendesk.com/api/v2/tickets/"+$ID+".json"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()
    $result = Invoke-RestMethod -Method Get -Uri $URI -Headers $Headers
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

    Return $result

}

Function Create-Ticket {
    Param(
        [Parameter(Mandatory = $True)]
        $TicketType,

        [Parameter(Mandatory = $False)]
        $TicketID
    )
    Begin {
        $Ticket = @()
    }
    Process {
        if (($TicketType -eq "new") -or ($TicketType -eq "open") -or ($TicketType -eq "pending")) {

            #Add a comment to the existing ticket
            $Body = ""
            $Body += '{"ticket": {"comment": {"body": '
            
            #Live Author
            $Body += '"Nexthink is still reporting this device as having ' + ([double]$result.system_drive_usage * 100) + '% system drive space used, please investigate and rectify this.", "author_id": 13765178749 '
            #Sandbox Author
            #$Body += '"Nexthink is still reporting this device as having ' + ([double]$result.system_drive_usage * 100) + '% system drive space used, please investigate and rectify this.", "author_id": 360422454399 '

            $Body += '}}}'

            #Live URI
            $URI = "https://LIVE_URI.zendesk.com/api/v2/tickets/" + $TicketID + ".json"
            #Sandbox URI
            #$URI = "https://SANDBOX_URI.zendesk.com/api/v2/tickets/"+$TicketID+".json"

            $InvokeMethod = [Microsoft.PowerShell.Commands.WebRequestMethod]::Put

            $Action = "Comment Added"

        }
        elseif ($TicketType -eq "solved") {

            $Action = "solved"
                
        }
        elseif ($TicketType -eq "closed") {

            $ADDescription = Try { (Get-ADComputer -Identity $result.name -Properties Description).Description } Catch { "Not found in AD" }
            if ($ADDescription -eq "") { $ADDescription = "Blank" }

            $distinguished_name = $result.distinguished_name -split '/'

            #Create a followup ticket
            $Body = ""
            $Body += '{"ticket": {"via_followup_source_id": ' + $TicketID + ', "comment": {"body": '
            $Body += '"A follow-up ticket has been created as Nexthink is reporting this device as having ' + ([double]$result.system_drive_usage * 100) + '% system drive space used, please investigate and rectify this:\n\n'
            $Body += '\nHostname: ' + $result.name + '\n'
            $Body += 'AD Description: ' + $ADDescription + '\n'
            $Body += 'Last Known IP Address: ' + $result.last_ip_address + '\n'
            $Body += 'Last Logged on User: ' + $result.last_logged_on_user + '\n'
            $Body += 'Distinguished Name: ' + ($distinguished_name[($distinguished_name.length - 2)] -replace 'OU=') + '\n'
            $Body += 'Last Seen: ' + $result.last_seen + '\n'
            $Body += '\nIf you belive this ticket has been logged in error, please check the Nexthink record and remove if appropriate (https://doc.nexthink.com/Documentation/Nexthink/latest/InstallationAndConfiguration/Removingdevices#Manually_removing_devices).\n\n"'
            #Zendesk Live Group
            $Body += ' }, "priority": "High", "requester_id":13765178749, "group_id":21205352}}'
            #Zendesk Sandbox Group
            #$Body += ' }, "priority": "High", "requester_id":360422454399, "group_id":28219389}}'
            
            #Live URI
            $URI = "https://LIVE_URI.zendesk.com/api/v2/tickets.json"
            #Sandbox URI
            #$URI = "https://SANDBOX_URI.zendesk.com/api/v2/tickets.json"
            
            $InvokeMethod = [Microsoft.PowerShell.Commands.WebRequestMethod]::Post

            $Action = "Followup Ticket Logged"

        }
        else {
        
            #Create a new ticket
            if ([double]($_.system_drive_free_space) -eq 0) {
                $system_drive_free_space = "0 GB"
            }
            elseif ([double]($result.system_drive_free_space) -lt 1073741824) {
            
                $system_drive_free_space = "<1 GB"
            }
            elseif ([double]($result.system_drive_free_space) -ge 1073741824) {
                #Display in GB
                $system_drive_free_space = (($result.system_drive_free_space / 1073741824).ToString("#.##") + "GB")
            }

            $ADDescription = Try { (Get-ADComputer -Identity $result.name -Properties Description).Description } Catch { "Not found in AD" }
            if ($ADDescription -eq "") { $ADDescription = "Blank" }

            $distinguished_name = $result.distinguished_name -split '/'

            $Body += '{ "ticket": {"subject": "Nexthink Alert - Low Disk Space: ' + $result.name + ' - OS: ' + $result.os_version_and_architecture + '", "comment": { "body": '
            $Body += '"The following device has ' + ([double]$result.system_drive_usage * 100) + '% system drive space used, please investigate and rectify this:\n\n'
            $Body += '\nHostname: ' + $result.name + '\n'
            $Body += 'Device Type: ' + $result.device_type + '\n'
            $Body += 'Device Model: ' + $result.device_model + '\n'
            $Body += 'Device Model: ' + $result.os_version_and_architecture + '\n'
            $Body += 'System Drive Capacity: ' + ($result.system_drive_capacity / 1073741824).ToString("#.##") + ' GB\n'
            $Body += 'System Drive Free Space: ' + $system_drive_free_space + '\n'
            $Body += 'Logical Drives: ' + $result.logical_drives + '\n'
            $Body += 'AD Description: ' + $ADDescription + '\n'
            $Body += 'Last Known IP Address: ' + $result.last_ip_address + '\n'
            $Body += 'Last Logged on User: ' + $result.last_logged_on_user + '\n'
            $Body += 'Distinguished Name: ' + ($distinguished_name[($distinguished_name.length - 2)] -replace 'OU=') + '\n'
            $Body += 'Last Seen: ' + $result.last_seen + '\n"'
            #Zendesk Live Group
            $Body += ' }, "priority": "High", "requester_id":13765178749, "group_id":21205352}}'
            #Zendesk Sandbox Group
            #$Body += ' }, "priority": "High", "requester_id":360422454399, "group_id":28219389}}'

            #Live URI
            $URI = "https://LIVE_URI.zendesk.com/api/v2/tickets.json"
            #Sandbox URI
            #$URI = "https://SANDBOX_URI.zendesk.com/api/v2/tickets.json"

            $InvokeMethod = [Microsoft.PowerShell.Commands.WebRequestMethod]::Post

            $Action = "New Ticket Logged"
        }
        $Ticket += [pscustomobject]@{
            Body         = $Body
            URI          = $URI
            InvokeMethod = $InvokeMethod
            Action       = $Action
        }
    }
    End {
        Return $Ticket
    }
}


Function Write-Ticket ($URI, $Body, $InvokeMethod, $Action) {

    Begin {
        #-------------------------------------------DECLERATIONS-------------------------------------------#

        $ZendeskLog = @()

        #Force the use of TLS 1.2 for API calls
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
        #Create the authorisation header to be used in all Invoke-RestMethod for authentication and what format the results should be returned in.
        
        #Email address of agent (MUST BE EQUIVILENT OF AGENT IN LIVE/SANDBOX)
        $email = ""
        
        #Live API Token
        $APIToken = ""
        #SandBox API Token
        #$APIToken = ""
        
        $ZendeskAuthToken = $email + $APIToken
        $ZendeskAuthTokenEncoded = [Convert]::ToBase64String( [System.Text.Encoding]::ASCII.GetBytes( $ZendeskAuthToken ) )
        $Headers = @{ Authorization = ("Basic " + $ZendeskAuthTokenEncoded); Accept = "application/json" }
    }
    Process {
        if ($action -eq "solved") {
            $ZendeskLog = [pscustomobject]@{
                Action       = "Ticket is solved"
                TicketNumber = $existingTicket.ticket.id
                TicketURL    = $existingTicket.ticket.url
                Hostname     = $result.name
                
            }

            Write-Log "$($ZendeskLog.Action),$($ZendeskLog.TicketNumber),$($ZendeskLog.TicketURL),$($ZendeskLog.Hostname)"
        }
        else {
            try {
            
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()
                $ticketStatus = Invoke-RestMethod -Method $InvokeMethod -Uri $URI -Body $Body -ContentType "application/json" -Headers $Headers
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

                $ZendeskLog = [pscustomobject]@{
                    Action       = $Action
                    TicketNumber = $ticketStatus.ticket.id
                    TicketURL    = $ticketStatus.ticket.url
                    Hostname     = $result.name
                
                }

                Write-Log "$($ZendeskLog.Action),$($ZendeskLog.TicketNumber),$($ZendeskLog.TicketURL),$($ZendeskLog.Hostname)"

            }
            catch { Write-Log -Message $error[0] }
        }
    }
    End {
        
    }

}

Function Debug-CloseTicket ($TicketID) {

    $Body = ""
    $Body += '{"ticket": {"comment": {"body": '
    $Body += '"Debugging step to close ticket."'
    $Body += '},"status": "closed" }}'

    #Live URI
    $URI = "https://LIVE_URI.zendesk.com/api/v2/tickets/" + $TicketID + ".json"
    #Sandbox URI
    #$URI = "https://SANDBOX_URI.zendesk.com/api/v2/tickets/"+$TicketID+".json"

    $InvokeMethod = [Microsoft.PowerShell.Commands.WebRequestMethod]::Put
    
    $Action = "DEBUG Closing Ticket"

    Write-Ticket -URI $URI -Body $Body -InvokeMethod $InvokeMethod -Action $Action
}
Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $Message,

        [Parameter(Mandatory = $False)]
        [string]
        $logfile = "C:\temp\Script_NexthinkLowDiskSpace.log"
    )

    $log_exist = Test-Path $logfile
    if ($log_exist -eq $false) {
        New-Item $logfile -ItemType file -Force > $null
    }

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Message"
    If ($logfile) {
        Add-Content $logfile -Value $Line
    }
    Else {
        Write-Output $Line
    }
}

$SecurePassword = Get-Content "C:\temp\NexthinkServiceCredentials.txt" | ConvertTo-SecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

$NexthinkResults = (Invoke-Nxql -ServerName 10.32.4.134 -UserName SRV-Nexthink-prd -UserPassword $UnsecurePassword `
        -Platform windows -OuputFormat csv -Query "(select `
 (id name device_type device_model last_ip_address os_version_and_architecture system_drive_free_space system_drive_capacity system_drive_usage logical_drives last_logged_on_user distinguished_name last_seen) `
 (from device (where device (gt system_drive_usage (percent 0.85)))) (order_by system_drive_usage desc) (limit 3))") `
| ConvertFrom-Csv -Delimiter "`t" | Where-Object { ($_.device_model -ne "VMware Virtual Platform") -and ($_.device_model -ne "Virtual Machine") }

$logFile = get-content "C:\temp\Script_NexthinkLowDiskSpace.log" | ForEach-Object {

    $item = $_.Split(",")

    $customLog += [pscustomobject]@{
        Hostname     = $item[3]
        TicketNumber = $item[1]
        TicketURL    = $item[2]
    }
}

$exceptionList = get-content "C:\Scripts\NexthinkLowDiskSpace\NexthinkLowDiskSpace_Exceptions.txt" | ForEach-Object {

    $item = $_.Split(",")

    $ExceptionLog += [pscustomobject]@{
        Hostname     = $item[0]
        TicketNumber = $item[1]
    }
}

foreach ($result in $NexthinkResults) {
            
    $index = ($customLog | Where-Object { $_.Hostname -contains $result.name })
    
    if($ExceptionLog.Hostname -contains $result.name) {
        Write-Log "$($result.name) is contained within the exception list and has been skipped, see exception list for more details."
    } else {
        #if the object is not null
        if (!($null -eq $index)) {
            
            $existingTicket = Read-Ticket ($index[0].TicketNumber)

            if ($existingTicket.ticket.status -eq "closed") {

                $existingTicket = Read-Ticket ($index[($index.count - 1)].TicketNumber)
            }
            $newTicket = Create-Ticket -TicketType $existingTicket.ticket.status -TicketID $existingTicket.ticket.id
            Write-Ticket -URI $newTicket.URI -Body $newTicket.Body -InvokeMethod $newTicket.InvokeMethod -Action $newTicket.Action
        }
        else {
            $newTicket = Create-Ticket -TicketType "create"
            Write-Ticket -URI $newTicket.URI -Body $newTicket.Body -InvokeMethod $newTicket.InvokeMethod -Action $newTicket.Action
        }
    }
}