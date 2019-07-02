<#PSScriptInfo

.VERSION 1.1
.AUTHOR Ian Meigh
.COMPANYNAME UOD
.EXTERNALSCRIPTDEPENDENCIES
.RELEASEDATE 10/04/19
.RELEASENOTES https://community.spiceworks.com/topic/1947438-delete-sccm-device-and-ad-computer-account-in-1-step
#>

Function Start-SCCMRuntimeChecks
{
    [CmdletBinding()]
Param
(
    [switch]$silent
)
    if ($silent -eq $false){
        Write-Host "Running Pre-Requisite Checks..." -ForegroundColor Green
    }
    $SCCMSite = "DB1"
    $SCCMSitePath = $SCCMSite + ":"

    if ($null -ne ($env:SMS_ADMIN_UI_PATH)) {
        #Write-Information "SCCM Environment path exists:" $env:SMS_ADMIN_UI_PATH -ForegroundColor Green
    }
    else {
        Write-Error "You have not run up the SCCM Console before .... please run up SCCM console first and then re-run script  exiting........"
        break
    }

    <#
    # Check to see if user acocunt has rights to SCCM to carry out function
    # REMOVED as no common group to control SCCM access
    if ((Get-ADPrincipalGroupMembership -Identity $env:USERNAME | Where-Object name -eq "ROLE-G-SnrDskEng-UNV")) {
        #Write-Information "$env:USERNAME belongs to ROLE-G-SnrDskEng-UNV AD Group" -ForegroundColor Green
    }
    else {
        Write-Error "You do not belong to the SEC_SCCM_Admin group.. Gain access and then re-run script  exiting........"
        break
    }
    #>
    
    # Check if the user has run SCCM Console once
    # If they have then the "HKCU:\Software\Microsoft\ConfigMgr10" registry entry will exist
    try {
        Set-Location "HKCU:\Software\Microsoft\ConfigMgr10" -ErrorAction Stop
    }

    catch [System.Net.WebException], [System.Exception] {
        Write-Error "User: $env:Username has NOT SCCM Console before ... Exiting"
        Break
    }

    #Write-Output "User: $env:Username has run SCCM Console before carrying on"

    Import-Module (Join-Path $(Split-Path $env:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1)
    # Set current directory to SCCM site
    Set-Location -Path $SCCMSitePath
    if ($silent -eq $false){
        Write-Host "`nPASS!" -ForegroundColor Green
    }
}