<#PSScriptInfo

.VERSION 1.0
.AUTHOR Ian Meigh
.COMPANYNAME UOD
.EXTERNALSCRIPTDEPENDENCIES @(Start-SCCMRuntimeChecks.ps1)
.RELEASEDATE 10/04/19
.RELEASENOTES

#>

<#
.SYNOPSIS
    Script will check if a hostname exsits in Active Directory and SCCM.
.DESCRIPTION
    This script will test if a given hostname (either specified explicilty or from the pipeline) exsits in Active Directory and SCCM.
    It will futher check that if the SCCM client is installed.
.INPUTS
    You can pipe an array of hostnames to Test-DeviceExists.
.OUTPUTS
    System.Array - Test-DeviceExists returns an array with results if multiple values are supplied.
    System.Object  - Test-DeviceExists returns a PSCustomObject if a single value is supplied.
.PARAMETER ComputerName [Mandatory]
    The ComputerName, which can be provided through the pipeline or via a comma deliminated list, defines the hostname you wish to test.
.EXAMPLE
    Get-Content "C:\hostnames.txt" | Test-DeviceExists
    
    Command will test if all computers in the file specifed exist in AD and SCCM.
.EXAMPLE
    Test-DeviceExists -ComputerName HOST1

    Command will test if the computer "HOST1" exists in AD and SCCM.
.EXAMPLE
    Test-DeviceExists -ComputerName HOST1, HOST2, HOST3
    
    exists in AD and SCCM "HOST1", "HOST2" and "HOST3" exists in AD and SCCM.
#>
Function Test-DeviceExists {
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        $ComputerName
    )

    Begin {
        if ((Get-Item -Path ".\").Name -ne "DB1") {
            Start-SCCMRuntimeChecks
        }
        $results = @()
    }
    Process {
        try {
            Get-ADComputer -Identity $ComputerName | Out-Null
            $ADResult = "Exists"
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            $ADResult = "Not found"
        }
        if ($null -eq (Get-CMDevice -name $ComputerName)) {
            $SCCMResult = "Not found"
        }
        elseif ($false -eq ((Get-CMDevice -name $ComputerName).IsClient)) {
            $SCCMResult = "Client not Installed"
        }
        else {
            $SCCMResult = "Exists"
        }
        $results += [pscustomobject]@{
            ComputerName = $ComputerName
            ADResult     = $ADResult
            SCCMResult   = $SCCMResult
        }
    }
    End {
        return ($results | Sort-Object -Property ADResult, SCCMResult)
    }
}