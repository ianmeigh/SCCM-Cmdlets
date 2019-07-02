<#PSScriptInfo

.VERSION 1.0
.AUTHOR Ian Meigh
.COMPANYNAME UOD
.EXTERNALSCRIPTDEPENDENCIES
    Join-Object.ps1
    Start-SCCMRuntimeChecks.ps1
.RELEASEDATE 10/04/19
.RELEASENOTES
.TODO
 - Remove from Azure

#>

<#
.SYNOPSIS
    This function will remove an array of hostnames from SCCM.
.DESCRIPTION
    This function will remove a array of hostname from SCCM. It will report on devices that cannot be found. 
.EXAMPLE
    Remove-SCCM $array

    Command will remove the supplied array of hostnames from SCCM.
#>
Function Remove-SCCM ($computers) {

    $results = foreach ($computer in $computers) {
        if ($null -eq (Get-CMDevice -name $computer)) {
            $SCCMResult = "Not found"
        }
        else  
        {
            Remove-CMDevice -DeviceName $computer -Force
            $SCCMResult = "Success"
        }
        [pscustomobject]@{
            ComputerName = $computer
            SCCMResult = $SCCMResult
        }
    }
    return $results
}

<#
.SYNOPSIS
    This function will remove an array of hostnames from AD.
.DESCRIPTION
    This function will remove a array of hostname from AD. It will report on devices that cannot be found. 
.EXAMPLE
    Remove-AD $array

    Command will remove the supplied array of hostnames from AD.
#>
Function Remove-AD ($computers) {

    $results = foreach ($computer in $computers) {
        try {
            Get-ADComputer -Identity $computer | Remove-ADComputer -Confirm:$false -ErrorAction SilentlyContinue
            $ADResult = "Success"
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            $ADResult = "Not found"
        } catch [Microsoft.ActiveDirectory.Management.Commands.RemoveADComputer] {
            try {
                Get-ADComputer -Identity $computer | Remove-ADObject -Recursive -Confirm:$false
                $ADResult = "Success - W10"
            } catch {
                $ADResult = $error[0].message
            }
        }
        [pscustomobject]@{
            ComputerName = $computer
            ADResult = $ADResult
        }
    }
    return $results
}

<#
.SYNOPSIS
    This function will remove a host from either AD, SCCM or Both.
.DESCRIPTION
    This function will remove a given hostname (either specified explicilty or from the pipeline) from either AD, SCCM or 
    both (if no switch parameters are specified). It will report on devices that cannot be found. 
.INPUTS
    System.Array - An array of hostnames.
.OUTPUTS
    System.Object
.PARAMETER ComputerName
    Mandatory parameter - Hostname to be removed.
.PARAMETER AD
    Switch parameter which when specified will only remove the object from AD.
.PARAMETER SCCM
    Switch parameter which when specified will only remove the object from SCCM.
.EXAMPLE
    Remove-Device HOST1

    Command will remove the specified Host from AD and SCCM.
.EXAMPLE
    Get-Content "C:\hostnames.txt" | Remove-Device -AD

    Command will remove the piped hostnames from AD only.
#>
Function Remove-Device {

    param
    (
      [Parameter(Mandatory = $true,
      ValueFromPipeline = $true)]
      $ComputerName,
      [Switch]$AD,
      [Switch]$SCCM
    )

    Begin { 
        Start-SCCMRuntimeChecks
        $array = @()
    }
    Process { $array += $ComputerName }
    End {
        if ($SCCM)
        {
            write-host "SCCM ONLY" 
            Remove-SCCM $array
        }
        if ($AD) {
            write-host "AD"
            Remove-AD $array
        }
        if (!($SCCM -or $AD)) {
            $SCCMResults = Remove-SCCM $array
            $ADResults = Remove-AD $array

            #merge objects
            $results = $SCCMResults | LeftJoin $ADResults -On ComputerName
            return $results
        }
    }
}