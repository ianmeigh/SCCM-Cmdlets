<#PSScriptInfo

.VERSION 1.0
.AUTHOR Ian Meigh
.COMPANYNAME UOD
.EXTERNALSCRIPTDEPENDENCIES @(Start-SCCMRuntimeChecks, Test-DeviceExists)
.RELEASEDATE 10/04/19
.RELEASENOTES

#>

<#
.SYNOPSIS
    Script will add a given hostname to a given collection.
.DESCRIPTION
    This script will add a given hostname (either specified explicilty or from the pipeline) and add it as a query to a given collection while also setting a given comment.
    It will not add devices that do not exist in SCCM.
.INPUTS
    You can pipe an array of hostnames to Add-ComputerToSCCMCollection.
.OUTPUTS
    System.Array - Add-ComputerToSCCMCollection returns an array with results if multiple values are supplied.
    System.Object  - Add-ComputerToSCCMCollection returns a PSCustomObject if a single value is supplied.
.PARAMETER ComputerName [Mandatory]
    The ComputerName, which can be provided through the pipeline or via a comma deliminated list, defines the hostname you wish to add to the collection.
.PARAMETER CollectionName [Mandatory]
    The CollectionName, provided by the (first) argument, defines the the name of the collection you wish to add the hostname(s) to.
.PARAMETER Query [Switch]
    By default the collection member will be added using a Direct Membership Rule, specifing the Query switch will add to the collection using a Query Membership Rule.
.PARAMETER Comment 
    The comment parameter is only required if the Query switch is specified, as using a Query Membership Rule means the rule name can be modified.
.EXAMPLE
    Get-Content "C:\hostnames.txt" | Add-ComputersToCollection -CollectionName "Test_Collection" -Comment "Test Comment"
    
    Command will add all computers in the file specifed to the collection "Test-Collection" as Direct Membership Rules.
.EXAMPLE
    Add-ComputersToCollection -ComputerName HOST1 -CollectionName "Test_Collection"

    Command will add the computer "HOST1" to the collection "Test-Collection" as a Direct Membership Rule.
.EXAMPLE
    Add-ComputerToSCCMCollection -ComputerName HOST1, HOST2, HOST3 -CollectionName "Test-Collection" -Query -Comment "Test Comment"
    
    Command will add the hostnames "HOST1", "HOST2" and "HOST3" to the collection "Test-Collection" as Query Membership Rules with the comment "Test Comment".
#>
Function Add-ComputerToSCCMCollection {
    [CmdletBinding(DefaultParametersetName = 'None')] 
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $ComputerName,
        [Parameter(Mandatory = $true)]
        $CollectionName,

        [Parameter(ParameterSetName = 'QueryMembership', Mandatory = $false)]
        [Switch] $Query,
        [Parameter(ParameterSetName = 'QueryMembership', Mandatory = $true)]
        $Comment = "$([Environment]::UserName) - $(Get-Date -format g)"
    )

    Begin {
        if ((Get-Item -Path ".\").Name -ne "DB1") {
            Start-SCCMRuntimeChecks
        }
        $Results = @()
    }
    Process {
        foreach ($Hostname in $ComputerName) {
            $Hostname = $Hostname.Trim()
            $Devicetest = Test-DeviceExists $Hostname
            If ((($Devicetest.ADResult) -ne "Exists") -or (($Devicetest.SCCMResult) -ne "Exists")) {
                $Result = $Devicetest.ADResult + " in AD + " + $Devicetest.SCCMResult + " in SCCM"
            }
            elseif ($null -eq (Get-CMCollection -Name $CollectionName)) {
                $Result = "Invalid Collection"
            }
            else {
                if ($Query) {
                    $SQLQuery = "select *  from  SMS_R_System where SMS_R_System.Name = """ + $Hostname + '"'
                    Add-CMDeviceCollectionQueryMembershipRule -CollectionName $collectionName -QueryExpression $SQLQuery -RuleName "$Hostname - $comment"
                    $Result = "Query"   
                }
                else {   
                    Add-CMDeviceCollectionDirectMembershipRule -CollectionName $collectionName -ResourceID (Get-CMDevice -Name $Hostname).ResourceID
                    $Result = "Direct"   
                }
            }
            $Results += [pscustomobject]@{
                ComputerName = $Hostname
                Collection   = $CollectionName
                Result       = $Result
            }
        }
    }
    End {
        Return $Results
    }
}