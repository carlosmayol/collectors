<#
 Disclaimer:
 This sample script is not supported under any Microsoft standard support program or service. 
 The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
 all implied warranties including, without limitation, any implied warranties of merchantability 
 or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
 the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
 or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
 damages whatsoever (including, without limitation, damages for loss of business profits, business 
 interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
 inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
 possibility of such damages
#>

#Requires -version 3
#Requires -module FailoverClusters

<#
.SYNOPSIS
  Script that exports event logs from a subset of servers. Also exports cluster nodes information (failover cluster events, cluster configuration & binary files version)

.DESCRIPTION
  Healthcheck.ps1 scripts allow you to collect health data (events, cluster events, binary information etc) to evaluate the health of a given environment or service.

.PARAMETER TargetFolder
   Optional. Defines the output folder, if any, will create a folder with the time stamp in C:\Temp\

.PARAMETER Servers
    Optional. Defines the location of the source file containing the list of server to collect the data, if any, the script will look into .\servers.txt.
    This file must exist but the parameter is optional.

.PARAMETER EventStart
    Optional. Defines event log collection start date in MM/DD/YYYY format, if any, the script will go 7 days back in time.

.PARAMETER EventEnd
    Optional. Defines the event log collection end date in MM/DD/YYYY format, if any, the script will finish today.

.PARAMETER CollectClusters
    Optional. Defines if the Healthcheck script must collect Cluster nodes. 
    If defined, will collect Cluster information, Files information and Event log channel: Microsoft-Windows-FailoverClustering/Operational
    It requires Files.txt (Path of files to collect binary information) and Clusters.txt (Contains the name of the Cluster CNOs to be collected)
    It requires Cluster PowerShell Module in the collector machine

.PARAMETER Clusters
    Optional. Defines the location of the source file containing the list of CNO.
    This file must exist but the parameter is optional.
    
.PARAMETER FileList
    Optional. Defines the location of the source file containing the list of files to extract the version and hash information.
    This file must exist but the parameter is optional.

.INPUTS
  txt files containing servers and clusters FQDNs to be collected

.OUTPUTS
  CSV files for the different sections. CSV files are stored on user selected target folder or C:\Temp\[date] folder
  Execution Log file stored in C:\Temp\<name>.log>

.NOTES

V5.1 (under development)

##########
Changelog:
##########

TO DOs:
PTE evaluate if is necessary to export all the certificate stores (Trusted CAs, Intermediate, etc)


CM 06/2017 5.1.02
    Added Critical event level for both System and Failovercluster sources
    Added Windows installed features export
    Added MPIO & HBA information for Cluster Nodes
    Added LBFO Export for Cluster Nodes

CM 04/2017 5.1
    Cosmetics across the script (write-hosts, comments etc)
    Changed parameters default values (if blank) 
    Fixes on healthcheck.log entries for files.txt
    Fixes on KBs export, now creates one CSV file per cluster

CM 04/2017 5.02
    Replace mkdir for new-item command

CM 03/2017 5.01 
    Added KBs extraction and comparision for cluster nodes

CM 03/2017 5.0
    Implemented more information on the script header
    Reviewed Cluster.csv & files.csv export to work on multiple clusters collection
    Implemented Cluster file collection (nodes) to use FQDN from the Cluster CNO property
    Removed System events for clusters nodes, the cluster nodes should be defined in the servers.txt file
    Re-added Informational events for cluster nodes
    Removed Credential files requirement and associated code. Now the interactive/scheduled user run the collection
    Implemented console logging output
    Implemented progress bar for loops
    Improved & cleaned console outputs

CM 11/2016 4.3
    Removed Informational events for cluster nodes
    Implemented Cluster CSV export collection to add multiple clusters in the same collection

CM 08/2016 4.2
    Added Cluster Switch as a parameter -CollectClusters, requires clusters.txt file
    Added FileVersion output for Cluster Nodes if -CollectCluster is present, requires files.txt file
    Added Cluster event logs export for cluster nodes using log: Microsoft-Windows-FailoverClustering/Operational
    Added Cluster CSV per Cluster dataset type (11 exports currently)

CM 07/2016 4.1
    Changed result files from XML to CSV, performance, compatibility ( invalid XML characters issues) and manageability
    Removed specific EventId file requieriment/filter/variable
    Updated exported fields for both events and certificates
    Added the file "Signature Hash algorithm" (related to supported Cipher types, Event logs events on the systems)

CM 06/2016 4.0
    Added detection and replacement of invalid characters on XML file (ampersand "&" and others ), to avoid import issues
    Addded field "Source" for the Eventlogs info


CM 03/2016 3.0
    Adding name of the servers in the output xml files to be able to combine, changed encoding to UTF8 (excel to process) & removing the item numbering to have a proper structure easy to consume
    Combining the Events and Certificates collection in just 1 file for better analysis
    Changed the event collector from XML Filter to a hash table and updated the log Level integers to collect
    Cosmetics: Added some tracking outputs and colors

CM 02/2016 2.0
    Discarded by now: Performance collector, Registry collector, system config collector, hotfix collector, because SPA does it
    Combined the other collectors in just one script, avoiding duplicities
    Sanitize: Cleaning old lines, outputs like when creating a new target folder etc
    Changed the way to obtain the credentials & generate the password & check password encrypted file
    Changes the write-information to write-host (not supported in 2012 or 2008)
    Adding default setting for events looking -7 days back if no dates are defined & cleaning the necessity to look for specific eventid numbers

/NOTES:

.EXAMPLE
  Run the script to collect System event logs & cluster information (cluster event logs, cluster nodes file versions, cluster nodes KBs comparison)
  Powershell.exe -file "[Path]\healthcheckv5.ps1" -CollectClusters

#>


#----------------------------------------------------------[Declarations]----------------------------------------------------------

Param(      
      [string]$TargetFolder, #Parameter to define target location of result csv files, default C:\temp\$date
      [string]$Servers=".\Servers.txt", #TXT containing the list of server names to collect cert and event information, default .\servers.txt
      [DateTime]$EventStart, #Parameter to define Start Event log date
      [DateTime]$EventEnd, #Parameter to define End Event log date
      [switch]$CollectClusters, #Boolean parameter to define if we collect cluster and file information for Clusters and Cluster nodes
      [string]$Clusters=".\Clusters.txt", #TXT containing the list of cluster Names to collect cluster information, default .\clusters.txt
      [string]$FileList=".\Files.txt"#TXT containing the list of files to collect fileversioninfo, default .\files.txt
      )
 

#Get current date/time
$Date = Get-Date -f yyyy_MM_dd_hhmmss

#If the following parameters are not passed, used the defaults
If (!$TargetFolder)
{
    $TargetFolder = "c:\temp\$Date"
}
If (!$EventStart)
{
    $EventStart = (((Get-Date).addDays(-7)).date)
}
If (!$EventEnd)
{
    $EventEnd   = (Get-Date)
}
#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Set-StrictMode -version Latest

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

#Script Version
$sScriptVersion = "5.1"

#Log File Info
$sLogPath = $TargetFolder
$sLogName = "Healthcheck.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName


#Dot Source required Function Libraries
. ".\Logging_Functions.ps1" 

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#Verify the target folder exists, we need to create the folder first because of the logging file
If (!(Test-Path -Path $TargetFolder))
{
    Write-Warning "The Target folder ($TargetFolder) was not found!  Creating folder ($TargetFolder)..."
    New-item -Path $TargetFolder -ItemType Directory > $null
    Write-Warning "The Target folder ($TargetFolder) was created."
    Write-Host ""
    Write-Host ""
}

Log-Start -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion

Log-Write -LogPath $sLogFile -LineValue "Checking pre-requisites and setting environment..."

#Check if running as admin - if not, fail
Log-Write -LogPath $sLogFile -LineValue "Checking admin credentials..."  

  
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
   [Security.Principal.WindowsBuiltInRole] "Administrator"))

   {
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Write-Host ""
    Write-Host ""
    Log-Error -LogPath $sLogFile -ErrorDesc "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!" -ExitGracefully $True
   }
 
 
#Verifying the servers txt file exists
Log-Write -LogPath $sLogFile -LineValue "Verifying the servers txt file exists..."  

If (!(Test-Path $Servers))
{
    Write-Warning "The Servers file ($Servers) was not found!  Please check if the the file $Servers exists."
    Write-Host ""
    Write-Host ""
    Log-Error -LogPath $sLogFile -ErrorDesc "The Servers file ($Servers) was not found!  Please check if the the file $Servers exists." -ExitGracefully $True
    
}


#Reading server list from txt file
Log-Write -LogPath $sLogFile -LineValue "Reading server list from txt file..."
$ServersList = $null
$ServersList = Get-Content $Servers | Where-Object { ($_.Trim() -ne '') -and ($_.Trim() -notlike '#*') }
$ServersListCount = $ServersList.count
Log-write -LogPath $sLogFile -LineValue "Server List Count: $ServersListCount"

Write-Host "Starting Health Check scripts..."  -ForegroundColor Green
Log-Write -LogPath $sLogFile -LineValue "Starting Health Check scripts..."
Write-Host ""
Write-Host ""


###START CERTS
Write-Host "Starting Certs collection..." -ForegroundColor Cyan
Log-Write -LogPath $sLogFile -LineValue "Starting Certs collection..."
Write-Host ""
Write-Host ""

#File to write output
$OutputCert = "$TargetFolder\Certificates.csv"

#If Output file exists, delete it to create a new one
If (Test-Path $OutputCert) {Remove-Item $OutputCert -Force}


#Iterate through each server in $ServerList and run commands below

#Progress Bar artifact before the loop
$I = $null 
$I = 0
ForEach ($Server in $ServersList)
{
    If (Test-Connection -ComputerName $Server -count 1 -Quiet)
    {
        Write-Verbose ("Server: $Server") -Verbose
        Write-Host ""
        #Progress Bar artifact 
        Write-Progress -Activity CERTS -Status 'Progress->' -PercentComplete ($I/$ServersList.Count*100)
        
        $Certificates = @()

        #Connect to the "Trusted Root" store on $Server for the local machine
        $personal  = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\My","LocalMachine")
        $root      = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\Root","LocalMachine")
        $authroot  = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\AuthRoot","LocalMachine")
        $ca        = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\CA","LocalMachine")
        $enttrust  = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\Trust","LocalMachine")
        $rd        = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\Remote Desktop","LocalMachine")
        $people    = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\TrustedPeople","LocalMachine")
        $devices   = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\TrustedDevices","LocalMachine")
        $publisher = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\TrustedPublisher","LocalMachine")
        $cauth     = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\ClientAuthIssuer","LocalMachine")


        #Open the certificate stores read-only
        $personal.Open("ReadOnly")
        $root.Open("ReadOnly")
        $authroot.Open("ReadOnly")
        $ca.Open("ReadOnly")
        $enttrust.Open("ReadOnly")
        $rd.Open("ReadOnly")
        $people.Open("ReadOnly")
        $devices.Open("ReadOnly")
        $publisher.Open("ReadOnly")
        $cauth.Open("ReadOnly")

        #Put certs from $store into $Certificates for parsing
        $Certificates += $personal.Certificates
        $Certificates += $root.CertificatesSignatureAlgorithm
        $Certificates += $authroot.Certificates
        $Certificates += $ca.Certificates
        $Certificates += $enttrust.Certificates
        $Certificates += $rd.Certificates
        $Certificates += $people.Certificates
        $Certificates += $devices.Certificates
        $Certificates += $publisher.Certificates
        $Certificates += $cauth.Certificates
        $certificates | Select-Object @{N="Server";E={$Server}},DnsNameList, FriendlyName, Subject, Issuer, NotBefore, NotAfter, Version, EnhancedKeyUsageList, HasPrivateKey,@{N="SignatureAlgorithm";E={$_.SignatureAlgorithm.FriendlyName}}, SerialNumber, Thumbprint | Export-Csv -Path $OutputCert -Append -NoTypeInformation 
        
        #Progress Bar artifact 
        $I = $I +1
      }

    Else
    {
        Write-Warning "Connection to $Server does not work properly! going to next one ...." 
        Log-Error -LogPath $sLogFile -ErrorDesc "Connection to $Server does not work properly! going to next one ...." -ExitGracefully $false
        Write-Host ""
        Write-Host ""
    }

}

#Progress Bar artifact 
Write-Progress -Activity CERTS -Completed
Log-write -LogPath $sLogFile -LineValue " Processed Servers Count:$I "
#####END CERTS


#####START EVENTS
Write-Host "Starting Events collection..." -ForegroundColor Cyan
Log-Write -LogPath $sLogFile -LineValue "Starting Events Collection..."
Write-Host ""
Write-Host ""

#File to write output
$OutputEvents = "$TargetFolder\EventInfo.csv"

#If output file exists, delete it to create a new one
If (Test-Path $OutputEvents)
{
    Remove-Item $OutputEvents -force
}

#Iterate through each server in $Servers and run commands below

#Progress Bar artifact before the loop
$I = $null 
$I = 0

ForEach ($Server in $ServersList)
{
    If (Test-Connection -ComputerName $Server -count 1 -Quiet)
    {
        Write-Verbose ("Server: $Server") -Verbose
        Write-Host ""

        #Progress Bar artifact 
        Write-Progress -Activity EVENTS -Status 'Progress->' -PercentComplete ($I/$ServersList.Count*100)

       $Events = @()
       #Event Level 1 = Critical, Level 2 = Error, 3 = Warning, 4 = Info (https://msdn.microsoft.com/en-us/library/aa394226(v=vs.85).aspx)
       $Events += Get-WinEvent -Oldest -ComputerName $Server -FilterHashtable @{LogName='system'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
       $Events += Get-WinEvent -Oldest -ComputerName $Server -FilterHashtable @{LogName='system'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
       $Events += Get-WinEvent -Oldest -ComputerName $Server -FilterHashtable @{LogName='system'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
       #$Events += Get-WinEvent -Oldest -ComputerName $Server -FilterHashtable @{LogName='system'; Level=[int]4; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue   
       $Events| Select-Object MachineName,LogName,LevelDisplayName,Id,ProviderName,RecordId,Message,ProcessId,ThreadId,UserId,TimeCreated,ActivityId,RelatedActivityId |Export-Csv -Path $OutputEvents -Append -NoTypeInformation                    

       #Progress Bar artifact 
       $I = $I +1

    }

    Else
    {
        Write-Warning "Connection to $Server does not work properly! going to next one ...." 
        Log-Error -LogPath $sLogFile -ErrorDesc "Connection to $Server does not work properly! going to next one ...." -ExitGracefully $false
        Write-Host ""
        Write-Host ""
    }
}


#Progress Bar artifact 
Write-Progress -Activity EVENTS -Completed
Log-write -LogPath $sLogFile -LineValue " Processed Servers Count:$I "  
#####END EVENTS


#START Windows Features
Write-Host "Starting Windows Features collection..." -ForegroundColor Cyan
Log-Write -LogPath $sLogFile -LineValue "Starting Windows Features collection..."
Write-Host ""
Write-Host ""

#File to write output
$OutputWinFeats = "$TargetFolder\WindowsFeats.csv"

#If output file exists, delete it to create a new one
If (Test-Path $OutputWinFeats)
{
    Remove-Item $OutputWinFeats -force
}

#Iterate through each server in $Servers and run commands below

#Progress Bar artifact before the loop
$I = $null 
$I = 0

ForEach ($Server in $ServersList)
{
    If (Test-Connection -ComputerName $Server -count 1 -Quiet)
    {
        Write-Verbose ("Server: $Server") -Verbose
        Write-Host ""

        #Progress Bar artifact 
        Write-Progress -Activity WindowsFeats -Status 'Progress->' -PercentComplete ($I/$ServersList.Count*100)

       $WinFeats = @()

       $WinFeats +=  Get-WindowsFeature -ComputerName $Server | Where-Object installed | Select-Object @{N="ComputerName";E={$Server}}, Name, DisplayName, FeatureType
       $WinFeats | Export-Csv -Path $OutputWinFeats -Append -NoTypeInformation              

       #Progress Bar artifact 
       $I = $I +1

    }

    Else
    {
        Write-Warning "Connection to $Server does not work properly! going to next one ...." 
        Log-Error -LogPath $sLogFile -ErrorDesc "Connection to $Server does not work properly! going to next one ...." -ExitGracefully $false
        Write-Host ""
        Write-Host ""
    }
}


#Progress Bar artifact 
Write-Progress -Activity EVENTS -Completed
Log-write -LogPath $sLogFile -LineValue " Processed Servers Count:$I "  
#END WindowsFeatures


#####START CLUSTER
if ($CollectClusters) 
{
    Write-Host "Starting Cluster collection..." $CollectClusters -ForegroundColor Cyan
    Write-Host ""
    Write-Host ""
    Log-Write -LogPath $sLogFile -LineValue "Starting Cluster collection..." 

    ####Importing Cluster PowerShell Module in the collector machine
    Import-Module FailoverClusters

    #Verifying output files
    #File to write output for cluster export
    $OutputCluster01 = "$TargetFolder\Cluster-Core.csv"
    $OutputCluster02 = "$TargetFolder\Cluster-nodes.csv"
    $OutputCluster03 = "$TargetFolder\Cluster-group.csv"
    $OutputCluster04 = "$TargetFolder\Cluster-groupadv.csv"
    $OutputCluster05 = "$TargetFolder\Cluster-groupowners.csv"
    $OutputCluster06 = "$TargetFolder\Cluster-res.csv"
    $OutputCluster07 = "$TargetFolder\Cluster-resadv.csv"
    $OutputCluster08 = "$TargetFolder\Cluster-resowners.csv"
    $OutputCluster09 = "$TargetFolder\Cluster-net.csv"
    $OutputCluster10 = "$TargetFolder\Cluster-netint.csv"
    $OutputCluster11 = "$TargetFolder\Cluster-access.csv"

    #If Output file exists, delete it
    If (Test-Path $OutputCluster01) {Remove-Item $OutputCluster -Force}
    If (Test-Path $OutputCluster02) {Remove-Item $OutputCluster -Force}
    If (Test-Path $OutputCluster03) {Remove-Item $OutputCluster -Force}
    If (Test-Path $OutputCluster04) {Remove-Item $OutputCluster -Force}
    If (Test-Path $OutputCluster05) {Remove-Item $OutputCluster -Force}
    If (Test-Path $OutputCluster06) {Remove-Item $OutputCluster -Force}
    If (Test-Path $OutputCluster07) {Remove-Item $OutputCluster -Force}
    If (Test-Path $OutputCluster08) {Remove-Item $OutputCluster -Force}
    If (Test-Path $OutputCluster09) {Remove-Item $OutputCluster -Force}
    If (Test-Path $OutputCluster10) {Remove-Item $OutputCluster -Force}
    If (Test-Path $OutputCluster11) {Remove-Item $OutputCluster -Force}

    #File to write output for files collection
    $OutputFileversion = "$TargetFolder\Files.csv"

    #If Output file exists, delete it
    If (Test-Path $OutputFileversion) {Remove-Item $OutputFileversion -Force}

    #Verifying txt files to read
    #Verifying the Clusters txt file exists
    Log-Write -LogPath $sLogFile -LineValue "Verifying the Clusters txt file exists..."  

    If (!(Test-Path $Clusters))
    {
        Write-Warning "The Clusters file ($Clusters) was not found!  Please check if the the file $Clusters exists."
        Write-Host ""
        Write-Host ""
        Log-Error -LogPath $sLogFile -ErrorDesc "The Servers file ($Clusters) was not found!  Please check if the the file $Clusters exists." -ExitGracefully $True
        
    }
    
    #Reading Clusters list from file
    $ClusterList = Get-Content $clusters | Where-Object { ($_.Trim() -ne '') -and ($_.Trim() -notlike '#*') }


    #Verifying the Files txt file exists
    Log-Write -LogPath $sLogFile -LineValue "Verifying the Files txt file exists..."  

    If (!(Test-Path $FileList))
    {
        Write-Warning "The Clusters file ($FileList) was not found!  Please check if the the file $FileList exists."
        Write-Host ""
        Write-Host ""
        Log-Error -LogPath $sLogFile -ErrorDesc "The Servers file ($FileList) was not found!  Please check if the the file $FileList exists." -ExitGracefully $True
        
    }

    #Reading Files list from file
    $files = Get-content $fileList | Where-Object { ($_.Trim() -ne '') -and ($_.Trim() -notlike '#*') }  

    ###START CLUSTER Loop
    #Iterate through each Cluster in $ClusterList and run commands below
    ForEach ($cluster in $ClusterList)
    {

        If (Test-Connection -ComputerName $cluster -count 1 -Quiet)
        {
            Write-Verbose ("Exporting Cluster settings for: $cluster...") -Verbose
            Write-Host ""
            Log-Write -LogPath $sLogFile -LineValue "Exporting Cluster settings for: $cluster..." 


            #Preparing artifacts for Cluster & Cluster Nodes collection

            #Getting Cluster domain
            $clusterdomain = $null
            $clusterdomain = (get-cluster -name $cluster).domain

            #Colleting nodes name for FileVersion & Hotfixes collection to be used later
            $ClusterSrvNodes = $null
            $ClusterSrvNodes = Get-ClusterNode -cluster $cluster | ForEach-Object{$_.Name}
            $ClusterSrvNodesCount = $ClusterSrvNodes.count

            write-Host "Nodes in cluster" $ClusterSrvNodes.count
            Write-Host "" 
            Log-Write -LogPath $sLogFile -LineValue "Nodes in cluster $ClusterSrvNodesCount"

            #####Start Cluster Objects collection
            $clustercore = Get-Cluster -Name $Cluster | Select-Object -Property * 
            $clusternodes = Get-ClusterNode -Cluster $cluster | Select-Object -Property *
            $clustergroup = Get-ClusterGroup -Cluster $cluster | Select-Object -Property *
            $clustergroupadv = Get-ClusterGroup -Cluster $cluster | get-clusterparameter | Select-Object -Property *
            $clustergroupownernode = Get-ClusterGroup -Cluster $cluster | Get-ClusterOwnerNode | Select-Object -Property ClusterObject -ExpandProperty OwnerNodes | Select-Object -Property *
            $clusterresources = Get-ClusterResource -Cluster $cluster | get-clusterparameter | Select-Object -Property *
            $clusterresourcesadv = Get-ClusterResource -Cluster $cluster | Select-Object -Property *
            $clusterresourceownernode = Get-ClusterResource -Cluster $cluster | Get-ClusterOwnerNode | Select-Object -Property ClusterObject -ExpandProperty OwnerNodes | Select-Object -Property *
            $clusternetwork = Get-ClusterNetwork -Cluster $cluster | Select-Object -Property *
            $clusternetworkinterface = Get-ClusterNetworkInterface -Cluster $cluster | Select-Object -Property *
            $clusteraccess = Get-ClusterAccess -Cluster $cluster | Select-Object -Property *
            
            #Exporting Cluster Objects & appending results if more than one cluster is collected.
            $clustercore | Export-Csv -Path $OutputCluster01 -NoTypeInformation -Append
            $clusternodes | Export-Csv -Path $OutputCluster02 -NoTypeInformation -Append
            $clustergroup | Export-Csv -Path $OutputCluster03 -NoTypeInformation -Append
            $clustergroupadv | Export-Csv -Path $OutputCluster04 -NoTypeInformation -Append
            $clustergroupownernode | Export-Csv -Path $OutputCluster05 -NoTypeInformation -Append
            $clusterresources | Export-Csv -Path $OutputCluster06 -NoTypeInformation -Append
            $clusterresourcesadv | Export-Csv -Path $OutputCluster07 -NoTypeInformation -Append
            $clusterresourceownernode | Export-Csv -Path $OutputCluster08 -NoTypeInformation -Append
            $clusternetwork | Export-Csv -Path $OutputCluster09 -NoTypeInformation -Append
            $clusternetworkinterface | Export-Csv -Path $OutputCluster10 -NoTypeInformation -Append
            $clusteraccess | Export-Csv -Path $OutputCluster11 -NoTypeInformation -Append
            #####End Cluster Objects collection & Export process 

            #Defining objects for Hotfixes collection
            $Hotfixes = $null
            $Hotfixes = @()
            $hfresult = $null
            $hfresult = @()

            #File to write output for MPIO/HBA
            $OutputMPIO = "$TargetFolder\MPIOData"+"_$cluster.csv"
            $OutputHBA = "$TargetFolder\HBAData"+"_$cluster.csv"

            #If Output file exists, delete it to create a new one
            If (Test-Path $OutputMPIO) {Remove-Item $OutputMPIO -Force}
            If (Test-Path $OutputHBA) {Remove-Item $OutputHBA -Force}

            #File to write output for LBFO
            $OutputLBFO = "$TargetFolder\LBFO"+"_$cluster.csv"
    
            #If Output file exists, delete it to create a new one
            If (Test-Path $OutputLBFO) {Remove-Item $OutputLBFO -Force}

            ###START CLUSTERNODE Loop
            #Iterate through each ClusterNode in $ClusterSrvNodes and run commands below
            Log-write -LogPath $sLogFile -LineValue " Exporting Cluster Nodes..." 

            #Progress Bar artifact before the loop
            $I = $null 
            $I = 0
 
            #Starting ClusterNode loop
            foreach ($ClusterNode in $ClusterSrvNodes)
            {
            #Binding ClusterNode & Cluster Domain to have FQDN naming
            $Clusternode = "$ClusterNode"+"."+"$clusterdomain"

            if (Test-Connection $ClusterNode -count 1 -Quiet) 
                { 
                    Write-Verbose ("Server: $ClusterNode") -Verbose
                    Write-Host ""
                    Log-write -LogPath $sLogFile -LineValue " Processing $ClusterNode ...." 

                    #Progress Bar artifact 
                    Write-Progress -Activity CLUSTERNODES -Status 'Progress->' -PercentComplete ($I/$ClusterSrvNodes.Count*100)
            
                    #Starting remote PSSession for FileVersion Export
                    $session = New-PSSession -ComputerName $ClusterNode
    
                    Invoke-Command -Session $session -ArgumentList @($files) -ScriptBlock {
                                            
                        #New Crypto Obj for Hash gattering
                        $sha2 = New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider

                        #Creating Hash array
                        $fileinfo = $null
                        $fileinfo = @();
                        
                        Add-Member -InputObject $fileinfo -MemberType NoteProperty -Name Server -Value ""
                        Add-Member -InputObject $fileinfo -MemberType NoteProperty -Name Name -Value ""
                        Add-Member -InputObject $fileinfo -MemberType NoteProperty -Name FileVersion -Value ""
                        Add-Member -InputObject $fileinfo -MemberType NoteProperty -Name SHA2Hash -value ""

                        #$args contains the passed argument as an array to the remote host in the invoke command line
                        foreach ($file in $args) {

                            #Commenting because get-filehash is only available in PS4 and beyond
                            #$fileinfo += get-item $file -ErrorAction Ignore  | Select @{N="Server";E={$env:COMPUTERNAME}},Name, FileVersionUpdated, @{N="SHA2Hash";E={Get-FileHash -Path $file | %{$_.hash}}}
                            
                            $sha2Hash = [System.BitConverter]::ToString( $sha2.ComputeHash( [System.IO.File]::ReadAllBytes($file) ) ) 
                            $sha2Hash = $sha2Hash.Replace("-", "")

                            #ErrorAction is set to silentContinue in case a file defined in the txt does not exist in the system
                            $fileinfo += get-item $file  -ErrorAction SilentlyContinue | Select-Object @{N="Server";E={$env:COMPUTERNAME}},Name,@{N="FileVersion";E={"$($_.VersionInfo.FileMajorPart).$($_.VersionInfo.FileMinorPart).$($_.VersionInfo.FileBuildPart).$($_.VersionInfo.FilePrivatePart)"}},@{N="SHA2Hash";E={$sha2Hash}}

                            } #End foreach file collection
                        
                    } #End Remote ScriptBlock
			   
                    #Collection the results of the previous commands to retreive the information to the local system
                    $filesresult = Invoke-Command -session $session -ScriptBlock {$fileinfo}
                                                
                    $filesresult | Where-Object {$_} | Export-Csv -Path $OutputFileversion -Append -NoTypeInformation -Verbose

                    Remove-PSSession -Session $session
                    #Finishing remote PSSession for FileVersion Export

                    #End FileVersion Export process inside the cluster loop

                    #Starting Cluster Events export for Microsoft-Windows-FailoverClustering/Operational, system entries are collected using the servers.txt.                    
                    Log-write -LogPath $sLogFile -LineValue "  Collecting Failover Cluster events for $Clusternode..."
                    $Events = @()
                   
                    #Event Level 1 = Critical, Level 2 = Error, 3 = Warning, 4 = Info (https://msdn.microsoft.com/en-us/library/aa394226(v=vs.85).aspx)
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-FailoverClustering/Operational'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-FailoverClustering/Operational'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-FailoverClustering/Operational'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-FailoverClustering/Operational'; Level=[int]4; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                 
                    $Events| Select-Object MachineName,LogName,LevelDisplayName,Id,ProviderName,RecordId,Message,ProcessId,ThreadId,UserId,TimeCreated,ActivityId,RelatedActivityId | Export-Csv -Path $OutputEvents -Append -NoTypeInformation
                    #End Cluster Events export inside the cluster loop
                    
                    #Starting MPIO/HBA collection
                    Log-write -LogPath $sLogFile -LineValue "  Collecting MPIO/HBA info for $Clusternode..."                
                    $MPIOStatistics = @()
                    $HBAStatistics = @()

                    $MPIOStatistics += Invoke-Command -ComputerName $ClusterNode -ScriptBlock {Get-WMIObject -NameSpace "root/wmi" -Class "MPIO_DISK_HEALTH_INFO" | Select-Object -Expand DiskHealthPackets} | Select-Object @{L="ComputerName";E={$ClusterNode}}, Name, NumberReads, NumberWrites, PathFailures, NumberIoErrors, NumberRetries | Sort-Object ComputerName, Name
                    $HBAStatistics += Invoke-Command -ComputerName $ClusterNode -ScriptBlock {Get-WMIObject -NameSpace "root/wmi" -Class "MSFC_FibrePortHBAStatistics" | Select-Object -Expand Statistics} | Select-Object @{L="ComputerName";E={$ClusterNode}}, DumpedFrames, ErrorFrames, InvalidCRCCount, InvalidTxWordCount, LinkFailureCount, LIPCount, LossOfSignalCount, LossOfSyncCount, NOSCount, SecondsSinceLastReset | Sort-Object ComputerName, InvalidTxWordCount
                   
                    $MPIOStatistics | Export-Csv -Path $OutputMPIO -Append -NoTypeInformation
                    $HBAStatistics | Export-Csv -Path $OutputHBA -Append -NoTypeInformation
                    #End MPIO/HBA collection

                    #Starting LBFO/TEAM Export
                    Log-write -LogPath $sLogFile -LineValue "  Collecting LBFO info for $Clusternode..."
                    $LBFO = @()
                                      
                    $LBFO += Get-NetLbfoTeam -CimSession $ClusterNode | Select-Object @{N="ComputerName";E={$ClusterNode}}, Name, Members, TeamNics, TeamingMode, LoadBalancingAlgorithm, Status
                    $LBFO | Export-Csv -Path $OutputLBFO -Append -NoTypeInformation
                    #Ending LBFO/TEAM Export

                    #Starting Hotfixes collection process Part I (inside the cluster loop)
                    Log-write -LogPath $sLogFile -LineValue "  Collecting KBs for $Clusternode..."

                    #File to write output for Hotfixes
                    $OutputHotfixes = "$TargetFolder\Hotfixes"+"_$cluster.csv"

                    #If Output file exists, delete it to create a new one
                    If (Test-Path $OutputHotfixes) {Remove-Item $OutputHotfixes -Force}

                    foreach ($hotfix in (Get-HotFix -ComputerName $ClusterNode | Select-Object HotfixId))
                        {
                            $h = New-Object System.Object
                            $h | Add-Member -Type NoteProperty -name "Cluster" -Value $Cluster
                            $h | Add-Member -type NoteProperty -name "Server" -value $ClusterNode
                            $h | Add-Member -type NoteProperty -name "Hotfix" -value $hotfix.HotfixId
                            $hotfixes += $h
                        }
                    #End Hotfixes collection
                                  
                    #Progress Bar artifact 
                    $I = $I +1
                     
                 } #EndIf Server is respoding, if not skip to next
 
            else
                {
                Write-Host "Connection to"$ClusterNode "does not work properly! going to next one ...." -ForegroundColor "red"
                Write-Host ""
                Write-Host ""
                Log-Error -LogPath $sLogFile -ErrorDesc "Connection to $ClusterNode does not work properly! going to next one ...." -ExitGracefully $false
                }
        
            } #End foreach clusternode loop inside the cluster loop


            #Starting Hotfixes collection process Part II (comparison for the current Cluster outside the cluster node loop)
            Log-write -LogPath $sLogFile -LineValue " Starting Hotfixes comparison for Cluster nodes in cluster $cluster..." 
            
            $AllcomputerList = $hotfixes | Select-Object -unique Server | Sort-Object Server
            foreach ($hotfix in $hotfixes | Select-Object -unique Hotfix | Sort-Object Hotfix)
            {
                $h = New-Object System.Object
                $h | Add-Member -type NoteProperty -name "Cluster" -Value $cluster
                $h | Add-Member -type NoteProperty -name "Hotfix" -value $hotfix.Hotfix
                
                foreach ($Server in $AllcomputerList)
                {
                    if ($hotfixes | Select-Object |Where-Object {($Server.server -eq $_.server) -and ($hotfix.Hotfix -eq $_.Hotfix)}) 
                    {
                    $h | Add-Member -type NoteProperty -name $Server.server -value "OK"
                    }
                    else
                    {
                    $h | Add-Member -type NoteProperty -name $Server.server -value "- MISSING -"
                    }
                }
                $hfresult += $h

            } #End Foreach hotfixes

            $hfresult | Export-csv -Path $OutputHotfixes -NoTypeInformation -Append
            #End Hotfixes Export process outside the cluster loop

        } #EndIf Cluster is respoding, if not skip to next

        Else
        {
            Write-Host "Connection to"$Cluster "does not work properly! going to next one ...." -ForegroundColor "red"
            Write-Host ""
            Write-Host ""
            Log-Error -LogPath $sLogFile -ErrorDesc "Connection to $Cluster does not work properly! going to next one ...." -ExitGracefully $false

        }

       Log-write -LogPath $sLogFile -LineValue " Processed ClusterNode Count:$I "  
    } #END Cluster loop

} #END If CollectClusters


#Progress Bar artifact 
Write-Progress -Activity CLUSTERNODES -Completed
#####END CLUSTER

Write-Host "Health Check scripts completed." -ForegroundColor Green
Write-Host ""
Write-Host ""
Log-Write -LogPath $sLogFile -LineValue "Health Check scripts completed."
Log-Finish -LogPath $sLogFile
