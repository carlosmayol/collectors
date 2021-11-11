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

.PARAMETER Clusters
    Optional. Defines the location of the source file containing the list of CNO.
    This file must exist but the parameter is optional.

.PARAMETER FileList
    Optional. Defines the location of the source file containing the list of files to extract the version and hash information.
    This file must exist but the parameter is optional.

.PARAMETER TargetFolder
   Optional. Defines the output folder, if any, will create a folder with the time stamp in C:\Temp\

.PARAMETER EventStart
    Optional. Defines event log collection start date in MM/DD/YYYY format, if any, the script will go 7 days back in time.

.PARAMETER EventEnd
    Optional. Defines the event log collection end date in MM/DD/YYYY format, if any, the script will finish today.

.PARAMETER EventsOnly
    Optional. Defines if the Healthcheck script must collect Events only. 

.INPUTS
  txt files containing servers and clusters FQDNs to be collected

.OUTPUTS
  CSV files for the different sections. CSV files are stored on user selected target folder or C:\Temp\[date] folder
  Execution Log file will be stored as Healthcheck.log.

.NOTES

V6.0 (under development, Hyper-V/S2D Clusters 3.0)

This version is ortiented to collect Hyper-V Cluster nodes & S2D nodes, all the nodes must belong to a cluster. Standalone nodes are not supported.

Pending:
Host mitigations (side channel)
QoS (PFC, ETS, QoS)

##########
Changelog:
##########

/NOTES:

.EXAMPLE
Run the script to collect Events and configuration information only
  Powershell.exe -file "[Path]\healthcheckv5.ps1" -CollectEvents -CollectConfigInfo

Run the script to collect Events only 
  Powershell.exe -file "[Path]\healthcheckv5.ps1" -CollectEvents

#>

#----------------------------------------------------------[Declarations]----------------------------------------------------------

# [CmdletBinding(DefaultParametersetName='None')] 

Param(      
      [string]$TargetFolder, #Parameter to define target location of result csv files, default C:\temp\$date
      [string]$Clusters=".\Clusters.txt", #TXT containing the list of cluster Names to collect cluster information, default .\clusters.txt
      [string]$FileList=".\Files.txt", #TXT containing the list of files to collect fileversioninfo, default .\files.txt
      [switch]$CollectClusterLogs, #Boolean parameter to define if we collect clusterlogs
      [switch]$CollectS2DHealthLogs, #Boolean parameter to define if we collect Health clusterlogs
      [switch]$CollectConfigInfo, #Boolean parameter to define if we collect clusterlogs     
      [switch]$CollectDiskHistory, #Boolean parameter to define if we collect Disk History Events (time consuming)
      [switch]$CollectEvents, ##Boolean parameter to define if we collect Windows eventlogs
      [Parameter (ParameterSetName = 'EventDates', Mandatory=$false)]
      [DateTime]$EventStart, #Parameter to define Start Event log date
      [Parameter (ParameterSetName = 'EventDates', Mandatory=$false)]
      [ValidateScript({$_ -le (Get-Date)})]
      [DateTime]$EventEnd  #Parameter to define End Event log date
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
$sScriptVersion = "6.0"

#Log File Info
$sLogPath = $TargetFolder
$sLogName = "Healthcheck.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

#Dot Source required Function Libraries
. ".\Logging_Functions.ps1" -Verbose

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#Verify the target folder exists, we need to create the folder first because of the logging file
If (!(Test-Path -Path $TargetFolder))
{
    Write-Warning "The Target folder ($TargetFolder) was not found!  Creating folder ($TargetFolder)..."
    New-item -Path $TargetFolder -ItemType Directory > $null
    Write-Information "The Target folder ($TargetFolder) was created." 
    Write-Host ""
    Write-Host ""
}

Log-Start -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion

Write-Host "Starting Health Check scripts..."  -ForegroundColor Green
Log-Write -LogPath $sLogFile -LineValue "Starting Health Check scripts..."
Write-Host ""
Write-Host ""

Write-Host "  Checking pre-requisites and setting environment..."  -ForegroundColor Green
Log-Write -LogPath $sLogFile -LineValue "Checking pre-requisites and setting environment..."
Write-Host ""
Write-Host ""

#Verifying credentials
Write-Host "  Verifying admin credentials..."  -ForegroundColor Green
Log-Write -LogPath $sLogFile -LineValue "Verifying Credentials..."
Write-Host ""
Write-Host ""
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole] "Administrator"))
{
 Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
 Write-Host ""
 Write-Host ""
 Log-Error -LogPath $sLogFile -ErrorDesc "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!" -ExitGracefully $True
}

#Verifying the Clusters txt file exists
Log-Write -LogPath $sLogFile -LineValue "Verifying the Clusters txt file exists..."  
If (!(Test-Path $Clusters))
{
    Write-Warning "The Clusters file ($Clusters) was not found!  Please check if the the file $Clusters exists."
    Write-Host ""
    Write-Host ""
    Log-Error -LogPath $sLogFile -ErrorDesc "The Servers file ($Clusters) was not found!  Please check if the the file $Clusters exists." -ExitGracefully $True
}

#Verifying the Files txt file exists
Log-Write -LogPath $sLogFile -LineValue "Verifying the Files txt file exists..."  
If (!(Test-Path $FileList))
{
    Write-Warning "The Clusters file ($FileList) was not found!  Please check if the the file $FileList exists."
    Write-Host ""
    Write-Host ""
    Log-Error -LogPath $sLogFile -ErrorDesc "The Servers file ($FileList) was not found!  Please check if the the file $FileList exists." -ExitGracefully $True
}

#Reading Clusters list from file
$ClusterList = Get-Content $clusters | Where-Object { ($_.Trim() -ne '') -and ($_.Trim() -notlike '#*') }
[string]$ClusterListCount = $ClusterList.count
Log-write -LogPath $sLogFile -LineValue "Cluster List Count: $ClusterListCount"

#Reading Files list from file
$files = Get-content $fileList | Where-Object { ($_.Trim() -ne '') -and ($_.Trim() -notlike '#*') }  

##### WRITE OUTPUT FILES, ONE FILE PER COLLECTION #######################################################
#File to write output, if exists, delete it.

$OutputCluster01 = "$TargetFolder\Cluster-Core.csv"; If (Test-Path $OutputCluster01) {Remove-Item $OutputCluster -Force}
$OutputCluster02 = "$TargetFolder\Cluster-nodes.csv"; If (Test-Path $OutputCluster02) {Remove-Item $OutputCluster -Force}
$OutputCluster03 = "$TargetFolder\Cluster-group.csv" ; If (Test-Path $OutputCluster03) {Remove-Item $OutputCluster -Force}
$OutputCluster04 = "$TargetFolder\Cluster-groupadv.csv" ; If (Test-Path $OutputCluster04) {Remove-Item $OutputCluster -Force}
$OutputCluster05 = "$TargetFolder\Cluster-groupowners.csv"; If (Test-Path $OutputCluster05) {Remove-Item $OutputCluster -Force}
$OutputCluster06 = "$TargetFolder\Cluster-res.csv"; If (Test-Path $OutputCluster06) {Remove-Item $OutputCluster -Force}
$OutputCluster07 = "$TargetFolder\Cluster-resadv.csv"; If (Test-Path $OutputCluster07) {Remove-Item $OutputCluster -Force}
$OutputCluster08 = "$TargetFolder\Cluster-resowners.csv"; If (Test-Path $OutputCluster08) {Remove-Item $OutputCluster -Force}
$OutputCluster09 = "$TargetFolder\Cluster-net.csv"; If (Test-Path $OutputCluster09) {Remove-Item $OutputCluster -Force}
$OutputCluster10 = "$TargetFolder\Cluster-netint.csv"; If (Test-Path $OutputCluster10) {Remove-Item $OutputCluster -Force}
$OutputCluster11 = "$TargetFolder\Cluster-access.csv"; If (Test-Path $OutputCluster11) {Remove-Item $OutputCluster -Force}
$OutputCSV = "$TargetFolder\Cluster-CSV.csv"; If (Test-Path $OutputCSV) {Remove-Item $OutputCSV -Force}
$OutputCSVState = "$TargetFolder\Cluster-CSVState.csv"; If (Test-Path $OutputCSVState) {Remove-Item $OutputCSVState -Force}
$OutputEvents = "$TargetFolder\HostEventInfo.csv"; If (Test-Path $OutputEvents) {Remove-Item $OutputEvents -force}
$OutputComputerinfo = "$TargetFolder\HostComputerinfo.csv"; If (Test-Path $OutputComputerinfo) {Remove-Item $OutputComputerinfo -force}
$OutputHotfixes = "$TargetFolder\HostHotfixes.csv"; If (Test-Path $OutputHotfixes) {Remove-Item $OutputHotfixes -Force}
$OutputFiles = "$TargetFolder\HostFiles.csv.csv"; If (Test-Path $OutputFiles) {Remove-Item $OutputFiles -Force}
$OutputWinFeats = "$TargetFolder\HostWindowsFeats.csv"; If (Test-Path $OutputWinFeats) {Remove-Item $OutputWinFeats -force}
$OutputVMHost = "$TargetFolder\VMHost.csv"; If (Test-Path $OutputVMHost) {Remove-Item $OutputVMHost -Force}
$OutputVMHostDDA = "$TargetFolder\VMHostDDA.csv"; If (Test-Path $OutputVMHostDDA) {Remove-Item $OutputVMHostDDA -Force}
$OutputVMHostNuma   = "$TargetFolder\VMHostNuma.csv"; If (Test-Path $OutputVMHostNuma) {Remove-Item $OutputVMHostNuma -Force}
$OutputVMHostNumaStatus  = "$TargetFolder\VMHostNumaStatus.csv"; If (Test-Path $OutputVMHostNumaStatus) {Remove-Item $OutputVMHostNumaStatus -Force}
$OutputVMHostGPU  = "$TargetFolder\VMHostGPU.csv"; If (Test-Path $OutputVMHostGPU) {Remove-Item $OutputVMHostGPU -Force}
$OutputVMHostVersions = "$TargetFolder\VMHostVersions.csv"; If (Test-Path $OutputVMHostVersions) {Remove-Item $OutputVMHostVersions -Force}
$OutputNetAdapters = "$TargetFolder\NetAdapters.csv"; If (Test-Path $OutputNetAdapters) {Remove-Item $OutputNetAdapters -force}
$OutputNetAdpRSS = "$TargetFolder\NetAdpRSS.csv"; If (Test-Path $OutputNetAdpRSS) {Remove-Item $OutputNetAdpRSS -force}
$OutputNetAdpRDMA = "$TargetFolder\NetAdpRDMA.csv"; If (Test-Path $OutputNetAdpRDMA) {Remove-Item $OutputNetAdpRDMA -force}
$OutputNetHW = "$TargetFolder\NetHW.csv"; If (Test-Path $OutputNetHW) {Remove-Item $OutputNetHW -Force}
$OutputNetAdvProp = "$TargetFolder\NetAdvProp.csv"; If (Test-Path $OutputNetAdvProp) {Remove-Item $OutputNetAdvProp -Force}
$OutputNetPower = "$TargetFolder\NetPower.csv" ; If (Test-Path $OutputNetPower) {Remove-Item $OutputNetPower -Force}
$OutputNetBinding = "$TargetFolder\NetBinding.csv" ; If (Test-Path $OutputNetBinding) {Remove-Item $OutputNetBinding -Force}
$OutputNetRss = "$TargetFolder\NetRss.csv" ; If (Test-Path $OutputNetRss) {Remove-Item $OutputNetRss -Force}
$OutputNetBIOS = "$TargetFolder\NetBIOS.csv" ; If (Test-Path $OutputNetBIOS) {Remove-Item $OutputNetBIOS -Force}
$OutputTCPSettings = "$TargetFolder\TCPSetting.csv" ; If (Test-Path $OutputTCPSettings) {Remove-Item $OutputTCPSettings -Force}
$OutputSmbShare = "$TargetFolder\SmbShare.csv" ; If (Test-Path $OutputSmbShare) {Remove-Item $OutputSmbShare -Force}
$OutputSmbSrvConfig = "$TargetFolder\SmbSrvConfig.csv" ; If (Test-Path $OutputSmbSrvConfig) {Remove-Item $OutputSmbSrvConfig -Force}
$OutputSmbCliConfig = "$TargetFolder\SmbCliConfig.csv" ; If (Test-Path $OutputSmbCliConfig) {Remove-Item $OutputSmbCliConfig -Force}
$OutputSmbCliNets = "$TargetFolder\SmbCliNets.csv" ; If (Test-Path $OutputSmbCliNets) {Remove-Item $OutputSmbCliNets -Force}
$OutputSmbSession = "$TargetFolder\SmbSession.csv" ; If (Test-Path $OutputSmbSession) {Remove-Item $OutputSmbSession -Force}
$OutputSmbConn = "$TargetFolder\SmbConn.csv" ; If (Test-Path $OutputSmbConn) {Remove-Item $OutputSmbConn -Force}
$OutputSmbMulti = "$TargetFolder\SmbMulti.csv" ; If (Test-Path $OutputSmbMulti) {Remove-Item $OutputSmbMulti -Force}
$OutputLBFO = "$TargetFolder\TeamLBFO.csv"; If (Test-Path $OutputLBFO) {Remove-Item $OutputLBFO -Force}
$OutputVMSWitch = "$TargetFolder\VMSwitch.csv"; If (Test-Path $OutputVMSWitch) {Remove-Item $OutputVMSWitch -Force}
$OutputVMSwithTeam = "$TargetFolder\VMSwitchTeam.csv"; If (Test-Path $OutputVMSwithTeam) {Remove-Item $OutputVMSwithTeam -Force}
$OutputSwitchExt = "$TargetFolder\VMSwitchExt.csv"; If (Test-Path $OutputSwitchExt) {Remove-Item $OutputSwitchExt -Force}
$OutputvNIC = "$TargetFolder\NetvNIC.csv"; If (Test-Path $OutputvNIC) {Remove-Item $OutputvNIC -Force}
$OutputvNICACL = "$TargetFolder\NetvNICACL.csv"; If (Test-Path $OutputvNICACL) {Remove-Item $OutputvNICACL -Force}
$OutputvNICIso = "$TargetFolder\NetvNICISO.csv"; If (Test-Path $OutputvNICIso) {Remove-Item $OutputvNICIso -Force}
$OutputvNICVlan = "$TargetFolder\NetvNICVLAN.csv"; If (Test-Path $OutputvNICVlan) {Remove-Item $OutputvNICVlan -Force}
$OutputPhysicaldisk = "$TargetFolder\StoragePhyDisk.csv"; If (Test-Path $OutputPhysicaldisk) {Remove-Item $OutputPhysicaldisk -Force}
$OutputDiskHistory = "$TargetFolder\StorageDiskHistory.csv"; If (Test-Path $OutputDiskHistory) {Remove-Item $OutputDiskHistory -Force}
$OutputMPIO = "$TargetFolder\StorageMPIOData.csv"; If (Test-Path $OutputMPIO) {Remove-Item $OutputMPIO -Force}
$OutputHBA = "$TargetFolder\StorageHBAData.csv"; If (Test-Path $OutputHBA) {Remove-Item $OutputHBA -Force}
$OutputMPIOSettings = "$TargetFolder\StorageMPIOSettings.csv"; If (Test-Path $OutputMPIOSettings) {Remove-Item $OutputMPIOSettings -Force}
$OutputvDisk = "$TargetFolder\StoragevDisk.csv"; If (Test-Path $OutputvDisk) {Remove-Item $OutputvDisk -Force}
$OutputVolume = "$TargetFolder\Storagevolume.csv"; If (Test-Path $OutputVolume) {Remove-Item $OutputVolume -Force}
       
#### END Output files init

##### START CLUSTER LOOP ######################################################################
    Write-Host "Starting Cluster collection..." $CollectClusters -ForegroundColor Cyan
    Write-Host ""
    Write-Host ""
    Log-Write -LogPath $sLogFile -LineValue "Starting Cluster collection..." 

    # CLUSTER ACTIVITY Progress Bar artifact before the loop
    $I = $null 
    $I = 0

    ####Importing Cluster PowerShell Module in the collector machine
    Import-Module FailoverClusters  
    
    ###START CLUSTER Loop for ALL
    #Iterate through each Cluster in $ClusterList and run commands below
    ForEach ($cluster in $ClusterList)
    {
        #Progress Bar artifact 
        Write-Progress -Activity CLUSTERS -Status 'Progress->' -PercentComplete ($I/$ClusterList.Count*100)

        If (Test-Connection -ComputerName $cluster -count 1 -Quiet)
        {
            Write-Verbose ("Exporting Cluster settings for $cluster...") -Verbose
            Write-Host ""
            Log-Write -LogPath $sLogFile -LineValue "Exporting Cluster settings for $cluster..." 

            #Preparing artifacts for Cluster & Cluster Nodes collection
            #Getting Cluster domain
            $clusterdomain = $null
            $clusterdomain = (get-cluster -name $cluster).domain

            #Colleting nodes name to be used later
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
            $clusterCSV = Get-ClusterSharedVolume -Cluster $cluster | Select-Object -Property *
            $clusterCSVState =Get-ClusterSharedVolumeState -Cluster $cluster | Select-Object -Property *

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
            $clusterCSV | Export-Csv -Path $OutputCSV -NoTypeInformation -Append
            $clusterCSVState | Export-Csv -Path $OutputCSVState -NoTypeInformation -Append
            #####End Cluster Objects collection & Export process 

            if ($CollectClusterLogs) {
            ###Collecting ClusterLogs 
            Write-Host "Starting ClusterLog collection for Cluster $cluster ..." -ForegroundColor Cyan
            Log-Write -LogPath $sLogFile -LineValue "Starting ClusterLog collection for Cluster $cluster..."
            Write-Host ""
            Write-Host ""
            Get-clusterlog -Cluster $cluster -destination $TargetFolder -TimeSpan 259200 -UseLocalTime #Last 3 days only
            } #end collectClusterLogs

            if ($CollectS2DHealthLogs) {
            ###Collecting Cluster Health Logs 
            Write-Host "Starting ClusterHealth Log collection for Cluster $cluster ..." -ForegroundColor Cyan
            Log-Write -LogPath $sLogFile -LineValue "Starting ClusterHealth Log collection for Cluster $cluster..."
            Write-Host ""
            Write-Host ""
            Get-clusterlog -Cluster $cluster -Health -destination $TargetFolder -TimeSpan 259200 -UseLocalTime #Last 3 days only
            } #end collectS2DhealthLogs

            #Progress Bar artifact before the loop
            $P = $null 
            $P = 0
            
            ###START CLUSTERNODE Loop
            #Iterate through each ClusterNode in $ClusterSrvNodes and run commands below

            Log-write -LogPath $sLogFile -LineValue " Exporting Cluster Nodes..." 
            foreach ($ClusterNode in $ClusterSrvNodes)
            {
            #Progress Bar artifact 
            Write-Progress -id 1 -Activity Nodes -Status 'Progress->' -PercentComplete ($P/$ClusterSrvNodes.Count*100)

            #Binding ClusterNode & Cluster Domain to have FQDN naming
            $ClusterNode = "$ClusterNode"+"."+"$clusterdomain"           
            
            if (Test-Connection $ClusterNode -count 1 -Quiet) 
                { 
                    Write-Verbose ("Server: $ClusterNode") -Verbose
                    Write-Host ""
                    Log-write -LogPath $sLogFile -LineValue " Processing $ClusterNode ...." 

                    if ($CollectEvents) 
                    {
                    #####START EVENTS
                    Write-Host "Starting Events collection..." -ForegroundColor Cyan
                    Log-Write -LogPath $sLogFile -LineValue "Starting Events Collection..."
                    Write-Host ""
                    Write-Host ""
                    
                    $Events = $null
                    $Events = @()
                 
                    #Event Level 1 = Critical, Level 2 = Error, 3 = Warning, 4 = Info (https://msdn.microsoft.com/en-us/library/aa394226(v=vs.85).aspx)
                        #SYSTEM 
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='system'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='system'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='system'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        #HV
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Compute-Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Compute-Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Compute-Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue              
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Config-Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Config-Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Config-Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Guest-Drivers/Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Guest-Drivers/Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Guest-Drivers/Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Hypervisor-Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Hypervisor-Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Hypervisor-Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue                        
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-VMMS-Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-VMMS-Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-VMMS-Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue                        
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Worker-Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Worker-Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Worker-Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        #SMB
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-SmbClient/Connectivity'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-SMBClient/Operational'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-SmbClient/Security'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-SMBServer/Connectivity'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-SMBServer/Operational'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-SMBServer/Security'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue                       
                        #Cluster
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-FailoverClustering/Operational'; Level=[int]4; starttime=$EventStart; endtime=$EventEnd} -MaxEvents 1000 -ErrorAction SilentlyContinue
                        # Limiting Informational Events to 1K per Node, as faulty nodes creates a huge amount of entries.
                        #S2D
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='microsoft-windows-storagespaces-spacemanager/operational'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue         
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='microsoft-windows-storagespaces-spacemanager/diagnostic'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue         
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='microsoft-windows-storagespaces-driver/operational'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue         
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='microsoft-windows-storagespaces-driver/diagnostic'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue    
                        #Export the eventlogs
                        $Events | Select-Object @{N="Cluster";E={$Cluster}}, MachineName,LogName,LevelDisplayName,Id,ProviderName,RecordId,Message,ProcessId,ThreadId,UserId,TimeCreated | Export-Csv -Path $OutputEvents -Append -NoTypeInformation
                    
                    } #end collectEvents

                    if ($CollectConfigInfo)
                    {

                        Write-Host "Starting Configuration Information collection..." -ForegroundColor Cyan
                        Log-Write -LogPath $sLogFile -LineValue "Starting Configuration Information collection..."
                        Write-Host ""
                        Write-Host ""

                        # HOST Info
                        $Computerinfo = Invoke-Command -ComputerName $ClusterNode -ScriptBlock  {Get-computerinfo} | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}},*
                        $Computerinfo | Export-Csv -Path $OutputComputerinfo -Append -NoTypeInformation 
                        Get-WindowsFeature -ComputerName $ClusterNode | Where-Object installed | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, Name, DisplayName, FeatureType  | Export-Csv -Path $OutputWinFeats -Append -NoTypeInformation
                        Get-HotFix -ComputerName $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, Description, HotFixID, InstalledBy, InstalledOn  | Export-csv -Path $OutputHotfixes -Append -NoTypeInformation
                        
                        #HOST Files FileVersion (requires RemotePS Session)
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

                        ##HOST remote PSSession for FileVersion -> Collecting the results into the local system
                        $filesresult = Invoke-Command -session $session -ScriptBlock {$fileinfo}
                        $filesresult | Where-Object {$_} | Export-Csv -Path $OutputFiles -Append -NoTypeInformation
                        Remove-PSSession -Session $session

                        # Hyper-V Host
                        Get-VMHost -ComputerName  $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-csv -Path $OutputVMHost -Append -NoTypeInformation
                        Get-VMHostAssignableDevice -ComputerName  $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-csv -Path $OutputVMHostDDA -Append -NoTypeInformation
                        Get-VMHostNumaNode -ComputerName  $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-csv -Path $OutputVMHostNuma -Append -NoTypeInformation
                        Get-VMHostNumaNodeStatus -ComputerName  $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-csv -Path $OutputVMHostNumaStatus -Append -NoTypeInformation
                        Get-VMHostPartitionableGpu -ComputerName  $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-csv -Path $OutputVMHostGPU -Append -NoTypeInformation
                        Get-VMHostSupportedVersion -ComputerName  $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-csv -Path $OutputVMHostVersions -Append -NoTypeInformation

                        #HOST Mitigations/Hyper-Care
                        ## PENDING

                        # HOST Network
                        Get-Netadapter -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputNetAdapters -Append -NoTypeInformation                    
                        Get-NetAdapter -CimSession $ClusterNode | Where-Object {$_.ifOperStatus -eq "Up"} | Get-NetAdapterAdvancedProperty  | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputNetAdvProp -Append -NoTypeInformation
                        Get-NetAdapter -CimSession $ClusterNode | Where-Object {$_.ifOperStatus -eq "Up"} | Get-NetAdapterBinding -ErrorAction SilentlyContinue | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, Name, DisplayName, ComponentID, Enabled | Export-Csv -Path $OutputNetBinding -Append -NoTypeInformation
                        Get-NetAdapterRSS -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputNetAdpRSS -Append -NoTypeInformation
                        Get-NetAdapterRDMA -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputNetAdpRDMA -Append -NoTypeInformation
                        Get-NetAdapterHardwareInfo -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}}, @{N="ComputerName";E={$ClusterNode}}, *| Export-Csv -Path $OutputNetHW -Append -NoTypeInformation           
                        Get-NetLbfoTeam -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputLBFO -Append -NoTypeInformation
                        Get-NetAdapterPowerManagement -CimSession $Clusternode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, Name, SelectiveSuspend, DeviceSleepOnDisconnect, WakeOnMagicPacket, WakeOnPattern  | Export-Csv -Path $OutputNetPower -Append -NoTypeInformation   
                        Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $Clusternode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, Description, TcpipNetbiosOptions* | Export-Csv -Path $OutputNetBIOS -Append -NoTypeInformation      
                        Get-NetTCPSetting -CimSession $Clusternode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputTCPSettings -Append -NoTypeInformation
                        
                        #Hyper-V Switch
                        Get-VMSwitch -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputVMSWitch -Append -NoTypeInformation
                        Get-VMSwitch -CimSession $ClusterNode | Get-VMSwitchTeam -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, Name, Id, TeamingMode, LoadBalancingAlgorithm, @{N="NetAdapterInterfaceDescription" ;E={$_ | Select-Object * -ExpandProperty NetAdapterInterfaceDescription}}| Export-Csv -Path $OutputVMSwithTeam -Append -NoTypeInformation
                        Get-VMSwitch -CimSession $ClusterNode | Get-VMSwitchExtension -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputSwitchExt -Append -NoTypeInformation            
                        Get-VMNetworkAdapter -ManagementOS -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputvNIC -Append -NoTypeInformation
                        Get-VMNetworkAdapterAcl -ManagementOS  -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputvNICACL -Append -NoTypeInformation
                        Get-VMNetworkAdapterIsolation -ManagementOS  -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, ** | Export-Csv -Path $OutputvNICIso -Append -NoTypeInformation
                        Get-VMNetworkAdapterVlan -ManagementOS  -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputvNICVlan -Append -NoTypeInformation

                        #SMB Information  
                        Get-SmbShare -CimSession $ClusterNode | Where-Object {$_.ScopeName -ne "*"} | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputSmbShare -Append -NoTypeInformation   
                        Get-SmbServerConfiguration -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}},  * | Export-Csv -Path $OutputSmbSrvConfig -Append -NoTypeInformation
                        Get-SmbClientConfiguration -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputSmbCliConfig -Append -NoTypeInformation
                        Get-SmbClientNetworkInterface -CimSession $ClusterNode | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputSmbCliNets -Append -NoTypeInformation
                        Get-SmbSession -CimSession $ClusterNode -SmbInstance CSV | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputSmbSession -Append -NoTypeInformation
                        Get-SmbSession -CimSession $ClusterNode -SmbInstance SBL | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputSmbSession -Append -NoTypeInformation
                        Get-SmbConnection -CimSession $ClusterNode -SmbInstance CSV | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputSmbConn -Append -NoTypeInformation
                        Get-SmbConnection -CimSession $ClusterNode -SmbInstance SBL | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputSmbConn -Append -NoTypeInformation
                        Get-SmbMultichannelConnection -CimSession $ClusterNode -SmbInstance CSV | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputSmbMulti -Append -NoTypeInformation
                        Get-SmbMultichannelConnection -CimSession $ClusterNode -SmbInstance CSV | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}}, * | Export-Csv -Path $OutputSmbMulti -Append -NoTypeInformation
                        

                        # HOST Storage (requires invoked sessions)
                        $physicaldisk = Invoke-Command -ComputerName $ClusterNode -ScriptBlock  {Get-PhysicalDisk} | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}},*
                        $physicaldisk | Export-Csv -Path $Outputphysicaldisk -Append -NoTypeInformation 
                        
                        if ($CollectDiskHistory)
                        {
                        Write-Host "Starting physical disk history collection (this might take a while)..." -ForegroundColor Cyan
                        Log-Write -LogPath $sLogFile -LineValue "Starting physical disk history collection..."
                        Write-Host ""
                        Write-Host ""
                        $diskhistory = Invoke-Command -ComputerName $ClusterNode -ScriptBlock  {Get-PhysicalDisk | Get-StorageHistory -NumberOfHours 168} | Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}},FriendlyName,SerialNumber,FirmwareRevision,DeviceNumber,MediaType,StartTime,EndTime,TotalIoCount,SuccessIoCount,FailedIoCount,AvgIoLatency,TotalErrors,BucketIoPercent 
                        $diskhistory | Export-Csv -Path $OutputDiskHistory -Append -NoTypeInformation
                        } 

                        $MPIOStatistics = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {Get-WMIObject -NameSpace "root/wmi" -Class "MPIO_DISK_HEALTH_INFO" | Select-Object -Expand DiskHealthPackets} | Select-Object @{N="Cluster";E={$Cluster}},@{L="ComputerName";E={$ClusterNode}}, Name, NumberReads, NumberWrites, PathFailures, NumberIoErrors, NumberRetries 
                        $MPIOStatistics | Export-Csv -Path $OutputMPIO -Append -NoTypeInformation
                        $HBAStatistics = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {Get-WMIObject -NameSpace "root/wmi" -Class "MSFC_FibrePortHBAStatistics" | Select-Object -Expand Statistics} | Select-Object @{N="Cluster";E={$Cluster}},@{L="ComputerName";E={$ClusterNode}}, DumpedFrames, ErrorFrames, InvalidCRCCount, InvalidTxWordCount, LinkFailureCount, LIPCount, LossOfSignalCount, LossOfSyncCount, NOSCount, SecondsSinceLastReset
                        $HBAStatistics | Export-Csv -Path $OutputHBA -Append -NoTypeInformation        
                        $MPIOSettings = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {Get-MPIOSetting}| Select-Object @{N="Cluster";E={$Cluster}},@{N="ComputerName";E={$ClusterNode}},PathVerificationState, PathVericationPeriod, PDORemovePeriod, RetryCount, RetryInterval, UseCustomPathRecoveryTime, CustomPathRecoveryTime, DiskTimeoutValue
                        $MPIOSettings | Export-Csv -Path $OutputMPIOSettings -Append -NoTypeInformation
                        $virtualDisk = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {Get-VirtualDisk} | Select-Object @{N="Cluster";E={$Cluster}},@{L="ComputerName";E={$ClusterNode}}, *
                        $virtualDisk | Export-Csv -Path $OutputvDisk -Append -NoTypeInformation 
                        $Volumes = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {Get-Volume} | Select-Object @{N="Cluster";E={$Cluster}},@{L="ComputerName";E={$ClusterNode}}, *
                        $Volumes| Export-Csv -Path $OutputVolume -Append -NoTypeInformation 

                    } #end collectconfiginfo

                    #Progress Bar artifact 
                    $P = $P +1

                } #EndIf Node is respoding, if not skip to next
 
            else #ClusterNode is not respoding, we write output and write log and go next
                {
                Write-Host "Connection to"$ClusterNode "does not work properly! going to next one ...." -ForegroundColor "red"
                Write-Host ""
                Write-Host ""
                Log-Error -LogPath $sLogFile -ErrorDesc "Connection to $ClusterNode does not work properly! going to next one ...." -ExitGracefully $false
                }
        
            } #End foreach ClusterNode loop inside the cluster loop

        } #EndIf CLUSTER is respoding, if not skip to next

       
        else #CLUSTER is not respoding, write output and error in log and go next
        {
            Write-Host "Connection to"$Cluster "does not work properly! going to next one ...." -ForegroundColor "red"
            Write-Host ""
            Write-Host ""
            Log-Error -LogPath $sLogFile -ErrorDesc "Connection to $Cluster does not work properly! going to next one ...." -ExitGracefully $false
        }

        #Progress Bar artifact 
        Write-Progress -Activity Nodes -Completed
        Log-write -LogPath $sLogFile -LineValue " Processed ClusterNode Count:$P out of $ClusterSrvNodesCount in Cluster $cluster" 
        
        #Progress Bar artifact
        $I = $I +1 
    } #END forech CLUSTER loop

    Write-Progress -Activity CLUSTERS -Completed
#####END CLUSTER

Write-Host "Health Check scripts completed." -ForegroundColor Green
Write-Host ""
Write-Host ""
Log-write -LogPath $sLogFile -ErrorDesc "Finishing Events and Configuration collection." -ExitGracefully $True
Log-Finish -LogPath $sLogFile
#####END Events & configuration collection