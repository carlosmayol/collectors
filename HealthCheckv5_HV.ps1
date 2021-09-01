﻿<#
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
  Execution Log file stored in C:\Temp\<name>.log>

.NOTES

V5.7 (under development, Hyper-V/S2D Clusters 2.1)

This version is ortiented to colect Hyper-V Cluster nodes, all the nodes must belong to a cluster. 
Standalone nodes are not supported.

 Event logs (System, Cluster, S2D, HV, SMB)
 Cluster information ALL nodes
 Windows Features ALL Nodes
 Network Adapter Drivers ALL Nodes
 Per Cluster nodes KBs comparison
 Per Cluster nodes File versions
 Per Cluster nodes Network Adapter
 Per Cluster nodes Network Adapter Advanced properties
 Per Cluster nodes Network HW information
 Per Cluster nodes Network LBFO Settings
 Per Cluster nodes Virtual NICs Adapter settings (Vmq, vmmq, vrss)
 Per Cluster nodes MPIO & HBA health stats
 
Pending:
Events entries for Storage/PnP/Storport
SET Team data
Virtual Disk And Physical Disk Data (S2D)
Per Cluster nodes MPIO & MSDSM settings


##########
Changelog:
##########

/NOTES:

.EXAMPLE
Run the script to collect Events and configuration information 
  Powershell.exe -file "[Path]\healthcheckv5.ps1"

Run the script to collect Events only 
  Powershell.exe -file "[Path]\healthcheckv5.ps1" -EventsOnly

#>

#----------------------------------------------------------[Declarations]----------------------------------------------------------

Param(      
      [string]$TargetFolder, #Parameter to define target location of result csv files, default C:\temp\$date
      [string]$Clusters=".\Clusters.txt", #TXT containing the list of cluster Names to collect cluster information, default .\clusters.txt
      [string]$FileList=".\Files.txt", #TXT containing the list of files to collect fileversioninfo, default .\files.txt     
      [DateTime]$EventStart, #Parameter to define Start Event log date
      [DateTime]$EventEnd, #Parameter to define End Event log date
      [switch]$EventsOnly #Boolean parameter to define if we collect event logs only
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
$sScriptVersion = "5.7"

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

#File to write output
$OutputWinFeats = "$TargetFolder\WindowsFeats.csv"
#If output file exists, delete it to create a new one
If (Test-Path $OutputWinFeats) {Remove-Item $OutputWinFeats -force}

#File to write output
$OutputNetFDrivers = "$TargetFolder\NetDrivers.csv"
#If output file exists, delete it to create a new one
If (Test-Path $OutputNetFDrivers) {Remove-Item $OutputNetFDrivers -force}

#Defining objects for Event collection
$Events = $null
$Events = @()

##### CONDITION to determine collection SCOPE, JUST Events or Everything ################
if ($EventsOnly) 
{
    
    ###START CLUSTER Loop for EVENTS
    Write-Host "Starting Cluster collection for Events only..." $CollectClusters -ForegroundColor Cyan
    Write-Host ""
    Write-Host ""
    Log-Write -LogPath $sLogFile -LineValue "Starting Cluster collection for Events only..." 

    # CLUSTER ACTIVITY Progress Bar artifact before the loop
    $I = $null 
    $I = 0

    #Iterate through each Cluster in $ClusterList and run commands below
    ForEach ($cluster in $ClusterList)
        {   

        If (Test-Connection -ComputerName $cluster -count 1 -Quiet)
        {
            Write-Verbose ("Exporting Cluster settings for: $cluster...") -Verbose
            Write-Host ""
            Log-Write -LogPath $sLogFile -LineValue "Exporting Cluster settings for: $cluster..." 

            #Progress Bar artifact 
            Write-Progress -Activity CLUSTERS -Status 'Progress->' -PercentComplete ($I/$ClusterList.Count*100)

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


            ##### WRITE OUTPUT FILES, ONE FILE PER CLUSTER #######################################################
            #File to write output for Events collection per Cluster
            $OutputEvents = "$TargetFolder\EventInfo_$Cluster.csv"
            #If output file exists, delete it to create a new one
            If (Test-Path $OutputEvents) {Remove-Item $OutputEvents -force}

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
                $Clusternode = "$ClusterNode"+"."+"$clusterdomain"
                if (Test-Connection $ClusterNode -count 1 -Quiet) 
                    { 
                        Write-Verbose ("Server: $ClusterNode") -Verbose
                        Write-Host ""
                        Log-write -LogPath $sLogFile -LineValue " Processing $ClusterNode ...." 

                        #####START EVENTS
                        Write-Host "Starting Events collection..." -ForegroundColor Cyan
                        Log-Write -LogPath $sLogFile -LineValue "Starting Events Collection..."
                        Write-Host ""
                        Write-Host ""

                        #Starting Events export for Microsoft-Windows-FailoverClustering/Operational, system entries are collected using the servers.txt.                    
                        Log-write -LogPath $sLogFile -LineValue "  Collecting Failover Cluster events for $Clusternode..."
                        
                        #Event Level 1 = Critical, Level 2 = Error, 3 = Warning, 4 = Info (https://msdn.microsoft.com/en-us/library/aa394226(v=vs.85).aspx)
                        #SYSTEM
                        $Events = $null
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='system'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='system'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='system'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
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
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-FailoverClustering/Operational'; Level=[int]4; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        #S2D
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='microsoft-windows-storagespaces-spacemanager/operational'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue         
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='microsoft-windows-storagespaces-spacemanager/diagnostic'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue         
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='microsoft-windows-storagespaces-driver/operational'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue         
                        $Events += Get-WinEvent -Oldest  -ComputerName $ClusterNode -FilterHashtable @{LogName='microsoft-windows-storagespaces-driver/diagnostic'; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue    
                        
                        #Cluster
                        $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-FailoverClustering/Operational'; Level=[int]4; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                        
                        $Events | Select-Object MachineName,LogName,LevelDisplayName,Id,ProviderName,RecordId,Message,ProcessId,ThreadId,UserId,TimeCreated | Export-Csv -Path $OutputEvents -Append -NoTypeInformation
                        #End Cluster Events export inside the cluster loop

                    } #End test connection

                else #ClusterNode is not respoding, we write output and write log and go next
                    {
                    Write-Host "Connection to"$ClusterNode "does not work properly! going to next one ...." -ForegroundColor "red"
                    Write-Host ""
                    Write-Host ""
                    Log-Error -LogPath $sLogFile -ErrorDesc "Connection to $ClusterNode does not work properly! going to next one ...." -ExitGracefully $false
                    }
            
            } #End foreach ClusterNode loop inside the cluster loop if connection works

            #Progress Bar artifact 
            $P = $P +1

            }#END foreach ClusterNode loop inside the cluster loop if connection fails


        Else #CLUSTER is not respoding, write output and error in log and go next
            {
                Write-Host "Connection to"$Cluster "does not work properly! going to next one ...." -ForegroundColor "red"
                Write-Host ""
                Write-Host ""
                Log-Error -LogPath $sLogFile -ErrorDesc "Connection to $Cluster does not work properly! going to next one ...." -ExitGracefully $false

            }

        #Progress Bar artifact 
        $I = $I +1

        }#End CLUSTER loop

Log-write -LogPath $sLogFile -ErrorDesc "Finishing EventOnly collection." -ExitGracefully $True
Log-Finish -LogPath $sLogFile
} #END EventsOnly collection ##################################################################


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
    #Defining objects for Hotfixes collection
    $Hotfixes = $null
    $Hotfixes = @()
    $hfresult = $null
    $hfresult = @()

        If (Test-Connection -ComputerName $cluster -count 1 -Quiet)
        {
            Write-Verbose ("Exporting Cluster settings for: $cluster...") -Verbose
            Write-Host ""
            Log-Write -LogPath $sLogFile -LineValue "Exporting Cluster settings for: $cluster..." 

            #Progress Bar artifact 
            Write-Progress -Activity CLUSTERS -Status 'Progress->' -PercentComplete ($I/$ClusterList.Count*100)

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

            ##### WRITE OUTPUT FILES, ONE FILE PER CLUSTER #######################################################

            #File to write output for Events collection per Cluster
            $OutputEvents = "$TargetFolder\EventInfo_$Cluster.csv"
            #If output file exists, delete it to create a new one
            If (Test-Path $OutputEvents) {Remove-Item $OutputEvents -force}

            #File to write output for files collection per Cluster
            $OutputFileversion = "$TargetFolder\Files.csv_$cluster.csv"
            #If Output file exists, delete it
            If (Test-Path $OutputFileversion) {Remove-Item $OutputFileversion -Force}

            #File to write output for LBFO per Cluster
            $OutputLBFO = "$TargetFolder\LBFO"+"_$cluster.csv"
            #If Output file exists, delete it to create a new one
            If (Test-Path $OutputLBFO) {Remove-Item $OutputLBFO -Force}

            #File to write output for NetAdapterHWInfo per Cluster
            $OutputNetHW = "$TargetFolder\NetHW"+"_$cluster.csv"
            #If Output file exists, delete it to create a new one
            If (Test-Path $OutputNetHW) {Remove-Item $OutputNetHW -Force}

            #File to write output for NetAdvProp per Cluster
            $OutputNetAdvProp = "$TargetFolder\NetAdvProp"+"_$cluster.csv"
            #If Output file exists, delete it to create a new one
            If (Test-Path $OutputNetAdvProp) {Remove-Item $OutputNetAdvProp -Force}
            
            #File to write output for vNIC per Cluster
            $OutputvNIC = "$TargetFolder\NetvNIC"+"_$cluster.csv"
            #If Output file exists, delete it to create a new one
            If (Test-Path $OutputvNIC) {Remove-Item $OutputvNIC -Force}

            #File to write output for MPIO/HBA per Cluster
            $OutputMPIO = "$TargetFolder\MPIOData"+"_$cluster.csv"
            $OutputHBA = "$TargetFolder\HBAData"+"_$cluster.csv"
            #If Output file exists, delete it to create a new one
            If (Test-Path $OutputMPIO) {Remove-Item $OutputMPIO -Force}
            If (Test-Path $OutputHBA) {Remove-Item $OutputHBA -Force}

            #File to write output for MPIO Settings per Cluster
            $OutputMPIOSettings = "$TargetFolder\MPIOSettings"+"_$cluster.csv"
            #If Output file exists, delete it to create a new one
            If (Test-Path $OutputLBFO) {Remove-Item $OutputMPIOSettings -Force}
            
            #File to write output for Hotfixes per Cluster
            $OutputHotfixes = "$TargetFolder\Hotfixes"+"_$cluster.csv"
            #If Output file exists, delete it to create a new one
            If (Test-Path $OutputHotfixes) {Remove-Item $OutputHotfixes -Force}
            
            #### END Output files init


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
            $Clusternode = "$ClusterNode"+"."+"$clusterdomain"           
            
            if (Test-Connection $ClusterNode -count 1 -Quiet) 
                { 
                    Write-Verbose ("Server: $ClusterNode") -Verbose
                    Write-Host ""
                    Log-write -LogPath $sLogFile -LineValue " Processing $ClusterNode ...." 

                    #####START EVENTS
                    Write-Host "Starting Events collection..." -ForegroundColor Cyan
                    Log-Write -LogPath $sLogFile -LineValue "Starting Events Collection..."
                    Write-Host ""
                    Write-Host ""

                    #Starting Events export for Microsoft-Windows-FailoverClustering/Operational, system entries are collected using the servers.txt.                    
                    Log-write -LogPath $sLogFile -LineValue "  Collecting Failover Cluster events for $Clusternode..."
                  
                    #Event Level 1 = Critical, Level 2 = Error, 3 = Warning, 4 = Info (https://msdn.microsoft.com/en-us/library/aa394226(v=vs.85).aspx)
                    #SYSTEM
                    $Events = $null
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='system'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='system'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='system'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    #HV
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Compute-Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Compute-Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Compute-Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Config-Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Config-Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Config-Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue

                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Guest-Drivers/Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Guest-Drivers/Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Guest-Drivers/Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue

                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Hypervisor-Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Hypervisor-Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Hypervisor-Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-VMMS-Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-VMMS-Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-VMMS-Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Worker-Admin'; Level=[int]3; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Worker-Admin'; Level=[int]2; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Worker-Admin'; Level=[int]1; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                    #Cluster
                    $Events += Get-WinEvent -Oldest -ComputerName $ClusterNode -FilterHashtable @{LogName='Microsoft-Windows-FailoverClustering/Operational'; Level=[int]4; starttime=$EventStart; endtime=$EventEnd} -ErrorAction SilentlyContinue
                 
                    $Events| Select-Object MachineName,LogName,LevelDisplayName,Id,ProviderName,RecordId,Message,ProcessId,ThreadId,UserId,TimeCreated | Export-Csv -Path $OutputEvents -Append -NoTypeInformation
                    #End Cluster Events export inside the cluster loop

                    #START Windows Features
                    Write-Host "Starting Windows Features collection..." -ForegroundColor Cyan
                    Log-Write -LogPath $sLogFile -LineValue "Starting Windows Features collection..."
                    Write-Host ""
                    Write-Host ""
                    $WinFeats = @()
                    $WinFeats +=  Get-WindowsFeature -ComputerName $ClusterNode | Where-Object installed | Select-Object @{N="ComputerName";E={$ClusterNode}}, Name, DisplayName, FeatureType
                    $WinFeats | Export-Csv -Path $OutputWinFeats -Append -NoTypeInformation
                    
                    #START Network configuration  
                    Write-Host "Starting Network configuration collection..." -ForegroundColor Cyan
                    Log-Write -LogPath $sLogFile -LineValue "Starting Network configuration collection..."
                    Write-Host ""
                    Write-Host ""

                    #Starting NetAdapter Export
                    Log-write -LogPath $sLogFile -LineValue "  Collecting Netadapter info for $Clusternode..."
                    $NetDrvs = @()
                    $NetDrvs +=  Get-Netadapter -CimSession $ClusterNode | Select-Object @{N="ComputerName";E={$ClusterNode}}, Name, DriverName, DriverVersion, DriverDate, DriverDescription, DriverProvider
                    $NetDrvs | Export-Csv -Path $OutputNetFDrivers -Append -NoTypeInformation         
                    #Ending NetAdapter Export
                    
                    #Starting NetAdvProp Export
                    Log-write -LogPath $sLogFile -LineValue "  Collecting Netadapter AdvProp info for $Clusternode..."
                    $NetAdvProp = @()                
                    $NetAdvProp += Get-NetAdapter -CimSession $ClusterNode | Where-Object {$_.ifOperStatus -eq "Up"} | Get-NetAdapterAdvancedProperty  | Select-Object @{N="ComputerName";E={$ClusterNode}}, Name, DisplayName, DisplayValue, RegistryKeyword, RegistryKeyword
                    $NetAdvProp | Export-Csv -Path $OutputNetAdvProp -Append -NoTypeInformation
                    #Ending NetAdvProp Export

                    #Starting NetHWinfo Export
                    Log-write -LogPath $sLogFile -LineValue "  Collecting Netadapter HW info for $Clusternode..."
                    $NetHW = @()                 
                    $NetHW += Get-NetAdapterHardwareInfo -CimSession $ClusterNode | Select-Object @{N="ComputerName";E={$ClusterNode}}, Name, Bus, Device, Function, Slot, NumaNode, PcieLinkSpeed, PcieLinkWidth, Version
                    $NetHW | Export-Csv -Path $OutputNetHW -Append -NoTypeInformation
                    #Ending NetHWinfo Export

                    #Starting LBFO/TEAM Export
                    Log-write -LogPath $sLogFile -LineValue "  Collecting LBFO info for $Clusternode..."
                    $LBFO = @()               
                    $LBFO += Get-NetLbfoTeam -CimSession $ClusterNode | Select-Object @{N="ComputerName";E={$ClusterNode}}, Name, Members, TeamNics, TeamingMode, LoadBalancingAlgorithm, Status
                    $LBFO | Export-Csv -Path $OutputLBFO -Append -NoTypeInformation
                    #Ending LBFO/TEAM Export

                    #Starting vNIC Export
                    Log-write -LogPath $sLogFile -LineValue "  Collecting vNIC info for $Clusternode..."
                    $LBFO = @()               
                    $LBFO += Get-VMNetworkAdapter -ManagementOS -CimSession $ClusterNode | Select-Object @{N="ComputerName";E={$ClusterNode}}, Name, vr*,vmq*, vmmq*
                    $LBFO | Export-Csv -Path $OutputvNIC -Append -NoTypeInformation
                    #Ending vNIC Export
                    
                    #START Storage configuration collection
                    Write-Host "Starting Storage configuration collection..." -ForegroundColor Cyan
                    Log-Write -LogPath $sLogFile -LineValue "Starting Storage collection..."
                    Write-Host ""
                    Write-Host ""

                    #Starting MPIO/HBA Stats collection
                    Log-write -LogPath $sLogFile -LineValue "  Collecting MPIO/HBA Stats info for $Clusternode..."                
                    $MPIOStatistics = @()
                    $HBAStatistics = @()
                    $MPIOStatistics += Invoke-Command -ComputerName $ClusterNode -ScriptBlock {Get-WMIObject -NameSpace "root/wmi" -Class "MPIO_DISK_HEALTH_INFO" | Select-Object -Expand DiskHealthPackets} | Select-Object @{L="ComputerName";E={$ClusterNode}}, Name, NumberReads, NumberWrites, PathFailures, NumberIoErrors, NumberRetries | Sort-Object ComputerName, Name
                    $HBAStatistics += Invoke-Command -ComputerName $ClusterNode -ScriptBlock {Get-WMIObject -NameSpace "root/wmi" -Class "MSFC_FibrePortHBAStatistics" | Select-Object -Expand Statistics} | Select-Object @{L="ComputerName";E={$ClusterNode}}, DumpedFrames, ErrorFrames, InvalidCRCCount, InvalidTxWordCount, LinkFailureCount, LIPCount, LossOfSignalCount, LossOfSyncCount, NOSCount, SecondsSinceLastReset | Sort-Object ComputerName, InvalidTxWordCount
                    $MPIOStatistics | Export-Csv -Path $OutputMPIO -Append -NoTypeInformation
                    $HBAStatistics | Export-Csv -Path $OutputHBA -Append -NoTypeInformation
                    #End MPIO/HBA Stats collection

                    #Starting MPIOSettings Export #[CM] THIS is not working...
                    Log-write -LogPath $sLogFile -LineValue "  Collecting MPIO Settings info for $Clusternode..."
                    $MPIOSettings = @()               
                    $MPIOSettings += Get-MPIOSetting -CimSession $ClusterNode | Select-Object @{N="ComputerName";E={$ClusterNode}}, PathVerificationState, PathVericationPeriod, PDORemovePeriod, RetryCount, RetryInterval, UseCustomPathRecoveryTime, CustomPathRecoveryTime, DiskTimeoutValue
                    $MPIOSettings | Export-Csv -Path $OutputMPIOSettings -Append -NoTypeInformation
                    #Ending MPIOSettings Export

                    #Starting remote PSSession for FileVersion Export
                    Write-Host "Starting File version collection..." -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host ""
                    Log-Write -LogPath $sLogFile -LineValue "Starting File version collection..."
            
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
                    $filesresult | Where-Object {$_} | Export-Csv -Path $OutputFileversion -Append -NoTypeInformation
                    Remove-PSSession -Session $session
                    #Finishing remote PSSession for FileVersion Export
                    #End FileVersion Export process inside the cluster loop

                    #Starting Hotfixes collection process Part I (inside the cluster loop)
                    Write-Host "Starting KBs collection..." -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host ""
                    Log-write -LogPath $sLogFile -LineValue "Starting KBs collection..."

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

        } #EndIf CLUSTER is respoding, if not skip to next

       
        Else #CLUSTER is not respoding, write output and error in log and go next
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