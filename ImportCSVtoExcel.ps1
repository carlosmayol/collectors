#PowerAutomate approach
#https://docs.microsoft.com/en-us/office/dev/scripts/resources/samples/convert-csv

#import multiple CSV files into separate Excel worksheets
$inputfolder='C:\Temp\2021_11_15_012208’
$mergedwb='C:\Temp\2021_11_15_012208\hcv6.xlsx'

$excel = New-Object -ComObject Excel.Application
$excel.Visible = $true
$wb = $excel.Workbooks.Add()

Get-ChildItem $inputfolder\*.csv | ForEach-Object {
    if ((Import-Csv $_.FullName).Length -gt 0) {
        $csvBook = $excel.Workbooks.Open($_.FullName)
        $csvBook.ActiveSheet.Copy($wb.Worksheets($wb.Worksheets.Count))
        $csvBook.Close()
    }
}

$wb.Sheets.Item('sheet1').Delete()
$wb.Sheets.Item('sheet2').Delete()

$wb.SaveAs($mergedwb)
$wb.Close()
$excel.Quit()

$null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($sheet); 
$null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($wb); 
$null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($xl); 
[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()