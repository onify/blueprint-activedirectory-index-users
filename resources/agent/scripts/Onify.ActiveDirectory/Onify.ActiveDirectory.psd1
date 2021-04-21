@{
  RootModule = 'Onify.ActiveDirectory.psm1'
  ModuleVersion = '1.0.0.0'
  GUID = '5f1f5c2d-3d2e-43ad-828a-55f3b38c17f5'
  Author = 'Zitac Consulting AB'
  CompanyName = 'Zitac Consulting AB'
  Copyright = '(c) 2021 Enfo Zipper. All rights reserved.'
  Description = 'Module that helps you index AD objects into Onify.'
  PowerShellVersion = '3.0'
  FunctionsToExport = @(
    'Get-ADDSObject','Write-Log'
  )
  ModuleList = @('Onify.ActiveDirectorypsm1')
  FileList = @(
    'Onify.ActiveDirectory.psm1',
    'Onify.ActiveDirectory.psd1'
  )
}