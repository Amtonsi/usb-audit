# Проверка строгого распознавания истории после удаления ПО. Права на диске не меняются.
$ErrorActionPreference='Stop'
$parser=[Management.Automation.Language.Parser]
$tokens=$null; $errors=$null
$ast=$parser::ParseFile((Join-Path $PSScriptRoot '..\src\Install.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw $errors[0].Message }
$fn=$ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-RetainedAcl' },$true)
. ([scriptblock]::Create($fn.Extent.Text))
function Assert-RegularPath([string]$Path) {}
function Get-Acl([string]$LiteralPath,[string]$ErrorAction) { return $script:sample }
$rule='O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FR;;;BU)'
$sample=[Security.AccessControl.DirectorySecurity]::new()
$sample.SetSecurityDescriptorSddlForm('O:BAG:BAD:PAI(A;;FR;;;BU)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)')
Assert-RetainedAcl $PSScriptRoot $rule
foreach ($bad in @($rule.Replace('FR;;;BU','FW;;;BU'),$rule.Replace('O:BA','O:BU'),$rule.Replace('D:P','D:'),($rule+'(A;;FW;;;AU)'))) {
    $sample.SetSecurityDescriptorSddlForm($bad)
    $rejected=$false
    try { Assert-RetainedAcl $PSScriptRoot $rule } catch {$rejected=$true}
    if (!$rejected) { throw "Недоверенный дескриптор распознан как штатный: $bad" }
}
Write-Output 'Проверены доверенный владелец, защита DACL, состав и маски разрешений для сохранённой истории.'
