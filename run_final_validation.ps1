$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
$oldPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = "$root;$oldPythonPath"
Push-Location $env:TEMP
try {
	& $py -m unittest discover -s (Join-Path $root "tests") -p "test_*.py"
	if ($LASTEXITCODE -ne 0) { throw "Unit tests failed." }

	& $py (Join-Path $root "validate_passive_opcua_services.py")
	if ($LASTEXITCODE -ne 0) { throw "Passive service validation failed." }
	& $py (Join-Path $root "validate_ground_truth_opcua.py")
	if ($LASTEXITCODE -ne 0) { throw "Ground-truth enrichment validation failed." }
	& $py (Join-Path $root "run_probe.py") --mode offline --benchmark-dir (Join-Path $root "release_pcaps") --benchmark-output "$env:TEMP\opcua_benchmark_report.json"
	if ($LASTEXITCODE -ne 0) { throw "Release PCAP benchmark failed." }

	Write-Host "OPC UA research prototype validation passed."
}
finally {
	Pop-Location
	$env:PYTHONPATH = $oldPythonPath
}

