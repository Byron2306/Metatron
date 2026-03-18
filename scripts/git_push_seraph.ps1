$repo = 'C:\Users\User\source\repos\Metatron-cursor-metatron-system-governance-a999'
Set-Location $repo
Write-Host '--- Git: current HEAD ---'
git rev-parse --abbrev-ref HEAD
Write-Host '--- Git: status (porcelain) ---'
$stat = git status --porcelain
if ([string]::IsNullOrWhiteSpace($stat)) {
    Write-Host 'No uncommitted changes.'
} else {
    Write-Host 'Uncommitted changes found — committing snapshot.'
    git add -A
    git commit -m "WIP: snapshot before pushing branch 'Seraph v11'"
}
Write-Host '--- Git: remotes ---'
git remote -v
$remotes = git remote
if (-not ($remotes -match 'origin')) {
    Write-Host "No 'origin' remote found. Aborting automatic push. To push, add a remote and re-run:\n  git remote add origin <url>\n  git push -u origin 'Seraph v11'"
    exit 2
}
Write-Host '--- Creating branch "Seraph v11" ---'
# Create branch from current HEAD (ignore error if it already exists)
git branch --no-track "Seraph v11" 2>$null
git checkout "Seraph v11"
Write-Host '--- Pushing branch to origin ---'
git push -u origin "Seraph v11"
Write-Host 'Done.'
