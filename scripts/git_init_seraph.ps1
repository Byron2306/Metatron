$repo = 'C:\Users\User\source\repos\Metatron-cursor-metatron-system-governance-a999'
Set-Location $repo
Write-Host 'Initializing git repository and committing all files...'
git init
git add -A
try {
    git commit -m "Import: Seraph v11"
}
catch {
    Write-Host "Commit may have failed (nothing to commit or error): $_"
}
Write-Host 'Creating and switching to branch "Seraph v11"'
git checkout -b "Seraph v11"
Write-Host "Repository initialized and branch 'Seraph v11' created locally."
Write-Host "To push to a remote, run (example):\n  git remote add origin <url>\n  git push -u origin 'Seraph v11'"
