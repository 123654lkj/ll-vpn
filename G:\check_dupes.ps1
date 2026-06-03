Write-Host "=== 重复进程统计 ==="
$procs = Get-Process | Group-Object ProcessName | Where-Object Count -gt 1 | Sort-Object Count -Descending
$procs | Format-Table Count, Name -AutoSize

Write-Host "`n=== ToDesk 详情 ==="
Get-Process | Where-Object ProcessName -match 'ToDesk|toDesk' | Select-Object Id, ProcessName, @{N="MemMB";E={[int]($_.WorkingSet64/1MB)}}, StartTime, @{N="CPU(s)";E={[math]::Round($_.CPU,1)}} | Format-Table -AutoSize

Write-Host "`n=== AweSun / Sunshine 详情（3个实例）==="
Get-Process | Where-Object ProcessName -match 'AweSun|Sunshine|sunshine' | Select-Object Id, ProcessName, @{N="MemMB";E={[int]($_.WorkingSet64/1MB)}}, StartTime, @{N="CPU(s)";E={[math]::Round($_.CPU,1)}} | Format-Table -AutoSize

Write-Host "`n=== node.js 详情 ==="
Get-Process node | Select-Object Id, ProcessName, @{N="MemMB";E={[int]($_.WorkingSet64/1MB)}}, StartTime, @{N="CPU(s)";E={[math]::Round($_.CPU,1)}} | Format-Table -AutoSize

Write-Host "`n=== ASUS 全家桶 ==="
$asus = Get-Process | Where-Object { $_.ProcessName -match 'asus|Armoury|AcPower|ROG' }
$asus | Select-Object Id, ProcessName, @{N="MemMB";E={[int]($_.WorkingSet64/1MB)}}, StartTime, @{N="CPU(s)";E={[math]::Round($_.CPU,1)}} | Format-Table -AutoSize

Write-Host "`n=== UlanziDeck ==="
Get-Process UlanziDeck -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, @{N="MemMB";E={[int]($_.WorkingSet64/1MB)}}, StartTime, @{N="CPU(s)";E={[math]::Round($_.CPU,1)}} | Format-Table -AutoSize

Write-Host "`n=== EDR/安全软件 ==="
$secProcs = Get-Process | Where-Object { $_.ProcessName -match 'edr|Yaramon|sysmon|MsMpEng' }
$secProcs | Select-Object Id, ProcessName, @{N="MemMB";E={[int]($_.WorkingSet64/1MB)}}, StartTime, @{N="CPU(s)";E={[math]::Round($_.CPU,1)}} | Format-Table -AutoSize

Write-Host "`n=== 资源占用排名 ==="
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 20 @{N="Name";E={$_.ProcessName}}, @{N="MemMB";E={[int]($_.WorkingSet64/1MB)}}, @{N="CPU(s)";E={[math]::Round($_.CPU,1)}} | Format-Table -AutoSize

Write-Host "`n=== 总结：可关闭的建议 ==="
Write-Host "1. AweSun x3 - 串流服务器，不用远程玩游戏可关"
Write-Host "2. ToDesk x2 - 远程桌面，不用时可关"
Write-Host "3. ASUS 全家桶 - 华硕控制台+风扇，不需要可禁用开机启动"
Write-Host "4. UlanziDeck (461MB) - 推流控制台，不用时可关"
Write-Host "5. node x5 - 给 UlanziDeck 用的，关了 Ulanzi 就一起没了"
Write-Host "6. EDR + Yaramon + sysmon - 安全监控，建议保留"
