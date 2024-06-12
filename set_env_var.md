---
id: set_env_var
aliases: []
tags: []
---

# set env var 設定環境變數

set envirement variables
config envirement variables

```sh
# cmd
# 暫時 user
set VAR_NAME "VALUE"
# 暫時 global
set /M VAR_NAME "VALUE"
# 永久
setx VAR_NAME "VALUE"
# 永久 global
setx /M VAR_NAME "VALUE"

# powershell
# (replaces existing path)
$env:PATH = "SomeRandomPath";
# (appends to existing path)
$env:PATH += ";SomeRandomPath"
# global
[System.Environment]::SetEnvironmentVariable('<NAME>','<VALUE>', 'Machine')
# user
[System.Environment]::SetEnvironmentVariable('<NAME>','<VALUE>', 'User')

# Unix / Linux / MacOS
# 暫時
VAR_NAME="VALUE"
# 永久
export VAR_NAME="VALUE"
```
