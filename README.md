# Bypass UAC

This bypass-UAC method is based on 

https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/UAC-TokenMagic.ps1

Generally you must satisfy the following 2 requirements:

1. There is an already elevated process.

2. You have `PROCESS_QUERY_LIMITED_INFORMATION` right to this elevated process.

If your account is under `Administrators` group, you can open __Task Manager__ to meet those requirements.

## How to build

Open `Developer Command Prompt` and

```
> cl _tmain.cpp /Fe:GetSystem.exe
```

## How to use

Just run it.

```
> GetSystem.exe
```

## Screenshot

![](Screenshot.gif)

