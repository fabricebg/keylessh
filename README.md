# Keylessh for automated password entry in ssh.exe

This small Windows utility allows automated authentication using the `password` method with `ssh.exe`. In other words, it automates login. It does not work like the `sshpass` program on Linux. Instead of reading and writing directly on the terminal (`/dev/tty`), it merely sends keyboard events to the `ssh.exe` program.

## Security Warning
<span style="color:red;">This utility is inherently **extremely <u>not</u> secure**.</span>

Because the password needs to be explicitly specified, stored and transmitted to `ssh`, the password becomes very vulnerable. For instance, a password specified on the command line can be easily retrieved from your command history. This utility was designed in a very specific environment where this kind of nonchalant approach was acceptable.

To avoid typing passwords to login with ssh, do not use keylessh and use instead:
* [Key-based authentication in OpenSSH for Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)
* [Public key authentication for PuTTY on Windows](https://www.ionos.ca/digitalguide/server/configuration/ssh-key-with-putty/)
* Kerberos on Windows for PuTTY. The idea is to obtain a session ticket which you use when authenticating. See [this](https://gist.github.com/onlineth/05da79c38d21d207d6102a4777372a0f) for instance.

You have been warned.

## Usage
Make sure you already have `ssh.exe` installed on your system.

```
Usage: keylessh.exe [options] [parameters to pass to ssh]
   /f filename   Take password to use from file
   /p password   Provide password as argument (don't)
   /e            Password is passed as environment variable "KEYLESSHPWD"
   /c credname   Passsword from Windows Credentials Manager key "credname"
   /V            Print version information
```

Most options are self-explanatory. The `/c` option allows to fetch the password from the Credential Manager on Windows, a simple GUI. See for instance [this guide](https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0). You select "Windows Credentials" > "Add a generic credential", then fill out the name of the credential in the "Internet or network address" as well as the password. Username is ignored. For instance, for a credential named `ssh_connection_1`, the command would be

`keyless.exe /c ssh_connection_1 [any ssh parameters you want]`

e.g.

`keyless.exe /c ssh_connection_1 user@localhost -p 22 dir`

The arguments after `ssh_connection_1` are all passed verbatim to `ssh.exe`, then the password is sent over when `ssh.exe` asks for a password.

## Limitations

* does not redirect input and output, i.e. no `> output.txt`
* does not support non-ANSI characters
* PuTTY's `plink` can do the same better
