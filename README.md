# Duke's Keep
Duke's Keep is a open-source, completely machine local password manager that securely manages your password entries. It was made from the ground up so that the user, if needed, could use their passwords on a "need-to-know" basis. Duke's Keep has various functions that can be used to reduce the chances of passwords being compromised, even if malware, such as Spyware or Keyloggers are active on the system.

### Supported platforms
* 64bit Windows 10/11.

## <font color="red">This is currently a prototype/POC</font>
In it's current build, Duke's Keep is made to showcase the functionalities of anti-malware (Spyware, Keylogger) counter-measures. It is currently still lacking a secure store for it's main encryption key while the program is running. Additionally there are no recovery options, if you've forgotten your master password. **In it's current form, it is not recommened to use this as your main password manager** *yet*.

## Releases
You can view the current releases on the [releases page](https://github.com/DoKaUni/Dukes-Keep/releases). After you've downloaded one of the realeases, make sure to also check if the MD5/SHA256 hash matches the ones given.

## Features List

### Basic
* Create password entries with names and usernames
* Create tags
* Filter entries by tags
* Password generation with character set options

### Anti Spyware/Keylogger features
* Password 'fake' sections (Memory scraping countermeasure)
* Application specific on-screen keyboard (Keylogger countermeasure)
* Randomized automatic copy and pasting with fake sections (Clipboard logger countermeasure)
* Copying or automatically pasting your password without seeing it (Screen-recording spyware countermeasure)

## In development
* Main encryption secure keystore
* More robust error-handling
* Better UX (informing the user of invalid inputs, errors)
* Unit tests
* Recovery options
* Linux version
* UI customization

## Security/Encryption
* PBKDF2_HMAC - master password key derivation for main key file encryption
* AES-CTR - pseudo/deterministic random generation
* AES-256-CBC - data encryption
* SHA-256 - hashing operation

## Building Duke's Keep from source
Instructions on how to build the program for source are available [here](./INSTALL.md)

## License
The code of Duke's Keep code is licensed under GPL-3. Additional licensing for third-party libraries and files is detailed in [NOTICE](./NOTICE.md).
