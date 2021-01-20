package main

import (
	"fmt"
	"os"
	"path/filepath"
    "os/user"
    "flag"
    "crypto/sha256"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
    "encoding/hex"
)


type cliOptions struct {
    encrypt  bool
    decrypt    bool
    shellcode  string
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

func encrypt(shellcode string, envKey []byte) (encryptedShellcode string, err error) {
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
    return hex.EncodeToString(ciphertextWithNonce), nil
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

