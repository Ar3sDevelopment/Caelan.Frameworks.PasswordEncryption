namespace Caelan.Frameworks.PasswordEncryption.NUnit

open System
open NUnit.Framework
open Caelan.Frameworks.PasswordEncryption.Classes

type CustomPasswordEncryptor() = 
    inherit PasswordEncryptor("default", "secret", "saltsalt")

[<TestFixture>]
type PasswordTest() = 
    [<Test>]
    member __.TestEncryption() = 
        let pwd = CustomPasswordEncryptor()
        let crypted = "password" |> pwd.EncryptPassword
        crypted |> printfn "%s"
        let decrypted = crypted |> pwd.DecryptPassword
        (decrypted, "password") |> Assert.AreEqual
        decrypted |> printfn "%s"
        pwd.DefaultPasswordEncrypted |> printfn "%s"
