namespace Caelan.Frameworks.PasswordEncryption.Interfaces

open System

type IPasswordEncryptor = 
    /// <summary>
    /// This function encrypt the given password with a secret password and a salt 
    /// </summary>
    /// <param name="password">The password to be encrypted</param>
    /// <param name="secret">The secret password used for encryption</param>
    /// <param name="salt">The salt used for encryption</param>
    abstract EncryptPassword : password:string*secret:string*salt:string -> string
    /// <summary>
    /// This function decrypts a crypted string with a secret password and a salt
    /// </summary>
    /// <param name="crypted">The crypted data to be decrypted</param>
    /// <param name="secret">The secret password used for decryption</param>
    /// <param name="salt">The salt used for decryption</param>
    abstract DecryptPassword : crypted:string*secret:string*salt:string -> string