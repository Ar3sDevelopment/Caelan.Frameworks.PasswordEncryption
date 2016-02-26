namespace Caelan.Frameworks.PasswordEncryption.Classes

open Caelan.Frameworks.Common.Helpers
open Caelan.Frameworks.PasswordEncryption.Interfaces
open System
open System.Text
open System.IO
open System.Security.Cryptography

type PasswordEncryptor(defaultPassword : string, secret : string, salt : string, encryptor : IPasswordEncryptor) = 
    
    /// <summary>
    /// 
    /// </summary>
    member val DefaultPassword = defaultPassword
    
    /// <summary>
    /// 
    /// </summary>
    member this.DefaultPasswordEncrypted = this.EncryptPassword(this.DefaultPassword)
    
    /// <summary>
    /// This function encrypts given password using the encryptor inside the class
    /// </summary>
    /// <param name="password">The password to be encrypted</param>
    member __.EncryptPassword(password) = (encryptor, password) |> MemoizeHelper.Memoize(fun (e, p) -> e.EncryptPassword(p, secret, salt))
    
    /// <summary>
    /// This function decrypts given password using the encryptor inside the class
    /// </summary>
    /// <param name="crypted">The crypted data to be decrypted</param>
    member __.DecryptPassword(crypted) = (encryptor, crypted) |> MemoizeHelper.Memoize(fun (e, p) -> e.DecryptPassword(p, secret, salt))
    
    new(defaultPassword, secret, salt) = 
        let encryptor = 
            { new IPasswordEncryptor with
                  
                  member __.EncryptPassword(password, secret, salt) = 
                      let saltBytes = salt |> Encoding.ASCII.GetBytes
                      let writeStream (swEncrypt : StreamWriter) = swEncrypt.Write(password)
                      let writeCrypto (csEncrypt : CryptoStream) = using (new StreamWriter(csEncrypt)) writeStream
                      
                      let writeEncryptedData (msEncrypt : MemoryStream) (aes : RijndaelManaged) = 
                          msEncrypt.Write(BitConverter.GetBytes(aes.IV.Length), 0, sizeof<int>)
                          msEncrypt.Write(aes.IV, 0, aes.IV.Length)
                          using (new CryptoStream(msEncrypt, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write)) writeCrypto
                          Convert.ToBase64String(msEncrypt.ToArray())
                      
                      let aesEncryption (aes : RijndaelManaged) (key : Rfc2898DeriveBytes) = 
                          aes.Key <- key.GetBytes(aes.KeySize / 8)
                          using (new MemoryStream()) (fun t -> writeEncryptedData t aes)
                      
                      let startEncryption (key : Rfc2898DeriveBytes) = using (new RijndaelManaged()) (fun t -> aesEncryption t key)
                      using (new Rfc2898DeriveBytes(secret, saltBytes)) startEncryption
                  
                  member __.DecryptPassword(crypted, secret, salt) = 
                      let saltBytes = salt |> Encoding.ASCII.GetBytes
                      let readStream (srDecrypt : StreamReader) = srDecrypt.ReadToEnd()
                      let readCrypto (csDecrypt : CryptoStream) = using (new StreamReader(csDecrypt)) readStream
                      
                      let startDecryption (msDecrypt : MemoryStream) = 
                          let iv = 
                              let mutable rawLength : byte [] = sizeof<int> |> Array.zeroCreate
                              msDecrypt.Read(rawLength, 0, rawLength.Length) |> ignore
                              let mutable buffer : byte [] = BitConverter.ToInt32(rawLength, 0) |> Array.zeroCreate
                              msDecrypt.Read(buffer, 0, buffer.Length) |> ignore
                              buffer
                          
                          let aesDecryption (aes : RijndaelManaged) (key : Rfc2898DeriveBytes) = 
                              aes.Key <- key.GetBytes(aes.KeySize / 8)
                              aes.IV <- iv
                              using (new CryptoStream(msDecrypt, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read)) readCrypto
                          
                          let keyDecryption (key : Rfc2898DeriveBytes) = using (new RijndaelManaged()) (fun t -> aesDecryption t key)
                          using (new Rfc2898DeriveBytes(secret, saltBytes)) keyDecryption
                      using (new MemoryStream(Convert.FromBase64String(crypted))) startDecryption }
        PasswordEncryptor(defaultPassword, secret, salt, encryptor)
