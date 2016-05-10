using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace OpenApi.Utility
{
    /// <summary>
    /// RSA加解密、签名及验签
    /// 同JAVA互通，以JAVA生成的密钥为基础
    /// </summary>
    public class RsaCryptoHelper
    {
        /// <summary>
        /// 生成密钥对
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns>数组[0:公钥,1:私钥]</returns>
        public static string[] GenrateRSAKey(int keySize = 1024)
        {
            var kpgen = new RsaKeyPairGenerator();
            kpgen.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), keySize));
            var keyPair = kpgen.GenerateKeyPair();
            PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            string privateKey = Convert.ToBase64String(pkInfo.GetDerEncoded());
            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            string publicKey = Convert.ToBase64String(info.GetDerEncoded());

            return new string[] { publicKey, privateKey };
        }

        #region 加密解密
        public static byte[] EncryptByPublicKey(byte[] publicKey, byte[] data)
        {
            using (RSACryptoServiceProvider rsa = BuildRsaServiceProviderFromPublicKey(publicKey))
            {
                byte[] result = rsa.Encrypt(data, false);
                return result;
            }
        }

        public static string EncryptByPublicKey(string publicKey, string data)
        {
            return Convert.ToBase64String(EncryptByPublicKey(Convert.FromBase64String(publicKey), System.Text.Encoding.UTF8.GetBytes(data)));
        }

        public static byte[] DecryptByPrivateKey(byte[] privateKey, byte[] data)
        {
            using (RSACryptoServiceProvider rsa = BuildRsaServiceProviderFromPrivateKey(privateKey))
            {
                byte[] result = rsa.Decrypt(data, false);
                return result;
            }
        }

        public static string DecryptByPrivateKey(string privateKey, string data)
        {
            return System.Text.Encoding.UTF8.GetString(
                DecryptByPrivateKey(Convert.FromBase64String(privateKey), Convert.FromBase64String(data)));
        }

        #endregion

        #region 签名&验签

        /// <summary>
        /// RSA魔码
        /// </summary>
        private static byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };

        /// <summary>
        /// 比较两数组是否相等
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        private static bool CompareByteArrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        /// <summary>
        /// 获取整数长度
        /// </summary>
        /// <param name="binr"></param>
        /// <returns></returns>
        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)		//expect integer
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();	// data size in next byte
            else
                if (bt == 0x82)
            {
                highbyte = binr.ReadByte(); // data size in next 2 bytes
                lowbyte = binr.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;     // we already have the data size
            }

            while (binr.ReadByte() == 0x00)
            {	//remove high order zeros in data
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);		//last ReadByte wasn't a removed zero, so back up a byte
            return count;
        }

        /// <summary>
        /// 由公钥创建Rsa的服务提供者
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <returns>Rsa服务提供者</returns>
        private static RSACryptoServiceProvider BuildRsaServiceProviderFromPublicKey(byte[] publicKey)
        {
            if (publicKey.Length < 162)
            {
                throw new ArgumentException("公钥内容无效！");
            }
            byte[] modulus = new byte[128];
            byte[] exponent = new byte[3];
            Array.Copy(publicKey, 29, modulus, 0, 128);
            Array.Copy(publicKey, 159, exponent, 0, 3);
            RSAParameters para = new RSAParameters();
            para.Modulus = modulus;
            para.Exponent = exponent;
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.ImportParameters(para);
            return provider;
        }

        /// <summary>
        /// 由私钥创建Rsa的服务提供者
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <returns>Rsa服务提供者</returns>
        private static RSACryptoServiceProvider BuildRsaServiceProviderFromPrivateKey(byte[] keyData)
        {
            return BuildRsaServiceProviderFromPKCS8(keyData) ?? BuildRsaServiceProviderFromPKCS1(keyData);
        }

        /// <summary>
        /// 由私钥创建Rsa的服务提供者--pkcs8
        /// </summary>
        /// <param name="privkey"></param>
        /// <returns></returns>
        private static RSACryptoServiceProvider BuildRsaServiceProviderFromPKCS8(byte[] privkey)
        {
            using (MemoryStream memoryStream = new MemoryStream(privkey))
            {
                using (BinaryReader binaryReader = new BinaryReader(memoryStream))
                {
                    byte bt = 0;
                    ushort twobytes = 0;

                    twobytes = binaryReader.ReadUInt16();
                    if (twobytes == 0x8130)	//data read as little endian order (actual data order for Sequence is 30 81)
                        binaryReader.ReadByte();	//advance 1 byte
                    else if (twobytes == 0x8230)
                        binaryReader.ReadInt16();	//advance 2 bytes
                    else
                        return null;

                    bt = binaryReader.ReadByte();
                    if (bt != 0x02)
                        return null;

                    twobytes = binaryReader.ReadUInt16();

                    if (twobytes != 0x0001)
                        return null;

                    byte[] seq = binaryReader.ReadBytes(15);		//read the Sequence OID
                    if (!CompareByteArrays(seq, SeqOID))	//make sure Sequence for OID is correct
                        return null;

                    bt = binaryReader.ReadByte();
                    if (bt != 0x04)	//expect an Octet string 
                        return null;

                    bt = binaryReader.ReadByte();		//read next byte, or next 2 bytes is  0x81 or 0x82; otherwise bt is the byte count
                    if (bt == 0x81)
                        binaryReader.ReadByte();
                    else
                        if (bt == 0x82)
                        binaryReader.ReadUInt16();

                    byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

                    twobytes = binaryReader.ReadUInt16();
                    if (twobytes == 0x8130)	//data read as little endian order (actual data order for Sequence is 30 81)
                        binaryReader.ReadByte();	//advance 1 byte
                    else if (twobytes == 0x8230)
                        binaryReader.ReadInt16();	//advance 2 bytes
                    else
                        return null;

                    twobytes = binaryReader.ReadUInt16();
                    if (twobytes != 0x0102)	//version number
                        return null;
                    bt = binaryReader.ReadByte();
                    if (bt != 0x00)
                        return null;

                    //------  all private key components are Integer sequences ----
                    int elems = GetIntegerSize(binaryReader);
                    MODULUS = binaryReader.ReadBytes(elems);

                    elems = GetIntegerSize(binaryReader);
                    E = binaryReader.ReadBytes(elems);

                    elems = GetIntegerSize(binaryReader);
                    D = binaryReader.ReadBytes(elems);

                    elems = GetIntegerSize(binaryReader);
                    P = binaryReader.ReadBytes(elems);

                    elems = GetIntegerSize(binaryReader);
                    Q = binaryReader.ReadBytes(elems);

                    elems = GetIntegerSize(binaryReader);
                    DP = binaryReader.ReadBytes(elems);

                    elems = GetIntegerSize(binaryReader);
                    DQ = binaryReader.ReadBytes(elems);

                    elems = GetIntegerSize(binaryReader);
                    IQ = binaryReader.ReadBytes(elems);

                    RSAParameters para = new RSAParameters();
                    para.Modulus = MODULUS;
                    para.Exponent = E;
                    para.D = D;
                    para.P = P;
                    para.Q = Q;
                    para.DP = DP;
                    para.DQ = DQ;
                    para.InverseQ = IQ;

                    RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
                    provider.ImportParameters(para);
                    return provider;
                }
            }
        }

        /// <summary>
        /// 由私钥创建Rsa的服务提供者--pkcs1
        /// </summary>
        /// <param name="privkey"></param>
        /// <returns></returns>
        private static RSACryptoServiceProvider BuildRsaServiceProviderFromPKCS1(byte[] privkey)
        {
            // --------- Set up stream to decode the asn.1 encoded RSA private key ------
            using (MemoryStream memoryStream = new MemoryStream(privkey))
            {
                //wrap Memory Stream with BinaryReader for easy reading
                using (BinaryReader binaryReader = new BinaryReader(memoryStream))
                {
                    byte bt = 0;
                    ushort twobytes = 0;
                    int elems = 0;
                    try
                    {
                        twobytes = binaryReader.ReadUInt16();
                        if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                            binaryReader.ReadByte();    //advance 1 byte
                        else if (twobytes == 0x8230)
                            binaryReader.ReadInt16();    //advance 2 bytes
                        else
                            return null;

                        twobytes = binaryReader.ReadUInt16();
                        if (twobytes != 0x0102) //version number
                            return null;
                        bt = binaryReader.ReadByte();
                        if (bt != 0x00)
                            return null;


                        //------ all private key components are Integer sequences ----

                        byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;
                        elems = GetIntegerSize(binaryReader);
                        MODULUS = binaryReader.ReadBytes(elems);

                        elems = GetIntegerSize(binaryReader);
                        E = binaryReader.ReadBytes(elems);

                        elems = GetIntegerSize(binaryReader);
                        D = binaryReader.ReadBytes(elems);

                        elems = GetIntegerSize(binaryReader);
                        P = binaryReader.ReadBytes(elems);

                        elems = GetIntegerSize(binaryReader);
                        Q = binaryReader.ReadBytes(elems);

                        elems = GetIntegerSize(binaryReader);
                        DP = binaryReader.ReadBytes(elems);

                        elems = GetIntegerSize(binaryReader);
                        DQ = binaryReader.ReadBytes(elems);

                        elems = GetIntegerSize(binaryReader);
                        IQ = binaryReader.ReadBytes(elems);

                        // ------- create RSACryptoServiceProvider instance and initialize with public key -----

                        RSAParameters para = new RSAParameters();
                        para.Modulus = MODULUS;
                        para.Exponent = E;
                        para.D = D;
                        para.P = P;
                        para.Q = Q;
                        para.DP = DP;
                        para.DQ = DQ;
                        para.InverseQ = IQ;

                        CspParameters CspParameters = new CspParameters();
                        CspParameters.Flags = CspProviderFlags.UseMachineKeyStore;
                        RSACryptoServiceProvider provider = new RSACryptoServiceProvider(1024, CspParameters);
                        provider.ImportParameters(para);
                        return provider;
                    }
                    catch (Exception ex)
                    {
                        return null;
                    }
                }
            }
        }

        public static byte[] SignByPrivateKey(byte[] privateKey, byte[] data)
        {
            using (RSACryptoServiceProvider rsa = BuildRsaServiceProviderFromPrivateKey(privateKey))
            {
                using (SHA1 sh = new SHA1CryptoServiceProvider())
                {
                    byte[] signData = rsa.SignData(data, sh);
                    return signData;
                }
            }
        }

        public static string SignByPrivateKey(string privateKey, string data)
        {
            return Convert.ToBase64String(SignByPrivateKey(Convert.FromBase64String(privateKey), System.Text.Encoding.UTF8.GetBytes(data)));
        }

        /// <summary>
        /// 利用公钥验签
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="stringData">数据字符串</param>
        /// <param name="signString">签名字符串</param>
        /// <returns>是否验签成功</returns>
        public static bool VerifyByPublicKey(string publicKey, string stringData, string signString)
        {
            return VerifyByPublicKey(Convert.FromBase64String(publicKey), System.Text.Encoding.UTF8.GetBytes(stringData), Convert.FromBase64String(signString));
        }

        /// <summary>
        /// 利用公钥验签
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="data">数据</param>
        /// <param name="sign">签名</param>
        /// <returns>是否验签成功</returns>
        public static bool VerifyByPublicKey(byte[] publicKey, byte[] data, byte[] sign)
        {
            try
            {
                using (RSACryptoServiceProvider rsaPub = BuildRsaServiceProviderFromPublicKey(publicKey))
                {
                    using (SHA1 sh = new SHA1CryptoServiceProvider())
                    {
                        bool result = rsaPub.VerifyData(data, sh, sign);
                        return result;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        #endregion
    }
}
