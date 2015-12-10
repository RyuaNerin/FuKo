//
// PKCS8.cs: PKCS #8 - Private-Key Information Syntax Standard
//	ftp://ftp.rsasecurity.com/pub/pkcs/doc/pkcs-8.doc
//
// Author:
//	Sebastien Pouliot <sebastien@xamarin.com>
//
// (C) 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004-2006 Novell Inc. (http://www.novell.com)
// Copyright 2013 Xamarin Inc. (http://www.xamarin.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;

namespace Mono.Security.Cryptography
{
    public sealed class PKCS8
    {
        public class EncryptedPrivateKeyInfo
        {
            private string	_algorithm;
            private byte[]	_salt;
            private int		_iterations;
            private byte[]	_data;

            public EncryptedPrivateKeyInfo(byte[] data)
            {
                Decode(data);
            }

            // properties

            public string Algorithm
            {
                get { return _algorithm; }
                set { _algorithm = value; }
            }

            public byte[] EncryptedData
            {
                get { return (_data == null) ? null : (byte[])_data.Clone(); }
                set { _data = (value == null) ? null : (byte[])value.Clone(); }
            }

            public byte[] Salt
            {
                get { return (byte[])_salt.Clone(); }
                set { _salt = (byte[])value.Clone(); }
            }

            public int IterationCount
            {
                get { return _iterations; }
                set { _iterations = value; }
            }

            // methods

            private void Decode(byte[] data)
            {
                ASN1 encryptedPrivateKeyInfo = new ASN1(data);
                if (encryptedPrivateKeyInfo.Tag != 0x30)
                    throw new Exception("invalid EncryptedPrivateKeyInfo");

                ASN1 encryptionAlgorithm = encryptedPrivateKeyInfo[0];
                if (encryptionAlgorithm.Tag != 0x30)
                    throw new Exception("invalid encryptionAlgorithm");
                ASN1 algorithm = encryptionAlgorithm[0];
                if (algorithm.Tag != 0x06)
                    throw new Exception("invalid algorithm");
                _algorithm = ASN1Convert.ToOid(algorithm);
                // parameters ANY DEFINED BY algorithm OPTIONAL
                if (encryptionAlgorithm.Count > 1)
                {
                    ASN1 parameters = encryptionAlgorithm[1];
                    if (parameters.Tag != 0x30)
                        throw new Exception("invalid parameters");

                    ASN1 salt = parameters[0];
                    if (salt.Tag != 0x04)
                        throw new Exception("invalid salt");
                    _salt = salt.Value;

                    ASN1 iterationCount = parameters[1];
                    if (iterationCount.Tag != 0x02)
                        throw new Exception("invalid iterationCount");
                    _iterations = ASN1Convert.ToInt32(iterationCount);
                }

                ASN1 encryptedData = encryptedPrivateKeyInfo[1];
                if (encryptedData.Tag != 0x04)
                    throw new Exception("invalid EncryptedData");
                _data = encryptedData.Value;
            }

            // Note: PKCS#8 doesn't define how to generate the key required for encryption
            // so you're on your own. Just don't try to copy the big guys too much ;)
            // Netscape:	http://www.cs.auckland.ac.nz/~pgut001/pubs/netscape.txt
            // Microsoft:	http://www.cs.auckland.ac.nz/~pgut001/pubs/breakms.txt
            public byte[] GetBytes()
            {
                if (_algorithm == null)
                    throw new Exception("No algorithm OID specified");

                ASN1 encryptionAlgorithm = new ASN1(0x30);
                encryptionAlgorithm.Add(ASN1Convert.FromOid(_algorithm));

                // parameters ANY DEFINED BY algorithm OPTIONAL
                if ((_iterations > 0) || (_salt != null))
                {
                    ASN1 salt = new ASN1(0x04, _salt);
                    ASN1 iterations = ASN1Convert.FromInt32(_iterations);

                    ASN1 parameters = new ASN1(0x30);
                    parameters.Add(salt);
                    parameters.Add(iterations);
                    encryptionAlgorithm.Add(parameters);
                }

                // encapsulates EncryptedData into an OCTET STRING
                ASN1 encryptedData = new ASN1(0x04, _data);

                ASN1 encryptedPrivateKeyInfo = new ASN1(0x30);
                encryptedPrivateKeyInfo.Add(encryptionAlgorithm);
                encryptedPrivateKeyInfo.Add(encryptedData);

                return encryptedPrivateKeyInfo.GetBytes();
            }
        }
    }
}