//
// ASN1Convert.cs: Abstract Syntax Notation 1 convertion routines
//
// Authors:
//	Sebastien Pouliot  <sebastien@ximian.com>
//	Jesper Pedersen  <jep@itplus.dk>
//
// (C) 2003 Motus Technologies Inc. (http://www.motus.com)
// (C) 2004 IT+ A/S (http://www.itplus.dk)
// Copyright (C) 2004-2007 Novell, Inc (http://www.novell.com)
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
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Mono.Security
{

    // References:
    // a.	ITU ASN.1 standards (free download)
    //	http://www.itu.int/ITU-T/studygroups/com17/languages/

    //////////////////////////////////////////////////
    // RYUANERIN
    public static class ASN1Convert
    {

        static public ASN1 FromInt32(Int32 value)
        {
            //////////////////////////////////////////////////
            // RYUANERIN
            byte[] integer = new byte[4];
            integer[0] = (byte)((value >> 24) & 0xFF);
            integer[1] = (byte)((value >> 16) & 0xFF);
            integer[2] = (byte)((value >> 08) & 0xFF);
            integer[3] = (byte)((value >> 00) & 0xFF);


            int x = 0;
            while ((x < integer.Length) && (integer[x] == 0x00))
                x++;
            ASN1 asn1 = new ASN1(0x02);
            switch (x)
            {
                case 0:
                    asn1.Value = integer;
                    break;
                case 4:
                    asn1.Value = new byte[1];
                    break;
                default:
                    byte[] smallerInt = new byte[4 - x];
                    Buffer.BlockCopy(integer, x, smallerInt, 0, smallerInt.Length);
                    asn1.Value = smallerInt;
                    break;
            }
            return asn1;
        }

        static public ASN1 FromOid(string oid)
        {
            if (oid == null)
                throw new ArgumentNullException("oid");

            return new ASN1(CryptoConfig.EncodeOID(oid));
        }

        static public int ToInt32(ASN1 asn1)
        {
            if (asn1 == null)
                throw new ArgumentNullException("asn1");
            if (asn1.Tag != 0x02)
                throw new FormatException("Only integer can be converted");

            int x = 0;
            for (int i=0; i < asn1.Value.Length; i++)
                x = (x << 8) + asn1.Value[i];
            return x;
        }

        // Convert a binary encoded OID to human readable string representation of 
        // an OID (IETF style). Based on DUMPASN1.C from Peter Gutmann.
        static public string ToOid(ASN1 asn1)
        {
            if (asn1 == null)
                throw new ArgumentNullException("asn1");

            byte[] aOID = asn1.Value;
            StringBuilder sb = new StringBuilder();
            // Pick apart the OID
            byte x = (byte)(aOID[0] / 40);
            byte y = (byte)(aOID[0] % 40);
            if (x > 2)
            {
                // Handle special case for large y if x = 2
                y += (byte)((x - 2) * 40);
                x = 2;
            }
            sb.Append(x.ToString(CultureInfo.InvariantCulture));
            sb.Append(".");
            sb.Append(y.ToString(CultureInfo.InvariantCulture));
            ulong val = 0;
            for (x = 1; x < aOID.Length; x++)
            {
                val = ((val << 7) | ((byte)(aOID[x] & 0x7F)));
                if (!((aOID[x] & 0x80) == 0x80))
                {
                    sb.Append(".");
                    sb.Append(val.ToString(CultureInfo.InvariantCulture));
                    val = 0;
                }
            }
            return sb.ToString();
        }
    }
}