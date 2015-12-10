// http://thermidor.tistory.com/430

using System;
using System.Text;

namespace PnPeople.Security
{
    /// <summary>
    /// SEED에 대한 요약 설명입니다.
    /// </summary>
    public class SEED
    {
        //	SEED에 관련된 상수들
        private const int SEED_BLOCK_LEN = 0x10;		//	in BYTEs
        private const int SEED_USER_KEY_LEN = 0x10;		//	in BYTEs
        private const int SEED_USER_IV_LEN = 0x10;		//	in BYTEs
        private const int SEED_NO_ROUNDS = 0x10;
        private const int SEED_NO_ROUNDKEY = (2 * SEED_NO_ROUNDS);	//	in DWORDs

        public enum MODE
        {
            AI_ECB = 1,
            AI_CBC = 2,
            AI_OFB = 3,
            AI_CFB = 4
        }

        public enum PADDING
        {
            AI_NO_PADDING = 1,		//	Padding 없음(입력이 16바이트의 배수)
            AI_PKCS_PADDING = 2		//	padding되는 바이트 수로 padding
        }

        public enum CODE
        {
            CTR_SUCCESS = 0,
            CTR_FATAL_ERROR = 0x1001,
            CTR_INVALID_USERKEYLEN = 0x1002,	//	비밀키의 길이가 부적절함.
            CTR_PAD_CHECK_ERROR = 0x1003,	//	
            CTR_DATA_LEN_ERROR = 0x1004,	//	평문의 길이가 부적절함.
            CTR_CIPHER_LEN_ERROR = 0x1005,	//	암호문이 블록의 배수가 아님.
            CTR_USAGE_ERROR = 0x2001,
            CTR_KEYFILE_ERROR = 0x2002,
            CTR_FILE_OPEN_ERROR = 0x2003,	//  파일 입출력 에러.
            CTR_INVALID_KEY = 0x2004	//  비밀키가 잘못됨.
        }

        internal struct SEED_ALG_INFO
        {
            public MODE ModeID;						//	ECB or CBC
            public PADDING PadType;					//	블록암호의 Padding type
            public byte[] IV;			//	Initial Vector
            public byte[] ChainVar;	//	Chaining Variable
            public byte[] Buffer;		//	Buffer for unfilled block
            public uint BufLen; 					//	Buffer의 유효 바이트 수
            public uint[] RoundKey;	//	라운드 키의 DWORD 수
        }

        private byte[] _key;
        private byte[] _iv;
        private MODE _modType;
        private PADDING _padType;

        public SEED()
        {
            _modType = MODE.AI_CBC;
            _padType = PADDING.AI_PKCS_PADDING;
        }

        public byte[] KeyBytes
        {
            get { return _key; }
            set { _key = value; }
        }

        public byte[] IV
        {
            get { return _iv; }
            set { _iv = value; }
        }

        public MODE ModType
        {
            get { return _modType; }
            set { _modType = value; }
        }

        public PADDING PadType
        {
            get { return _padType; }
            set { _padType = value; }
        }

        #region SEED 헤더 부분

        private static uint ROTL_DWORD(uint x, int n)
        {
            return ((x) << (n)) | ((x) >> (32-(n)));
        }

        private static uint ROTR_DWORD(uint x, int n)
        {
            return ((x) >> (n)) | ((x) << (32-(n)));
        }

        private static uint ENDIAN_REVERSE_DWORD(uint dwS)
        {
            return (ROTL_DWORD((dwS), 8) & (uint)0x00ff00ff) | (ROTL_DWORD((dwS), 24) & 0xff00ff00);
        }

        private static void BIG_B2D(byte[] B, int count, ref uint D)
        {
            uint dwB = (uint)B[count] * 0x1000000 + (uint)B[count + 1] * 0x10000 + (uint)B[count + 2] * 0x100 + (uint)B[count + 3];
            D = dwB; // ENDIAN_REVERSE_DWORD(dwB);
        }

        private static void BIG_D2B(uint D, ref byte[] B, int count)
        {
            uint dwB = D; // ENDIAN_REVERSE_DWORD(D);
            B[count] = (byte)((dwB & 0xff000000) >> 24);
            B[count+1] = (byte)((dwB & 0xff0000) >> 16);
            B[count+2] = (byte)((dwB & 0xff00) >> 8);
            B[count+3] = (byte)(dwB & 0xff);
        }

        private static void LITTLE_B2D(byte[] B, int count, ref uint D)
        {
            uint dwB = (uint)B[count] * 0x1000000 + (uint)B[count + 1] * 0x10000 + (uint)B[count + 2] * 0x100 + (uint)B[count + 3];
            D = ENDIAN_REVERSE_DWORD(dwB); //dwB;
        }

        private static void LITTLE_D2B(uint D, ref byte[] B, int count)
        {
            uint dwB = ENDIAN_REVERSE_DWORD(D); //D;
            B[count] = (byte)((dwB & 0xff000000) >> 24);
            B[count+1] = (byte)((dwB & 0xff0000) >> 16);
            B[count+2] = (byte)((dwB & 0xff00) >> 8);
            B[count+3] = (byte)(dwB & 0xff);
        }

        #endregion


        #region SEED 기본 정의 부분

        private const uint KC0 = 0x9e3779b9;
        private const uint KC1 = 0x3c6ef373;
        private const uint KC2 = 0x78dde6e6;
        private const uint KC3 = 0xf1bbcdcc;
        private const uint KC4 = 0xe3779b99;
        private const uint KC5 = 0xc6ef3733;
        private const uint KC6 = 0x8dde6e67;
        private const uint KC7 = 0x1bbcdccf;
        private const uint KC8 = 0x3779b99e;
        private const uint KC9 = 0x6ef3733c;
        private const uint KC10 = 0xdde6e678;
        private const uint KC11 = 0xbbcdccf1;
        private const uint KC12 = 0x779b99e3;
        private const uint KC13 = 0xef3733c6;
        private const uint KC14 = 0xde6e678d;
        private const uint KC15 = 0xbcdccf1b;

        private static uint[,] SEED_SL = new uint[,] {	{
            0x2989a1a8, 0x05858184, 0x16c6d2d4, 0x13c3d3d0, 0x14445054, 0x1d0d111c, 0x2c8ca0ac, 0x25052124,
            0x1d4d515c, 0x03434340, 0x18081018, 0x1e0e121c, 0x11415150, 0x3cccf0fc, 0x0acac2c8, 0x23436360,
            0x28082028, 0x04444044, 0x20002020, 0x1d8d919c, 0x20c0e0e0, 0x22c2e2e0, 0x08c8c0c8, 0x17071314,
            0x2585a1a4, 0x0f8f838c, 0x03030300, 0x3b4b7378, 0x3b8bb3b8, 0x13031310, 0x12c2d2d0, 0x2ecee2ec,
            0x30407070, 0x0c8c808c, 0x3f0f333c, 0x2888a0a8, 0x32023230, 0x1dcdd1dc, 0x36c6f2f4, 0x34447074,
            0x2ccce0ec, 0x15859194, 0x0b0b0308, 0x17475354, 0x1c4c505c, 0x1b4b5358, 0x3d8db1bc, 0x01010100,
            0x24042024, 0x1c0c101c, 0x33437370, 0x18889098, 0x10001010, 0x0cccc0cc, 0x32c2f2f0, 0x19c9d1d8,
            0x2c0c202c, 0x27c7e3e4, 0x32427270, 0x03838380, 0x1b8b9398, 0x11c1d1d0, 0x06868284, 0x09c9c1c8,
            0x20406060, 0x10405050, 0x2383a3a0, 0x2bcbe3e8, 0x0d0d010c, 0x3686b2b4, 0x1e8e929c, 0x0f4f434c,
            0x3787b3b4, 0x1a4a5258, 0x06c6c2c4, 0x38487078, 0x2686a2a4, 0x12021210, 0x2f8fa3ac, 0x15c5d1d4,
            0x21416160, 0x03c3c3c0, 0x3484b0b4, 0x01414140, 0x12425250, 0x3d4d717c, 0x0d8d818c, 0x08080008,
            0x1f0f131c, 0x19899198, 0x00000000, 0x19091118, 0x04040004, 0x13435350, 0x37c7f3f4, 0x21c1e1e0,
            0x3dcdf1fc, 0x36467274, 0x2f0f232c, 0x27072324, 0x3080b0b0, 0x0b8b8388, 0x0e0e020c, 0x2b8ba3a8,
            0x2282a2a0, 0x2e4e626c, 0x13839390, 0x0d4d414c, 0x29496168, 0x3c4c707c, 0x09090108, 0x0a0a0208,
            0x3f8fb3bc, 0x2fcfe3ec, 0x33c3f3f0, 0x05c5c1c4, 0x07878384, 0x14041014, 0x3ecef2fc, 0x24446064,
            0x1eced2dc, 0x2e0e222c, 0x0b4b4348, 0x1a0a1218, 0x06060204, 0x21012120, 0x2b4b6368, 0x26466264,
            0x02020200, 0x35c5f1f4, 0x12829290, 0x0a8a8288, 0x0c0c000c, 0x3383b3b0, 0x3e4e727c, 0x10c0d0d0,
            0x3a4a7278, 0x07474344, 0x16869294, 0x25c5e1e4, 0x26062224, 0x00808080, 0x2d8da1ac, 0x1fcfd3dc,
            0x2181a1a0, 0x30003030, 0x37073334, 0x2e8ea2ac, 0x36063234, 0x15051114, 0x22022220, 0x38083038,
            0x34c4f0f4, 0x2787a3a4, 0x05454144, 0x0c4c404c, 0x01818180, 0x29c9e1e8, 0x04848084, 0x17879394,
            0x35053134, 0x0bcbc3c8, 0x0ecec2cc, 0x3c0c303c, 0x31417170, 0x11011110, 0x07c7c3c4, 0x09898188,
            0x35457174, 0x3bcbf3f8, 0x1acad2d8, 0x38c8f0f8, 0x14849094, 0x19495158, 0x02828280, 0x04c4c0c4,
            0x3fcff3fc, 0x09494148, 0x39093138, 0x27476364, 0x00c0c0c0, 0x0fcfc3cc, 0x17c7d3d4, 0x3888b0b8,
            0x0f0f030c, 0x0e8e828c, 0x02424240, 0x23032320, 0x11819190, 0x2c4c606c, 0x1bcbd3d8, 0x2484a0a4,
            0x34043034, 0x31c1f1f0, 0x08484048, 0x02c2c2c0, 0x2f4f636c, 0x3d0d313c, 0x2d0d212c, 0x00404040,
            0x3e8eb2bc, 0x3e0e323c, 0x3c8cb0bc, 0x01c1c1c0, 0x2a8aa2a8, 0x3a8ab2b8, 0x0e4e424c, 0x15455154,
            0x3b0b3338, 0x1cccd0dc, 0x28486068, 0x3f4f737c, 0x1c8c909c, 0x18c8d0d8, 0x0a4a4248, 0x16465254,
            0x37477374, 0x2080a0a0, 0x2dcde1ec, 0x06464244, 0x3585b1b4, 0x2b0b2328, 0x25456164, 0x3acaf2f8,
            0x23c3e3e0, 0x3989b1b8, 0x3181b1b0, 0x1f8f939c, 0x1e4e525c, 0x39c9f1f8, 0x26c6e2e4, 0x3282b2b0,
            0x31013130, 0x2acae2e8, 0x2d4d616c, 0x1f4f535c, 0x24c4e0e4, 0x30c0f0f0, 0x0dcdc1cc, 0x08888088,
            0x16061214, 0x3a0a3238, 0x18485058, 0x14c4d0d4, 0x22426260, 0x29092128, 0x07070304, 0x33033330,
            0x28c8e0e8, 0x1b0b1318, 0x05050104, 0x39497178, 0x10809090, 0x2a4a6268, 0x2a0a2228, 0x1a8a9298
        },	
        {
            0x38380830, 0xe828c8e0, 0x2c2d0d21, 0xa42686a2, 0xcc0fcfc3, 0xdc1eced2, 0xb03383b3, 0xb83888b0,
            0xac2f8fa3, 0x60204060, 0x54154551, 0xc407c7c3, 0x44044440, 0x6c2f4f63, 0x682b4b63, 0x581b4b53,
            0xc003c3c3, 0x60224262, 0x30330333, 0xb43585b1, 0x28290921, 0xa02080a0, 0xe022c2e2, 0xa42787a3,
            0xd013c3d3, 0x90118191, 0x10110111, 0x04060602, 0x1c1c0c10, 0xbc3c8cb0, 0x34360632, 0x480b4b43,
            0xec2fcfe3, 0x88088880, 0x6c2c4c60, 0xa82888a0, 0x14170713, 0xc404c4c0, 0x14160612, 0xf434c4f0,
            0xc002c2c2, 0x44054541, 0xe021c1e1, 0xd416c6d2, 0x3c3f0f33, 0x3c3d0d31, 0x8c0e8e82, 0x98188890,
            0x28280820, 0x4c0e4e42, 0xf436c6f2, 0x3c3e0e32, 0xa42585a1, 0xf839c9f1, 0x0c0d0d01, 0xdc1fcfd3,
            0xd818c8d0, 0x282b0b23, 0x64264662, 0x783a4a72, 0x24270723, 0x2c2f0f23, 0xf031c1f1, 0x70324272,
            0x40024242, 0xd414c4d0, 0x40014141, 0xc000c0c0, 0x70334373, 0x64274763, 0xac2c8ca0, 0x880b8b83,
            0xf437c7f3, 0xac2d8da1, 0x80008080, 0x1c1f0f13, 0xc80acac2, 0x2c2c0c20, 0xa82a8aa2, 0x34340430,
            0xd012c2d2, 0x080b0b03, 0xec2ecee2, 0xe829c9e1, 0x5c1d4d51, 0x94148490, 0x18180810, 0xf838c8f0,
            0x54174753, 0xac2e8ea2, 0x08080800, 0xc405c5c1, 0x10130313, 0xcc0dcdc1, 0x84068682, 0xb83989b1,
            0xfc3fcff3, 0x7c3d4d71, 0xc001c1c1, 0x30310131, 0xf435c5f1, 0x880a8a82, 0x682a4a62, 0xb03181b1,
            0xd011c1d1, 0x20200020, 0xd417c7d3, 0x00020202, 0x20220222, 0x04040400, 0x68284860, 0x70314171,
            0x04070703, 0xd81bcbd3, 0x9c1d8d91, 0x98198991, 0x60214161, 0xbc3e8eb2, 0xe426c6e2, 0x58194951,
            0xdc1dcdd1, 0x50114151, 0x90108090, 0xdc1cccd0, 0x981a8a92, 0xa02383a3, 0xa82b8ba3, 0xd010c0d0,
            0x80018181, 0x0c0f0f03, 0x44074743, 0x181a0a12, 0xe023c3e3, 0xec2ccce0, 0x8c0d8d81, 0xbc3f8fb3,
            0x94168692, 0x783b4b73, 0x5c1c4c50, 0xa02282a2, 0xa02181a1, 0x60234363, 0x20230323, 0x4c0d4d41,
            0xc808c8c0, 0x9c1e8e92, 0x9c1c8c90, 0x383a0a32, 0x0c0c0c00, 0x2c2e0e22, 0xb83a8ab2, 0x6c2e4e62,
            0x9c1f8f93, 0x581a4a52, 0xf032c2f2, 0x90128292, 0xf033c3f3, 0x48094941, 0x78384870, 0xcc0cccc0,
            0x14150511, 0xf83bcbf3, 0x70304070, 0x74354571, 0x7c3f4f73, 0x34350531, 0x10100010, 0x00030303,
            0x64244460, 0x6c2d4d61, 0xc406c6c2, 0x74344470, 0xd415c5d1, 0xb43484b0, 0xe82acae2, 0x08090901,
            0x74364672, 0x18190911, 0xfc3ecef2, 0x40004040, 0x10120212, 0xe020c0e0, 0xbc3d8db1, 0x04050501,
            0xf83acaf2, 0x00010101, 0xf030c0f0, 0x282a0a22, 0x5c1e4e52, 0xa82989a1, 0x54164652, 0x40034343,
            0x84058581, 0x14140410, 0x88098981, 0x981b8b93, 0xb03080b0, 0xe425c5e1, 0x48084840, 0x78394971,
            0x94178793, 0xfc3cccf0, 0x1c1e0e12, 0x80028282, 0x20210121, 0x8c0c8c80, 0x181b0b13, 0x5c1f4f53,
            0x74374773, 0x54144450, 0xb03282b2, 0x1c1d0d11, 0x24250521, 0x4c0f4f43, 0x00000000, 0x44064642,
            0xec2dcde1, 0x58184850, 0x50124252, 0xe82bcbe3, 0x7c3e4e72, 0xd81acad2, 0xc809c9c1, 0xfc3dcdf1,
            0x30300030, 0x94158591, 0x64254561, 0x3c3c0c30, 0xb43686b2, 0xe424c4e0, 0xb83b8bb3, 0x7c3c4c70,
            0x0c0e0e02, 0x50104050, 0x38390931, 0x24260622, 0x30320232, 0x84048480, 0x68294961, 0x90138393,
            0x34370733, 0xe427c7e3, 0x24240420, 0xa42484a0, 0xc80bcbc3, 0x50134353, 0x080a0a02, 0x84078783,
            0xd819c9d1, 0x4c0c4c40, 0x80038383, 0x8c0f8f83, 0xcc0ecec2, 0x383b0b33, 0x480a4a42, 0xb43787b3
        },	
        {
            0xa1a82989, 0x81840585, 0xd2d416c6, 0xd3d013c3, 0x50541444, 0x111c1d0d, 0xa0ac2c8c, 0x21242505,
            0x515c1d4d, 0x43400343, 0x10181808, 0x121c1e0e, 0x51501141, 0xf0fc3ccc, 0xc2c80aca, 0x63602343,
            0x20282808, 0x40440444, 0x20202000, 0x919c1d8d, 0xe0e020c0, 0xe2e022c2, 0xc0c808c8, 0x13141707,
            0xa1a42585, 0x838c0f8f, 0x03000303, 0x73783b4b, 0xb3b83b8b, 0x13101303, 0xd2d012c2, 0xe2ec2ece,
            0x70703040, 0x808c0c8c, 0x333c3f0f, 0xa0a82888, 0x32303202, 0xd1dc1dcd, 0xf2f436c6, 0x70743444,
            0xe0ec2ccc, 0x91941585, 0x03080b0b, 0x53541747, 0x505c1c4c, 0x53581b4b, 0xb1bc3d8d, 0x01000101,
            0x20242404, 0x101c1c0c, 0x73703343, 0x90981888, 0x10101000, 0xc0cc0ccc, 0xf2f032c2, 0xd1d819c9,
            0x202c2c0c, 0xe3e427c7, 0x72703242, 0x83800383, 0x93981b8b, 0xd1d011c1, 0x82840686, 0xc1c809c9,
            0x60602040, 0x50501040, 0xa3a02383, 0xe3e82bcb, 0x010c0d0d, 0xb2b43686, 0x929c1e8e, 0x434c0f4f,
            0xb3b43787, 0x52581a4a, 0xc2c406c6, 0x70783848, 0xa2a42686, 0x12101202, 0xa3ac2f8f, 0xd1d415c5,
            0x61602141, 0xc3c003c3, 0xb0b43484, 0x41400141, 0x52501242, 0x717c3d4d, 0x818c0d8d, 0x00080808,
            0x131c1f0f, 0x91981989, 0x00000000, 0x11181909, 0x00040404, 0x53501343, 0xf3f437c7, 0xe1e021c1,
            0xf1fc3dcd, 0x72743646, 0x232c2f0f, 0x23242707, 0xb0b03080, 0x83880b8b, 0x020c0e0e, 0xa3a82b8b,
            0xa2a02282, 0x626c2e4e, 0x93901383, 0x414c0d4d, 0x61682949, 0x707c3c4c, 0x01080909, 0x02080a0a,
            0xb3bc3f8f, 0xe3ec2fcf, 0xf3f033c3, 0xc1c405c5, 0x83840787, 0x10141404, 0xf2fc3ece, 0x60642444,
            0xd2dc1ece, 0x222c2e0e, 0x43480b4b, 0x12181a0a, 0x02040606, 0x21202101, 0x63682b4b, 0x62642646,
            0x02000202, 0xf1f435c5, 0x92901282, 0x82880a8a, 0x000c0c0c, 0xb3b03383, 0x727c3e4e, 0xd0d010c0,
            0x72783a4a, 0x43440747, 0x92941686, 0xe1e425c5, 0x22242606, 0x80800080, 0xa1ac2d8d, 0xd3dc1fcf,
            0xa1a02181, 0x30303000, 0x33343707, 0xa2ac2e8e, 0x32343606, 0x11141505, 0x22202202, 0x30383808,
            0xf0f434c4, 0xa3a42787, 0x41440545, 0x404c0c4c, 0x81800181, 0xe1e829c9, 0x80840484, 0x93941787,
            0x31343505, 0xc3c80bcb, 0xc2cc0ece, 0x303c3c0c, 0x71703141, 0x11101101, 0xc3c407c7, 0x81880989,
            0x71743545, 0xf3f83bcb, 0xd2d81aca, 0xf0f838c8, 0x90941484, 0x51581949, 0x82800282, 0xc0c404c4,
            0xf3fc3fcf, 0x41480949, 0x31383909, 0x63642747, 0xc0c000c0, 0xc3cc0fcf, 0xd3d417c7, 0xb0b83888,
            0x030c0f0f, 0x828c0e8e, 0x42400242, 0x23202303, 0x91901181, 0x606c2c4c, 0xd3d81bcb, 0xa0a42484,
            0x30343404, 0xf1f031c1, 0x40480848, 0xc2c002c2, 0x636c2f4f, 0x313c3d0d, 0x212c2d0d, 0x40400040,
            0xb2bc3e8e, 0x323c3e0e, 0xb0bc3c8c, 0xc1c001c1, 0xa2a82a8a, 0xb2b83a8a, 0x424c0e4e, 0x51541545,
            0x33383b0b, 0xd0dc1ccc, 0x60682848, 0x737c3f4f, 0x909c1c8c, 0xd0d818c8, 0x42480a4a, 0x52541646,
            0x73743747, 0xa0a02080, 0xe1ec2dcd, 0x42440646, 0xb1b43585, 0x23282b0b, 0x61642545, 0xf2f83aca,
            0xe3e023c3, 0xb1b83989, 0xb1b03181, 0x939c1f8f, 0x525c1e4e, 0xf1f839c9, 0xe2e426c6, 0xb2b03282,
            0x31303101, 0xe2e82aca, 0x616c2d4d, 0x535c1f4f, 0xe0e424c4, 0xf0f030c0, 0xc1cc0dcd, 0x80880888,
            0x12141606, 0x32383a0a, 0x50581848, 0xd0d414c4, 0x62602242, 0x21282909, 0x03040707, 0x33303303,
            0xe0e828c8, 0x13181b0b, 0x01040505, 0x71783949, 0x90901080, 0x62682a4a, 0x22282a0a, 0x92981a8a
        },	
        {
            0x08303838, 0xc8e0e828, 0x0d212c2d, 0x86a2a426, 0xcfc3cc0f, 0xced2dc1e, 0x83b3b033, 0x88b0b838,
            0x8fa3ac2f, 0x40606020, 0x45515415, 0xc7c3c407, 0x44404404, 0x4f636c2f, 0x4b63682b, 0x4b53581b,
            0xc3c3c003, 0x42626022, 0x03333033, 0x85b1b435, 0x09212829, 0x80a0a020, 0xc2e2e022, 0x87a3a427,
            0xc3d3d013, 0x81919011, 0x01111011, 0x06020406, 0x0c101c1c, 0x8cb0bc3c, 0x06323436, 0x4b43480b,
            0xcfe3ec2f, 0x88808808, 0x4c606c2c, 0x88a0a828, 0x07131417, 0xc4c0c404, 0x06121416, 0xc4f0f434,
            0xc2c2c002, 0x45414405, 0xc1e1e021, 0xc6d2d416, 0x0f333c3f, 0x0d313c3d, 0x8e828c0e, 0x88909818,
            0x08202828, 0x4e424c0e, 0xc6f2f436, 0x0e323c3e, 0x85a1a425, 0xc9f1f839, 0x0d010c0d, 0xcfd3dc1f,
            0xc8d0d818, 0x0b23282b, 0x46626426, 0x4a72783a, 0x07232427, 0x0f232c2f, 0xc1f1f031, 0x42727032,
            0x42424002, 0xc4d0d414, 0x41414001, 0xc0c0c000, 0x43737033, 0x47636427, 0x8ca0ac2c, 0x8b83880b,
            0xc7f3f437, 0x8da1ac2d, 0x80808000, 0x0f131c1f, 0xcac2c80a, 0x0c202c2c, 0x8aa2a82a, 0x04303434,
            0xc2d2d012, 0x0b03080b, 0xcee2ec2e, 0xc9e1e829, 0x4d515c1d, 0x84909414, 0x08101818, 0xc8f0f838,
            0x47535417, 0x8ea2ac2e, 0x08000808, 0xc5c1c405, 0x03131013, 0xcdc1cc0d, 0x86828406, 0x89b1b839,
            0xcff3fc3f, 0x4d717c3d, 0xc1c1c001, 0x01313031, 0xc5f1f435, 0x8a82880a, 0x4a62682a, 0x81b1b031,
            0xc1d1d011, 0x00202020, 0xc7d3d417, 0x02020002, 0x02222022, 0x04000404, 0x48606828, 0x41717031,
            0x07030407, 0xcbd3d81b, 0x8d919c1d, 0x89919819, 0x41616021, 0x8eb2bc3e, 0xc6e2e426, 0x49515819,
            0xcdd1dc1d, 0x41515011, 0x80909010, 0xccd0dc1c, 0x8a92981a, 0x83a3a023, 0x8ba3a82b, 0xc0d0d010,
            0x81818001, 0x0f030c0f, 0x47434407, 0x0a12181a, 0xc3e3e023, 0xcce0ec2c, 0x8d818c0d, 0x8fb3bc3f,
            0x86929416, 0x4b73783b, 0x4c505c1c, 0x82a2a022, 0x81a1a021, 0x43636023, 0x03232023, 0x4d414c0d,
            0xc8c0c808, 0x8e929c1e, 0x8c909c1c, 0x0a32383a, 0x0c000c0c, 0x0e222c2e, 0x8ab2b83a, 0x4e626c2e,
            0x8f939c1f, 0x4a52581a, 0xc2f2f032, 0x82929012, 0xc3f3f033, 0x49414809, 0x48707838, 0xccc0cc0c,
            0x05111415, 0xcbf3f83b, 0x40707030, 0x45717435, 0x4f737c3f, 0x05313435, 0x00101010, 0x03030003,
            0x44606424, 0x4d616c2d, 0xc6c2c406, 0x44707434, 0xc5d1d415, 0x84b0b434, 0xcae2e82a, 0x09010809,
            0x46727436, 0x09111819, 0xcef2fc3e, 0x40404000, 0x02121012, 0xc0e0e020, 0x8db1bc3d, 0x05010405,
            0xcaf2f83a, 0x01010001, 0xc0f0f030, 0x0a22282a, 0x4e525c1e, 0x89a1a829, 0x46525416, 0x43434003,
            0x85818405, 0x04101414, 0x89818809, 0x8b93981b, 0x80b0b030, 0xc5e1e425, 0x48404808, 0x49717839,
            0x87939417, 0xccf0fc3c, 0x0e121c1e, 0x82828002, 0x01212021, 0x8c808c0c, 0x0b13181b, 0x4f535c1f,
            0x47737437, 0x44505414, 0x82b2b032, 0x0d111c1d, 0x05212425, 0x4f434c0f, 0x00000000, 0x46424406,
            0xcde1ec2d, 0x48505818, 0x42525012, 0xcbe3e82b, 0x4e727c3e, 0xcad2d81a, 0xc9c1c809, 0xcdf1fc3d,
            0x00303030, 0x85919415, 0x45616425, 0x0c303c3c, 0x86b2b436, 0xc4e0e424, 0x8bb3b83b, 0x4c707c3c,
            0x0e020c0e, 0x40505010, 0x09313839, 0x06222426, 0x02323032, 0x84808404, 0x49616829, 0x83939013,
            0x07333437, 0xc7e3e427, 0x04202424, 0x84a0a424, 0xcbc3c80b, 0x43535013, 0x0a02080a, 0x87838407,
            0xc9d1d819, 0x4c404c0c, 0x83838003, 0x8f838c0f, 0xcec2cc0e, 0x0b33383b, 0x4a42480a, 0x87b3b437
        }	};

        private static void EncRoundKeyUpdate0(ref uint[] K, int offset, ref uint A, ref uint B, uint C, uint D, uint KC)
        {
            uint T0 = A;
            A = (A >> 8) ^ (B << 24);
            B = (B >> 8) ^ (T0 << 24);
            T0 = A + C - KC;
            uint T1 = B + KC - D;
            K[offset + 0] = SEED_SL[0, T0 & 0xFF] ^ SEED_SL[1, (T0 >> 8) & 0xFF] ^ SEED_SL[2, (T0 >> 16) & 0xFF] ^ SEED_SL[3, (T0 >> 24) & 0xFF];
            K[offset + 1] = SEED_SL[0, T1 & 0xFF] ^ SEED_SL[1, (T1 >> 8) & 0xFF] ^ SEED_SL[2, (T1 >> 16) & 0xFF] ^ SEED_SL[3, (T1 >> 24) & 0xFF];
        }

        private static void EncRoundKeyUpdate1(ref uint[] K, int offset, uint A, uint B, ref uint C, ref uint D, uint KC)
        {
            uint T0 = C;
            C = (C << 8) ^ (D >> 24);
            D = (D << 8) ^ (T0 >> 24);
            T0 = A + C - KC;
            uint T1 = B + KC - D;
            K[offset + 0] = SEED_SL[0, T0 & 0xFF] ^ SEED_SL[1, (T0 >> 8) & 0xFF] ^ SEED_SL[2, (T0 >> 16) & 0xFF] ^ SEED_SL[3, (T0 >> 24) & 0xFF];
            K[offset + 1] = SEED_SL[0, T1 & 0xFF] ^ SEED_SL[1, (T1 >> 8) & 0xFF] ^ SEED_SL[2, (T1 >> 16) & 0xFF] ^ SEED_SL[3, (T1 >> 24) & 0xFF];
        }

        private static CODE SEED_KeySchedule(
            byte[] UserKey,		//	사용자 비밀키 입력
            uint UserKeyLen,		//	사용자 비밀키의 바이트 수
            ref SEED_ALG_INFO algoInfo)	//	암호용/복호용 Round Key 생성/저장
        {
            uint	A = 0, B = 0, C = 0, D = 0, T0 = 0, T1 = 0;
            uint[] K = algoInfo.RoundKey;

            ////
            if (UserKeyLen != (uint)SEED_USER_KEY_LEN)
                return CODE.CTR_INVALID_USERKEYLEN;

            ////
            BIG_B2D(UserKey, 0, ref A);
            BIG_B2D(UserKey, 4, ref B);
            BIG_B2D(UserKey, 8, ref C);
            BIG_B2D(UserKey, 12, ref D);

            T0 = A + C - KC0;
            T1 = B - D + KC0;
            K[0] = SEED_SL[0, T0 & 0xFF] ^ SEED_SL[1, (T0 >> 8) & 0xFF]
                ^ SEED_SL[2, (T0 >> 16) & 0xFF] ^ SEED_SL[3, (T0 >> 24) & 0xFF];
            K[1] = SEED_SL[0, T1 & 0xFF] ^ SEED_SL[1, (T1 >> 8) & 0xFF]
                ^ SEED_SL[2, (T1 >> 16) & 0xFF] ^ SEED_SL[3, (T1 >> 24) & 0xFF];

            EncRoundKeyUpdate0(ref K, 2, ref A, ref B, C, D, KC1);
            EncRoundKeyUpdate1(ref K, 4, A, B, ref C, ref D, KC2);
            EncRoundKeyUpdate0(ref K, 6, ref A, ref B, C, D, KC3);
            EncRoundKeyUpdate1(ref K, 8, A, B, ref C, ref D, KC4);
            EncRoundKeyUpdate0(ref K, 10, ref A, ref B, C, D, KC5);
            EncRoundKeyUpdate1(ref K, 12, A, B, ref C, ref D, KC6);
            EncRoundKeyUpdate0(ref K, 14, ref A, ref B, C, D, KC7);
            EncRoundKeyUpdate1(ref K, 16, A, B, ref C, ref D, KC8);
            EncRoundKeyUpdate0(ref K, 18, ref A, ref B, C, D, KC9);
            EncRoundKeyUpdate1(ref K, 20, A, B, ref C, ref D, KC10);
            EncRoundKeyUpdate0(ref K, 22, ref A, ref B, C, D, KC11);
            EncRoundKeyUpdate1(ref K, 24, A, B, ref C, ref D, KC12);
            EncRoundKeyUpdate0(ref K, 26, ref A, ref B, C, D, KC13);
            EncRoundKeyUpdate1(ref K, 28, A, B, ref C, ref D, KC14);
            EncRoundKeyUpdate0(ref K, 30, ref A, ref B, C, D, KC15);

            //	Remove sensitive data
            A = B = C = D = T0 = T1 = 0;
            algoInfo.RoundKey = K;
            K = null;

            //
            return CODE.CTR_SUCCESS;
        }

        private static void SeedRound(ref uint A, ref uint B, uint C, uint D, uint[] K, int offset)
        {
            uint T0, T1;
            T0 = C ^ K[offset + 0];
            T1 = D ^ K[offset + 1];
            T1 ^= T0;
            T1 = SEED_SL[0, T1 & 0xFF] ^ SEED_SL[1, (T1 >> 8) & 0xFF]
                ^ SEED_SL[2, (T1 >> 16) & 0xFF] ^ SEED_SL[3, (T1 >> 24) & 0xFF];
            T0 += T1;
            T0 = SEED_SL[0, T0 & 0xFF] ^ SEED_SL[1, (T0 >> 8) & 0xFF]
                ^ SEED_SL[2, (T0 >> 16) & 0xFF] ^ SEED_SL[3, (T0 >> 24) & 0xFF];
            T1 += T0;
            T1 = SEED_SL[0, T1 & 0xFF] ^ SEED_SL[1, (T1 >> 8) & 0xFF]
                ^ SEED_SL[2, (T1 >> 16) & 0xFF] ^ SEED_SL[3, (T1 >> 24) & 0xFF];
            T0 += T1;

            A ^= T0;
            B ^= T1;
        }

        private static void SEED_Encrypt(
            uint[] CipherKey,		//	암/복호용 Round Key
            ref byte[] Data,			//	입출력을 위한 블록을 가리키는 pointer
            int offset)
        {
            uint	A = 0, B = 0, C = 0, D = 0;
            uint[] K = CipherKey;

            BIG_B2D(Data, offset +  8, ref C);
            BIG_B2D(Data, offset + 12, ref D);
            BIG_B2D(Data, offset +  0, ref A);
            BIG_B2D(Data, offset +  4, ref B);

            //
            SeedRound(ref A, ref B, C, D, K, 0);
            SeedRound(ref C, ref D, A, B, K, 2);
            SeedRound(ref A, ref B, C, D, K, 4);
            SeedRound(ref C, ref D, A, B, K, 6);
            SeedRound(ref A, ref B, C, D, K, 8);
            SeedRound(ref C, ref D, A, B, K, 10);
            SeedRound(ref A, ref B, C, D, K, 12);
            SeedRound(ref C, ref D, A, B, K, 14);
            SeedRound(ref A, ref B, C, D, K, 16);
            SeedRound(ref C, ref D, A, B, K, 18);
            SeedRound(ref A, ref B, C, D, K, 20);
            SeedRound(ref C, ref D, A, B, K, 22);
            SeedRound(ref A, ref B, C, D, K, 24);
            SeedRound(ref C, ref D, A, B, K, 26);
            SeedRound(ref A, ref B, C, D, K, 28);
            SeedRound(ref C, ref D, A, B, K, 30);

            //
            BIG_D2B(A, ref Data, offset +  8);
            BIG_D2B(B, ref Data, offset + 12);
            BIG_D2B(C, ref Data, offset +  0);
            BIG_D2B(D, ref Data, offset +  4);

            //	Remove sensitive data
            A = B = C = D = 0;
            K = null;
        }

        private static void SEED_Decrypt(
            uint[] CipherKey,		//	암/복호용 Round Key
            ref byte[] Data,			//	입출력을 위한 블록을 가리키는 pointer
            int offset)
        {
            uint	A = 0, B = 0, C = 0, D = 0;
            uint[] K = CipherKey;

            //
            BIG_B2D(Data, offset +  8, ref C);
            BIG_B2D(Data, offset + 12, ref D);
            BIG_B2D(Data, offset +  0, ref A);
            BIG_B2D(Data, offset +  4, ref B);

            //
            SeedRound(ref A, ref B, C, D, K, 30);
            SeedRound(ref C, ref D, A, B, K, 28);
            SeedRound(ref A, ref B, C, D, K, 26);
            SeedRound(ref C, ref D, A, B, K, 24);
            SeedRound(ref A, ref B, C, D, K, 22);
            SeedRound(ref C, ref D, A, B, K, 20);
            SeedRound(ref A, ref B, C, D, K, 18);
            SeedRound(ref C, ref D, A, B, K, 16);
            SeedRound(ref A, ref B, C, D, K, 14);
            SeedRound(ref C, ref D, A, B, K, 12);
            SeedRound(ref A, ref B, C, D, K, 10);
            SeedRound(ref C, ref D, A, B, K, 8);
            SeedRound(ref A, ref B, C, D, K, 6);
            SeedRound(ref C, ref D, A, B, K, 4);
            SeedRound(ref A, ref B, C, D, K, 2);
            SeedRound(ref C, ref D, A, B, K, 0);

            //
            BIG_D2B(A, ref Data, offset +  8);
            BIG_D2B(B, ref Data, offset + 12);
            BIG_D2B(C, ref Data, offset +  0);
            BIG_D2B(D, ref Data, offset +  4);

            //	Remove sensitive data
            A = B = C = D = 0;
            K = null;
        }

        #endregion


        #region SEED 암호화/복호화 메인 부분

        private static void BlockCopy(ref byte[] dst, byte[] src)
        {
            Buffer.BlockCopy(src, 0, dst, 0, SEED_BLOCK_LEN);
        }

        private static void BlockCopy(ref byte[] dst, int offset, byte[] src)
        {
            Buffer.BlockCopy(src, 0, dst, offset, SEED_BLOCK_LEN - offset);
        }

        private static void BlockXor(ref byte[] dst, byte[] src)
        {
            for (int i = 0; i < SEED_BLOCK_LEN; i += 4)
            {
                Buffer.BlockCopy(BitConverter.GetBytes(BitConverter.ToUInt32(dst, i) ^ BitConverter.ToUInt32(src, i)), 0, dst, i, 4);
            }
        }

        private static void BlockXor(ref byte[] dst, int offset, byte[] src1, byte[] src2)
        {
            for (int i = 0; i < SEED_BLOCK_LEN; i += 4)
            {
                Buffer.BlockCopy(BitConverter.GetBytes(BitConverter.ToUInt32(src1, i) ^ BitConverter.ToUInt32(src2, i)), 0, dst, offset + i, 4);
            }
        }

        private static uint PaddSet(ref byte[] buffer, uint offset, int blkLen, PADDING paddingType)
        {
            uint padLen = 0;

            switch (paddingType)
            {
                case PADDING.AI_NO_PADDING:
                    if (offset == 0)
                        return 0;
                    else
                        return (uint)CODE.CTR_DATA_LEN_ERROR;

                case PADDING.AI_PKCS_PADDING:
                    padLen = (uint)blkLen - offset;
                    if (padLen == 0) padLen = (uint)blkLen; // 무조건 패딩
                    for (int i = 0; i < (int)padLen; i++)
                        buffer[offset + i] = (byte)padLen;
                    return padLen;

                default:
                    return (uint)CODE.CTR_FATAL_ERROR;
            }
        }

        private static uint PaddCheck(ref byte[] buffer, int offset, uint blkLen, PADDING paddingType)
        {
            switch (paddingType)
            {
                case PADDING.AI_NO_PADDING:
                    return 0;			//	padding된 데이타가 0바이트임.

                case PADDING.AI_PKCS_PADDING:
                    int padLen = (int)buffer[offset + (int)blkLen - 1];
                    if ((padLen <= 0) || (padLen > (int)blkLen))
                        return (uint)CODE.CTR_PAD_CHECK_ERROR;

                    for (int i = 1; i <= padLen; i++)
                        if (buffer[offset + (int)blkLen - i] != (byte)padLen)
                            return (uint)CODE.CTR_PAD_CHECK_ERROR;

                    return (uint)padLen;

                default:
                    return (uint)CODE.CTR_FATAL_ERROR;
            }
        }

        private static void SEED_SetAlgInfo(MODE modeId, PADDING PadType, byte[] IV, ref SEED_ALG_INFO algoInfo)
        {
            algoInfo.ModeID = modeId;
            algoInfo.PadType = PadType;

            if (IV != null)
                algoInfo.IV = IV;
            else
                algoInfo.IV = new byte[SEED_BLOCK_LEN];
        }

        private static CODE SEED_AlgInit(ref SEED_ALG_INFO algoInfo)
        {
            algoInfo.BufLen = 0;
            if (algoInfo.ModeID != MODE.AI_ECB) BlockCopy(ref algoInfo.ChainVar, 0, algoInfo.IV);
            return CODE.CTR_SUCCESS;
        }

        private static CODE SEED_EncInit(ref SEED_ALG_INFO algoInfo)
        {
            return SEED_AlgInit(ref algoInfo);
        }

        private static CODE SEED_EncUpdate(ref SEED_ALG_INFO algoInfo, byte[] plainText, uint plainTextLen,
                                           ref byte[] cipherText, ref uint cipherTextLen)
        {
            switch (algoInfo.ModeID)
            {
                case MODE.AI_ECB: return ECB_EncUpdate(ref algoInfo, plainText, plainTextLen, ref cipherText, ref cipherTextLen);
                case MODE.AI_CBC: return CBC_EncUpdate(ref algoInfo, plainText, plainTextLen, ref cipherText, ref cipherTextLen);
                case MODE.AI_OFB: return OFB_EncUpdate(ref algoInfo, plainText, plainTextLen, ref cipherText, ref cipherTextLen);
                case MODE.AI_CFB: return CFB_EncUpdate(ref algoInfo, plainText, plainTextLen, ref cipherText, ref cipherTextLen);
                default: return CODE.CTR_FATAL_ERROR;
            }
        }

        private static CODE SEED_EncFinal(ref SEED_ALG_INFO algoInfo, ref byte[] cipherText, int offset, ref uint cipherTextLen)
        {
            switch (algoInfo.ModeID)
            {
                case MODE.AI_ECB: return ECB_EncFinal(ref algoInfo, ref cipherText, offset, ref cipherTextLen);
                case MODE.AI_CBC: return CBC_EncFinal(ref algoInfo, ref cipherText, offset, ref cipherTextLen);
                case MODE.AI_OFB: return OFB_EncFinal(ref algoInfo, ref cipherText, offset, ref cipherTextLen);
                case MODE.AI_CFB: return CFB_EncFinal(ref algoInfo, ref cipherText, offset, ref cipherTextLen);
                default: return CODE.CTR_FATAL_ERROR;
            }
        }

        private static CODE SEED_DecInit(ref SEED_ALG_INFO algoInfo)
        {
            return SEED_AlgInit(ref algoInfo);
        }

        private static CODE SEED_DecUpdate(ref SEED_ALG_INFO algoInfo, byte[] cipherText, uint cipherTextLen,
                                           ref byte[] plainText, ref uint plainTextLen)
        {
            switch (algoInfo.ModeID)
            {
                case MODE.AI_ECB: return ECB_DecUpdate(ref algoInfo, cipherText, cipherTextLen, ref plainText, ref plainTextLen);
                case MODE.AI_CBC: return CBC_DecUpdate(ref algoInfo, cipherText, cipherTextLen, ref plainText, ref plainTextLen);
                case MODE.AI_OFB: return OFB_DecUpdate(ref algoInfo, cipherText, cipherTextLen, ref plainText, ref plainTextLen);
                case MODE.AI_CFB: return CFB_DecUpdate(ref algoInfo, cipherText, cipherTextLen, ref plainText, ref plainTextLen);
                default: return CODE.CTR_FATAL_ERROR;
            }
        }

        private static CODE SEED_DecFinal(ref SEED_ALG_INFO algoInfo, ref byte[] plainText, int offset, ref uint plainTextLen)
        {
            switch (algoInfo.ModeID)
            {
                case MODE.AI_ECB: return ECB_DecFinal(ref algoInfo, ref plainText, offset, ref plainTextLen);
                case MODE.AI_CBC: return CBC_DecFinal(ref algoInfo, ref plainText, offset, ref plainTextLen);
                case MODE.AI_OFB: return OFB_DecFinal(ref algoInfo, ref plainText, offset, ref plainTextLen);
                case MODE.AI_CFB: return CFB_DecFinal(ref algoInfo, ref plainText, offset, ref plainTextLen);
                default: return CODE.CTR_FATAL_ERROR;
            }
        }

        // Cipher Block Chaining (CBC) mode
        #region CBC

        private static CODE CBC_EncUpdate(ref SEED_ALG_INFO algoInfo, byte[] plainText, uint plainTextLen,
                                          ref byte[] cipherText, ref uint cipherTextLen)
        {
            //	평문 크기가 한 블럭 미만인 경우
            if (plainTextLen <= (uint)SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(plainText, 0, algoInfo.Buffer, 0, (int)plainTextLen);

                algoInfo.BufLen = plainTextLen;
                cipherTextLen = 0;
                return CODE.CTR_SUCCESS;
            }

            cipherTextLen = plainTextLen;

            //	core part
            int count = 0;
            while ((int)plainTextLen > SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(plainText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, SEED_BLOCK_LEN);
                plainTextLen -= (uint)SEED_BLOCK_LEN;

                BlockXor(ref algoInfo.Buffer, algoInfo.ChainVar);
                SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.Buffer, 0);
                Buffer.BlockCopy(algoInfo.Buffer, 0, cipherText, SEED_BLOCK_LEN * count, SEED_BLOCK_LEN);

                Buffer.BlockCopy(cipherText, SEED_BLOCK_LEN * count, algoInfo.ChainVar, 0, SEED_BLOCK_LEN);
                count++;
            }

            //	save remained data
            Buffer.BlockCopy(plainText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, (int)plainTextLen);
            algoInfo.BufLen = plainTextLen;
            cipherTextLen -= plainTextLen;

            return CODE.CTR_SUCCESS;
        }

        private static CODE CBC_EncFinal(ref SEED_ALG_INFO algoInfo, ref byte[] cipherText, int offset, ref uint cipherTextLen)
        {
            uint bufferLen = algoInfo.BufLen;
            uint PaddByte = 0;

            //	Padding
            PaddByte = PaddSet(ref algoInfo.Buffer, bufferLen, SEED_BLOCK_LEN, algoInfo.PadType);
            if (PaddByte > (uint)SEED_BLOCK_LEN) return CODE.CTR_DATA_LEN_ERROR;

            if (PaddByte == 0)
            {
                cipherTextLen = 0;
                return CODE.CTR_SUCCESS;
            }

            //	core part
            BlockXor(ref algoInfo.Buffer, algoInfo.ChainVar);
            SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.Buffer, 0);
            Buffer.BlockCopy(algoInfo.Buffer, 0, cipherText, offset, SEED_BLOCK_LEN);
            cipherTextLen = (uint)SEED_BLOCK_LEN;

            return CODE.CTR_SUCCESS;
        }

        private static CODE CBC_DecUpdate(ref SEED_ALG_INFO algoInfo, byte[] cipherText, uint cipherTextLen,
                                          ref byte[] plainText, ref uint plainTextLen)
        {
            //	암호문 크기가 한 블럭 미만인 경우
            if (cipherTextLen <= (uint)SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(cipherText, 0, algoInfo.Buffer, 0, (int)cipherTextLen);

                algoInfo.BufLen = cipherTextLen;
                plainTextLen = 0;
                return CODE.CTR_SUCCESS;
            }

            //	first block
            plainTextLen = cipherTextLen;

            //	core part
            int count = 0;
            while ((int)cipherTextLen > SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(cipherText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, SEED_BLOCK_LEN);
                cipherTextLen -= (uint)SEED_BLOCK_LEN;

                SEED_Decrypt(algoInfo.RoundKey, ref algoInfo.Buffer, 0);
                BlockXor(ref algoInfo.Buffer, algoInfo.ChainVar);
                Buffer.BlockCopy(algoInfo.Buffer, 0, plainText, SEED_BLOCK_LEN * count, SEED_BLOCK_LEN);

                Buffer.BlockCopy(cipherText, SEED_BLOCK_LEN * count, algoInfo.ChainVar, 0, SEED_BLOCK_LEN);
                count++;
            }

            //	save remained data
            Buffer.BlockCopy(cipherText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, (int)cipherTextLen);
            algoInfo.BufLen = cipherTextLen;
            plainTextLen -= cipherTextLen;

            return CODE.CTR_SUCCESS;
        }

        private static CODE CBC_DecFinal(ref SEED_ALG_INFO algoInfo, ref byte[] plainText, int offset, ref uint plainTextLen)
        {
            uint bufferLen = algoInfo.BufLen;
            uint ret = 0;

            //	Check Output Memory Size
            if (bufferLen == 0)
            {
                plainTextLen = 0;
                return CODE.CTR_SUCCESS;
            }
            plainTextLen = (uint)SEED_BLOCK_LEN;

            if (bufferLen != (uint)SEED_BLOCK_LEN) return CODE.CTR_CIPHER_LEN_ERROR;

            //	core part
            SEED_Decrypt(algoInfo.RoundKey, ref algoInfo.Buffer, 0);
            BlockXor(ref algoInfo.Buffer, algoInfo.ChainVar);
            Buffer.BlockCopy(algoInfo.Buffer, 0, plainText, offset, SEED_BLOCK_LEN);

            //	Padding Check
            ret = PaddCheck(ref plainText, offset, (uint)SEED_BLOCK_LEN, algoInfo.PadType);
            unchecked
            {
                if ((ret == (uint)CODE.CTR_PAD_CHECK_ERROR) || (ret == (uint)-3)) return CODE.CTR_PAD_CHECK_ERROR;
                if ((ret == (uint)CODE.CTR_FATAL_ERROR) || (ret == (uint)-1)) return CODE.CTR_FATAL_ERROR;
            }
            plainTextLen = (uint)SEED_BLOCK_LEN - ret;

            return CODE.CTR_SUCCESS;
        }

        #endregion

        // Cipher Feedback (CFB) mode
        // Ci = Ek(C[i-1]) ^ Pi
        // Pi = Ek(C[i-1]) ^ Ci
        // C0 = IV
        #region CFB

        private static CODE CFB_EncUpdate(ref SEED_ALG_INFO algoInfo, byte[] plainText, uint plainTextLen,
                                          ref byte[] cipherText, ref uint cipherTextLen)
        {
            //	평문 크기가 한 블럭 미만인 경우
            if (plainTextLen <= (uint)SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(plainText, 0, algoInfo.Buffer, 0, (int)plainTextLen);

                algoInfo.BufLen = plainTextLen;
                cipherTextLen = 0;
                return CODE.CTR_SUCCESS;
            }

            cipherTextLen = plainTextLen;

            //	core part
            int count = 0;
            while ((int)plainTextLen > SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(plainText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, SEED_BLOCK_LEN);
                plainTextLen -= (uint)SEED_BLOCK_LEN;

                SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.ChainVar, 0);
                BlockXor(ref algoInfo.ChainVar, algoInfo.Buffer);
                Buffer.BlockCopy(algoInfo.ChainVar, 0, cipherText, SEED_BLOCK_LEN * count, SEED_BLOCK_LEN);
                count++;
            }

            //	save remained data
            Buffer.BlockCopy(plainText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, (int)plainTextLen);
            algoInfo.BufLen = plainTextLen;
            cipherTextLen -= plainTextLen;

            //	control the case that plainText and cipherText are the same buffer
            return CODE.CTR_SUCCESS;
        }

        private static CODE CFB_EncFinal(ref SEED_ALG_INFO algoInfo, ref byte[] cipherText, int offset, ref uint cipherTextLen)
        {
            uint bufferLen = algoInfo.BufLen;

            //	core part
            SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.ChainVar, 0);
            BlockXor(ref algoInfo.ChainVar, algoInfo.Buffer);
            Buffer.BlockCopy(algoInfo.ChainVar, 0, cipherText, offset, (int)bufferLen);

            cipherTextLen = bufferLen;

            return CODE.CTR_SUCCESS;
        }

        private static CODE CFB_DecUpdate(ref SEED_ALG_INFO algoInfo, byte[] cipherText, uint cipherTextLen,
                                          ref byte[] plainText, ref uint plainTextLen)
        {
            //	암호문 크기가 한 블럭 미만인 경우
            if (cipherTextLen <= (uint)SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(cipherText, 0, algoInfo.Buffer, 0, (int)cipherTextLen);

                algoInfo.BufLen = cipherTextLen;
                plainTextLen = 0;
                return CODE.CTR_SUCCESS;
            }

            //	first block
            plainTextLen = cipherTextLen;

            //	core part
            int count = 0;
            while ((int)cipherTextLen > SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(cipherText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, SEED_BLOCK_LEN);
                cipherTextLen -= (uint)SEED_BLOCK_LEN;

                SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.ChainVar, 0);
                BlockXor(ref algoInfo.ChainVar, algoInfo.Buffer);
                Buffer.BlockCopy(algoInfo.ChainVar, 0, plainText, SEED_BLOCK_LEN * count, SEED_BLOCK_LEN);

                BlockCopy(ref algoInfo.ChainVar, algoInfo.Buffer);
                count++;
            }

            //	save remained data
            Buffer.BlockCopy(cipherText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, (int)cipherTextLen);
            algoInfo.BufLen = cipherTextLen;
            plainTextLen -= cipherTextLen;

            return CODE.CTR_SUCCESS;
        }

        private static CODE CFB_DecFinal(ref SEED_ALG_INFO algoInfo, ref byte[] plainText, int offset, ref uint plainTextLen)
        {
            uint bufferLen = algoInfo.BufLen;

            //	core part
            SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.ChainVar, 0);
            BlockXor(ref algoInfo.ChainVar, algoInfo.Buffer);
            Buffer.BlockCopy(algoInfo.ChainVar, 0, plainText, offset, (int)bufferLen);

            plainTextLen = bufferLen;

            return CODE.CTR_SUCCESS;
        }

        #endregion

        // Electronic Codebook (ECB) mode
        #region ECB

        private static CODE ECB_EncUpdate(ref SEED_ALG_INFO algoInfo, byte[] plainText, uint plainTextLen,
                                          ref byte[] cipherText, ref uint cipherTextLen)
        {
            //	평문 크기가 한 블럭 미만인 경우
            if (plainTextLen <= (uint)SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(plainText, 0, algoInfo.Buffer, 0, (int)plainTextLen);

                algoInfo.BufLen = plainTextLen;
                cipherTextLen = 0;
                return CODE.CTR_SUCCESS;
            }

            cipherTextLen = plainTextLen;

            //	core part
            int count = 0;
            while ((int)plainTextLen > SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(plainText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, SEED_BLOCK_LEN);
                plainTextLen -= (uint)SEED_BLOCK_LEN;

                SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.Buffer, 0);
                Buffer.BlockCopy(algoInfo.Buffer, 0, cipherText, SEED_BLOCK_LEN * count, SEED_BLOCK_LEN);

                count++;
            }

            //	save remained data
            Buffer.BlockCopy(plainText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, (int)plainTextLen);
            algoInfo.BufLen = plainTextLen;
            cipherTextLen -= plainTextLen;

            //	control the case that plainText and cipherText are the same buffer
            return CODE.CTR_SUCCESS;
        }

        private static CODE ECB_EncFinal(ref SEED_ALG_INFO algoInfo, ref byte[] cipherText, int offset, ref uint cipherTextLen)
        {
            uint bufferLen = algoInfo.BufLen;
            uint PaddByte = 0;

            //	Padding
            PaddByte = PaddSet(ref algoInfo.Buffer, bufferLen, SEED_BLOCK_LEN, algoInfo.PadType);
            if (PaddByte > (uint)SEED_BLOCK_LEN) return CODE.CTR_DATA_LEN_ERROR;

            if (PaddByte == 0)
            {
                cipherTextLen = 0;
                return CODE.CTR_SUCCESS;
            }

            //	core part
            SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.Buffer, 0);
            Buffer.BlockCopy(algoInfo.Buffer, 0, cipherText, offset, SEED_BLOCK_LEN);
            cipherTextLen = (uint)SEED_BLOCK_LEN;

            return CODE.CTR_SUCCESS;
        }

        private static CODE ECB_DecUpdate(ref SEED_ALG_INFO algoInfo, byte[] cipherText, uint cipherTextLen,
                                          ref byte[] plainText, ref uint plainTextLen)
        {
            //	first block
            plainTextLen = cipherTextLen;

            //	core part
            int count = 0;
            while ((int)cipherTextLen > SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(cipherText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, SEED_BLOCK_LEN);
                cipherTextLen -= (uint)SEED_BLOCK_LEN;

                SEED_Decrypt(algoInfo.RoundKey, ref algoInfo.Buffer, 0);
                Buffer.BlockCopy(algoInfo.Buffer, 0, plainText, SEED_BLOCK_LEN * count, SEED_BLOCK_LEN);

                count++;
            }

            //	save remained data
            Buffer.BlockCopy(cipherText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, (int)cipherTextLen);
            algoInfo.BufLen = cipherTextLen;
            plainTextLen -= cipherTextLen;
            //
            return CODE.CTR_SUCCESS;
        }

        private static CODE ECB_DecFinal(ref SEED_ALG_INFO algoInfo, ref byte[] plainText, int offset, ref uint plainTextLen)
        {
            uint bufferLen = algoInfo.BufLen;
            uint ret = 0;

            //	Check Output Memory Size
            if (bufferLen == 0)
            {
                plainTextLen = 0;
                return CODE.CTR_SUCCESS;
            }
            plainTextLen = (uint)SEED_BLOCK_LEN;

            if (bufferLen != (uint)SEED_BLOCK_LEN) return CODE.CTR_CIPHER_LEN_ERROR;

            //	core part
            SEED_Decrypt(algoInfo.RoundKey, ref algoInfo.Buffer, 0);
            Buffer.BlockCopy(algoInfo.Buffer, 0, plainText, offset, SEED_BLOCK_LEN);

            //	Padding Check
            ret = PaddCheck(ref plainText, offset, (uint)SEED_BLOCK_LEN, algoInfo.PadType);
            unchecked
            {
                if ((ret == (uint)CODE.CTR_PAD_CHECK_ERROR) || (ret == (uint)-3)) return CODE.CTR_PAD_CHECK_ERROR;
                if ((ret == (uint)CODE.CTR_FATAL_ERROR) || (ret == (uint)-1)) return CODE.CTR_FATAL_ERROR;
            }
            plainTextLen = (uint)SEED_BLOCK_LEN - ret;

            return CODE.CTR_SUCCESS;
        }

        #endregion

        // Output Feedback (OFB) mode
        // Cj = Pj ^ Oj
        // Pj = Cj ^ Oj
        // Oj = Ek(Ij)
        // Ij = O[j-1]
        // I0 = IV
        #region OFB

        private static CODE OFB_EncUpdate(ref SEED_ALG_INFO algoInfo, byte[] plainText, uint plainTextLen,
                                          ref byte[] cipherText, ref uint cipherTextLen)
        {
            //	평문 크기가 한 블럭 미만인 경우
            if (plainTextLen <= (uint)SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(plainText, 0, algoInfo.Buffer, 0, (int)plainTextLen);

                algoInfo.BufLen = plainTextLen;
                cipherTextLen = 0;
                return CODE.CTR_SUCCESS;
            }

            cipherTextLen = plainTextLen;

            //	core part
            int count = 0;
            while ((int)plainTextLen > SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(plainText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, SEED_BLOCK_LEN);
                plainTextLen -= (uint)SEED_BLOCK_LEN;

                SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.ChainVar, 0);
                BlockXor(ref algoInfo.Buffer, algoInfo.ChainVar);
                Buffer.BlockCopy(algoInfo.Buffer, 0, cipherText, SEED_BLOCK_LEN * count, SEED_BLOCK_LEN);
                count++;
            }

            //	save remained data
            Buffer.BlockCopy(plainText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, (int)plainTextLen);
            algoInfo.BufLen = plainTextLen;
            cipherTextLen -= plainTextLen;

            //	control the case that plainText and cipherText are the same buffer
            return CODE.CTR_SUCCESS;
        }

        private static CODE OFB_EncFinal(ref SEED_ALG_INFO algoInfo, ref byte[] cipherText, int offset, ref uint cipherTextLen)
        {
            uint bufferLen = algoInfo.BufLen;

            //	core part
            SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.ChainVar, 0);
            BlockXor(ref algoInfo.Buffer, algoInfo.ChainVar);
            Buffer.BlockCopy(algoInfo.Buffer, 0, cipherText, offset, (int)bufferLen);

            cipherTextLen = bufferLen;
            return CODE.CTR_SUCCESS;
        }

        private static CODE OFB_DecUpdate(ref SEED_ALG_INFO algoInfo, byte[] cipherText, uint cipherTextLen,
                                          ref byte[] plainText, ref uint plainTextLen)
        {
            //	암호문 크기가 한 블럭 미만인 경우
            if (cipherTextLen <= (uint)SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(cipherText, 0, algoInfo.Buffer, 0, (int)cipherTextLen);

                algoInfo.BufLen = cipherTextLen;
                plainTextLen = 0;
                return CODE.CTR_SUCCESS;
            }

            //	first block
            plainTextLen = cipherTextLen;

            //	core part
            int count = 0;
            while ((int)cipherTextLen > SEED_BLOCK_LEN)
            {
                Buffer.BlockCopy(cipherText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, SEED_BLOCK_LEN);
                cipherTextLen -= (uint)SEED_BLOCK_LEN;

                SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.ChainVar, 0);
                BlockXor(ref algoInfo.Buffer, algoInfo.ChainVar);
                Buffer.BlockCopy(algoInfo.Buffer, 0, plainText, SEED_BLOCK_LEN * count, SEED_BLOCK_LEN);

                count++;
            }

            //	save remained data
            Buffer.BlockCopy(cipherText, SEED_BLOCK_LEN * count, algoInfo.Buffer, 0, (int)cipherTextLen);
            algoInfo.BufLen = cipherTextLen;
            plainTextLen -= cipherTextLen;

            return CODE.CTR_SUCCESS;
        }

        private static CODE OFB_DecFinal(ref SEED_ALG_INFO algoInfo, ref byte[] plainText, int offset, ref uint plainTextLen)
        {
            uint bufferLen = algoInfo.BufLen;

            //	core part
            SEED_Encrypt(algoInfo.RoundKey, ref algoInfo.ChainVar, 0);
            BlockXor(ref algoInfo.Buffer, algoInfo.ChainVar);
            Buffer.BlockCopy(algoInfo.Buffer, 0, plainText, offset, (int)bufferLen);

            plainTextLen = bufferLen;
            return CODE.CTR_SUCCESS;
        }

        #endregion

        #endregion


        #region 메인 처리 함수 부분

        private void GetKeyIV(string sKeyString, ref byte[] key, ref uint keyLen, ref byte[] iv, ref uint ivLen)
        {
            GetKey(sKeyString, ref key, ref keyLen);
            GetIV(sKeyString, ref iv, ref ivLen);
        }

        private void GetKey(string sKeyString, ref byte[] key, ref uint keyLen)
        {
            int i = 0, j = 0;
            byte[] bKeyString = Encoding.Default.GetBytes(sKeyString);

            j = bKeyString.Length;

            keyLen = (uint)SEED_USER_KEY_LEN;
            for (i = 0; i < SEED_USER_KEY_LEN; i++)
            {
                if (i >= SEED_BLOCK_LEN) break;

                if (i >= j)
                    key[i] = (byte)' ';
                else
                    key[i] = bKeyString[i];
            }
        }

        private void GetIV(string sIVString, ref byte[] iv, ref uint ivLen)
        {
            int i = 0, j = 0;
            byte[] bIV = Encoding.Default.GetBytes(sIVString);

            j = bIV.Length;

            ivLen = (uint)SEED_USER_IV_LEN;
            for (i = 0; i < SEED_USER_IV_LEN; i++)
            {
                if (i >= SEED_BLOCK_LEN) break;

                if (i >= j)
                    iv[i] = (byte)' ';
                else
                    iv[i] = bIV[i];
            }
        }

        /// <summary>
        /// SEED 암호화/복호화 메인 함수
        /// </summary>
        /// <param name="EncType">Type of the enc.</param>
        /// <param name="ModeType">Type of the mode.</param>
        /// <param name="PadType">Type of the pad.</param>
        /// <param name="sKeyString">The s key string.</param>
        /// <param name="sValue">The s value.</param>
        /// <param name="sReturn">The s return.</param>
        /// <returns></returns>
        private CODE SEEDString(
            uint EncType,
            MODE ModeType,
            PADDING PadType,
            string sKeyString,
            string sValue,
            out string sReturn)
        {
            return SEEDString(EncType, ModeType, PadType, sKeyString, sKeyString, sValue, out sReturn);
        }

        /// <summary>
        /// SEED 암호화/복호화 메인 함수
        /// </summary>
        /// <param name="EncType">Type of the enc.</param>
        /// <param name="ModeType">Type of the mode.</param>
        /// <param name="PadType">Type of the pad.</param>
        /// <param name="sKeyString">The s key string.</param>
        /// <param name="sIV">The s IV.</param>
        /// <param name="sValue">The s value.</param>
        /// <param name="sReturn">The s return.</param>
        /// <returns></returns>
        private CODE SEEDString(
            uint EncType,
            MODE ModeType,
            PADDING PadType,
            string sKeyString,
            string sIV,
            string sValue,
            out string sReturn)
        {
            uint keyLen = 0, ivLen = 0;
            CODE nErr = CODE.CTR_SUCCESS;

            sReturn = string.Empty;
            _key = new byte[SEED_USER_KEY_LEN];
            GetKey(sKeyString, ref _key, ref keyLen);
            _iv = new byte[SEED_USER_IV_LEN];
            GetIV(sIV, ref _iv, ref ivLen);
            _padType = PadType;
            _modType = ModeType;

            if (EncType == 0)
            {
                byte[] bValue = Encoding.Default.GetBytes(sValue);

                byte[] enc = Encrypt(bValue);
                if (enc == null) return CODE.CTR_FATAL_ERROR;

                sReturn = Convert.ToBase64String(enc);
            }
            else
            {
                byte[] bValue = Convert.FromBase64String(sValue);

                byte[] dec = Decrypt(bValue);
                if (dec == null) return CODE.CTR_FATAL_ERROR;

                sReturn = Encoding.Default.GetString(dec);
            }

            return nErr;
        }

        public byte[] Encrypt(byte[] bValue)
        {
            byte[] tmpData, finalData;
            uint SrcLen = 0, DstLen = 0, tmpLen = 0;

            SEED_ALG_INFO algoInfo = new SEED_ALG_INFO();
            algoInfo.IV = new byte[SEED_USER_IV_LEN];
            algoInfo.ChainVar = new byte[SEED_BLOCK_LEN];
            algoInfo.Buffer = new byte[SEED_BLOCK_LEN];
            algoInfo.RoundKey = new uint[SEED_NO_ROUNDKEY];

            SEED_SetAlgInfo(_modType, _padType, _iv, ref algoInfo);
            CODE ret = SEED_KeySchedule(_key, SEED_USER_KEY_LEN, ref algoInfo);
            if (ret != CODE.CTR_SUCCESS) return null;

            //	Encryption
            ret = SEED_EncInit(ref algoInfo);
            if (ret != CODE.CTR_SUCCESS) return null;

            SrcLen = (uint)bValue.Length;
            tmpData = new byte[(int)SrcLen + 32];

            ret = SEED_EncUpdate(ref algoInfo, bValue, SrcLen, ref tmpData, ref tmpLen);
            if (ret != CODE.CTR_SUCCESS) return null;

            ret = SEED_EncFinal(ref algoInfo, ref tmpData, (int)tmpLen, ref DstLen);
            if (ret != CODE.CTR_SUCCESS) return null;

            finalData = new byte[tmpLen + DstLen];
            Buffer.BlockCopy(tmpData, 0, finalData, 0, (int)(tmpLen + DstLen));

            return finalData;
        }

        public byte[] Decrypt(byte[] bValue)
        {
            byte[] tmpData, finalData;
            uint DstLen = 0, tmpLen = 0, nLen = 0;

            SEED_ALG_INFO algoInfo = new SEED_ALG_INFO();
            algoInfo.IV = new byte[SEED_USER_IV_LEN];
            algoInfo.ChainVar = new byte[SEED_BLOCK_LEN];
            algoInfo.Buffer = new byte[SEED_BLOCK_LEN];
            algoInfo.RoundKey = new uint[SEED_NO_ROUNDKEY];

            SEED_SetAlgInfo(_modType, _padType, _iv, ref algoInfo);
            CODE ret = SEED_KeySchedule(_key, SEED_USER_KEY_LEN, ref algoInfo);
            if (ret != CODE.CTR_SUCCESS) return null;

            //	Decryption
            ret = SEED_DecInit(ref algoInfo);
            if (ret != CODE.CTR_SUCCESS) return null;

            nLen = (uint)bValue.Length;

            tmpData = new byte[bValue.Length];

            ret = SEED_DecUpdate(ref algoInfo, bValue, nLen, ref tmpData, ref tmpLen);
            if (ret != CODE.CTR_SUCCESS) return null;

            ret = SEED_DecFinal(ref algoInfo, ref tmpData, (int)tmpLen, ref DstLen);
            if (ret != CODE.CTR_SUCCESS) return null;
            if (DstLen > SEED_BLOCK_LEN) return null;

            finalData = new byte[tmpLen + DstLen];
            Buffer.BlockCopy(tmpData, 0, finalData, 0, (int)(tmpLen + DstLen));
            return finalData;
        }

        public string seedEncryptString(string sKey, string sValue)
        {
            uint encType = 0;
            MODE modeType = MODE.AI_CBC;
            PADDING padType = PADDING.AI_PKCS_PADDING;
            string sRet;
            CODE nErr;

            nErr = SEEDString(encType, modeType, padType, sKey, sValue, out sRet);
            if (nErr == CODE.CTR_SUCCESS)
                return sRet;
            else
                return "";
        }

        public string seedDecryptString(string sKey, string sValue)
        {
            uint encType = 1;
            MODE modeType = MODE.AI_CBC;
            PADDING padType = PADDING.AI_PKCS_PADDING;
            string sRet;
            CODE nErr;

            nErr = SEEDString(encType, modeType, padType, sKey, sValue, out sRet);
            if (nErr == CODE.CTR_SUCCESS)
                return sRet;
            else
                return "";
        }

        public string seedDecryptString(string sKey, string iv, string sValue)
        {
            uint encType = 1;
            MODE modeType = MODE.AI_CBC;
            PADDING padType = PADDING.AI_PKCS_PADDING;
            string sRet;
            CODE nErr;

            nErr = SEEDString(encType, modeType, padType, sKey, iv, sValue, out sRet);
            if (nErr == CODE.CTR_SUCCESS)
                return sRet;
            else
                return "";
        }

        #endregion
    }
}