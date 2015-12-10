using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using Mono.Security.Cryptography;
using PnPeople.Security;

namespace FuKo
{
    public partial class Main : Form
    {
        Dictionary<string, string>	m_path = new Dictionary<string, string>();

        public Main()
        {
            InitializeComponent();

            this.ctlRefresh_Click(null, null);
        }

        private void ctlRefresh_Click(object sender, EventArgs e)
        {
            this.Enabled = false;

            this.lstCertificates.Items.Clear();
            this.m_path.Clear();

            foreach (var drive in Directory.GetLogicalDrives())
                GetNPKI(drive);

            string path = Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData);
            path = Path.Combine(path, "..");
            path = Path.Combine(path, "LocalLow");

            GetNPKI(path);

            this.Enabled = true;
        }

        private void GetNPKI(string path)
        {
            try
            {
                string npki = Path.Combine(path, "NPKI");
                if (!Directory.Exists(npki)) return;

                string caPath;
                string userPath;


                foreach (var ca in Directory.GetDirectories(npki))
                {
                    caPath = Path.Combine(ca, "User");
                    if (!Directory.Exists(caPath)) continue;

                    foreach (var user in Directory.GetDirectories(caPath))
                    {
                        userPath = Directory.GetDirectoryRoot(user) + " - " + Path.GetFileName(user);

                        this.lstCertificates.Items.Add(userPath);
                        this.m_path.Add(userPath, Directory.GetFiles(user, "*.key")[0]);
                    }
                }
            }
            catch
            { }
        }

        private byte[] PrivateKeyDataDecrypt(string password, string algorithmOid, byte[] salt, int iterationCount, byte[] encryptedData)
        {
            if (algorithmOid != "1.2.410.200004.1.15") return null;

            var seed = CreateSeed(Encoding.Default.GetBytes(password), salt, iterationCount);

            return seed.Decrypt(encryptedData);
        }

        private byte[] PrivateKeyDataEncrypt(string password, string algorithmOid, byte[] salt, int iterationCount, byte[] decryptedData)
        {
            if (algorithmOid != "1.2.410.200004.1.15") return null;

            var seed = CreateSeed(Encoding.Default.GetBytes(password), salt, iterationCount);

            return seed.Encrypt(decryptedData);
        }

        private SEED CreateSeed(byte[] password, byte[] salt, int iterationCount)
        {
            var pdb = new PasswordDeriveBytes(password, salt, "SHA1", iterationCount);

            var pdbBytes = pdb.GetBytes(20);

            var seed = new SEED();
            seed.ModType = SEED.MODE.AI_CBC;

            // 16 B / 00 ~ 16 Byte
            seed.KeyBytes = new byte[16];
            Buffer.BlockCopy(pdbBytes, 0, seed.KeyBytes, 0, 16);

            // 4 B  / 16 ~ 20 Byte
            seed.IV = new byte[16];

            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                byte[] derivedIV = sha1.ComputeHash(pdbBytes, 16, 4);
                Buffer.BlockCopy(derivedIV, 0, seed.IV, 0, 16);
            }

            return seed;
        }

        private void btnCheckPass_Click(object sender, EventArgs e)
        {
            if (this.lstCertificates.SelectedIndex == -1) return;

            string path = this.m_path[(string)this.lstCertificates.SelectedItem];

            using (var frm = new InputPassword())
            {
                string pass;

                frm.Text = "인증서 암호 입력";
                if (frm.ShowDialog() != DialogResult.OK) return;
                pass = frm.Password;

                var pkInfo = new PKCS8.EncryptedPrivateKeyInfo(File.ReadAllBytes(path));

                byte[] decrypted = null;
                try
                {
                    decrypted = PrivateKeyDataDecrypt(pass, pkInfo.Algorithm, pkInfo.Salt, pkInfo.IterationCount, pkInfo.EncryptedData);
                }
                catch
                { }

                if (decrypted != null)
                    MessageBox.Show(this, "올바른 비밀번호입니다.", "성공", MessageBoxButtons.OK, MessageBoxIcon.Information);
                else
                    MessageBox.Show(this, "잘못된 비밀번호입니다.", "오류", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void btnChangePass_Click(object sender, EventArgs e)
        {
            if (this.lstCertificates.SelectedIndex == -1) return;

            string path = this.m_path[(string)this.lstCertificates.SelectedItem];

            using (var frm = new InputPassword())
            {
                string pass;

                frm.Text = "인증서 암호 입력";
                if (frm.ShowDialog() != DialogResult.OK) return;
                pass = frm.Password;

                var pkInfo = new PKCS8.EncryptedPrivateKeyInfo(File.ReadAllBytes(path));

                byte[] decrypted = null;
                try
                {
                    decrypted = PrivateKeyDataDecrypt(pass, pkInfo.Algorithm, pkInfo.Salt, pkInfo.IterationCount, pkInfo.EncryptedData);
                }
                catch
                { }

                if (decrypted == null)
                {
                    MessageBox.Show(this, "잘못된 비밀번호입니다.", "오류", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                frm.Text = "변경할 암호 입력";
                if (frm.ShowDialog() != DialogResult.OK) return;
                pass = frm.Password;

                frm.Text = "변경할 암호 다시 입력";
                if (frm.ShowDialog() != DialogResult.OK) return;
                if (pass != frm.Password)
                {
                    MessageBox.Show(this, "비밀번호가 일치하지 않습니다", "오류", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Salt 변경
                byte[] newSalt = new byte[8];
                Random rnd = new Random(DateTime.Now.Millisecond);
                rnd.NextBytes(newSalt);

                pkInfo.Salt = newSalt;

                pkInfo.EncryptedData = PrivateKeyDataEncrypt(pass, pkInfo.Algorithm, pkInfo.Salt, pkInfo.IterationCount, decrypted);

                File.WriteAllBytes(path, pkInfo.GetBytes());

                MessageBox.Show(this, "암호를 변경했습니다", "성공", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
    }
}
