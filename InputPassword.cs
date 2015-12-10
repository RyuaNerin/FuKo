using System.Windows.Forms;

namespace FuKo
{
    public partial class InputPassword : Form
    {
        public string Password { get { return this.txtPassword.Text; } }

        public InputPassword()
        {
            InitializeComponent();
        }

        public new DialogResult ShowDialog()
        {
            this.DialogResult = DialogResult.None;
            this.txtPassword.Text = null;
            return base.ShowDialog();
        }

        private void txtPassword_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                this.DialogResult = this.txtPassword.TextLength > 0 ? DialogResult.OK : DialogResult.None;
                this.Close();
            }
        }

        private void InputPassword_Activated(object sender, System.EventArgs e)
        {
            this.txtPassword.Focus();
        }

        private void txtPassword_TextChanged(object sender, System.EventArgs e)
        {
            this.lblLen.Text = this.txtPassword.TextLength.ToString();
        }
    }
}
