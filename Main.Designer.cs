namespace FuKo
{
    partial class Main
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.lstCertificates = new System.Windows.Forms.ListBox();
            this.btnRefresh = new System.Windows.Forms.Button();
            this.btnChangePass = new System.Windows.Forms.Button();
            this.btnCheckPass = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // lstCertificates
            // 
            this.lstCertificates.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.lstCertificates.HorizontalScrollbar = true;
            this.lstCertificates.IntegralHeight = false;
            this.lstCertificates.ItemHeight = 15;
            this.lstCertificates.Location = new System.Drawing.Point(12, 46);
            this.lstCertificates.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.lstCertificates.Name = "lstCertificates";
            this.lstCertificates.ScrollAlwaysVisible = true;
            this.lstCertificates.Size = new System.Drawing.Size(349, 150);
            this.lstCertificates.Sorted = true;
            this.lstCertificates.TabIndex = 0;
            // 
            // btnRefresh
            // 
            this.btnRefresh.Location = new System.Drawing.Point(12, 12);
            this.btnRefresh.Name = "btnRefresh";
            this.btnRefresh.Size = new System.Drawing.Size(88, 27);
            this.btnRefresh.TabIndex = 1;
            this.btnRefresh.Text = "갱신";
            this.btnRefresh.UseVisualStyleBackColor = true;
            this.btnRefresh.Click += new System.EventHandler(this.ctlRefresh_Click);
            // 
            // btnChangePass
            // 
            this.btnChangePass.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnChangePass.Location = new System.Drawing.Point(283, 12);
            this.btnChangePass.Name = "btnChangePass";
            this.btnChangePass.Size = new System.Drawing.Size(78, 27);
            this.btnChangePass.TabIndex = 2;
            this.btnChangePass.Text = "암호 변경";
            this.btnChangePass.UseVisualStyleBackColor = true;
            this.btnChangePass.Click += new System.EventHandler(this.btnChangePass_Click);
            // 
            // btnCheckPass
            // 
            this.btnCheckPass.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnCheckPass.Location = new System.Drawing.Point(199, 12);
            this.btnCheckPass.Name = "btnCheckPass";
            this.btnCheckPass.Size = new System.Drawing.Size(78, 27);
            this.btnCheckPass.TabIndex = 3;
            this.btnCheckPass.Text = "암호 확인";
            this.btnCheckPass.UseVisualStyleBackColor = true;
            this.btnCheckPass.Click += new System.EventHandler(this.btnCheckPass_Click);
            // 
            // label1
            // 
            this.label1.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.label1.Location = new System.Drawing.Point(12, 200);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(349, 30);
            this.label1.TabIndex = 4;
            this.label1.Text = "이 프로그램은 공식적인 프로그램이 아니며\r\n이 프로그램으로 인한 피해에 대한 책임을 지지 않습니다";
            this.label1.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // Main
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(373, 239);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.btnCheckPass);
            this.Controls.Add(this.btnChangePass);
            this.Controls.Add(this.btnRefresh);
            this.Controls.Add(this.lstCertificates);
            this.Font = new System.Drawing.Font("맑은 고딕", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(129)));
            this.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.MinimumSize = new System.Drawing.Size(389, 277);
            this.Name = "Main";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "FuKo : 공인인증서 암호변경 (RyuaNerin)";
            this.ResumeLayout(false);

        }

        private System.Windows.Forms.ListBox lstCertificates;
        private System.Windows.Forms.Button btnRefresh;
        private System.Windows.Forms.Button btnChangePass;
        private System.Windows.Forms.Button btnCheckPass;
        private System.Windows.Forms.Label label1;
    }
}

