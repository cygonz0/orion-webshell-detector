namespace wsd_gui
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.btn_folderPath = new System.Windows.Forms.Button();
            this.folderBrowserDialog1 = new System.Windows.Forms.FolderBrowserDialog();
            this.btn_start = new System.Windows.Forms.Button();
            this.lb_status = new System.Windows.Forms.Label();
            this.tb_arguments = new System.Windows.Forms.TextBox();
            this.rtb_results = new System.Windows.Forms.RichTextBox();
            this.ddl_logfiles = new System.Windows.Forms.ComboBox();
            this.progressBar1 = new System.Windows.Forms.ProgressBar();
            this.lb_directory = new System.Windows.Forms.Label();
            this.btn_reset = new System.Windows.Forms.Button();
            this.lb_indicator = new System.Windows.Forms.Label();
            this.lb_scantype = new System.Windows.Forms.Label();
            this.cb_option1 = new System.Windows.Forms.CheckBox();
            this.cb_option2 = new System.Windows.Forms.CheckBox();
            this.ddl_logfiles2 = new System.Windows.Forms.ComboBox();
            this.lb_logs = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.lb_version = new System.Windows.Forms.Label();
            this.btn_summary = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.tb_folderPath = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // btn_folderPath
            // 
            this.btn_folderPath.Location = new System.Drawing.Point(745, 61);
            this.btn_folderPath.Name = "btn_folderPath";
            this.btn_folderPath.Size = new System.Drawing.Size(119, 24);
            this.btn_folderPath.TabIndex = 0;
            this.btn_folderPath.Text = "Load Directory";
            this.btn_folderPath.UseVisualStyleBackColor = true;
            this.btn_folderPath.Click += new System.EventHandler(this.btn_folderPath_Click);
            // 
            // btn_start
            // 
            this.btn_start.Enabled = false;
            this.btn_start.FlatStyle = System.Windows.Forms.FlatStyle.System;
            this.btn_start.Location = new System.Drawing.Point(745, 116);
            this.btn_start.Name = "btn_start";
            this.btn_start.Size = new System.Drawing.Size(119, 24);
            this.btn_start.TabIndex = 2;
            this.btn_start.Text = "Start Scan";
            this.btn_start.UseVisualStyleBackColor = true;
            this.btn_start.Click += new System.EventHandler(this.btn_scan_Click);
            // 
            // lb_status
            // 
            this.lb_status.AutoSize = true;
            this.lb_status.BackColor = System.Drawing.Color.Transparent;
            this.lb_status.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lb_status.Location = new System.Drawing.Point(115, 683);
            this.lb_status.Name = "lb_status";
            this.lb_status.Size = new System.Drawing.Size(98, 14);
            this.lb_status.TabIndex = 3;
            this.lb_status.Text = "<status here>";
            // 
            // tb_arguments
            // 
            this.tb_arguments.Location = new System.Drawing.Point(442, 89);
            this.tb_arguments.Name = "tb_arguments";
            this.tb_arguments.ReadOnly = true;
            this.tb_arguments.Size = new System.Drawing.Size(10, 24);
            this.tb_arguments.TabIndex = 7;
            this.tb_arguments.Visible = false;
            // 
            // rtb_results
            // 
            this.rtb_results.BackColor = System.Drawing.Color.White;
            this.rtb_results.Font = new System.Drawing.Font("Trebuchet MS", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rtb_results.Location = new System.Drawing.Point(6, 172);
            this.rtb_results.Name = "rtb_results";
            this.rtb_results.ReadOnly = true;
            this.rtb_results.Size = new System.Drawing.Size(858, 488);
            this.rtb_results.TabIndex = 8;
            this.rtb_results.Text = "";
            // 
            // ddl_logfiles
            // 
            this.ddl_logfiles.BackColor = System.Drawing.Color.White;
            this.ddl_logfiles.Enabled = false;
            this.ddl_logfiles.FormattingEnabled = true;
            this.ddl_logfiles.Location = new System.Drawing.Point(101, 116);
            this.ddl_logfiles.Name = "ddl_logfiles";
            this.ddl_logfiles.Size = new System.Drawing.Size(637, 23);
            this.ddl_logfiles.TabIndex = 9;
            this.ddl_logfiles.SelectedIndexChanged += new System.EventHandler(this.ddl_logfiles_SelectedIndexChanged);
            // 
            // progressBar1
            // 
            this.progressBar1.Location = new System.Drawing.Point(693, 666);
            this.progressBar1.Name = "progressBar1";
            this.progressBar1.Size = new System.Drawing.Size(170, 20);
            this.progressBar1.Style = System.Windows.Forms.ProgressBarStyle.Marquee;
            this.progressBar1.TabIndex = 10;
            this.progressBar1.Visible = false;
            // 
            // lb_directory
            // 
            this.lb_directory.AutoSize = true;
            this.lb_directory.BackColor = System.Drawing.Color.Transparent;
            this.lb_directory.Location = new System.Drawing.Point(8, 66);
            this.lb_directory.Name = "lb_directory";
            this.lb_directory.Size = new System.Drawing.Size(88, 15);
            this.lb_directory.TabIndex = 11;
            this.lb_directory.Text = "Scan Directory:";
            // 
            // btn_reset
            // 
            this.btn_reset.Location = new System.Drawing.Point(745, 89);
            this.btn_reset.Name = "btn_reset";
            this.btn_reset.Size = new System.Drawing.Size(119, 24);
            this.btn_reset.TabIndex = 13;
            this.btn_reset.Text = "Reset";
            this.btn_reset.UseVisualStyleBackColor = true;
            this.btn_reset.Click += new System.EventHandler(this.btn_reset_Click);
            // 
            // lb_indicator
            // 
            this.lb_indicator.AutoSize = true;
            this.lb_indicator.BackColor = System.Drawing.Color.Transparent;
            this.lb_indicator.Font = new System.Drawing.Font("Lucida Sans Unicode", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lb_indicator.Location = new System.Drawing.Point(3, 682);
            this.lb_indicator.Name = "lb_indicator";
            this.lb_indicator.Size = new System.Drawing.Size(116, 15);
            this.lb_indicator.TabIndex = 14;
            this.lb_indicator.Text = "Current Scan Status:";
            // 
            // lb_scantype
            // 
            this.lb_scantype.AutoSize = true;
            this.lb_scantype.BackColor = System.Drawing.Color.Transparent;
            this.lb_scantype.Location = new System.Drawing.Point(8, 92);
            this.lb_scantype.Name = "lb_scantype";
            this.lb_scantype.Size = new System.Drawing.Size(64, 15);
            this.lb_scantype.TabIndex = 15;
            this.lb_scantype.Text = "Scan Type:";
            // 
            // cb_option1
            // 
            this.cb_option1.AutoSize = true;
            this.cb_option1.BackColor = System.Drawing.Color.Transparent;
            this.cb_option1.Location = new System.Drawing.Point(101, 92);
            this.cb_option1.Name = "cb_option1";
            this.cb_option1.Size = new System.Drawing.Size(163, 19);
            this.cb_option1.TabIndex = 19;
            this.cb_option1.Text = "Dangerous Function Scan";
            this.cb_option1.UseVisualStyleBackColor = false;
            // 
            // cb_option2
            // 
            this.cb_option2.AutoSize = true;
            this.cb_option2.BackColor = System.Drawing.Color.Transparent;
            this.cb_option2.Location = new System.Drawing.Point(271, 92);
            this.cb_option2.Name = "cb_option2";
            this.cb_option2.Size = new System.Drawing.Size(155, 19);
            this.cb_option2.TabIndex = 20;
            this.cb_option2.Text = "Webshell Signature Scan";
            this.cb_option2.UseVisualStyleBackColor = false;
            // 
            // ddl_logfiles2
            // 
            this.ddl_logfiles2.BackColor = System.Drawing.Color.White;
            this.ddl_logfiles2.Enabled = false;
            this.ddl_logfiles2.FormattingEnabled = true;
            this.ddl_logfiles2.Location = new System.Drawing.Point(101, 143);
            this.ddl_logfiles2.Name = "ddl_logfiles2";
            this.ddl_logfiles2.Size = new System.Drawing.Size(637, 23);
            this.ddl_logfiles2.TabIndex = 21;
            this.ddl_logfiles2.SelectedIndexChanged += new System.EventHandler(this.ddl_logfiles2_SelectedIndexChanged);
            // 
            // lb_logs
            // 
            this.lb_logs.AutoSize = true;
            this.lb_logs.BackColor = System.Drawing.Color.Transparent;
            this.lb_logs.Location = new System.Drawing.Point(8, 119);
            this.lb_logs.Name = "lb_logs";
            this.lb_logs.Size = new System.Drawing.Size(36, 15);
            this.lb_logs.TabIndex = 22;
            this.lb_logs.Text = "Logs:";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.BackColor = System.Drawing.Color.Transparent;
            this.label1.Location = new System.Drawing.Point(8, 146);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(84, 15);
            this.label1.TabIndex = 23;
            this.label1.Text = "Signature Log:";
            // 
            // lb_version
            // 
            this.lb_version.AutoSize = true;
            this.lb_version.BackColor = System.Drawing.Color.Transparent;
            this.lb_version.Font = new System.Drawing.Font("Lucida Sans Unicode", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lb_version.Location = new System.Drawing.Point(818, 686);
            this.lb_version.Name = "lb_version";
            this.lb_version.Size = new System.Drawing.Size(47, 15);
            this.lb_version.TabIndex = 24;
            this.lb_version.Text = "v1.0.31";
            // 
            // btn_summary
            // 
            this.btn_summary.Enabled = false;
            this.btn_summary.Location = new System.Drawing.Point(745, 143);
            this.btn_summary.Name = "btn_summary";
            this.btn_summary.Size = new System.Drawing.Size(119, 24);
            this.btn_summary.TabIndex = 25;
            this.btn_summary.Text = "Back to Summary";
            this.btn_summary.UseVisualStyleBackColor = true;
            this.btn_summary.Click += new System.EventHandler(this.btn_summary_Click);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.BackColor = System.Drawing.Color.Transparent;
            this.label2.Font = new System.Drawing.Font("Britannic Bold", 36F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.ForeColor = System.Drawing.Color.White;
            this.label2.Location = new System.Drawing.Point(1, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(141, 53);
            this.label2.TabIndex = 26;
            this.label2.Text = "Orion";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.BackColor = System.Drawing.Color.Transparent;
            this.label3.Font = new System.Drawing.Font("Meiryo UI", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label3.ForeColor = System.Drawing.Color.White;
            this.label3.Location = new System.Drawing.Point(11, 40);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(119, 14);
            this.label3.TabIndex = 27;
            this.label3.Text = "Web Shell Detector";
            // 
            // tb_folderPath
            // 
            this.tb_folderPath.BackColor = System.Drawing.Color.White;
            this.tb_folderPath.Cursor = System.Windows.Forms.Cursors.Default;
            this.tb_folderPath.Location = new System.Drawing.Point(101, 62);
            this.tb_folderPath.Name = "tb_folderPath";
            this.tb_folderPath.ReadOnly = true;
            this.tb_folderPath.Size = new System.Drawing.Size(637, 24);
            this.tb_folderPath.TabIndex = 1;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("$this.BackgroundImage")));
            this.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Stretch;
            this.ClientSize = new System.Drawing.Size(869, 709);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.btn_summary);
            this.Controls.Add(this.lb_version);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.lb_logs);
            this.Controls.Add(this.ddl_logfiles2);
            this.Controls.Add(this.cb_option2);
            this.Controls.Add(this.cb_option1);
            this.Controls.Add(this.lb_scantype);
            this.Controls.Add(this.lb_indicator);
            this.Controls.Add(this.btn_reset);
            this.Controls.Add(this.lb_directory);
            this.Controls.Add(this.progressBar1);
            this.Controls.Add(this.ddl_logfiles);
            this.Controls.Add(this.rtb_results);
            this.Controls.Add(this.tb_arguments);
            this.Controls.Add(this.lb_status);
            this.Controls.Add(this.btn_start);
            this.Controls.Add(this.tb_folderPath);
            this.Controls.Add(this.btn_folderPath);
            this.DoubleBuffered = true;
            this.Font = new System.Drawing.Font("Lucida Sans Unicode", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.Name = "Form1";
            this.SizeGripStyle = System.Windows.Forms.SizeGripStyle.Hide;
            this.Text = "Orion - Webshell Detector";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button btn_folderPath;
        private System.Windows.Forms.FolderBrowserDialog folderBrowserDialog1;
        private System.Windows.Forms.Button btn_start;
        private System.Windows.Forms.Label lb_status;
        private System.Windows.Forms.TextBox tb_arguments;
        private System.Windows.Forms.RichTextBox rtb_results;
        private System.Windows.Forms.ComboBox ddl_logfiles;
        private System.Windows.Forms.ProgressBar progressBar1;
        private System.Windows.Forms.Label lb_directory;
        private System.Windows.Forms.Button btn_reset;
        private System.Windows.Forms.Label lb_indicator;
        private System.Windows.Forms.Label lb_scantype;
        private System.Windows.Forms.CheckBox cb_option1;
        private System.Windows.Forms.CheckBox cb_option2;
        private System.Windows.Forms.ComboBox ddl_logfiles2;
        private System.Windows.Forms.Label lb_logs;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label lb_version;
        private System.Windows.Forms.Button btn_summary;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox tb_folderPath;
    }
}

