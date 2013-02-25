using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;

namespace wsd_gui
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void btn_folderPath_Click(object sender, EventArgs e)
        {
            // gets directory path via dialog
            if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
            {
                tb_folderPath.Text = folderBrowserDialog1.SelectedPath;
                btn_start.Enabled = true;
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            // reset form elements
            btn_start.Enabled = false;
            btn_summary.Enabled = false;
            //ddl_logfiles.Enabled = false;
            //ddl_logfiles2.Enabled = false;
            tb_folderPath.Text = "";
            progressBar1.Enabled = true;
            lb_status.Text = "Idle";
            tb_arguments.Text = "";
            cb_option1.Checked = true;
            cb_option2.Checked = true;
            rtb_results.Text = "";
            //rtb_results.Enabled = false;
            ddl_logfiles.Text = "";
            ddl_logfiles.Items.Clear();
            ddl_logfiles2.Text = "";
            ddl_logfiles2.Items.Clear();
            progressBar1.Visible = false;

    
        }

        private void btn_scan_Click(object sender, EventArgs e)
        {
            btn_start.Enabled = false;
            //btn_exit.Enabled = false;
            btn_reset.Enabled = false;
            btn_folderPath.Enabled = false;
            progressBar1.Visible = true;
            rtb_results.Text = "";
            ddl_logfiles.Text = "";
            ddl_logfiles.Items.Clear();
            progressBar1.MarqueeAnimationSpeed = 100;
            Application.DoEvents();

            // initialize arguments
            string args = "";
            if (cb_option1.Checked == true && cb_option2.Checked == false)
            {
                args = "1";
            }
            else if (cb_option1.Checked == false && cb_option2.Checked == true)
            {
                args = "2";
            }
            else if (cb_option1.Checked == true && cb_option2.Checked == true)
            {
                args = "3";
            }
            tb_arguments.Text = "Arguments: " + args + " " + tb_folderPath.Text;

            if (args == "")
            {
                progressBar1.Visible = false;
                ddl_logfiles.Enabled = false;
                ddl_logfiles2.Enabled = false;
                MessageBox.Show("Please select a scan type.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                btn_start.Enabled = true;
                //btn_exit.Enabled = true;
                btn_reset.Enabled = true;
                btn_folderPath.Enabled = true;
            }

            // create process
            Process p1 = new Process();

            // initialize process information
            p1.StartInfo.FileName = "webshell-detector.exe";
            p1.StartInfo.UseShellExecute = false;
            p1.StartInfo.RedirectStandardOutput = true;
            p1.StartInfo.CreateNoWindow = true;
            p1.StartInfo.Arguments = args + " " + '"' + tb_folderPath.Text + '"';
            // Console.WriteLine("Executing: webshell-detector.exe " + args + " " + '"' + tb_folderPath.Text + '"');

            try
            {   
                // attempt to start the scan process
                // Console.WriteLine("Starting scan process...");
                p1.Start();
                
                // create stream to capture standard output
                StreamReader sr = p1.StandardOutput;
                while (!sr.EndOfStream)
                {
                    lb_status.Text = sr.ReadLine();
                    Application.DoEvents();
                    // Console.WriteLine("Scanning: " + sr.ReadLine());
                }
                // wait for process to end
                p1.WaitForExit();
                p1.Close();

                // stops progressbar animation
                progressBar1.MarqueeAnimationSpeed = 0;

                if (args == "1") {
                    // populates dropdownlist with logs

                    ddl_logfiles.Enabled = true;
                    ddl_logfiles.Items.Clear();
                    string logDir = tb_folderPath.Text + "\\logs";
                    string[] filePaths = System.IO.Directory.GetFiles(logDir, "*.txt");
                    Array.Sort(filePaths, new AlphanumComparatorFast());
                    Array.Reverse(filePaths);
                    foreach (string files in filePaths)
                    {
                        this.ddl_logfiles.Items.Add(files);
                    }

                    rtb_results.Enabled = true;
                    btn_start.Enabled = true;
                    btn_summary.Enabled = false;
                    //btn_exit.Enabled = true;
                    btn_reset.Enabled = true;
                    btn_folderPath.Enabled = true;
                    progressBar1.Visible = true;
                    progressBar1.Visible = false;
                    lb_status.Text = "Dangerous Function Scan Completed!";
                    MessageBox.Show("Scan Completed!", "Information", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    rtb_results.LoadFile(tb_folderPath.Text + "\\Summary\\Summary.txt", RichTextBoxStreamType.PlainText);
                    Application.DoEvents();
                }
                if (args == "2")
                {
                    // populates dropdownlist with logs

                    ddl_logfiles2.Enabled = true;
                    ddl_logfiles2.Items.Clear();
                    string logDir = tb_folderPath.Text + "\\signatureLogs";
                    string[] filePaths = System.IO.Directory.GetFiles(logDir, "*.txt");
                    Array.Sort(filePaths, new AlphanumComparatorFast());
                    Array.Reverse(filePaths);
                    foreach (string files in filePaths)
                    {
                        this.ddl_logfiles2.Items.Add(files);
                    }

                    rtb_results.Enabled = true;
                    btn_start.Enabled = true;
                    btn_summary.Enabled = false;
                    //btn_exit.Enabled = true;
                    btn_reset.Enabled = true;
                    btn_folderPath.Enabled = true;
                    progressBar1.Visible = true;
                    progressBar1.Visible = false;
                    lb_status.Text = "Signature Scan Completed!";
                    MessageBox.Show("Scan Completed!", "Information", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    rtb_results.LoadFile(tb_folderPath.Text + "\\Summary\\Summary.txt", RichTextBoxStreamType.PlainText);
                    Application.DoEvents();
                }
                if (args == "3")
                {
                    // populates dropdownlist with logs

                    ddl_logfiles.Enabled = true;
                    ddl_logfiles2.Enabled = true;
                    ddl_logfiles.Items.Clear();
                    ddl_logfiles2.Items.Clear();
                    string logDir = tb_folderPath.Text + "\\logs";
                    string[] filePaths = System.IO.Directory.GetFiles(logDir, "*.txt");
                    Array.Sort(filePaths, new AlphanumComparatorFast());
                    Array.Reverse(filePaths);
                    foreach (string files in filePaths)
                    {
                        this.ddl_logfiles.Items.Add(files);
                    }
                    string logDir2 = tb_folderPath.Text + "\\signatureLogs";
                    string[] filePaths2 = System.IO.Directory.GetFiles(logDir2, "*.txt");
                    Array.Sort(filePaths2, new AlphanumComparatorFast());
                    Array.Reverse(filePaths2);
                    foreach (string files in filePaths2)
                    {
                        this.ddl_logfiles2.Items.Add(files);
                    }

                    rtb_results.Enabled = true;
                    btn_start.Enabled = true;
                    btn_summary.Enabled = false;
                    //btn_exit.Enabled = true;
                    btn_reset.Enabled = true;
                    btn_folderPath.Enabled = true;
                    progressBar1.Visible = true;
                    progressBar1.Visible = false;
                    lb_status.Text = "Comprehensive Scan Completed!";
                    MessageBox.Show("Scan Completed!", "Information", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    rtb_results.LoadFile(tb_folderPath.Text + "\\Summary\\Summary.txt", RichTextBoxStreamType.PlainText);
                    Application.DoEvents();
                }

            }
            catch (Win32Exception ex)
            {
                // catch exception
                // Console.WriteLine(ex.Message);
                lb_status.Text = "Error - " + ex.Message;
                // stops progressbar animation
                progressBar1.MarqueeAnimationSpeed = 0;

            }
    
        }

        private void ddl_logfiles_SelectedIndexChanged(object sender, EventArgs e)
        {
            // to trigger and load textfiles into richtextbox
            // Console.WriteLine(ddl_logfiles.Text + " is loaded.");
            rtb_results.LoadFile(ddl_logfiles.Text,RichTextBoxStreamType.PlainText);
            btn_summary.Enabled = true;
        }

        private void btn_reset_Click(object sender, EventArgs e)
        {
            Form1_Load(this,e);
        }

        private void ll_website_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            System.Diagnostics.Process.Start("http://jremio.dyndns.org/fyp/");
        }

        private void ddl_logfiles2_SelectedIndexChanged(object sender, EventArgs e)
        {
            rtb_results.LoadFile(ddl_logfiles2.Text, RichTextBoxStreamType.PlainText);
            btn_summary.Enabled = true;
        }

        private void btn_summary_Click(object sender, EventArgs e)
        {
            rtb_results.LoadFile(tb_folderPath.Text + "\\Summary\\Summary.txt", RichTextBoxStreamType.PlainText);
            btn_summary.Enabled = false;
            Application.DoEvents();
        }
    }
}
