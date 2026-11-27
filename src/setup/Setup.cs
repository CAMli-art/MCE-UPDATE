using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Forms;
class Setup {
 static readonly string Home=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"MCE","V5");
 static readonly string[] Config={"credentials.json","sheet-id.txt","service_url.txt"};
 static readonly byte[] Magic=Encoding.ASCII.GetBytes("MCECFG1!");
 static readonly JavaScriptSerializer J=new JavaScriptSerializer{MaxJsonLength=1048576};
 static string Hash(string s){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(s))).Replace("-","").ToLowerInvariant();}
 static void Validate(Dictionary<string,string> c){
  if(c==null||c.Count!=3||Config.Any(k=>!c.ContainsKey(k)))throw new Exception("Thieu cau hinh MCE.");
  if(Hash(c["sheet-id.txt"].Trim())!="c96ecc0dc801aba538b3e9a7d0b9c6ab6fda62b598f1c437fb710055288dd6c7")throw new Exception("Ma kho khong dung.");
  if(!Regex.IsMatch(c["service_url.txt"].Trim(),@"\Ahttps://script\.google\.com/macros/s/[A-Za-z0-9_-]+/exec\z"))throw new Exception("URL dich vu khong hop le.");
  var d=J.DeserializeObject(c["credentials.json"]) as Dictionary<string,object>;
  if(d==null||!d.ContainsKey("installed"))throw new Exception("Can OAuth Desktop JSON.");
  var x=d["installed"] as Dictionary<string,object>;
  if(x==null||!x.ContainsKey("client_id")||!x.ContainsKey("client_secret")||String.IsNullOrWhiteSpace(Convert.ToString(x["client_id"]))||String.IsNullOrWhiteSpace(Convert.ToString(x["client_secret"])))throw new Exception("OAuth Desktop JSON khong day du.");
  if(d.Count!=1)throw new Exception("OAuth JSON chi duoc chua muc installed.");
 }
 static Dictionary<string,string> ReadLocal(){var c=new Dictionary<string,string>();foreach(var k in Config){var p=Path.Combine(Home,k);if(!File.Exists(p))throw new Exception("May quan tri thieu "+k);c[k]=File.ReadAllText(p,Encoding.UTF8);}Validate(c);return c;}
 static Dictionary<string,string> ReadPackage(byte[] b){if(b.Length<12||!b.Skip(b.Length-8).SequenceEqual(Magic))return null;int n=BitConverter.ToInt32(b,b.Length-12);if(n<1||n>262144||n>b.Length-12)throw new Exception("Goi cau hinh hong.");var c=J.Deserialize<Dictionary<string,string>>(Encoding.UTF8.GetString(b,b.Length-12-n,n));Validate(c);return c;}
 static byte[] Resource(string n){using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream(n)){if(s==null)throw new Exception("Thieu thanh phan "+n);using(var m=new MemoryStream()){s.CopyTo(m);return m.ToArray();}}}
 static void Write(string p,byte[] b){var tmp=p+".setup-tmp";File.WriteAllBytes(tmp,b);if(File.Exists(p))File.Replace(tmp,p,p+".setup-bak");else File.Move(tmp,p);}
 static void Export(byte[] exe){var c=ReadLocal();using(var dlg=new SaveFileDialog{FileName="MCE-Setup-NhanVien.exe",Filter="Windows Setup (*.exe)|*.exe",OverwritePrompt=true}){if(dlg.ShowDialog()!=DialogResult.OK)return;if(String.Equals(Path.GetFullPath(dlg.FileName),Path.GetFullPath(Application.ExecutablePath),StringComparison.OrdinalIgnoreCase))throw new Exception("Chon ten file khac.");var data=Encoding.UTF8.GetBytes(J.Serialize(c));if(data.Length>262144)throw new Exception("Cau hinh qua lon.");using(var f=File.Create(dlg.FileName)){f.Write(exe,0,exe.Length);f.Write(data,0,data.Length);var len=BitConverter.GetBytes(data.Length);f.Write(len,0,4);f.Write(Magic,0,Magic.Length);}MessageBox.Show("Da tao bo cai nhan vien.\nChi gui file nay noi bo. Khong co token, mat khau Gmail hay du lieu kho.","MCE Setup");}}
 static void Install(Dictionary<string,string> c,bool test){
  Validate(c);if(Process.GetProcessesByName("MCE.Client").Length>0||Process.GetProcessesByName("MCE").Length>0)throw new Exception("Dong MCE truoc khi cai.");
  Directory.CreateDirectory(Home);
  foreach(var k in Config){var p=Path.Combine(Home,k);if(File.Exists(p)&&File.ReadAllText(p,Encoding.UTF8).Trim()!=c[k].Trim())throw new Exception("Cau hinh hien co khac: "+k+". Khong ghi de.");}
  var client=Resource("MCE.Client.exe");var channel=Resource("channel.json");var launcher=Resource("MCE.exe");
  var cv=J.Deserialize<Dictionary<string,object>>(Encoding.UTF8.GetString(channel).TrimStart('\uFEFF'));
  var cp=Path.Combine(Home,"channel.json");var ep=Path.Combine(Home,"MCE.Client.exe");
  bool preserve=false;if(File.Exists(cp)&&File.Exists(ep)){var old=J.Deserialize<Dictionary<string,object>>(File.ReadAllText(cp));preserve=new Version(Convert.ToString(old["version"]))>new Version(Convert.ToString(cv["version"]));}
  foreach(var k in Config){var p=Path.Combine(Home,k);if(!File.Exists(p))Write(p,Encoding.UTF8.GetBytes(c[k]));}
  if(!preserve){Write(ep,client);Write(cp,channel);}
  Write(Path.Combine(Home,"MCE.exe"),launcher);
  if(!test){var desktop=Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);if(Directory.Exists(desktop)){var path=Path.Combine(desktop,"MCE Workspace.url");File.WriteAllText(path,"[InternetShortcut]\r\nURL="+new Uri(Path.Combine(Home,"MCE.exe")).AbsoluteUri+"\r\nIconFile="+Path.Combine(Home,"MCE.exe")+"\r\nIconIndex=0\r\n",Encoding.UTF8);}
  MessageBox.Show("Da cai dat MCE. Dang nhap bang Gmail rieng cua ban.","MCE Setup");Process.Start(new ProcessStartInfo(Path.Combine(Home,"MCE.exe")){WorkingDirectory=Home,UseShellExecute=true});}
 }
 [STAThread]static int Main(string[] args){try{if(args.Contains("--self-test")){foreach(var n in new[]{"MCE.exe","MCE.Client.exe","channel.json"})if(Resource(n).Length<20)return 2;return 0;}
 Application.EnableVisualStyles();var exe=File.ReadAllBytes(Application.ExecutablePath);var c=ReadPackage(exe);if(c!=null){if(MessageBox.Show("Cai MCE Workspace cho tai khoan Windows hien tai?","MCE Setup",MessageBoxButtons.OKCancel)==DialogResult.OK)Install(c,false);return 0;}
 if(MessageBox.Show("Chay tren may quan tri MCE da cau hinh de tao bo cai nhan vien.\nKhong sao chep token hay mat khau.\nTao bo cai ngay?","MCE Setup - Quan tri",MessageBoxButtons.OKCancel)==DialogResult.OK)Export(exe);return 0;
 }catch(Exception e){MessageBox.Show(e.Message,"MCE Setup");return 1;}}
}
