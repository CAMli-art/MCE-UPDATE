using System;
using System.IO;
using System.Net;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.Threading;
class UpdateClient:WebClient { protected override WebRequest GetWebRequest(Uri address){var r=base.GetWebRequest(address);r.Timeout=12000;var h=r as HttpWebRequest;if(h!=null)h.ReadWriteTimeout=12000;return r;} }
static class Launcher {
 const string Root="https://raw.githubusercontent.com/CAMli-art/MCE-UPDATE/";
 static readonly string Dir=AppDomain.CurrentDomain.BaseDirectory;
 static readonly JavaScriptSerializer J=new JavaScriptSerializer{MaxJsonLength=262144};
 static string P(string name){return Path.Combine(Dir,name);}
 static Dictionary<string,object> Read(string path){return (Dictionary<string,object>)J.DeserializeObject(File.ReadAllText(path,Encoding.UTF8));}
 static object Get(Dictionary<string,object>d,string k){object o;return d.TryGetValue(k,out o)?o:null;}
 static string Str(object o){return Convert.ToString(o)??"";}
 static byte[] Fetch(string url,int max){using(var wc=new UpdateClient())using(var stream=wc.OpenRead(url))using(var mem=new MemoryStream()){byte[] b=new byte[8192];int n;while((n=stream.Read(b,0,b.Length))>0){if(mem.Length+n>max)throw new Exception("Gói cập nhật quá lớn.");mem.Write(b,0,n);}return mem.ToArray();}}
 static string Hash(byte[] b){using(var s=SHA256.Create())return BitConverter.ToString(s.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
 static void Save(string path,byte[] bytes){string temp=path+".download";File.WriteAllBytes(temp,bytes);if(File.Exists(path))File.Replace(temp,path,path+".bak");else File.Move(temp,path);}
 static Version Ver(string s){Version v;if(!Regex.IsMatch(s,@"\A\d+\.\d+\.\d+\z")||!Version.TryParse(s,out v)||v.Major!=5)throw new Exception("Phiên bản không thuộc kênh V5.");return v;}
 static void Log(string s){try{File.AppendAllText(P("update.log"),DateTime.Now.ToString("s")+" | "+s+Environment.NewLine,Encoding.UTF8);}catch{}}
 static void Update(){
   var manifest=(Dictionary<string,object>)J.DeserializeObject(Encoding.UTF8.GetString(Fetch(Root+"main/latest-v5.json",65536)));
   var version=Ver(Str(Get(manifest,"version")));string commit=Str(Get(manifest,"commit"));if(!Regex.IsMatch(commit,@"\A[0-9a-f]{40}\z"))throw new Exception("Commit không hợp lệ.");
   Version local=new Version(5,1,0);try{local=Ver(Str(Get(Read(P("channel.json")),"version")));}catch{}
   if(version<=local){Log("Đã ở phiên bản "+local);return;}
   var files=Get(manifest,"files") as Dictionary<string,object>;if(files==null||!files.ContainsKey("channel.json")||!files.ContainsKey("MCE.Client.exe")||files.Keys.Any(k=>k!="channel.json"&&k!="MCE.Client.exe"))throw new Exception("Danh sách file không hợp lệ.");
   var payload=new Dictionary<string,byte[]>();foreach(var item in files){string h=Str(item.Value);if(!Regex.IsMatch(h,@"\A[0-9a-f]{64}\z"))throw new Exception("SHA256 không hợp lệ.");byte[] bytes=Fetch(Root+commit+"/v5/"+item.Key,item.Key=="channel.json"?32768:80*1024*1024);if(Hash(bytes)!=h)throw new Exception("Sai SHA256: "+item.Key);payload[item.Key]=bytes;}
   var config=(Dictionary<string,object>)J.DeserializeObject(Encoding.UTF8.GetString(payload["channel.json"]));if(Ver(Str(Get(config,"version")))!=version)throw new Exception("Phiên bản cấu hình không khớp.");
   bool binary=payload.ContainsKey("MCE.Client.exe");if(binary){var bytes=payload["MCE.Client.exe"];if(bytes.Length<1024||bytes[0]!=77||bytes[1]!=90)throw new Exception("Không phải file EXE.");string probe=P("MCE.Client.candidate.exe");File.WriteAllBytes(probe,bytes);try{using(var child=Process.Start(new ProcessStartInfo(probe,"--self-test"){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Dir})){if(!child.WaitForExit(12000)){child.Kill();throw new Exception("Bản mới không qua kiểm tra khởi động.");}if(child.ExitCode!=0)throw new Exception("Bản mới không qua kiểm tra khởi động.");}}finally{File.Delete(probe);}}
   byte[] previous=File.ReadAllBytes(P("MCE.Client.exe"));bool installed=false;try{if(binary){Save(P("MCE.Client.exe"),payload["MCE.Client.exe"]);installed=true;}Save(P("channel.json"),payload["channel.json"]);}catch{if(installed)Save(P("MCE.Client.exe"),previous);throw;}Log("Đã cập nhật "+version+(binary?" (EXE)":" (cấu hình)"));
 }
 [STAThread]static void Main(string[] args){ServicePointManager.SecurityProtocol=(SecurityProtocolType)3072;Application.EnableVisualStyles();try{if(args.Length==2&&args[0]=="--wait"){int pid;if(Int32.TryParse(args[1],out pid)){try{using(var p=Process.GetProcessById(pid)){if(!p.WaitForExit(20000))return;}}catch(ArgumentException){}}}using(var mutex=new Mutex(false,"Local\\MCE_V5_Launcher")){if(!mutex.WaitOne(0))return;try{if(Process.GetProcessesByName("MCE.Client").Length>0){MessageBox.Show("MCE đang chạy. Đóng ứng dụng trước khi cập nhật.");return;}if(args.Contains("--rollback")){string b=P("MCE.Client.exe.bak");if(!File.Exists(b))throw new Exception("Chưa có EXE sao lưu.");File.Copy(b,P("MCE.Client.exe"),true);if(File.Exists(P("channel.json.bak")))File.Copy(P("channel.json.bak"),P("channel.json"),true);Log("Khôi phục thủ công; lần mở tiếp theo có thể tải lại bản mới.");}else{try{Update();}catch(Exception ex){Log("Giữ bản cũ: "+ex.Message);}}if(!File.Exists(P("MCE.Client.exe")))throw new Exception("Thiếu MCE.Client.exe, chạy bộ tạo EXE một lần.");Process.Start(new ProcessStartInfo(P("MCE.Client.exe")){WorkingDirectory=Dir,UseShellExecute=true});}finally{mutex.ReleaseMutex();}}}catch(Exception e){MessageBox.Show(e.Message,"MCE Update");}}
}