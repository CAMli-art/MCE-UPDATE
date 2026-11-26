using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Drawing;
using System.Text.RegularExpressions;
class TimedClient:WebClient { protected override WebRequest GetWebRequest(Uri address){var r=base.GetWebRequest(address);r.Timeout=40000;var h=r as HttpWebRequest;if(h!=null)h.ReadWriteTimeout=40000;return r;} }
class Backend {
 string path=Path.Combine(App.Home,"service_url.txt");
 public string Url {get{try{return File.Exists(path)?App.Read(path).Trim():"";}catch{return "";}}}
 public bool Configured {get{return Valid(Url);}}
 static bool Valid(string x){return Regex.IsMatch(x??"",@"\Ahttps://script\.google\.com/macros/s/[A-Za-z0-9_-]+/exec\z");}
 public void Set(string url){url=(url??"").Trim();if(url!=""&&!Valid(url))throw new Exception("Chỉ chấp nhận URL HTTPS Web App của Google Apps Script dạng /exec.");App.Save(path,url);}
 public async Task<object> Call(string token,string action,Dictionary<string,object> data){string u=Url;if(!Valid(u))throw new Exception("Chưa cấu hình dịch vụ.");var req=new Dictionary<string,object>{{"token",token},{"action",action},{"data",data??new Dictionary<string,object>()},{"id",Guid.NewGuid().ToString()}};return await Task.Run(()=>{using(var wc=new TimedClient()){wc.Encoding=Encoding.UTF8;wc.Headers[HttpRequestHeader.ContentType]="application/json; charset=utf-8";string raw=wc.UploadString(u,"POST",App.Json.Serialize(req));var obj=App.Obj(App.Json.DeserializeObject(raw));if(!Object.Equals(App.Get(obj,"ok"),true))throw new Exception(App.Str(App.Get(obj,"error")));return App.Get(obj,"data");}});}
 public static int SyncInterval(){try{string p=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"channel.json");var o=App.Obj(App.Json.DeserializeObject(App.Read(p)));int seconds=Convert.ToInt32(App.Get(o,"sync_seconds"));return Math.Max(30,Math.Min(600,seconds))*1000;}catch{return 60000;}}
}
static class Fields {
 public static string[] Ask(string title,string[] labels,string[] values,Dictionary<int,string[]> options){using(var f=new Form{Text=title,ClientSize=new Size(560,Math.Min(620,labels.Length*66+85)),Font=new Font("Segoe UI",11),StartPosition=FormStartPosition.CenterParent,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,BackColor=Color.White}){var controls=new List<Control>();for(int i=0;i<labels.Length;i++){int y=10+i*66;f.Controls.Add(new Label{Text=labels[i],Left=20,Top=y,Width=520,Height=24});string[] choices;Control c;if(options!=null&&options.TryGetValue(i,out choices)){var cb=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList};cb.Items.AddRange(choices);cb.SelectedIndex=Math.Max(0,Array.IndexOf(choices,values[i]));c=cb;}else c=new TextBox{Text=values[i]};c.SetBounds(20,y+25,520,32);controls.Add(c);f.Controls.Add(c);}var ok=new Button{Text="Xác nhận",DialogResult=DialogResult.OK,Left=325,Top=labels.Length*66+16,Width=105,Height=38,BackColor=Color.FromArgb(22,117,209),ForeColor=Color.White,FlatStyle=FlatStyle.Flat};var cancel=new Button{Text="Hủy",DialogResult=DialogResult.Cancel,Left=435,Top=ok.Top,Width=105,Height=38};f.Controls.AddRange(new Control[]{ok,cancel});f.AcceptButton=ok;f.CancelButton=cancel;if(f.ShowDialog()!=DialogResult.OK)return null;return controls.Select(c=>c.Text.Trim()).ToArray();}}
}
