using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.Drawing;
using System.Diagnostics;
using System.Globalization;

static class App {
 public static readonly string Home=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"MCE", "V5");
 public static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=Int32.MaxValue,RecursionLimit=100};
 public static Dictionary<string,object> Obj(object x){return x as Dictionary<string,object> ?? new Dictionary<string,object>();}
 public static object Get(Dictionary<string,object> d,string k){object v;return d.TryGetValue(k,out v)?v:null;}
 public static string Str(object x){return Convert.ToString(x,CultureInfo.InvariantCulture)??"";}
 public static object[] Arr(object o){return o as object[] ?? new object[0];}
 public static string At(object[] a,int i){return i<a.Length?Str(a[i]):"";}
 public static string Read(string p){return File.ReadAllText(p,Encoding.UTF8);}
 public static void Save(string p,string t){string tmp=p+".tmp";File.WriteAllText(tmp,t,Encoding.UTF8);if(File.Exists(p))File.Replace(tmp,p,null);else File.Move(tmp,p);}
 [STAThread] static void Main(string[] args){if(args.Contains("--self-test")){if(!MaterialPicker.SelfTest())Environment.Exit(2);return;}Directory.CreateDirectory(Home);ServicePointManager.SecurityProtocol=(SecurityProtocolType)3072;Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);using(var login=new Login()){if(login.ShowDialog()!=DialogResult.OK)return;Application.Run(new MainForm(login.User));}}
}
class Login:Form {
 public string User; TextBox u=new TextBox(),p=new TextBox();
 public Login(){Text="MCE Workspace V5.5.1 | Đăng nhập";StartPosition=FormStartPosition.CenterScreen;ClientSize=new Size(440,375);FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=false;Font=new Font("Segoe UI",10);BackColor=Color.White;Controls.Add(new Label{Text="MCE  |  QUẢN LÝ KHO",ForeColor=Color.White,BackColor=Color.FromArgb(23,46,73),Dock=DockStyle.Top,Height=76,TextAlign=ContentAlignment.MiddleCenter,Font=new Font("Segoe UI",17,FontStyle.Bold)});var online=new Button{Text="Đăng nhập Google - dữ liệu thật",Left=35,Top=96,Width=370,Height=44,BackColor=Color.FromArgb(22,117,209),ForeColor=Color.White,FlatStyle=FlatStyle.Flat};online.Click+=(s,e)=>{User="Google";DialogResult=DialogResult.OK;};Controls.Add(online);Controls.Add(new Label{Text="Chế độ DEMO (không truy cập kho thật)",Left=35,Top=155,Width=370,Height=28});u.SetBounds(35,184,370,30);u.Text="xem";p.SetBounds(35,224,370,30);p.UseSystemPasswordChar=true;var demo=new Button{Text="Vào bản thử nghiệm",Left=35,Top=268,Width=370,Height=40};demo.Click+=(s,e)=>{string name=u.Text.Trim().ToLowerInvariant();if(new[]{"admin","kho","kythuat","xem"}.Contains(name)&&p.Text=="123123"){User=name;DialogResult=DialogResult.OK;}else MessageBox.Show("Sai tài khoản hoặc mật khẩu thử nghiệm.");};Controls.AddRange(new Control[]{u,p,demo,new Label{Text="Quyền ghi thật do Google và quản trị viên cấp.",Left=35,Top=324,Width=370,Height=30}});AcceptButton=online;}
}
class Google {
 const string Scope="https://www.googleapis.com/auth/spreadsheets.readonly openid email";
 string token,refresh;DateTime expiry; Dictionary<string,object> cred;
 string TokenPath {get{return Path.Combine(App.Home,"token-v51.bin");}}
 static string Q(string x){return Uri.EscapeDataString(x??"");}
 static string B64(byte[] x){return Convert.ToBase64String(x).TrimEnd('=').Replace('+','-').Replace('/','_');}
 static byte[] RandomBytes(int n){var b=new byte[n];using(var r=RandomNumberGenerator.Create())r.GetBytes(b);return b;}
 Dictionary<string,object> Post(string body){using(var wc=new TimedClient()){wc.Encoding=Encoding.UTF8;wc.Headers[HttpRequestHeader.ContentType]="application/x-www-form-urlencoded";return App.Obj(App.Json.DeserializeObject(wc.UploadString("https://oauth2.googleapis.com/token",body)));}}
 string C(string key){return App.Str(App.Get(cred,key));}
 void Receive(Dictionary<string,object> d){token=App.Str(App.Get(d,"access_token"));if(token=="")throw new Exception("Google không trả access token.");string r=App.Str(App.Get(d,"refresh_token"));if(r!="")refresh=r;expiry=DateTime.UtcNow.AddSeconds(Convert.ToDouble(App.Get(d,"expires_in")??3600)-90);var bytes=Encoding.UTF8.GetBytes(App.Json.Serialize(new Dictionary<string,object>{{"refresh",refresh}}));File.WriteAllBytes(TokenPath,ProtectedData.Protect(bytes,null,DataProtectionScope.CurrentUser));}
 public async Task Authorize(bool interactive){if(token!=null&&DateTime.UtcNow<expiry)return;var path=Path.Combine(App.Home,"credentials.json");if(!File.Exists(path))throw new Exception("Chưa có credentials.json. Chọn Cấu hình Google để nhập file OAuth Desktop.");cred=App.Obj(App.Get(App.Obj(App.Json.DeserializeObject(App.Read(path))),"installed"));if(C("client_id")=="")throw new Exception("File credentials phải là OAuth Desktop app.");if(refresh==null&&File.Exists(TokenPath)){try{refresh=App.Str(App.Get(App.Obj(App.Json.DeserializeObject(Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(TokenPath),null,DataProtectionScope.CurrentUser)))),"refresh"));}catch{refresh=null;}}
 string common="client_id="+Q(C("client_id"))+"&client_secret="+Q(C("client_secret"));if(!String.IsNullOrEmpty(refresh)){try{Receive(await Task.Run(()=>Post(common+"&grant_type=refresh_token&refresh_token="+Q(refresh))));return;}catch(WebException){if(!interactive)throw;}}
 if(!interactive)throw new Exception("Cần đăng nhập Google lần đầu qua nút Đồng bộ.");
 string verifier=B64(RandomBytes(48)),state=B64(RandomBytes(32)),challenge;using(var sha=SHA256.Create())challenge=B64(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier)));
 var probe=new System.Net.Sockets.TcpListener(IPAddress.Loopback,0);probe.Start();int port=((IPEndPoint)probe.LocalEndpoint).Port;probe.Stop();string redirect="http://127.0.0.1:"+port+"/";
 using(var listener=new HttpListener()){listener.Prefixes.Add(redirect);listener.Start();string url="https://accounts.google.com/o/oauth2/v2/auth?client_id="+Q(C("client_id"))+"&redirect_uri="+Q(redirect)+"&response_type=code&scope="+Q(Scope)+"&access_type=offline&prompt=consent%20select_account&state="+Q(state)+"&code_challenge="+Q(challenge)+"&code_challenge_method=S256";Process.Start(url);var incoming=listener.GetContextAsync();if(await Task.WhenAny(incoming,Task.Delay(180000))!=incoming)throw new Exception("Hết thời gian đăng nhập Google.");var ctx=await incoming;string code=ctx.Request.QueryString["code"];bool valid=ctx.Request.QueryString["state"]==state&&!String.IsNullOrEmpty(code);byte[] msg=Encoding.UTF8.GetBytes(valid?"MCE: Đã nhận phản hồi Google. Quay lại ứng dụng.":"MCE: Xác thực thất bại.");ctx.Response.ContentType="text/plain; charset=utf-8";ctx.Response.OutputStream.Write(msg,0,msg.Length);ctx.Response.Close();if(!valid)throw new Exception("Google từ chối hoặc phản hồi OAuth không hợp lệ.");Receive(await Task.Run(()=>Post(common+"&grant_type=authorization_code&code="+Q(code)+"&redirect_uri="+Q(redirect)+"&code_verifier="+Q(verifier))));}}
 public async Task<object[][][]> Pull(string id,bool interactive){await Authorize(interactive);string[] ranges={"'DANH MỤC VẬT TƯ'!A7:J","'TỔNG TỒN KHO'!A7:L","'NHẬP XUẤT HÀNG NGÀY'!A8:N"};string url="https://sheets.googleapis.com/v4/spreadsheets/"+Q(id)+"/values:batchGet?valueRenderOption=FORMATTED_VALUE&"+String.Join("&",ranges.Select(x=>"ranges="+Q(x)));return await Task.Run(()=>{using(var wc=new TimedClient()){wc.Encoding=Encoding.UTF8;wc.Headers[HttpRequestHeader.Authorization]="Bearer "+token;var raw=App.Obj(App.Json.DeserializeObject(wc.DownloadString(url)));var a=App.Arr(App.Get(raw,"valueRanges"));if(a.Length!=3)throw new Exception("Google trả thiếu bảng dữ liệu.");return a.Select(x=>App.Arr(App.Get(App.Obj(x),"values")).Select(App.Arr).ToArray()).ToArray();}});}
 public async Task<string> Access(bool interactive){await Authorize(interactive);return token;}
 public void Reset(){token=null;refresh=null;if(File.Exists(TokenPath))File.Delete(TokenPath);}
}
class MainForm:Form {
 readonly Label[] modernValues=new Label[4];
 readonly Dictionary<Button,string> modernButtons=new Dictionary<Button,string>();

 TreeView workspaceTree=new TreeView();
 Panel workspaceRight;
 TextBox workspaceDetail;
 bool workspaceChanging;
 readonly Label[] workspaceKpi=new Label[4];
 readonly Dictionary<Button,string> workspaceFilters=new Dictionary<Button,string>();
 string workspaceFilter="all";
 Label workspaceAccount;
 bool WorkspaceMatch(string[] r){
 if(workspaceFilter=="all")return true;
 if(r.Length<12)return false;
 if(workspaceFilter=="review")return new[]{"ÂM KHO","TRÙNG MÃ","CẦN ĐỐI SOÁT"}.Contains(r[11]);
 if(workspaceFilter=="low")return new[]{"CẦN NHẬP","HẾT HÀNG"}.Contains(r[11]);
 return r[11]=="ĐỦ HÀNG"&&r[10]!="";
 }
 void WorkspaceDashboard(){
 if(workspaceKpi[0]==null)return;
 workspaceKpi[0].Text=stock.Count.ToString("N0");
 workspaceKpi[1].Text=stock.Count(r=>r.Length>=12&&!new[]{"ÂM KHO","TRÙNG MÃ","CẦN ĐỐI SOÁT"}.Contains(r[11])&&r[10]!=""&&r[11]=="ĐỦ HÀNG").ToString("N0");
 workspaceKpi[2].Text=stock.Count(r=>r.Length>=12&&new[]{"CẦN NHẬP","HẾT HÀNG"}.Contains(r[11])).ToString("N0");
 workspaceKpi[3].Text=stock.Count(r=>r.Length>=12&&new[]{"ÂM KHO","TRÙNG MÃ","CẦN ĐỐI SOÁT"}.Contains(r[11])).ToString("N0");
 foreach(var entry in workspaceFilters){entry.Key.Enabled=!history;entry.Key.BackColor=entry.Value==workspaceFilter&&!history?Color.FromArgb(213,230,252):Color.White;}
 if(workspaceAccount!=null)workspaceAccount.Text=(liveAlias==""?"Chỉ đọc":liveAlias+" / "+liveRole)+"    |    V5.5.0";
 }

 class SoftCard:Panel {
 public SoftCard(){BackColor=Color.White;Padding=new Padding(9);DoubleBuffered=true;}
 protected override void OnPaint(PaintEventArgs e){base.OnPaint(e);if(Width<3||Height<3)return;e.Graphics.SmoothingMode=System.Drawing.Drawing2D.SmoothingMode.AntiAlias;using(var p=new Pen(Color.FromArgb(222,226,232))){int w=Width-1,h=Height-1,r=8;using(var path=new System.Drawing.Drawing2D.GraphicsPath()){path.AddArc(0,0,r,r,180,90);path.AddArc(w-r,0,r,r,270,90);path.AddArc(w-r,h-r,r,r,0,90);path.AddArc(0,h-r,r,r,90,90);path.CloseFigure();e.Graphics.DrawPath(p,path);}}}
 }
 Button CleanButton(string text,Action action){var b=Btn(text,action);b.FlatStyle=FlatStyle.Flat;b.FlatAppearance.BorderSize=0;b.FlatAppearance.MouseOverBackColor=Color.FromArgb(229,239,252);b.BackColor=Color.White;b.Font=new Font("Segoe UI",10);b.Cursor=Cursors.Hand;return b;}
 void ModernLayout(){
 Text="MCE WORKSPACE | V5.5.1";BackColor=Color.White;
 var side=Controls.OfType<FlowLayoutPanel>().First();
 var content=Controls.OfType<TableLayoutPanel>().First();
 var buttons=side.Controls.OfType<Button>().ToArray();
 side.Controls.Clear();side.Width=230;side.Padding=new Padding(10,8,10,8);side.BackColor=Color.FromArgb(249,249,250);
 string[][] sections={new[]{"QUẢN LÝ KHO","Danh mục và tồn kho","Nhập kho","Xuất kho","Thêm vật tư"},new[]{"GIAO DỊCH","Lịch sử nhập xuất","Sửa giao dịch","Xuất CSV"},new[]{"QUẢN TRỊ","Quản lý tài khoản","Đồng bộ Google","Cấu hình Google","Cấu hình dịch vụ","Cập nhật phiên bản","Đăng xuất"}};
 string[] icons={"▣","↓","↑","+","◷","✎","⇩","♙","↻","⚙","⚙","↻","↪"};int ix=0;
 foreach(var section in sections){side.Controls.Add(new Label{Text=section[0],Width=204,Height=25,Margin=new Padding(3,8,0,0),ForeColor=navy,Font=new Font("Segoe UI",10,FontStyle.Bold)});foreach(var name in section.Skip(1)){var button=buttons.FirstOrDefault(x=>x.Text==name);if(button==null)continue;modernButtons[button]=name;button.Text=icons[ix++%icons.Length]+"   "+(name=="Danh mục và tồn kho"?"Tra cứu vật tư":name);button.Width=204;button.Height=33;button.AutoSize=false;button.Margin=new Padding(0,0,0,2);button.TextAlign=ContentAlignment.MiddleLeft;button.ForeColor=navy;button.FlatStyle=FlatStyle.Flat;button.FlatAppearance.BorderSize=0;button.FlatAppearance.MouseOverBackColor=Color.FromArgb(229,239,252);button.Padding=new Padding(5,0,0,0);button.Font=new Font("Segoe UI",10);button.Cursor=Cursors.Hand;side.Controls.Add(button);}side.Controls.Add(new Panel{Width=204,Height=1,Margin=new Padding(0,8,0,3),BackColor=Color.FromArgb(225,228,232)});}
 content.Controls.Clear();content.RowStyles.Clear();content.ColumnStyles.Clear();content.ColumnCount=1;content.RowCount=8;content.Padding=new Padding(12,8,12,4);content.BackColor=Color.White;
 foreach(int height in new[]{36,124,42,34})content.RowStyles.Add(new RowStyle(SizeType.Absolute,height));content.RowStyles.Add(new RowStyle(SizeType.Percent,100));content.RowStyles.Add(new RowStyle(SizeType.Absolute,148));content.RowStyles.Add(new RowStyle(SizeType.Absolute,76));content.RowStyles.Add(new RowStyle(SizeType.Absolute,24));
 var top=new Panel{Dock=DockStyle.Fill,BackColor=Color.FromArgb(23,46,73),Margin=new Padding(0)};
 var brand=new Label{Text="▦   MCE WORKSPACE",Dock=DockStyle.Left,Width=300,ForeColor=Color.White,Font=new Font("Segoe UI",13,FontStyle.Bold),TextAlign=ContentAlignment.MiddleLeft,Padding=new Padding(12,0,0,0)};
 workspaceAccount=new Label{Dock=DockStyle.Right,Width=300,ForeColor=Color.White,TextAlign=ContentAlignment.MiddleRight,Padding=new Padding(0,0,12,0),Font=new Font("Segoe UI",9)};
 top.Controls.Add(brand);top.Controls.Add(workspaceAccount);
 var body=new Panel{Dock=DockStyle.Fill,Margin=new Padding(0),BackColor=Color.White};Controls.Remove(content);Controls.Remove(side);body.Controls.Add(content);body.Controls.Add(side);
 var shell=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=2,Margin=new Padding(0),Padding=new Padding(0)};shell.RowStyles.Add(new RowStyle(SizeType.Absolute,44));shell.RowStyles.Add(new RowStyle(SizeType.Percent,100));shell.Controls.Add(top,0,0);shell.Controls.Add(body,0,1);Controls.Add(shell);
 title.Text="Tra cứu vật tư";title.Font=new Font("Segoe UI",14,FontStyle.Bold);title.Dock=DockStyle.Fill;title.TextAlign=ContentAlignment.MiddleLeft;content.Controls.Add(title,0,0);
 var cards=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=2,Margin=new Padding(0,0,0,3)};cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));cards.RowStyles.Add(new RowStyle(SizeType.Percent,50));cards.RowStyles.Add(new RowStyle(SizeType.Percent,50));
 string[] names={"Mã vật tư","Đủ hàng","Cần nhập / hết hàng","Cần đối soát"};Color[] colors={Color.FromArgb(30,105,220),Color.FromArgb(20,145,95),Color.FromArgb(180,112,20),Color.FromArgb(150,65,160)};
 for(int i=0;i<4;i++){var p=new SoftCard{Dock=DockStyle.Fill,Margin=new Padding(0,0,5,5),Padding=new Padding(9,3,6,3)};var v=new Label{Dock=DockStyle.Fill,TextAlign=ContentAlignment.BottomLeft,Font=new Font("Segoe UI",16,FontStyle.Bold),ForeColor=colors[i]};var l=new Label{Text=names[i],Dock=DockStyle.Bottom,Height=20,ForeColor=Color.DimGray,Font=new Font("Segoe UI",9)};workspaceKpi[i]=v;p.Controls.Add(v);p.Controls.Add(l);cards.Controls.Add(p,i%2,i/2);}content.Controls.Add(cards,0,1);
 var tools=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=4,RowCount=1,Margin=new Padding(0,3,0,3)};tools.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));tools.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,165));tools.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,38));tools.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,64));search.Dock=DockStyle.Fill;search.Margin=new Padding(0,4,5,0);search.Font=new Font("Segoe UI",10);group.Dock=DockStyle.Fill;group.Margin=new Padding(0,4,4,0);tools.Controls.Add(search,0,0);tools.Controls.Add(group,1,0);var refresh=CleanButton("↻",()=>Sync(true));refresh.Dock=DockStyle.Fill;tools.Controls.Add(refresh,2,0);var clear=CleanButton("Xóa lọc",()=>{workspaceFilter="all";search.Clear();if(group.Items.Count>0)group.SelectedIndex=0;Render();});clear.Dock=DockStyle.Fill;tools.Controls.Add(clear,3,0);content.Controls.Add(tools,0,2);
 var filters=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false,Margin=new Padding(0)};string[] keys={"all","ok","low","review"};string[] labels={"Tất cả","Đủ hàng","Cần nhập","Cần đối soát"};for(int i=0;i<keys.Length;i++){string key=keys[i];var bt=CleanButton(labels[i],()=>{if(history)return;workspaceFilter=key;Render();});bt.Height=27;bt.Margin=new Padding(0,0,4,0);workspaceFilters[bt]=key;filters.Controls.Add(bt);}content.Controls.Add(filters,0,3);
 grid.Dock=DockStyle.Fill;grid.Margin=new Padding(0);grid.Font=new Font("Segoe UI",10);grid.RowTemplate.Height=39;grid.ColumnHeadersHeight=29;grid.ColumnHeadersDefaultCellStyle.BackColor=Color.White;grid.ColumnHeadersDefaultCellStyle.ForeColor=navy;grid.ColumnHeadersBorderStyle=DataGridViewHeaderBorderStyle.None;grid.CellBorderStyle=DataGridViewCellBorderStyle.SingleHorizontal;grid.GridColor=Color.FromArgb(234,236,240);grid.DefaultCellStyle.BackColor=Color.White;grid.AlternatingRowsDefaultCellStyle.BackColor=Color.White;grid.DefaultCellStyle.SelectionBackColor=Color.FromArgb(225,237,253);grid.DefaultCellStyle.SelectionForeColor=navy;grid.DefaultCellStyle.WrapMode=DataGridViewTriState.True;content.Controls.Add(grid,0,4);
 workspaceRight=new SoftCard{Dock=DockStyle.Fill,Margin=new Padding(0,5,0,3)};workspaceDetail=new TextBox{Dock=DockStyle.Fill,Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,BorderStyle=BorderStyle.None,BackColor=Color.White,Font=new Font("Segoe UI",9)};
 var detailBody=new Panel{Dock=DockStyle.Fill};detailBody.Controls.Add(workspaceDetail);
 var photoSide=new Panel{Dock=DockStyle.Left,Width=108,Padding=new Padding(0,0,7,0)};
 materialPhoto=new PictureBox{Dock=DockStyle.Fill,SizeMode=PictureBoxSizeMode.Zoom,BackColor=Color.FromArgb(249,250,252)};photoLabel=new Label{Dock=DockStyle.Bottom,Height=16,TextAlign=ContentAlignment.MiddleCenter,Font=new Font("Segoe UI",8),Text="Chưa có ảnh"};photoChoose=CleanButton("Chọn / đổi ảnh",()=>ChooseMaterialPhoto());photoChoose.Dock=DockStyle.Bottom;photoChoose.AutoSize=false;photoChoose.Height=24;photoChoose.Font=new Font("Segoe UI",8);photoSide.Controls.Add(materialPhoto);photoSide.Controls.Add(photoLabel);photoSide.Controls.Add(photoChoose);detailBody.Controls.Add(photoSide);workspaceRight.Controls.Add(detailBody);
 var heading=new Label{Text="▧   Chi tiết / Hình ảnh vật tư",Dock=DockStyle.Top,Height=25,Font=new Font("Segoe UI",10,FontStyle.Bold),ForeColor=navy};workspaceRight.Controls.Add(heading);content.Controls.Add(workspaceRight,0,5);
 var ai=new SoftCard{Dock=DockStyle.Fill,Margin=new Padding(0,3,0,3),Padding=new Padding(9,3,9,3)};var aiTitle=new Label{Text="✧   Trợ lý AI MCE",Dock=DockStyle.Top,Height=24,Font=new Font("Segoe UI",10,FontStyle.Bold),ForeColor=navy};var aiButtons=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false};var aiOpen=CleanButton("Mở ChatGPT Plus",()=>WorkspaceChat(false));var aiCopy=CleanButton("Sao chép dòng + mở ChatGPT",()=>WorkspaceChat(true));aiButtons.Controls.Add(aiOpen);aiButtons.Controls.Add(aiCopy);ai.Controls.Add(aiButtons);ai.Controls.Add(aiTitle);content.Controls.Add(ai,0,6);
 status.Font=new Font("Segoe UI",8);status.Dock=DockStyle.Fill;status.ForeColor=Color.DimGray;content.Controls.Add(status,0,7);
 grid.CellFormatting+=(sender,e)=>{if(!history&&e.RowIndex>=0&&e.ColumnIndex==1&&grid.Columns.Count==sc.Length){var row=grid.Rows[e.RowIndex];e.Value=Convert.ToString(row.Cells[0].Value)+Environment.NewLine+Convert.ToString(row.Cells[1].Value);e.FormattingApplied=true;}if(!history&&e.ColumnIndex==11&&e.RowIndex>=0){string v=Convert.ToString(e.Value);e.CellStyle.ForeColor=v=="ĐỦ HÀNG"?Color.FromArgb(20,145,95):new[]{"CẦN NHẬP","HẾT HÀNG"}.Contains(v)?Color.FromArgb(180,112,20):Color.FromArgb(150,65,160);}};grid.SelectionChanged+=(sender,e)=>WorkspaceDetails();grid.Sorted+=(sender,e)=>WorkspaceDetails();ModernRefresh();Render();
 }
 void CompactColumns(){
 if(history){foreach(DataGridViewColumn c in grid.Columns)c.Visible=true;grid.AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.DisplayedCells;return;}
 if(grid.Columns.Count!=sc.Length)return;
 grid.AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.None;
 foreach(DataGridViewColumn c in grid.Columns)c.Visible=false;
 foreach(int i in new[]{1,10,11})grid.Columns[i].Visible=true;
 grid.Columns[1].HeaderText="Vật tư";grid.Columns[10].HeaderText="Tồn";grid.Columns[11].HeaderText="Trạng thái";
 grid.Columns[1].AutoSizeMode=DataGridViewAutoSizeColumnMode.Fill;grid.Columns[1].FillWeight=65;grid.Columns[10].AutoSizeMode=DataGridViewAutoSizeColumnMode.Fill;grid.Columns[10].FillWeight=12;grid.Columns[11].AutoSizeMode=DataGridViewAutoSizeColumnMode.Fill;grid.Columns[11].FillWeight=23;
 }
 void WorkspaceChat(bool copy){
 try{
 if(copy){
 var r=Selected();var labels=history?tc:sc;
 if(r==null||r.Length<labels.Length){MessageBox.Show("Chọn một dòng vật tư hoặc giao dịch trước.");return;}
 if(MessageBox.Show("Sao chép thông tin dòng đang chọn vào clipboard? Chỉ dán sang ChatGPT nếu bạn được phép chia sẻ dữ liệu này.","MCE | ChatGPT Plus",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;
 Clipboard.SetText("Hãy phân tích dữ liệu MCE sau và không suy diễn thông tin chưa có:\r\n"+String.Join(Environment.NewLine,labels.Select((x,i)=>x+": "+r[i])));
 }
 Process.Start(new ProcessStartInfo("https://chatgpt.com/"){UseShellExecute=true});
 if(copy)MessageBox.Show("Đã sao chép. Nhấn Ctrl+V trong ChatGPT để gửi nội dung theo ý bạn.","MCE | ChatGPT Plus");
 }catch(Exception ex){MessageBox.Show(ex.Message,"MCE | ChatGPT Plus");}
 }
 PictureBox materialPhoto;
 Label photoLabel;
 Button photoChoose;
 string photoKey="";
 string PhotoPath(string code){
 using(var hash=SHA256.Create()){return Path.Combine(App.Home,"material-images",BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(code.Trim().ToUpperInvariant()))).Replace("-","")+".jpg");}
 }
 void RefreshMaterialPhoto(string code){
 if(materialPhoto==null)return;
 photoChoose.Enabled=!IsDemo&&(liveRole=="admin"||liveRole=="kho")&&code!="";
 if(photoKey==code)return;
 photoKey=code;
 var old=materialPhoto.Image;materialPhoto.Image=null;if(old!=null)old.Dispose();
 photoLabel.Text=code==""?"Chọn vật tư":"Chưa có ảnh";
 if(code=="")return;
 try{string path=PhotoPath(code);if(File.Exists(path)){using(var stream=File.OpenRead(path))using(var image=Image.FromStream(stream)){materialPhoto.Image=new Bitmap(image);}photoLabel.Text=code;}}catch{photoLabel.Text="Không đọc được ảnh";}
 }
 void ChooseMaterialPhoto(){
 if(IsDemo||(liveRole!="admin"&&liveRole!="kho")||photoKey=="")return;
 string code=photoKey;
 using(var dlg=new OpenFileDialog{Filter="Ảnh JPG, PNG, BMP|*.jpg;*.jpeg;*.png;*.bmp"}){
 if(dlg.ShowDialog(this)!=DialogResult.OK)return;
 try{
 if(new FileInfo(dlg.FileName).Length>20*1024*1024)throw new Exception("Ảnh tối đa 20 MB.");
 string path=PhotoPath(code);Directory.CreateDirectory(Path.GetDirectoryName(path));
 using(var image=Image.FromFile(dlg.FileName)){
 double scale=Math.Min(1.0,1000.0/Math.Max(image.Width,image.Height));
 using(var bitmap=new Bitmap(Math.Max(1,(int)(image.Width*scale)),Math.Max(1,(int)(image.Height*scale)))){
 using(var g=Graphics.FromImage(bitmap)){g.Clear(Color.White);g.DrawImage(image,0,0,bitmap.Width,bitmap.Height);}
 string temp=path+".tmp";bitmap.Save(temp,System.Drawing.Imaging.ImageFormat.Jpeg);if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);
 }}
 photoKey="";RefreshMaterialPhoto(code);
 }catch(Exception ex){MessageBox.Show(ex.Message,"Ảnh vật tư");}
 }}
 void WorkspaceDetails(){
 if(workspaceDetail==null)return;
 var r=Selected();if(r==null||r.Length<(history?13:12)){RefreshMaterialPhoto("");workspaceDetail.Text="Chọn một dòng để xem thông tin.";return;} RefreshMaterialPhoto(history?r[2]:r[0]);
 var labels=history?tc:sc;var lines=history?labels.Select((x,i)=>x+": "+r[i]).ToList():new List<string>{r[0]+"   |   "+r[1],r[2], "Tồn: "+r[10]+" "+r[5]+"   |   "+r[11],"Nhóm: "+r[3]+" / "+r[4],"Hãng: "+r[6]};
 if(!history){lines.Add("");lines.Add("GIAO DỊCH GẦN ĐÂY");foreach(var t in tx.Where(x=>x.Length>=10&&x[2]==r[0]).Take(12))lines.Add(t[0]+" | "+t[1]+" | "+t[6]+" | "+t[7]+" | "+t[9]);lines.Add("");lines.Add("Lịch sử giao dịch không xác nhận vị trí thực tế nếu chưa đối soát hoàn trả.");}
 workspaceDetail.Text=String.Join(Environment.NewLine,lines);
 }
 void ModernRefresh(){
 if(workspaceDetail==null)return;
 WorkspaceDashboard();
 foreach(var entry in modernButtons){var b=entry.Key;var name=entry.Value;if(IsAdminMenu(name)){b.Visible=VerifiedAdmin();b.Enabled=VerifiedAdmin();}if(new[]{"Nhập kho","Xuất kho","Thêm vật tư","Sửa giao dịch"}.Contains(name))b.Visible=!IsDemo&&(liveRole=="admin"||liveRole=="kho");b.BackColor=(name==title.Text||(name=="Danh mục và tồn kho"&&!history))?Color.FromArgb(212,229,250):Color.FromArgb(249,249,250);}
 var groups=stock.Where(x=>x.Length>4).GroupBy(x=>x[3]).OrderBy(x=>x.Key).ToArray();
 string signature=String.Join("|",groups.Select(x=>x.Key+":"+x.Count()));
 if(!Object.Equals(workspaceTree.Tag,signature)){workspaceChanging=true;try{workspaceTree.BeginUpdate();workspaceTree.Nodes.Clear();var root=workspaceTree.Nodes.Add("Tất cả vật tư ("+stock.Count+")");foreach(var g in groups){var node=root.Nodes.Add(g.Key+" ("+g.Count()+")");node.Tag=g.Key;}root.Expand();workspaceTree.Tag=signature;}finally{workspaceTree.EndUpdate();workspaceChanging=false;}}
 WorkspaceDetails();
 }
 readonly Dictionary<string,Button> adminMenu=new Dictionary<string,Button>(); readonly string user; bool IsDemo {get{return user!="Google";}} readonly Backend backend=new Backend(); string liveRole="xem",liveAlias=""; readonly Google google=new Google(); readonly DataGridView grid=new DataGridView(); readonly TextBox search=new TextBox(); readonly ComboBox group=new ComboBox(); readonly Label status=new Label(), metrics=new Label(), title=new Label(); readonly Timer timer=new Timer(); bool busy,history; List<string[]> stock=new List<string[]>(),tx=new List<string[]>(); string sheetId=SheetIdentity.Load(); string cache=Path.Combine(App.Home,"cache.json");
 string[] sc={"Mã MCE","Tên vật tư","Thông số kỹ thuật","Nhóm chính","Nhóm con","ĐVT","Hãng","Tồn đầu","Tổng nhập","Tổng xuất","Tồn hiện tại","Cảnh báo"};string[] tc={"Ngày","Loại phiếu","Mã MCE","Tên vật tư","Thông số","ĐVT","Số lượng","Bộ phận / dự án","Người lập","Ghi chú","Tồn hiện tại","Kiểm tra","Dòng nguồn"};
 Color navy=Color.FromArgb(23,46,73),blue=Color.FromArgb(22,117,209);Button Btn(string label,Action action){var b=new Button{Text=label,AutoSize=true,Height=36,FlatStyle=FlatStyle.Flat,BackColor=Color.White,ForeColor=navy,Margin=new Padding(5)};b.Click+=(s,e)=>action();return b;}
 bool IsAdminMenu(string p){return p=="Quản lý tài khoản"||p=="Đồng bộ Google"||p=="Cấu hình Google"||p=="Cấu hình dịch vụ";}
 bool VerifiedAdmin(){return !IsDemo&&liveRole=="admin"&&liveAlias!="";}
 void RefreshAdminMenu(){foreach(var b in adminMenu.Values){b.Visible=VerifiedAdmin();b.Enabled=VerifiedAdmin();}}
 public MainForm(string u){user=u;Text="MCE | Quản lý kho V5.1.3";WindowState=FormWindowState.Maximized;MinimumSize=new Size(960,580);Font=new Font("Segoe UI",10);BackColor=Color.FromArgb(241,245,249);var side=new FlowLayoutPanel{Dock=DockStyle.Left,Width=210,FlowDirection=FlowDirection.TopDown,WrapContents=false,BackColor=navy,Padding=new Padding(12)};side.Controls.Add(new Label{Text="MCE\nQUẢN LÝ KHO V5.1.3",ForeColor=Color.White,Font=new Font("Segoe UI",18,FontStyle.Bold),Width=185,Height=72});side.AutoScroll=true;foreach(var pair in new[]{"Danh mục và tồn kho","Lịch sử nhập xuất","Nhập kho","Xuất kho","Thêm vật tư","Sửa giao dịch","Quản lý tài khoản","Đồng bộ Google","Cấu hình Google","Cấu hình dịch vụ","Xuất CSV","Cập nhật phiên bản","Đăng xuất"}){string p=pair;var b=Btn(p,()=>Nav(p));b.Width=180;b.Height=34;b.AutoSize=false;b.BackColor=navy;b.ForeColor=Color.White;b.FlatAppearance.BorderSize=0;side.Controls.Add(b);if(IsAdminMenu(p)){adminMenu[p]=b;b.Visible=false;b.Enabled=false;}}var content=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=5,Padding=new Padding(18)};content.RowStyles.Add(new RowStyle(SizeType.Absolute,50));content.RowStyles.Add(new RowStyle(SizeType.Absolute,55));content.RowStyles.Add(new RowStyle(SizeType.Absolute,50));content.RowStyles.Add(new RowStyle(SizeType.Percent,100));content.RowStyles.Add(new RowStyle(SizeType.Absolute,32));title.Text="Danh mục và tồn kho";title.Font=new Font("Segoe UI",20,FontStyle.Bold);title.ForeColor=navy;title.Dock=DockStyle.Fill;metrics.Dock=DockStyle.Fill;metrics.BackColor=Color.White;metrics.Font=new Font("Segoe UI",14,FontStyle.Bold);metrics.ForeColor=blue;metrics.TextAlign=ContentAlignment.MiddleLeft;var bar=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false,BackColor=Color.White};search.Width=300;search.Margin=new Padding(5,10,5,5);group.Width=220;group.DropDownStyle=ComboBoxStyle.DropDownList;group.Margin=new Padding(5,10,5,5);bar.Controls.AddRange(new Control[]{new Label{Text="Tìm kiếm",AutoSize=true,Margin=new Padding(5,13,5,5)},search,group,Btn("Đồng bộ",()=>Sync(true)),Btn("Xóa lọc",()=>{search.Clear();if(group.Items.Count>0)group.SelectedIndex=0;})});grid.Dock=DockStyle.Fill;grid.BackgroundColor=Color.White;grid.BorderStyle=BorderStyle.None;grid.ReadOnly=true;grid.AllowUserToAddRows=false;grid.AllowUserToDeleteRows=false;grid.RowHeadersVisible=false;grid.SelectionMode=DataGridViewSelectionMode.FullRowSelect;grid.AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.DisplayedCells;grid.EnableHeadersVisualStyles=false;grid.ColumnHeadersDefaultCellStyle.BackColor=navy;grid.ColumnHeadersDefaultCellStyle.ForeColor=Color.White;grid.ColumnHeadersHeight=36;grid.RowTemplate.Height=29;grid.AlternatingRowsDefaultCellStyle.BackColor=Color.FromArgb(245,248,252);status.Dock=DockStyle.Fill;status.ForeColor=navy;content.Controls.Add(title,0,0);content.Controls.Add(metrics,0,1);content.Controls.Add(bar,0,2);content.Controls.Add(grid,0,3);content.Controls.Add(status,0,4);Controls.Add(content);Controls.Add(side);search.TextChanged+=(s,e)=>Render();group.SelectedIndexChanged+=(s,e)=>Render();timer.Interval=Backend.SyncInterval();timer.Tick+=(s,e)=>Sync(false);try{if(!IsDemo&&File.Exists(cache)){var obj=App.Obj(App.Json.DeserializeObject(App.Read(cache)));stock=App.Arr(App.Get(obj,"stock")).Select(x=>App.Arr(x).Select(App.Str).ToArray()).ToList();tx=App.Arr(App.Get(obj,"tx")).Select(x=>App.Arr(x).Select(App.Str).ToArray()).ToList();status.Text="Dữ liệu lưu tạm: "+App.Str(App.Get(obj,"time"));}}catch{status.Text="Không đọc được dữ liệu lưu tạm.";}RefreshGroups();Render();ModernLayout();Shown+=(s,e)=>{if(IsDemo){stock.Add(new[]{"DEMO-0001","Vật tư mẫu","Demo","NHÓM MẪU","","Cái","","10","0","0","10","ĐỦ HÀNG"});RefreshGroups();Render();status.Text="DEMO - không sử dụng dữ liệu kho thật.";}else{timer.Start();Sync(true);}};FormClosing+=(s,e)=>{if(busy){e.Cancel=true;MessageBox.Show("Đang xử lý dữ liệu, vui lòng đợi thao tác hoàn tất.");}else timer.Stop();};}
 void Nav(string p){if(IsAdminMenu(p)&&!VerifiedAdmin()){MessageBox.Show("Chỉ quản trị viên đã xác thực được sử dụng chức năng này.");return;}if(IsDemo&&p!="Danh mục và tồn kho"&&p!="Lịch sử nhập xuất"&&p!="Xuất CSV"&&p!="Cập nhật phiên bản"&&p!="Đăng xuất"){MessageBox.Show("Chế độ DEMO. Hãy đăng xuất và chọn Đăng nhập Google để dùng kho thật.");return;}if(p=="Danh mục và tồn kho"||p=="Lịch sử nhập xuất"){history=p.StartsWith("Lịch");title.Text=p=="Danh mục và tồn kho"?"Tra cứu vật tư":p;workspaceFilter="all";group.Enabled=!history;Render();}else if(p=="Nhập kho")DoTransaction("NHẬP");else if(p=="Xuất kho")DoTransaction("XUẤT");else if(p=="Thêm vật tư")AddMaterial();else if(p=="Sửa giao dịch")EditTransaction();else if(p=="Quản lý tài khoản")ManageUsers();else if(p=="Cấu hình dịch vụ")ConfigureBackend();else if(p=="Đồng bộ Google")Sync(true);else if(p=="Cấu hình Google"){if(busy)return;using(var dlg=new OpenFileDialog{Filter="OAuth Desktop JSON|*.json"}){if(dlg.ShowDialog()!=DialogResult.OK)return;try{var c=App.Obj(App.Get(App.Obj(App.Json.DeserializeObject(App.Read(dlg.FileName))),"installed"));if(App.Str(App.Get(c,"client_id"))=="")throw new Exception("Không phải OAuth Desktop JSON");App.Save(Path.Combine(App.Home,"credentials.json"),App.Read(dlg.FileName));google.Reset();Sync(true);}catch(Exception ex){MessageBox.Show(ex.Message);}}}else if(p=="Xuất CSV")Export();else if(p=="Cập nhật phiên bản"){if(busy){MessageBox.Show("Đang xử lý dữ liệu, vui lòng thử lại.");return;}string launcher=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"MCE.exe");if(!File.Exists(launcher)){MessageBox.Show("Chưa có bộ khởi động MCE.exe.");return;}Process.Start(launcher,"--wait "+Process.GetCurrentProcess().Id.ToString(CultureInfo.InvariantCulture));Close();}else {if(busy)return;if(!IsDemo)google.Reset();Close();}}
 void RefreshGroups(){string old=Convert.ToString(group.SelectedItem);group.Items.Clear();group.Items.Add("Tất cả nhóm");foreach(var g in stock.Select(x=>x[3]).Where(x=>x!="").Distinct().OrderBy(x=>x))group.Items.Add(g);group.SelectedIndex=Math.Max(0,group.Items.IndexOf(old));}
 void Render(){RefreshAdminMenu();grid.SuspendLayout();grid.Rows.Clear();grid.Columns.Clear();foreach(var h in history?tc:sc)grid.Columns.Add(h,h);string q=search.Text.Trim();string g=Convert.ToString(group.SelectedItem);foreach(var r in history?tx:stock){if(q.Length>0&&String.Join(" ",r).IndexOf(q,StringComparison.CurrentCultureIgnoreCase)<0)continue;if(!history&&g!=""&&g!="Tất cả nhóm"&&g!=r[3])continue;if(!history&&!WorkspaceMatch(r))continue;int idx=grid.Rows.Add(r.Cast<object>().ToArray());if(!history){string s=r[11];if(s=="ÂM KHO"||s=="TRÙNG MÃ"||s=="CẦN ĐỐI SOÁT")grid.Rows[idx].DefaultCellStyle.BackColor=Color.MistyRose;else if(s=="CẦN NHẬP"||s=="HẾT HÀNG")grid.Rows[idx].DefaultCellStyle.BackColor=Color.LemonChiffon;}}CompactColumns();grid.ResumeLayout();ModernRefresh();metrics.Text="   Vật tư: "+stock.Count+"     |     Giao dịch: "+tx.Count+"     |     Cần đối soát: "+stock.Count(x=>x[11]=="TRÙNG MÃ"||x[11]=="CẦN ĐỐI SOÁT")+"     |     "+(liveAlias==""?user+" (chỉ đọc)":liveAlias+" / "+liveRole);}
 async void Sync(bool interactive){if(IsDemo||busy)return;busy=true;status.Text="Đang đồng bộ Google Sheets...";try{if(String.IsNullOrEmpty(sheetId))throw new Exception("Thiếu mã kho cục bộ. Khôi phục bản V5.1 trước khi cập nhật.");var all=await google.Pull(sheetId,interactive);var dm=all[0].Where(x=>App.At(x,0)!=""&&App.At(x,1)!="").ToArray();if(dm.Length==0)throw new Exception("Danh mục trống; giữ dữ liệu cũ.");var counts=dm.GroupBy(x=>App.At(x,0)).ToDictionary(x=>x.Key,x=>x.Count());var sums=all[1].Where(x=>App.At(x,0)!="").GroupBy(x=>App.At(x,0)).ToDictionary(x=>x.Key,x=>x.ToArray());var next=new List<string[]>();foreach(var a in dm){string code=App.At(a,0);object[][] m;bool match=sums.TryGetValue(code,out m)&&m.Length==1&&App.At(m[0],1)==App.At(a,1)&&App.At(m[0],2)==App.At(a,4)&&App.At(m[0],8)!=""&&!App.At(m[0],8).StartsWith("#");var b=match?m[0]:new object[0];bool good=match&&counts[code]==1;next.Add(new[]{code,App.At(a,1),App.At(a,4),App.At(a,2),App.At(a,3),App.At(b,4)==""?App.At(a,5):App.At(b,4),App.At(a,6),App.At(a,7),good?App.At(b,6):"",good?App.At(b,7):"",good?App.At(b,8):"",counts[code]>1?"TRÙNG MÃ":good?App.At(b,10):"CẦN ĐỐI SOÁT"});}var nt=all[2].Select((x,i)=>new {Row=x,Number=i+8}).Where(o=>App.At(o.Row,0)!=""||App.At(o.Row,1)!=""||App.At(o.Row,3)!=""||App.At(o.Row,6)!="").Select(o=>Enumerable.Range(0,12).Select(i=>App.At(o.Row,i)).Concat(new[]{o.Number.ToString(CultureInfo.InvariantCulture)}).ToArray()).Reverse().ToList();string time=DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss");App.Save(cache,App.Json.Serialize(new{stock=next,tx=nt,time=time}));stock=next;tx=nt;RefreshGroups();Render();liveRole="xem";liveAlias="";string roleNote="Chỉ đọc";if(backend.Configured){try{var role=App.Obj(await backend.Call(await google.Access(false),"whoami",null));liveRole=App.Str(App.Get(role,"role"));liveAlias=App.Str(App.Get(role,"alias"));roleNote="Quyền: "+liveRole;}catch(Exception e){roleNote="Chỉ đọc | "+e.Message;}}Render();status.Text="Google Sheets: "+time+" | Đồng bộ "+(timer.Interval/1000)+" giây | "+roleNote;}catch(Exception ex){liveRole="xem";liveAlias="";Render();status.Text="Chưa đồng bộ: "+ex.Message;if(interactive)MessageBox.Show(ex.Message,"MCE");}finally{busy=false;}}

 string[] Selected(){if(grid.CurrentRow==null||grid.CurrentRow.IsNewRow)return null;return grid.CurrentRow.Cells.Cast<DataGridViewCell>().Select(c=>Convert.ToString(c.Value)??"").ToArray();}
 bool CanWrite(){if(IsDemo){MessageBox.Show("DEMO không có quyền ghi.");return false;}if(busy){MessageBox.Show("Đang xử lý dữ liệu.");return false;}if(!backend.Configured){MessageBox.Show("Chưa thiết lập dịch vụ trung tâm. Chọn Cấu hình dịch vụ.");return false;}if(liveRole!="admin"&&liveRole!="kho"){MessageBox.Show("Tài khoản Google chưa có quyền ghi. Đồng bộ và kiểm tra phân quyền.");return false;}return true;}
 void ConfigureBackend(){if(busy)return;var a=Fields.Ask("Cấu hình dịch vụ MCE",new[]{"URL Google Apps Script /exec"},new[]{backend.Url},null);if(a==null)return;try{backend.Set(a[0]);liveAlias="";liveRole="xem";RefreshAdminMenu();Sync(true);}catch(Exception e){MessageBox.Show(e.Message);}}
 async void WriteAction(string action,Dictionary<string,object> data){if(!CanWrite())return;busy=true;status.Text="Đang gửi yêu cầu lên kho chính...";bool ok=false;try{var ret=App.Obj(await backend.Call(await google.Access(true),action,data));ok=true;MessageBox.Show("Đã xác nhận trên máy chủ."+(App.Get(ret,"code")!=null?" Mã: "+App.Str(App.Get(ret,"code")):""),"MCE");}catch(Exception ex){MessageBox.Show(ex.Message+"\nNếu mất kết nối sau khi gửi, hãy đồng bộ và kiểm tra lịch sử trước khi làm lại.","MCE");}finally{busy=false;}Sync(false);}

 void DoTransaction(string kind){
 if(!CanWrite())return;
 var selected=history?null:Selected();
 var items=stock.Where(r=>r!=null&&r.Length>=12&&!String.IsNullOrWhiteSpace(r[0])&&!String.IsNullOrWhiteSpace(r[1])).GroupBy(r=>r[0],StringComparer.OrdinalIgnoreCase).Where(g=>g.Count()==1).Select(g=>g.First()).OrderBy(r=>r[1]).ThenBy(r=>r[2]).ToList();
 using(var f=new Form{Text=kind=="NHẬP"?"MCE | Nhập kho":"MCE | Xuất kho",ClientSize=new Size(760,635),StartPosition=FormStartPosition.CenterParent,Font=new Font("Segoe UI",10),BackColor=Color.White,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false}){
 Action<string,int> label=(t,y)=>f.Controls.Add(new Label{Text=t,Left=20,Top=y,Width=720,Height=24});
 label("Tìm tên vật tư / mã MCE / thông số kỹ thuật",12);
 var filter=new TextBox{Left=20,Top=37,Width=720};
 var results=new ListBox{Left=20,Top=72,Width=720,Height=146,HorizontalScrollbar=true,IntegralHeight=false};
 label("Mã MCE / thông số kỹ thuật / tồn hiện tại",222);
 var info=new TextBox{Left=20,Top=247,Width=720,ReadOnly=true,BackColor=Color.FromArgb(240,244,249)};
 label("Ngày "+(kind=="NHẬP"?"nhập":"xuất")+" (máy chủ hiện chỉ ghi ngày hiện tại)",282);
 var date=new DateTimePicker{Left=20,Top=307,Width=350,Format=DateTimePickerFormat.Custom,CustomFormat="dd/MM/yyyy",Value=DateTime.Today,MaxDate=DateTime.Today.AddDays(1).AddTicks(-1)};
 f.Controls.Add(new Label{Text="Người nhập liệu (tài khoản xác thực)",Left=390,Top=282,Width=350,Height=24});
 var actor=new TextBox{Left=390,Top=307,Width=350,ReadOnly=true,Text=liveAlias,BackColor=Color.FromArgb(240,244,249)};
 label("Số lượng",342);var qty=new TextBox{Left=20,Top=367,Width=720,Text="1"};
 label("Bộ phận / dự án",402);var project=new ComboBox{Left=20,Top=427,Width=720,DropDownStyle=ComboBoxStyle.DropDown,Text="Xưởng"};
 project.Items.AddRange(tx.Where(r=>r.Length>7&&!String.IsNullOrWhiteSpace(r[7])).Select(r=>r[7]).Concat(new[]{"Xưởng"}).Distinct(StringComparer.CurrentCultureIgnoreCase).OrderBy(x=>x).Cast<object>().ToArray());project.AutoCompleteMode=AutoCompleteMode.SuggestAppend;project.AutoCompleteSource=AutoCompleteSource.ListItems;
 label("Ghi chú",462);var note=new TextBox{Left=20,Top=487,Width=720};
 var hint=new Label{Left=20,Top=525,Width=720,Height=39,ForeColor=Color.FromArgb(105,85,40),Text="Chọn đúng tên + quy cách. Ngày khác hôm nay cần nâng cấp dịch vụ Google Apps Script trước."};
 var ok=new Button{Text="Xác nhận",Left=450,Top=578,Width=140,Height=38,BackColor=blue,ForeColor=Color.White,FlatStyle=FlatStyle.Flat};var cancel=new Button{Text="Hủy",Left=600,Top=578,Width=140,Height=38,DialogResult=DialogResult.Cancel};
 var visible=new List<string[]>();
 Action refresh=()=>{string q=filter.Text.Trim();visible=items.Where(r=>q.Length==0||String.Join(" ",new[]{r[0],r[1],r[2]}).IndexOf(q,StringComparison.CurrentCultureIgnoreCase)>=0).ToList();results.BeginUpdate();try{results.Items.Clear();foreach(var r in visible)results.Items.Add(r[1]+" | "+r[2]+" | "+r[0]);}finally{results.EndUpdate();}info.Clear();};
 results.SelectedIndexChanged+=(sender,e)=>{int i=results.SelectedIndex;if(i>=0&&i<visible.Count){var r=visible[i];info.Text=r[0]+" | "+r[2]+" | Tồn: "+r[10]+" "+r[5];}else info.Clear();};
 filter.TextChanged+=(sender,e)=>refresh();
 f.Controls.AddRange(new Control[]{filter,results,info,date,actor,qty,project,note,hint,ok,cancel});
 refresh();if(selected!=null&&selected.Length>0){filter.Text=selected[0];int idx=visible.FindIndex(r=>r[0]==selected[0]);if(idx>=0)results.SelectedIndex=idx;}
 f.AcceptButton=ok;f.CancelButton=cancel;
 ok.Click+=(sender,e)=>{
 if(results.SelectedIndex<0||results.SelectedIndex>=visible.Count){MessageBox.Show("Chọn chính xác vật tư trong danh sách.");return;}
 if(date.Value.Date!=DateTime.Today){MessageBox.Show("Dịch vụ hiện tại chỉ lưu ngày giao dịch thực tế. Chưa thể ghi ngày khác hôm nay.");return;}
 if(String.IsNullOrWhiteSpace(liveAlias)){MessageBox.Show("Chưa xác thực người nhập liệu. Đồng bộ lại.");return;}
 decimal q;if(!Decimal.TryParse(qty.Text.Replace(',','.'),NumberStyles.AllowDecimalPoint,CultureInfo.InvariantCulture,out q)||q<=0){MessageBox.Show("Số lượng không hợp lệ.");return;}
 if(String.IsNullOrWhiteSpace(project.Text)){MessageBox.Show("Nhập bộ phận / dự án.");return;}
 var r=visible[results.SelectedIndex];
 if(MessageBox.Show(kind+" "+q+" "+r[5]+" | "+r[1]+" | "+r[2]+" | "+r[0]+"?","Xác nhận",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;
 f.DialogResult=DialogResult.OK;
 WriteAction("transaction",new Dictionary<string,object>{{"code",r[0]},{"qty",q},{"type",kind},{"project",project.Text.Trim()},{"note",note.Text.Trim()}});
 };
 f.ShowDialog(this);
 }
 }
 void AddMaterial(){if(!CanWrite())return;var a=MaterialPicker.Ask(this,stock);if(a==null)return;WriteAction("addMaterial",new Dictionary<string,object>{{"name",a[0]},{"group",a[1]},{"sub",a[2]},{"spec",a[3]},{"unit",a[4]},{"brand",a[5]}});}
 void EditTransaction(){if(!CanWrite())return;if(!history){history=true;title.Text="Lịch sử nhập xuất";group.Enabled=false;Render();MessageBox.Show("Chọn một dòng giao dịch rồi nhấn Sửa giao dịch.");return;}var r=Selected();if(r==null||r.Length<13||r[12]==""){MessageBox.Show("Cần chọn giao dịch đã đồng bộ.");return;}var a=Fields.Ask("Sửa giao dịch (giới hạn 48 giờ cho Kho)",new[]{"Loại phiếu","Số lượng","Bộ phận / dự án","Ghi chú"},new[]{r[1],r[6],r[7],r[9]},new Dictionary<int,string[]>{{0,new[]{"NHẬP","XUẤT"}}});if(a==null)return;decimal q;if(!Decimal.TryParse(a[1].Replace(',','.'),NumberStyles.AllowDecimalPoint,CultureInfo.InvariantCulture,out q)||q<=0){MessageBox.Show("Số lượng không hợp lệ.");return;}WriteAction("editTransaction",new Dictionary<string,object>{{"row",r[12]},{"original",r.Take(10).ToArray()},{"type",a[0]},{"qty",q},{"project",a[2]},{"note",a[3]}});}
 async void ManageUsers(){if(!VerifiedAdmin()||!CanWrite())return;busy=true;object data=null;try{data=await backend.Call(await google.Access(true),"listUsers",null);}catch(Exception ex){MessageBox.Show(ex.Message);}finally{busy=false;}if(data==null)return;var rows=App.Arr(data).Select(App.Obj).ToList();string info=String.Join("\n",rows.Select(x=>App.Str(App.Get(x,"email"))+" | "+App.Str(App.Get(x,"alias"))+" | "+App.Str(App.Get(x,"role"))+" | "+App.Str(App.Get(x,"enabled"))));MessageBox.Show(info==""?"Chưa có tài khoản cấp dưới.":info,"Danh sách tài khoản được quản lý");var roles=liveRole=="admin"?new[]{"admin","kho","kythuat","xem"}:new[]{"kythuat","xem"};var a=Fields.Ask("Cấp quyền / khóa tài khoản Google",new[]{"Email Google","Tên hiển thị","Vai trò","Trạng thái"},new[]{"","",roles.Last(),"Hoạt động"},new Dictionary<int,string[]>{{2,roles},{3,new[]{"Hoạt động","Khóa"}}});if(a==null)return;WriteAction("setUser",new Dictionary<string,object>{{"email",a[0]},{"alias",a[1]},{"role",a[2]},{"enabled",a[3]=="Hoạt động"}});}
 void Export(){using(var dlg=new SaveFileDialog{Filter="CSV UTF-8|*.csv",FileName=history?"MCE_GiaoDich.csv":"MCE_TonKho.csv"}){if(dlg.ShowDialog()!=DialogResult.OK)return;Func<string,string> esc=x=>"\""+((x.Length>0&&"=+-@".IndexOf(x[0])>=0?"'":"")+x).Replace("\"","\"\"")+"\"";var lines=new List<string>{String.Join(",",(history?tc:sc).Select(esc))};foreach(DataGridViewRow row in grid.Rows)lines.Add(String.Join(",",row.Cells.Cast<DataGridViewCell>().Select(c=>esc(Convert.ToString(c.Value)??""))));File.WriteAllLines(dlg.FileName,lines,new UTF8Encoding(true));}}
}

static class SheetIdentity {
 static bool Good(string id){if(String.IsNullOrEmpty(id))return false;using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(id))).Replace("-","").ToLowerInvariant()=="c96ecc0dc801aba538b3e9a7d0b9c6ab6fda62b598f1c437fb710055288dd6c7";}
 public static string Load(){try{string p=Path.Combine(App.Home,"sheet-id.txt");if(File.Exists(p)){string v=App.Read(p).Trim();if(Good(v))return v;}string backup=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"MCE.Client.exe.bak");if(File.Exists(backup)){var b=File.ReadAllBytes(backup);for(int offset=0;offset<2;offset++){string data=Encoding.Unicode.GetString(b,offset,b.Length-offset);foreach(System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(data,@"(?=([A-Za-z0-9_-]{44}))")){string v=m.Groups[1].Value;if(Good(v)){App.Save(p,v);return v;}}}}}catch{}return "";}
}
static class MaterialPicker {
 static bool Eq(string a,string b){return String.Equals((a??"").Trim().Normalize(),(b??"").Trim().Normalize(),StringComparison.OrdinalIgnoreCase);}
 static string[] Choices(IEnumerable<string> items){return items.Where(v=>!String.IsNullOrWhiteSpace(v)).Select(v=>v.Trim()).Distinct(StringComparer.CurrentCultureIgnoreCase).OrderBy(v=>v,StringComparer.CurrentCultureIgnoreCase).ToArray();}
 public static bool SelfTest(){return Eq(" Bộ ","bộ")&&Choices(new[]{"Bộ","bộ","Cái",""}).Length==2&&!Eq("M8","M10");}
 static void Fill(ComboBox c,IEnumerable<string> items){string old=c.Text;c.BeginUpdate();try{c.AutoCompleteMode=AutoCompleteMode.None;c.AutoCompleteSource=AutoCompleteSource.None;c.Items.Clear();c.Items.AddRange(Choices(items));c.Text=old;c.AutoCompleteSource=AutoCompleteSource.ListItems;c.AutoCompleteMode=AutoCompleteMode.SuggestAppend;}finally{c.EndUpdate();}}
 public static string[] Ask(Form owner,List<string[]> stock){var rows=stock.Where(r=>r!=null&&r.Length>=7&&!String.IsNullOrWhiteSpace(r[1])).Select(r=>(string[])r.Clone()).ToList();using(var f=new Form{Text="Thêm vật tư mới",ClientSize=new Size(660,490),Font=new Font("Segoe UI",11),StartPosition=FormStartPosition.CenterParent,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,BackColor=Color.White}){
 string[] labels={"Tên vật tư (chọn hoặc nhập mới)","Nhóm chính","Nhóm con (theo nhóm chính)","Thông số kỹ thuật mới","ĐVT","Hãng"};var c=new ComboBox[6];bool updating=false;
 for(int i=0;i<6;i++){int y=12+i*62;f.Controls.Add(new Label{Text=labels[i],Left=20,Top=y,Width=620,Height=24});c[i]=new ComboBox{DropDownStyle=ComboBoxStyle.DropDown};c[i].SetBounds(20,y+24,620,30);f.Controls.Add(c[i]);}
 Fill(c[0],rows.Select(r=>r[1]));Fill(c[1],rows.Select(r=>r[3]));Fill(c[2],new string[0]);Fill(c[4],rows.Select(r=>r[5]).Concat(new[]{"Cái"}));Fill(c[5],rows.Select(r=>r[6]));c[4].Text="Cái";
 string lastGroup="";Action group=()=>{if(updating||Eq(lastGroup,c[1].Text))return;lastGroup=c[1].Text;updating=true;try{var items=rows.Where(r=>Eq(r[3],lastGroup)).Select(r=>r[4]).ToArray();if(!items.Any(v=>Eq(v,c[2].Text))){var same=Choices(rows.Where(r=>Eq(r[3],lastGroup)&&Eq(r[1],c[0].Text)).Select(r=>r[4]));c[2].Text=same.Length==1?same[0]:"";}Fill(c[2],items);}finally{updating=false;}};
 string last="";Action name=()=>{if(updating||Eq(last,c[0].Text))return;last=c[0].Text;updating=true;try{var matches=rows.Where(r=>Eq(r[1],last)).ToList();if(matches.Count==0)return;var gs=Choices(matches.Select(r=>r[3]));c[1].Text=gs.Length==1?gs[0]:"";lastGroup=c[1].Text;var ss=Choices(matches.Where(r=>Eq(r[3],c[1].Text)).Select(r=>r[4]));c[2].Text=ss.Length==1?ss[0]:"";Fill(c[2],rows.Where(r=>Eq(r[3],c[1].Text)).Select(r=>r[4]));var us=Choices(matches.Select(r=>r[5]));c[4].Text=us.Length==1?us[0]:"";var bs=Choices(matches.Select(r=>r[6]));c[5].Text=bs.Length==1?bs[0]:"";c[3].Text="";Fill(c[3],matches.Select(r=>r[2]));}finally{updating=false;}};
 c[0].SelectionChangeCommitted+=(a,b)=>name();c[0].Leave+=(a,b)=>name();c[1].SelectionChangeCommitted+=(a,b)=>group();c[1].Leave+=(a,b)=>group();
 f.Controls.Add(new Label{Text="Chọn tên cũ để kế thừa nhóm; nhập quy cách mới. Tên + quy cách trùng sẽ bị từ chối.",Left=20,Top=390,Width=620,Height=36});string[] result=null;var ok=new Button{Text="Xác nhận",Left=400,Top=438,Width=115,Height=36,BackColor=Color.FromArgb(22,117,209),ForeColor=Color.White};var cancel=new Button{Text="Hủy",Left=525,Top=438,Width=115,Height=36,DialogResult=DialogResult.Cancel};
 ok.Click+=(a,b)=>{var v=c.Select(x=>x.Text.Trim()).ToArray();if(new[]{0,1,2,4}.Any(i=>v[i]=="")){MessageBox.Show("Nhập đủ tên, nhóm chính, nhóm con và ĐVT.");return;}if(rows.Any(r=>Eq(r[1],v[0])&&Eq(r[2],v[3]))){MessageBox.Show("Tên và thông số đã có. Chọn vật tư hiện có hoặc nhập quy cách khác.");return;}result=v;f.DialogResult=DialogResult.OK;};f.Controls.AddRange(new Control[]{ok,cancel});f.AcceptButton=ok;f.CancelButton=cancel;return f.ShowDialog(owner)==DialogResult.OK?result:null;}}
}

