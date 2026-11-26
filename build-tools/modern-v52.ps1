param([string]$SourceDir='build/source')
$ErrorActionPreference='Stop'
$p=Join-Path $SourceDir 'MCE.cs'
$s=Get-Content -LiteralPath $p -Raw
if (!$s.Contains('class MainForm:Form {') -or !$s.Contains('void Render(){') -or !$s.Contains('FormClosing+=')) { throw 'Unsupported client source layout' }
$methods=@'
 readonly Label[] modernValues=new Label[4];
 readonly Dictionary<Button,string> modernButtons=new Dictionary<Button,string>();
 void ModernLayout(){
  Text="MCE | Warehouse ERP V5.2";
  AutoScaleMode=AutoScaleMode.Dpi;
  BackColor=Color.FromArgb(238,243,249);
  var side=Controls.OfType<FlowLayoutPanel>().FirstOrDefault();
  var content=Controls.OfType<TableLayoutPanel>().FirstOrDefault();
  if(side==null||content==null)throw new InvalidOperationException("MCE layout unavailable");
  side.SuspendLayout();side.Width=244;side.Padding=new Padding(12,12,12,12);side.BackColor=Color.FromArgb(18,35,59);
  var old=side.Controls.Cast<Control>().ToArray();
  var buttons=old.OfType<Button>().ToArray();
  side.Controls.Clear();
  side.Controls.Add(new Label{Text="MCE  /  ERP",Font=new Font("Segoe UI",22,FontStyle.Bold),ForeColor=Color.White,Width=210,Height=48});
  side.Controls.Add(new Label{Text="WAREHOUSE MANAGEMENT",Font=new Font("Segoe UI",9),ForeColor=Color.FromArgb(153,185,219),Width=210,Height=30});
  string[][] sections={new[]{"KHO VẬT TƯ","Danh mục và tồn kho","Thêm vật tư"},new[]{"GIAO DỊCH","Nhập kho","Xuất kho","Sửa giao dịch","Lịch sử nhập xuất"},new[]{"BÁO CÁO","Xuất CSV"},new[]{"HỆ THỐNG","Quản lý tài khoản","Đồng bộ Google","Cấu hình Google","Cấu hình dịch vụ","Cập nhật phiên bản","Đăng xuất"}};
  var used=new HashSet<Button>();
  foreach(var section in sections){
   side.Controls.Add(new Label{Text=section[0],Width=208,Height=27,Margin=new Padding(4,9,4,0),ForeColor=Color.FromArgb(139,165,198),Font=new Font("Segoe UI",9,FontStyle.Bold)});
   foreach(string name in section.Skip(1)){var b=buttons.FirstOrDefault(x=>x.Text.Trim()==name);if(b==null)continue;used.Add(b);modernButtons[b]=name;b.AutoSize=false;b.Width=210;b.Height=37;b.Margin=new Padding(2,1,2,1);b.TextAlign=ContentAlignment.MiddleLeft;b.Padding=new Padding(11,0,0,0);b.FlatStyle=FlatStyle.Flat;b.FlatAppearance.BorderSize=0;b.FlatAppearance.MouseOverBackColor=Color.FromArgb(42,70,105);b.ForeColor=Color.FromArgb(230,239,250);b.BackColor=side.BackColor;b.Font=new Font("Segoe UI",10);side.Controls.Add(b);}
  }
  foreach(var b in buttons.Where(x=>!used.Contains(x)))side.Controls.Add(b);
  side.ResumeLayout();
  content.Padding=new Padding(22,16,22,12);content.RowStyles[0].Height=52;content.RowStyles[1].Height=96;content.RowStyles[2].Height=54;
  title.Font=new Font("Segoe UI",23,FontStyle.Bold);title.ForeColor=Color.FromArgb(20,38,60);
  content.Controls.Remove(metrics);
  var cards=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=4,RowCount=1,Margin=new Padding(0,0,0,8)};
  string[] names={"DANH MỤC VẬT TƯ","GIAO DỊCH","CẦN NHẬP / ĐỐI SOÁT","TÀI KHOẢN"};
  for(int i=0;i<4;i++){cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,25));var p=new Panel{Dock=DockStyle.Fill,BackColor=Color.White,Margin=new Padding(0,0,8,0),Padding=new Padding(12)};var k=new Label{Text=names[i],Dock=DockStyle.Top,Height=23,Font=new Font("Segoe UI",9,FontStyle.Bold),ForeColor=Color.FromArgb(94,113,139)};var v=new Label{Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft,Font=new Font("Segoe UI",i==3?14:23,FontStyle.Bold),ForeColor=i==2?Color.FromArgb(180,100,22):Color.FromArgb(22,102,190),AutoEllipsis=true};modernValues[i]=v;p.Controls.Add(v);p.Controls.Add(k);cards.Controls.Add(p,i,0);}
  content.Controls.Add(cards,0,1);
  grid.Font=new Font("Segoe UI",10);grid.RowTemplate.Height=35;grid.ColumnHeadersHeight=42;grid.ColumnHeadersDefaultCellStyle.BackColor=Color.FromArgb(31,52,80);grid.ColumnHeadersDefaultCellStyle.Font=new Font("Segoe UI",10,FontStyle.Bold);grid.CellBorderStyle=DataGridViewCellBorderStyle.SingleHorizontal;grid.GridColor=Color.FromArgb(224,232,242);grid.DefaultCellStyle.SelectionBackColor=Color.FromArgb(218,235,253);grid.DefaultCellStyle.SelectionForeColor=Color.FromArgb(20,55,100);grid.AlternatingRowsDefaultCellStyle.BackColor=Color.FromArgb(247,250,254);grid.DefaultCellStyle.Padding=new Padding(4,0,4,0);
  foreach(DataGridViewRow row in grid.Rows)row.Height=35;
  metrics.TextChanged+=(sender,e)=>ModernRefresh();title.TextChanged+=(sender,e)=>ModernRefresh();
  ModernRefresh();
 }
 void ModernRefresh(){
  if(modernValues[0]==null)return;
  modernValues[0].Text=stock.Count.ToString("N0");modernValues[1].Text=tx.Count.ToString("N0");
  modernValues[2].Text=stock.Count(x=>x.Length>11&&new[]{"CẦN NHẬP","HẾT HÀNG","ÂM KHO","TRÙNG MÃ","CẦN ĐỐI SOÁT"}.Contains(x[11])).ToString("N0");
  modernValues[3].Text=liveAlias==""?"Chỉ đọc":liveAlias+" / "+liveRole;
  foreach(var entry in modernButtons){var b=entry.Key;string name=entry.Value;bool adminOnly=new[]{"Quản lý tài khoản","Đồng bộ Google","Cấu hình Google","Cấu hình dịch vụ"}.Contains(name);bool writes=new[]{"Nhập kho","Xuất kho","Thêm vật tư","Sửa giao dịch"}.Contains(name);if(adminOnly){b.Visible=!IsDemo&&liveRole=="admin";if(!IsDemo&&liveAlias==""&&(name=="Cấu hình Google"||name=="Cấu hình dịch vụ"))b.Visible=true;}if(writes)b.Visible=!IsDemo&&(liveRole=="admin"||liveRole=="kho");b.BackColor=name==title.Text?Color.FromArgb(36,83,136):Color.FromArgb(18,35,59);}
 }
'@
$s=$s.Replace('class MainForm:Form {',"class MainForm:Form {`r`n"+$methods)
# Attach after construction, before the initial Shown callback.
$anchor='Shown+=(s,e)=>'
if(!$s.Contains($anchor)){throw 'Cannot locate main form startup'}
# Target only MainForm, not Login.
$i=$s.IndexOf('class MainForm:Form {')
$head=$s.Substring(0,$i);$tail=$s.Substring($i)
$j=$tail.IndexOf($anchor)
if($j -lt 0){throw 'Cannot locate MainForm Shown callback'}
$tail=$tail.Insert($j,'ModernLayout();')
# Render always refreshes cards/role, including repeated metric text.
$tail=$tail.Replace('grid.ResumeLayout();','grid.ResumeLayout();ModernRefresh();')
$s=$head+$tail
Set-Content -LiteralPath $p -Value $s -Encoding utf8NoBOM
