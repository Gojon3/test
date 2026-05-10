import frida

BOUNTY_DELAY   = 0.3
GIFT_TABS      = [1, 2, 3, 4, 5]
CHEST_META_IDS = []

def get_game_pid():
    r = subprocess.run(
        ['powershell',
         'Get-Process | Where-Object {$_.Name -like "*Hero*"} | Select-Object -ExpandProperty Id'],
        capture_output=True, text=True)
    lines = [l.strip() for l in r.stdout.strip().split('\n') if l.strip()]
    if not lines:
        raise RuntimeError("Khong tim thay process Hero")
    return int(lines[0])

JS = """
'use strict';
var mono = Process.getModuleByName("mono-2.0-bdwgc.dll");
function mfn(n,r,a){ return new NativeFunction(mono.getExportByName(n),r,a); }
var m_root    = mfn("mono_get_root_domain",          "pointer",[]);
var m_attach  = mfn("mono_thread_attach",             "pointer",["pointer"]);
var m_foreach = mfn("mono_assembly_foreach",          "void",   ["pointer","pointer"]);
var m_img     = mfn("mono_assembly_get_image",        "pointer",["pointer"]);
var m_iname   = mfn("mono_image_get_name",            "pointer",["pointer"]);
var m_cls     = mfn("mono_class_from_name",           "pointer",["pointer","pointer","pointer"]);
var m_methods = mfn("mono_class_get_methods",         "pointer",["pointer","pointer"]);
var m_mname   = mfn("mono_method_get_name",           "pointer",["pointer"]);
var m_compile = mfn("mono_compile_method",            "pointer",["pointer"]);
var m_gfield  = mfn("mono_class_get_field_from_name", "pointer",["pointer","pointer"]);
var m_fget    = mfn("mono_field_get_value",           "void",   ["pointer","pointer","pointer"]);
var m_fset    = mfn("mono_field_set_value",           "void",   ["pointer","pointer","pointer"]);
var m_newobj  = mfn("mono_object_new",                "pointer",["pointer","pointer"]);
var m_foff    = mfn("mono_field_get_offset",          "int",    ["pointer"]);

var domain = m_root();
m_attach(domain);

var _img=null, _netThis=null, _sendPtr=null, _bagProxy=null;

function S(s){ return Memory.allocUtf8String(s); }
function clsG(n){ return _img ? m_cls(_img,S(""),S(n)) : ptr(0); }
function clsP(n){ return _img ? m_cls(_img,S("topHero.Protocol"),S(n)) : ptr(0); }
function gf(k,n){ return m_gfield(k,S(n)); }
function findMethod(klass,name){
    var it=Memory.alloc(8),m;
    while(!(m=m_methods(klass,it)).isNull())
        if(m_mname(m).readUtf8String()===name) return m;
    return ptr(0);
}
function wi32(o,f,v){ if(!f||f.isNull())return; var b=Memory.alloc(4);b.writeS32(v);m_fset(o,f,b); }
function wi64(o,f,v){ if(!f||f.isNull())return; var b=Memory.alloc(8);b.writeS64(v);m_fset(o,f,b); }
function rp(o,f){ if(!f||f.isNull())return ptr(0); var b=Memory.alloc(8);m_fget(o,f,b);return b.readPointer(); }

function newObj(name){
    var k=clsP(name); if(!k||k.isNull())return null;
    var o=m_newobj(domain,k); if(!o||o.isNull())return null;
    var ctor=findMethod(k,".ctor");
    if(!ctor.isNull()){
        try{ var f=m_compile(ctor); if(!f.isNull()) new NativeFunction(f,"void",["pointer"])(o); }
        catch(e){}
    }
    return o;
}
function sendProto(p){
    if(!_netThis||!_sendPtr||!p) return false;
    try{ new NativeFunction(_sendPtr,"void",["pointer","pointer"])(_netThis,p); return true; }
    catch(e){ return false; }
}

var _cb = new NativeCallback(function(asm,_){
    try{
        var img = m_img(asm);
        if(m_iname(img).readUtf8String() !== "ScriptProj") return;
        _img = img;
        var bk = m_cls(img,S(""),S("BagProxy"));
        if(!bk.isNull()){
            var it=Memory.alloc(8),m,n=0;
            while(!(m=m_methods(bk,it)).isNull()){
                var mn=m_mname(m).readUtf8String();
                if(mn.startsWith("<")||mn===".cctor") continue;
                try{
                    var c=m_compile(m);
                    if(!c.isNull()){
                        Interceptor.attach(c,{onEnter:function(a){
                            if(!_bagProxy&&a[0]&&!a[0].isNull()){
                                _bagProxy=a[0];
                                send({type:"bag_proxy_found",addr:a[0].toString()});
                            }
                        }});
                        n++;
                    }
                }catch(e){}
            }
            console.log("[*] BagProxy hooked "+n);
        }
        var nf = m_cls(img,S(""),S("NetFacade"));
        if(!nf.isNull()){
            var it2=Memory.alloc(8),m2;
            while(!(m2=m_methods(nf,it2)).isNull()){
                if(m_mname(m2).readUtf8String()!=="SendMessage") continue;
                try{
                    var c=m_compile(m2);
                    if(!c.isNull()){
                        _sendPtr=c;
                        Interceptor.attach(c,{onEnter:function(a){
                            if(!_netThis){ _netThis=a[0]; send({type:"ready"}); }
                        }});
                        console.log("[*] NetFacade.SendMessage hooked");
                    }
                }catch(e){}
            }
        }
    }catch(e){ console.log("[!] "+e); }
},"void",["pointer","pointer"]);
m_foreach(_cb,ptr(0));

// BagProxy fields:
//   items    = Dictionary<int,  List<BagItemVO>>  <- key=metaId
//   bagItems = Dictionary<long, BagItemVO>        <- key=uId  <- DUNG CAI NAY
//
// bagItems entry layout (Dictionary<long,BagItemVO>):
//   Entry size = 0x20:
//   +0x00  8  val ptr   (BagItemVO*)
//   +0x08  4  hashCode
//   +0x0C  4  next
//   +0x10  8  key i64   (uId)
//   +0x18  8  padding
//
// BagItemVO offsets (tu mono_field_get_offset):
//   uId    = 24
//   metaId = 32
//   itemNum= 36

var _offUid=-1, _offMeta=-1, _offNum=-1, _offsetsReady=false;

function ensureOffsets(){
    if(_offsetsReady) return;
    var k=clsG("BagItemVO"); if(!k||k.isNull()) return;
    var fU=gf(k,"<uId>k__BackingField");
    var fM=gf(k,"<metaId>k__BackingField");
    var fN=gf(k,"<itemNum>k__BackingField");
    if(!fU.isNull()) _offUid =m_foff(fU);
    if(!fM.isNull()) _offMeta=m_foff(fM);
    if(!fN.isNull()) _offNum =m_foff(fN);
    _offsetsReady=true;
    console.log("[*] offsets uId="+_offUid+" metaId="+_offMeta+" itemNum="+_offNum);
}

function readItem(vp){
    return {
        uid:    vp.add(_offUid).readS64().toString(),
        metaId: vp.add(_offMeta).readS32(),
        num:    vp.add(_offNum).readS32()
    };
}

// Doc Dictionary<long, BagItemVO> bagItems
// Entry size = 0x20: [valPtr 8][hash i32][next i32][key i64][pad 8]
function readBagItems(){
    ensureOffsets();
    var bk=clsG("BagProxy");

    // bagItems la field thu 2, sau items
    // Lay offset bang mono_field_get_offset
    var fBagItems = gf(bk,"bagItems");
    if(fBagItems.isNull()) return {error:"no bagItems field"};

    var dictPtr = rp(_bagProxy, fBagItems);
    if(dictPtr.isNull()) return {error:"null bagItems dict"};

    // Dict<long,BagItemVO>: entry size=0x20
    // Array header: [vtable 8][monitor 8][max_length i32][pad i32][data...]
    var arr   = dictPtr.add(0x18).readPointer();
    if(arr.isNull()) return {error:"null entries array"};
    var slots = arr.add(0x04).readS32();
    var data  = arr.add(0x18);

    if(slots<=0||slots>500000) return {error:"bad slots: "+slots};

    var items=[],errors=0,used=0;
    for(var i=0;i<slots;i++){
        var base=data.add(i*0x20);
        try{
            var vp   = base.add(0).readPointer();
            var hash = base.add(8).readS32();
            if(hash<0) continue;
            used++;
            if(!vp||vp.isNull()) continue;
            var it=readItem(vp);
            if(it.metaId>0) items.push(it);
        }catch(e){ errors++; }
    }
    return {ok:true, slots:slots, used:used,
            valid:items.length, errors:errors, items:items};
}

rpc.exports = {
    getState: function(){
        return { ready:!!_netThis, hasBagProxy:!!_bagProxy };
    },

    sendAllianceGifts: function(){
        var p=newObj("CgAllianceGifts");
        return (p&&sendProto(p)) ? "OK" : "FAILED";
    },
    sendTakeAllianceGift: function(tab){
        var p=newObj("CgTakeAllianceGift"); if(!p) return "FAILED";
        wi32(p, gf(clsP("CgTakeAllianceGift"),"GiftType"), tab);
        return sendProto(p) ? "OK" : "FAILED";
    },
    sendGetBountyInfo: function(){
        var p=newObj("CgGetBountyInfo");
        return (p&&sendProto(p)) ? "OK" : "FAILED";
    },
    sendBountyReward: function(taskId){
        var p=newObj("CgBountyReward"); if(!p) return "FAILED";
        wi64(p, gf(clsP("CgBountyReward"),"Id"), taskId);
        return sendProto(p) ? "OK" : "FAILED";
    },
    sendUseBagItem: function(itemId, num){
        var p=newObj("CgUseBagItem"); if(!p) return "FAILED";
        wi64(p, gf(clsP("CgUseBagItem"),"ItemId"), parseInt(itemId));
        wi32(p, gf(clsP("CgUseBagItem"),"ItemNum"), num);
        wi32(p, gf(clsP("CgUseBagItem"),"Type"), 1);
        return sendProto(p) ? "OK" : "FAILED";
    },

    readBag: function(){
        if(!_bagProxy) return {error:"no BagProxy"};
        return readBagItems();
    }
};
"""

class Bot:
    def __init__(self):
        self.api=None; self._ready=False; self._bag_found=False

    def inject(self):
        pid=get_game_pid()
        print(f"[*] Attach PID {pid} ...")
        session=frida.attach(pid)
        script=session.create_script(JS)
        script.on("message", self._msg)
        script.load()
        self.api=script.exports

    def _msg(self, msg, _):
        if msg.get("type")!="send": return
        p=msg.get("payload",{})
        if p.get("type")=="ready":
            self._ready=True; print("[*] NetFacade ready")
        elif p.get("type")=="bag_proxy_found":
            self._bag_found=True; print(f"[*] BagProxy @ {p.get('addr')}")

    def wait_ready(self, timeout=30):
        print("[*] Cho NetFacade...")
        t0=time.time()
        while not self._ready:
            if time.time()-t0>timeout: raise TimeoutError("Timeout")
            time.sleep(0.5)

    def wait_bag(self, timeout=20):
        if self._bag_found: return
        print("[*] Cho BagProxy...")
        t0=time.time()
        while not self._bag_found:
            if time.time()-t0>timeout: print("[!] Timeout"); return
            time.sleep(0.5)

    def do_gifts(self, tabs=None):
        tabs=tabs or GIFT_TABS
        print(f"[*] AllianceGifts -> {self.api.send_alliance_gifts()}")
        time.sleep(0.5)
        for t in tabs:
            print(f"    Tab {t} -> {self.api.send_take_alliance_gift(t)}")
            time.sleep(0.4)

    def do_bounty(self, task_ids):
        print(f"[*] GetBountyInfo -> {self.api.send_get_bounty_info()}")
        time.sleep(0.5)
        for tid in task_ids:
            print(f"    Task {tid} -> {self.api.send_bounty_reward(tid)}")
            time.sleep(BOUNTY_DELAY)

    def read_bag(self):
        r=self.api.read_bag()
        if "error" in r: print(f"    [!] {r['error']}"); return []
        items=r["items"]
        print(f"    slots={r['slots']}  used={r['used']}  valid={r['valid']}  errors={r['errors']}")
        by={}
        for it in items: by.setdefault(it["metaId"],[]).append(it)
        print(f"\n    {'metaId':>12}  {'stacks':>6}  {'total':>8}")
        print(f"    {'-'*12}  {'-'*6}  {'-'*8}")
        for mid,lst in sorted(by.items()):
            print(f"    {mid:>12d}  {len(lst):>6d}  {sum(x['num'] for x in lst):>8d}")
        return items

    def open_chests(self, meta_ids):
        if not meta_ids: print("[!] Chua co metaId"); return
        items=self.read_bag()
        chests=[x for x in items if x["metaId"] in meta_ids]
        print(f"[*] Tim thay {len(chests)} stack ruong")
        for c in chests:
            r=self.api.send_use_bag_item(c["uid"], c["num"])
            print(f"    metaId={c['metaId']} x{c['num']} uid={c['uid']} -> {r}")
            time.sleep(0.5)

    def use_item(self, uid, num=1):
        print(f"[*] UseBagItem {uid} x{num} -> {self.api.send_use_bag_item(str(uid), num)}")


def main():
    bot=Bot(); bot.inject(); bot.wait_ready()
    while True:
        print("""
+--------------------------------------+
|        TOP HERO AUTO BOT             |
+--------------------------------------+
| [1] Guild Gifts                      |
| [2] Bounty (nhap task ID)            |
| [3] Doc bag                          |
| [4] Mo ruong (nhap metaId)           |
| [5] Use item thu cong                |
| [6] Full auto                        |
| [0] Thoat                            |
+--------------------------------------+""")
        c=input("Chon: ").strip()
        if c=="0": break
        elif c=="1": bot.do_gifts()
        elif c=="2":
            s=input("Task IDs: ")
            try: bot.do_bounty([int(x.strip()) for x in s.split(",") if x.strip()])
            except ValueError: print("[!] Sai")
        elif c=="3":
            bot.wait_bag(10); bot.read_bag()
        elif c=="4":
            s=input(f"metaId (Enter=CHEST_META_IDS={CHEST_META_IDS}): ").strip()
            mids=[int(x.strip()) for x in s.split(",") if x.strip()] if s else CHEST_META_IDS
            bot.wait_bag(10); bot.open_chests(mids)
        elif c=="5":
            uid=input("UID: ").strip()
            num=int(input("So luong: ").strip() or "1")
            bot.use_item(uid, num)
        elif c=="6":
            bot.do_gifts(); time.sleep(1)
            if CHEST_META_IDS: bot.wait_bag(15); bot.open_chests(CHEST_META_IDS)
            else: print("[!] Dien CHEST_META_IDS truoc")
        else: print("[!] Sai")
    print("[*] Bye.")

if __name__ == "__main__":
    main()