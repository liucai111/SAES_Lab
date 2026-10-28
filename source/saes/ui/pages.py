"""Stage-specific views. Cryptography remains in core/service/workflows."""
import csv
import json
import queue
import threading
import tkinter as tk
from datetime import datetime, timezone
from tkinter import ttk, filedialog
from .config import EXAMPLES
from .widgets import COLORS, ScrollPage, TextBox, Field, ResultPanel, label, card
from ..service import execute, parse_word, parse_pairs
from ..core import key_schedule_trace
from ..modes import generate_iv
from ..workflows import combine_keys, multiple_trace, compare_peer, independent_check, cbc_tamper_compare
from ..attack import meet_in_the_middle


def group_bits(value):
    return " ".join(value[i:i+4] for i in range(0,len(value),4))


def save_json(app, record, name):
    target=filedialog.asksaveasfilename(parent=app.root,initialfile=name,defaultextension=".json",filetypes=[("JSON记录","*.json")])
    if not target:return False
    try:
        with open(target,"w",encoding="utf-8") as stream:
            json.dump(record,stream,ensure_ascii=True,indent=2)
        app.notify("记录已保存。")
        return True
    except OSError as error:
        app.notify(f"保存失败：{error}",True)
        return False


class CipherPage(ScrollPage):
    """One cipher mode: show only fields needed by that mode and action."""
    def __init__(self,parent,app,mode):
        super().__init__(parent)
        self.app,self.mode=app,mode
        self.result=None;self.capture=None;self.copy_value="";self._setting=True
        self.action=tk.StringVar(value="encrypt")
        self.padding=tk.BooleanVar(value=True)
        self.encoding=tk.StringVar(value="hex")
        self.layout=tk.Frame(self.body,bg=COLORS["bg"])
        self.layout.pack(fill="x",anchor="n")
        self.layout.columnconfigure(0,weight=6,uniform="columns")
        self.layout.columnconfigure(1,weight=5,uniform="columns")
        self.form=card(self.layout,"输入参数")
        self.form.grid(row=0,column=0,sticky="nsew",padx=(0,12),pady=(0,12))
        right=card(self.layout)
        self.right_card=right;self._stacked=None
        right.grid(row=0,column=1,sticky="nsew",pady=(0,12))
        action_row=tk.Frame(self.form,bg=COLORS["card"]);action_row.pack(fill="x",pady=(0,12))
        ttk.Radiobutton(action_row,text="加密明文",variable=self.action,value="encrypt",style="Mode.TRadiobutton").pack(side="left",padx=(0,16))
        ttk.Radiobutton(action_row,text="解密密文",variable=self.action,value="decrypt",style="Mode.TRadiobutton").pack(side="left")
        self.data_title=label(self.form,"",bold=True)
        self.data_title.pack(anchor="w",pady=(0,5))
        self.data=TextBox(self.form,height=4 if mode.text or mode.iv else 3,on_change=self.invalidate)
        self.data.pack(fill="x")
        self.data_hint=label(self.form,"",size=9,color=COLORS["muted"],wrap=520)
        self.data_hint.pack(anchor="w",pady=(5,12))
        self.key_fields=[]
        for index in range(mode.key_count):
            title="密钥 K（16 bit）" if mode.key_count==1 else f"子密钥 K{index+1}（16 bit）"
            field=Field(self.form,title,hint="16位二进制，或0x开头的4位Hex",on_change=self.invalidate)
            field.pack(fill="x",pady=(0,12));self.key_fields.append(field)
        self.iv_field=None;self.iv_frame=None
        if mode.iv:
            self.iv_frame=tk.Frame(self.form,bg=COLORS["card"])
            self.iv_frame.pack(fill="x",pady=(0,12))
            self.iv_field=Field(self.iv_frame,"初始向量 IV（16 bit）","0x1234",hint="解密时使用加密那次保存的IV。",on_change=self.invalidate)
            self.iv_field.pack(side="left",fill="x",expand=True)
            ttk.Button(self.iv_frame,text="随机生成",command=self.random_iv).pack(side="right",padx=(10,0))
        self.option_area=tk.Frame(self.form,bg=COLORS["card"])
        self.option_area.pack(fill="x",pady=(0,8))
        self.padding_control=None
        if mode.padding:
            self.padding_control=ttk.Checkbutton(self.option_area,text="自动补齐为2字节分组（PKCS#7）",variable=self.padding)
            self.padding_control.pack(anchor="w",pady=(0,6))
            label(self.option_area,"取消补齐时，原文长度必须为偶数字节。",size=9,color=COLORS["muted"]).pack(anchor="w",pady=(0,6))
        elif mode.text and mode.iv:
            label(self.option_area,"CBC文本自动使用PKCS#7补齐，无需另选填充。",size=9,color=COLORS["muted"],wrap=520).pack(anchor="w",pady=(0,6))
        self.encoding_frame=None
        if mode.text:
            self.encoding_frame=tk.Frame(self.option_area,bg=COLORS["card"])
            label(self.encoding_frame,"密文编码",bold=True).pack(side="left",padx=(0,10))
            ttk.Combobox(self.encoding_frame,textvariable=self.encoding,values=("hex","base64","latin1"),state="readonly",width=12).pack(side="left")
        self.error=label(self.form,"",color=COLORS["error"],wrap=520)
        self.error.pack(anchor="w",pady=(0,8))
        row=tk.Frame(self.form,bg=COLORS["card"]);row.pack(fill="x")
        self.run_button=ttk.Button(row,text="开始加密",style="Accent.TButton",command=self.run)
        self.run_button.pack(side="left")
        self.example_button=ttk.Button(row,text="载入示例",command=self.load_example)
        self.example_button.pack(side="left",padx=8)
        self.clear_button=ttk.Button(row,text="清空输入",command=self.clear)
        self.clear_button.pack(side="right")
        self.output=ResultPanel(right,self.copy_result,self.export,self.handoff)
        self.output.pack(fill="both",expand=True)
        self.tamper_card=None;self.tamper_result=None
        if mode.code=="cbc-blocks":self._build_tamper()
        self.action.trace_add("write",lambda *_:self.configure_action())
        self.padding.trace_add("write",lambda *_:self.invalidate())
        self.encoding.trace_add("write",lambda *_:self.invalidate())
        self._setting=False
        self.load_example()
        self.body.bind("<Configure>",self._responsive,add="+")

    def _responsive(self,event):
        stacked=event.width<920
        if stacked==self._stacked:return
        self._stacked=stacked
        self.form.grid_configure(row=0,column=0,columnspan=2 if stacked else 1,padx=(0,0 if stacked else 12))
        self.right_card.grid_configure(row=1 if stacked else 0,column=0 if stacked else 1,columnspan=2 if stacked else 1)

    def configure_action(self):
        decrypt=self.action.get()=="decrypt"
        kind="ASCII原文" if self.mode.text and not decrypt else "密文" if decrypt else "明文"
        suffix="（按16 bit分组）" if self.mode.iv and not self.mode.text else "（16 bit）" if not self.mode.text else ""
        self.data_title.configure(text=kind+suffix)
        if self.mode.text:
            hint="输入Hex/Base64或原始Latin-1密文，编码与所选项一致。" if decrypt else "支持英文、数字、符号和换行；首尾空格会保留。"
        elif self.mode.iv:
            hint="例如 0x1234 0x5678；也可输入16位整数倍的连续二进制。"
        else:
            hint="例如 1101011100101000 或 0xD728；空格可用于分组阅读。"
        self.data_hint.configure(text=hint)
        self.run_button.configure(text="开始解密" if decrypt else "开始加密")
        if self.encoding_frame is not None:
            if decrypt:self.encoding_frame.pack(fill="x",pady=(3,5))
            else:self.encoding_frame.pack_forget()
        self.invalidate()

    def invalidate(self):
        if self._setting:return
        self.result=None;self.capture=None;self.copy_value=""
        self.output.reset();self.error.configure(text="")
        if self.tamper_card is not None:
            self.tamper_card.pack_forget();self.tamper_result=None

    def clear(self):
        self.data.set("")
        self.invalidate();self.data.text.focus_set()
        self.app.notify("输入已清空；密钥保留，可继续当前测试。")

    def load_example(self):
        self._setting=True
        data,keys=EXAMPLES[self.mode.code]
        self.action.set("encrypt");self.encoding.set("hex");self.padding.set(True)
        self.data.set(data)
        for field,key in zip(self.key_fields,keys):field.set(key)
        if self.iv_field is not None:self.iv_field.set("0x1234")
        self._setting=False;self.configure_action()
        self.app.notify("示例已载入。确认参数后点击开始加密。")

    def random_iv(self):
        self.iv_field.set(f"0x{generate_iv():04X}")
        self.app.notify("已生成新IV。请在加密后保存它，并交给解密方。")

    def _key(self):
        return self.key_fields[0].get() if self.mode.key_count==1 else combine_keys(field.get() for field in self.key_fields)

    def run(self):
        self.invalidate()
        try:
            data=self.data.get();key=self._key();decrypt=self.action.get()=="decrypt"
            iv=self.iv_field.get() if self.iv_field is not None else "0x0000"
            result=execute(self.mode.code,data,key,decrypt=decrypt,iv=iv,padding=self.padding.get(),encoding=self.encoding.get())
            details=self._details(result,data,key,decrypt)
            if "plaintext" in result:
                value=result["plaintext"]
                secondary=f"已还原 {len(value)} 个ASCII字符"+(" · 空字符串" if not value else "")
                note="原文的首尾空格与换行均保留。"
                copied=value
            elif self.mode.text:
                value=result["hex"]
                secondary="Hex 密文 · "+str(result["byte_length"])+" 字节\nBase64："+result["base64"]
                note="可直接点击下方按钮解密；无需复制整份记录。"
                copied=result["hex"]
            else:
                value=group_bits(result["binary"])
                secondary="Hex："+result["hex"]
                note="每4位加空格便于阅读；复制结果使用可直接输入的Hex。"
                copied=result["hex"]
            if self.mode.iv:
                secondary+="\n共享 IV："+result["iv"]["hex"]
            if self.mode.code=="block":
                secondary+="\n轮密钥："+" / ".join(result["round_keys"])
            self.result=result;self.copy_value=copied
            self.capture={"version":"2.0.0","created_at_utc":datetime.now(timezone.utc).isoformat(),
                          "mode":self.mode.code,"action":"decrypt" if decrypt else "encrypt","input":data,"key":key,
                          "iv":iv if self.mode.iv else None,"padding":self.padding.get() if self.mode.padding else True if self.mode.text and self.mode.iv else None,
                          "encoding":self.encoding.get() if self.mode.text and decrypt else None,"result":result}
            self.output.show(value,secondary,note,details,decrypt)
            if self.tamper_card is not None and not decrypt:
                self.tamper_card.pack(fill="x",pady=(2,14))
                count=len(result["blocks"])
                self.tamper_index.configure(to=count)
                self.tamper_index_value.set("2" if count>=2 else "1")
            self.app.notify("解密完成，结果已显示。" if decrypt else "加密完成，结果已显示。")
            return result
        except ValueError as error:
            self.error.configure(text=str(error));self.app.notify(str(error),True)
            return None

    def _details(self,result,data,key,decrypt):
        if self.mode.code=="block":
            lines=["密钥扩展"]
            for row in key_schedule_trace(parse_word(key)):
                lines.append(f"{row['step']:<18} {row['hex']:>4}  {group_bits(row['bits'])}")
            lines+=["","解密执行过程" if decrypt else "加密执行过程"]
            for row in result["trace"]:
                lines.append(f"{row['step']:<20} {row['hex']}  {group_bits(row['bits'])}")
            return "\n".join(lines)
        if self.mode.key_count>1:
            rows=multiple_trace(parse_word(data),[parse_word(field.get()) for field in self.key_fields],decrypt)
            return "\n".join(f"{row['step']}\n  Hex {row['hex']}  |  {group_bits(row['bits'])}" for row in rows)
        if "blocks" in result:
            return "\n".join(f"分组 {i+1}: {row['hex']}  {group_bits(row['binary'])}" for i,row in enumerate(result["blocks"]))
        if "binary" in result:
            return "密文字节（二进制）\n"+group_bits(result["binary"])+"\n\nLatin-1转义展示\n"+result.get("latin1_repr","")
        return "已按所选编码还原密文字节，解密后删除约定填充并还原ASCII。"

    def handoff(self):
        if self.result is None:return
        old_decrypt=self.action.get()=="decrypt"
        result=self.result
        if old_decrypt:
            value=result["plaintext"] if "plaintext" in result else result["hex"]
        else:
            value=result["hex"]
        self._setting=True
        self.action.set("encrypt" if old_decrypt else "decrypt")
        self.encoding.set("hex")
        self.data.set(value)
        self._setting=False;self.configure_action()
        self.app.notify("结果已填入输入框，密钥、IV和填充约定已保留；点击开始继续。")

    def copy_result(self):
        if self.result is None:return
        self.app.root.clipboard_clear();self.app.root.clipboard_append(self.copy_value)
        self.app.notify("结果已复制，可直接粘贴使用。")

    def export(self):
        if self.capture is not None:save_json(self.app,self.capture,f"{self.mode.code}_record.json")

    def _build_tamper(self):
        self.tamper_card=card(self.body,"CBC 篡改对比","先完成上方加密，再选择一次修改。每次都从本次正常密文重新计算。")
        row=tk.Frame(self.tamper_card,bg=COLORS["card"]);row.pack(fill="x")
        self.tamper_kind=tk.StringVar(value="翻转密文位")
        ttk.Combobox(row,textvariable=self.tamper_kind,values=("翻转密文位","替换密文分组","翻转IV位"),state="readonly",width=18).pack(side="left",padx=(0,12))
        self.index_box=tk.Frame(row,bg=COLORS["card"])
        self.index_box.pack(side="left")
        label(self.index_box,"第几组").pack(side="left",padx=(0,5))
        self.tamper_index_value=tk.StringVar(value="2")
        self.tamper_index=ttk.Spinbox(self.index_box,from_=1,to=4,textvariable=self.tamper_index_value,width=5)
        self.tamper_index.pack(side="left",padx=(0,12))
        self.change_label=label(row,"异或差分")
        self.change_label.pack(side="left",padx=(0,5))
        self.tamper_value=tk.StringVar(value="0x0001")
        ttk.Entry(row,textvariable=self.tamper_value,width=14).pack(side="left",ipady=3)
        ttk.Button(row,text="对比解密结果",style="Accent.TButton",command=self.compare_tamper).pack(side="left",padx=12)
        self.tamper_note=label(self.tamper_card,"",size=9,color=COLORS["muted"],wrap=950)
        self.tamper_note.pack(anchor="w",pady=(10,8))
        columns=("index","original","normal","modified","delta")
        self.tamper_table=ttk.Treeview(self.tamper_card,columns=columns,show="headings",height=4)
        for name,title in zip(columns,("分组","原明文","正常解密","修改后解密","与原文XOR")):
            self.tamper_table.heading(name,text=title);self.tamper_table.column(name,width=80 if name=="index" else 160,anchor="center")
        self.tamper_table.pack(fill="x")
        self.tamper_save=ttk.Button(self.tamper_card,text="保存篡改对比",command=self.export_tamper,state="disabled")
        self.tamper_save.pack(anchor="w",pady=(10,0))
        self.tamper_kind.trace_add("write",lambda *_:self._tamper_options())
        self.tamper_value.trace_add("write",lambda *_:self._clear_tamper())
        self.tamper_index_value.trace_add("write",lambda *_:self._clear_tamper())

    def _tamper_options(self):
        kind=self.tamper_kind.get()
        if kind=="翻转IV位":self.index_box.pack_forget()
        elif not self.index_box.winfo_manager():self.index_box.pack(side="left",before=self.change_label)
        self.change_label.configure(text="替换为" if kind=="替换密文分组" else "异或差分")
        self.tamper_value.set("0x0000" if kind=="替换密文分组" else "0x0001")
        self._clear_tamper()

    def _clear_tamper(self):
        self.tamper_result=None
        self.tamper_save.configure(state="disabled")
        self.tamper_table.delete(*self.tamper_table.get_children())
        self.tamper_note.configure(text="")

    def compare_tamper(self):
        if self.capture is None or self.action.get()!="encrypt":return
        try:
            kind={"翻转密文位":"xor","替换密文分组":"replace","翻转IV位":"iv"}[self.tamper_kind.get()]
            try:index=int(self.tamper_index_value.get()) if kind!="iv" else 1
            except ValueError:raise ValueError("分组序号须为整数")
            record=cbc_tamper_compare(self.capture["input"],self.capture["key"],self.capture["iv"],kind=kind,block_index=index,value=self.tamper_value.get())
            self.tamper_table.delete(*self.tamper_table.get_children())
            for row in record["rows"]:
                self.tamper_table.insert("","end",values=(row["index"],row["original"],row["normal"],row["modified"],row["xor_delta"]))
            affected="、".join(map(str,record["changed_blocks"])) or "无"
            self.tamper_note.configure(text=f"变化的明文分组：{affected}。修改后IV：{record['modified_iv']}\n修改后密文：{record['modified_ciphertext']}",fg=COLORS["muted"])
            self.tamper_result=record;self.tamper_save.configure(state="normal")
            self.app.notify("篡改对比完成，请对照各分组的变化。")
            return record
        except ValueError as error:
            self.tamper_result=None;self.tamper_save.configure(state="disabled")
            self.tamper_table.delete(*self.tamper_table.get_children())
            self.tamper_note.configure(text=str(error),fg=COLORS["error"]);self.app.notify(str(error),True)
            return None

    def export_tamper(self):
        if self.tamper_result is not None:save_json(self.app,self.tamper_result,"cbc_tamper.json")


class CrossPage(ScrollPage):
    def __init__(self,parent,app):
        super().__init__(parent);self.app=app;self.records=[];self.last_check=None
        self.form=card(self.body,"双方结果核对","输入另一组程序实际生成的密文；仅输入预期答案不能作为外部交叉测试证据。")
        self.form.pack(fill="x",pady=(0,12))
        fields=tk.Frame(self.form,bg=COLORS["card"]);fields.pack(fill="x")
        for index in range(3):fields.columnconfigure(index,weight=1,uniform="fields")
        self.plaintext=Field(fields,"明文 P（16 bit）","0xD728")
        self.key=Field(fields,"共同密钥 K（16 bit）","0x4AF5")
        self.peer=Field(fields,"另一组生成的密文 C","",hint="例如0x24EC，请使用对方实际输出")
        for i,field in enumerate((self.plaintext,self.key,self.peer)):field.grid(row=0,column=i,sticky="nsew",padx=(0,12 if i<2 else 0))
        row=tk.Frame(self.form,bg=COLORS["card"]);row.pack(fill="x",pady=(14,8))
        self.local_button=ttk.Button(row,text="本组加密",command=self.local_encrypt,style="Accent.TButton");self.local_button.pack(side="left")
        self.verify_button=ttk.Button(row,text="核对并解密对方密文",command=self.verify);self.verify_button.pack(side="left",padx=8)
        self.export_button=ttk.Button(row,text="导出交叉记录 CSV",command=self.export_csv,state="disabled");self.export_button.pack(side="right")
        self.summary=label(self.form,"先生成本组密文，与另一组交换结果，再进行核对。",wrap=1000)
        self.summary.pack(anchor="w",pady=(5,0))
        record_card=card(self.body,"交叉记录");record_card.pack(fill="x",pady=(0,12))
        cols=("id","plain","key","ours","peer","decoded","status")
        self.table=ttk.Treeview(record_card,columns=cols,show="headings",height=5)
        for key,title in zip(cols,("编号","明文","密钥","本组密文","对方密文","本组解密对方","结论")):
            self.table.heading(key,text=title);self.table.column(key,width=90 if key!="decoded" else 145,anchor="center")
        self.table.pack(fill="x")
        reference_card=card(self.body,"内置独立实现对照","使用独立的矩阵实现比较1024组固定样本；这是内部验证，不能替代另一小组的实测。")
        reference_card.pack(fill="x",pady=(0,12))
        self.reference_button=ttk.Button(reference_card,text="运行1024组独立对照",command=self.run_reference)
        self.reference_button.pack(anchor="w")
        self.reference_status=label(reference_card,"尚未运行。",wrap=950)
        self.reference_status.pack(anchor="w",pady=(10,0))
        self.reference_export=ttk.Button(reference_card,text="保存独立对照结果",command=self.export_reference,state="disabled")
        self.reference_export.pack(anchor="w",pady=(10,0))
        for field in (self.plaintext,self.key,self.peer):field.value.trace_add("write",lambda *_:self._edited())

    def _edited(self):
        self.summary.configure(text="参数已修改，请重新生成或核对。",fg=COLORS["muted"])

    def local_encrypt(self):
        try:
            result=execute("block",self.plaintext.get(),self.key.get())
            self.summary.configure(text=f"本组密文：{result['hex']}  |  {group_bits(result['binary'])}\n将此密文与共同密钥交给对方解密，核对能否恢复原文。",fg=COLORS["ink"])
            self.app.notify("本组密文已生成；另一方向还需由对方程序实际解密验证。")
            return result
        except ValueError as error:
            self.summary.configure(text=str(error),fg=COLORS["error"]);return None

    def verify(self):
        try:
            result=compare_peer(self.plaintext.get(),self.key.get(),self.peer.get())
            result["id"]=f"X{len(self.records)+1:03d}"
            result["created_at_utc"]=datetime.now(timezone.utc).isoformat()
            self.records.append(result)
            status="一致" if result["passed"] else "不一致"
            self.table.insert("","end",values=(result["id"],result["plaintext"],result["key"],result["local_cipher"],result["peer_cipher"],result["peer_decrypted"],status))
            self.summary.configure(text=f"本条核对{status}。本组密文 {result['local_cipher']}；对方密文 {result['peer_cipher']}；本组解密对方得到 {result['peer_decrypted']}。",fg=COLORS["accent"] if result["passed"] else COLORS["error"])
            self.export_button.configure(state="normal")
            self.app.notify("核对结果已记入表格；仍需保留对方程序的来源和运行记录。")
            return result
        except ValueError as error:
            self.summary.configure(text=str(error),fg=COLORS["error"]);return None

    def run_reference(self):
        self.reference_button.configure(state="disabled")
        self.reference_status.configure(text="正在计算……")
        self.update_idletasks()
        try:
            result=independent_check()
            self.last_check=result
            self.reference_status.configure(text=f"{result['passed']} / {result['count']} 组通过；失败 {result['failed']}；耗时 {result['elapsed_seconds']:.3f} 秒。\n结论仅适用于内置独立实现，不代表已完成外部小组验证。")
            self.reference_export.configure(state="normal")
            return result
        finally:
            self.reference_button.configure(state="normal")

    def export_reference(self):
        if self.last_check is not None:save_json(self.app,self.last_check,"independent_check.json")

    def export_csv(self):
        if not self.records:return
        target=filedialog.asksaveasfilename(parent=self.app.root,initialfile="cross_test.csv",defaultextension=".csv",filetypes=[("CSV记录","*.csv")])
        if not target:return
        try:
            with open(target,"w",newline="",encoding="utf-8-sig") as stream:
                writer=csv.DictWriter(stream,fieldnames=list(self.records[0]));writer.writeheader();writer.writerows(self.records)
            self.app.notify("交叉记录已导出。请补充对方组名及双方截图。")
        except OSError as error:self.app.notify(str(error),True)


class AttackPanel(ScrollPage):
    def __init__(self,parent,app):
        super().__init__(parent);self.app=app;self.worker=None;self.stop=threading.Event()
        self.events=queue.Queue();self.result=None;self.job=0;self.poll_id=None;self.closed=False
        form=card(self.body,"已知明密文","每行一对：明文 密文。全部观测必须来自同一组未知的双重密钥。此处不输入真实密钥。")
        form.pack(fill="x",pady=(0,12))
        self.pairs=TextBox(form,height=4,on_change=self._edited);self.pairs.pack(fill="x")
        self.pairs.set("0x1234 0xF04D\n0x5678 0x031E\n0x9ABC 0xAAD1",notify=False)
        row=tk.Frame(form,bg=COLORS["card"]);row.pack(fill="x",pady=(12,10))
        self.start_button=ttk.Button(row,text="开始完整搜索",style="Accent.TButton",command=self.start);self.start_button.pack(side="left")
        self.cancel_button=ttk.Button(row,text="取消搜索",command=self.cancel,state="disabled");self.cancel_button.pack(side="left",padx=8)
        self.save_button=ttk.Button(row,text="保存全部候选",command=self.export,state="disabled");self.save_button.pack(side="right")
        self.progress=ttk.Progressbar(form,maximum=131072);self.progress.pack(fill="x")
        self.status=label(form,"前向与反向各搜索65536个子密钥；三组示例应得到唯一候选。",size=9,color=COLORS["muted"],wrap=1000)
        self.status.pack(anchor="w",pady=(8,0))
        result_card=card(self.body,"候选密钥");result_card.pack(fill="x",pady=(0,12))
        self.summary=label(result_card,"尚未运行。",size=12,bold=True,wrap=1000);self.summary.pack(anchor="w",pady=(0,10))
        cols=("k1","k2","combined")
        self.table=ttk.Treeview(result_card,columns=cols,show="headings",height=7)
        for name,title in zip(cols,("子密钥 K1","子密钥 K2","组合密钥（K1在前）")):
            self.table.heading(name,text=title);self.table.column(name,width=150 if name!="combined" else 400,anchor="center")
        self.table.pack(fill="x")
        label(result_card,"界面最多列出100组；导出文件始终包含全部候选。单对观测可能有很多解，需要更多同钥样本筛选。",size=9,color=COLORS["muted"],wrap=1000).pack(anchor="w",pady=(10,0))
        self.poll_id=self.after(70,self.poll)

    def _edited(self):
        if self.worker and self.worker.is_alive():return
        self.result=None;self.save_button.configure(state="disabled")
        self.table.delete(*self.table.get_children());self.summary.configure(text="输入已修改，请重新搜索。")

    def start(self):
        if self.worker and self.worker.is_alive():return
        try:pairs=parse_pairs(self.pairs.get())
        except ValueError as error:self.status.configure(text=str(error),fg=COLORS["error"]);return
        self.stop.clear();self.result=None;self.job+=1;job=self.job
        self.table.delete(*self.table.get_children())
        self.start_button.configure(state="disabled");self.cancel_button.configure(state="normal");self.save_button.configure(state="disabled")
        self.pairs.text.configure(state="disabled");self.progress["value"]=0
        self.summary.configure(text="搜索中……");self.status.configure(text="开始建立完整前向表。",fg=COLORS["muted"])
        def work():
            try:
                result=meet_in_the_middle(pairs,progress=lambda phase,done,total:self.events.put((job,"progress",(phase,done,total))),cancelled=self.stop.is_set)
                self.events.put((job,"done",result))
            except InterruptedError as error:self.events.put((job,"cancel",str(error)))
            except Exception as error:self.events.put((job,"error",str(error)))
        self.worker=threading.Thread(target=work,daemon=True);self.worker.start()

    def cancel(self):
        if self.worker and self.worker.is_alive():
            self.stop.set();self.cancel_button.configure(state="disabled");self.status.configure(text="正在取消，请等待当前批次结束。")

    def poll(self):
        if self.closed:return
        try:
            while True:
                job,kind,value=self.events.get_nowait()
                if job!=self.job:continue
                if kind=="progress":
                    phase,done,total=value
                    self.progress["value"]=done+(65536 if phase=="反向搜索" else 0)
                    self.status.configure(text=f"{phase} · {done} / {total}")
                else:
                    self.start_button.configure(state="normal");self.cancel_button.configure(state="disabled")
                    self.pairs.text.configure(state="normal")
                    if kind=="done":
                        self.result=value
                        count=value["candidate_count"]
                        self.summary.configure(text=f"找到 {count} 组候选"+(" · 此组样本唯一" if count==1 else " · 可增加观测继续筛选" if count>1 else " · 请检查样本是否一致"))
                        for k1,k2 in value["candidates"][:100]:self.table.insert("","end",values=(f"0x{k1:04X}",f"0x{k2:04X}",f"0x{k1:04X}{k2:04X}"))
                        self.status.configure(text=f"搜索完成 · 前向{value['forward_keys']} / 反向{value['backward_keys']} · 第一对命中{value['first_pair_matches']}组 · 耗时{value['elapsed_seconds']:.3f}秒")
                        self.save_button.configure(state="normal");self.app.notify(f"中间相遇搜索完成：{count}组候选。")
                    else:
                        self.result=None;self.summary.configure(text="已取消，未产生完整结果。" if kind=="cancel" else "搜索失败。")
                        self.status.configure(text=value,fg=COLORS["muted"] if kind=="cancel" else COLORS["error"])
        except queue.Empty:pass
        self.poll_id=self.after(70,self.poll)

    def export(self):
        if self.result is None:return
        record=dict(self.result)
        record["known_pairs"]=self.pairs.get()
        record["candidates"]=[{"key1":f"0x{k1:04X}","key2":f"0x{k2:04X}","combined":f"0x{k1:04X}{k2:04X}"} for k1,k2 in self.result["candidates"]]
        save_json(self.app,record,"mitm_candidates.json")

    def shutdown(self):
        self.closed=True;self.stop.set()
        if self.poll_id is not None:
            try:self.after_cancel(self.poll_id)
            except tk.TclError:pass
