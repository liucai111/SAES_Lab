"""Five-stage desktop workbench with independent, state-preserving pages."""
import tkinter as tk
from tkinter import ttk, font as tk_font
from .config import MODES, STAGES
from .widgets import COLORS, label
from .pages import CipherPage, CrossPage, AttackPanel


class SAESApp:
    def __init__(self,root):
        self.root=root
        families={name.casefold():name for name in tk_font.families(root)}
        self.ui_font=next((families[name.casefold()] for name in ("Microsoft YaHei","PingFang SC","Noto Sans CJK SC","WenQuanYi Micro Hei","Arial") if name.casefold() in families),"Arial")
        root.ui_font=self.ui_font
        for name in ("TkDefaultFont","TkTextFont","TkMenuFont","TkHeadingFont","TkCaptionFont"):
            tk_font.nametofont(name).configure(family=self.ui_font,size=10)
        root.title("S-AES 实验工作台 · 五关学习与验证")
        width=min(1280,max(1080,root.winfo_screenwidth()-70))
        height=min(820,max(700,root.winfo_screenheight()-70))
        root.geometry(f"{width}x{height}");root.minsize(1060,680)
        root.configure(bg=COLORS["bg"])
        self._style()
        self.nav_buttons=[];self.stage_pages=[];self.ciphers={};self.selected_stage=None
        outer=tk.Frame(root,bg=COLORS["bg"]);outer.pack(fill="both",expand=True)
        nav=tk.Frame(outer,bg="#FFFFFF",width=194,highlightbackground=COLORS["line"],highlightthickness=1)
        nav.pack(side="left",fill="y");nav.pack_propagate(False)
        label(nav,"S-AES",size=23,bold=True).pack(anchor="w",padx=23,pady=(26,2))
        label(nav,"实验工作台",size=11,color=COLORS["muted"]).pack(anchor="w",padx=23,pady=(0,23))
        label(nav,"按关卡开始实验",size=9,color=COLORS["muted"]).pack(anchor="w",padx=23,pady=(0,10))
        for index,(number,title,_) in enumerate(STAGES):
            button=tk.Button(nav,text=f"{number}   {title}",anchor="w",font=(self.ui_font,11),relief="flat",borderwidth=0,
                             bg="white",fg=COLORS["muted"],activebackground=COLORS["soft"],activeforeground=COLORS["accent"],
                             padx=16,pady=13,highlightthickness=0,cursor="hand2",command=lambda i=index:self.select_stage(i))
            button.pack(fill="x",padx=10,pady=3);self.nav_buttons.append(button)
        bottom=tk.Frame(nav,bg="white");bottom.pack(side="bottom",fill="x",padx=22,pady=22)
        label(bottom,"16 bit 分组",size=9,color=COLORS["muted"]).pack(anchor="w")
        label(bottom,"本地计算 · 无需联网",size=9,color=COLORS["muted"]).pack(anchor="w",pady=(4,0))
        label(bottom,"版本 2.0",size=9,color=COLORS["muted"]).pack(anchor="w",pady=(12,0))
        main=tk.Frame(outer,bg=COLORS["bg"]);main.pack(side="left",fill="both",expand=True,padx=22,pady=(19,12))
        self.badge=label(main,"",size=9,bold=True,color=COLORS["accent"],bg=COLORS["bg"]);self.badge.pack(anchor="w")
        self.heading=label(main,"",size=21,bold=True,bg=COLORS["bg"]);self.heading.pack(anchor="w",pady=(4,5))
        self.subtitle=label(main,"",size=10,color=COLORS["muted"],bg=COLORS["bg"],wrap=1000);self.subtitle.pack(anchor="w",pady=(0,16))
        self.host=tk.Frame(main,bg=COLORS["bg"]);self.host.pack(fill="both",expand=True)
        self.status=label(main,"就绪。",size=9,color=COLORS["muted"],bg=COLORS["bg"],wrap=1000);self.status.pack(anchor="w",pady=(10,0))
        basic=CipherPage(self.host,self,MODES["block"]);self.stage_pages.append(basic);self.ciphers["block"]=basic
        self.cross=CrossPage(self.host,self);self.stage_pages.append(self.cross)
        ascii_page=CipherPage(self.host,self,MODES["ascii"]);self.stage_pages.append(ascii_page);self.ciphers["ascii"]=ascii_page
        self.multiple_book=ttk.Notebook(self.host,style="Work.TNotebook")
        for code,caption in (("double","双重加密"),("triple","三重加密")):
            page=CipherPage(self.multiple_book,self,MODES[code]);self.ciphers[code]=page
            self.multiple_book.add(page,text=caption,padding=8)
        self.attack=AttackPanel(self.multiple_book,self);self.multiple_book.add(self.attack,text="中间相遇攻击",padding=8)
        self.stage_pages.append(self.multiple_book)
        self.cbc_book=ttk.Notebook(self.host,style="Work.TNotebook")
        for code,caption in (("cbc-blocks","分组数据与篡改"),("cbc-text","ASCII 文本")):
            page=CipherPage(self.cbc_book,self,MODES[code]);self.ciphers[code]=page
            self.cbc_book.add(page,text=caption,padding=8)
        self.stage_pages.append(self.cbc_book)
        root.protocol("WM_DELETE_WINDOW",self.close)
        self.select_stage(0)

    def _style(self):
        style=ttk.Style(self.root);style.theme_use("clam")
        style.configure("TButton",font=(self.ui_font,10),padding=(13,8),background="#F1F5F2",foreground=COLORS["ink"],bordercolor=COLORS["line"],relief="flat")
        style.map("TButton",background=[("active","#E0EBE3"),("disabled","#EFF2F0")],foreground=[("disabled","#9AA89F")])
        style.configure("Accent.TButton",background=COLORS["accent"],foreground="white",bordercolor=COLORS["accent"])
        style.map("Accent.TButton",background=[("active","#105341"),("disabled","#DCE5DE")],foreground=[("disabled","#91A398")])
        style.configure("TEntry",font=(self.ui_font,10),padding=(8,5),bordercolor=COLORS["line"],lightcolor=COLORS["line"],fieldbackground="white")
        style.configure("TCombobox",font=(self.ui_font,10),padding=(7,5),fieldbackground="white",bordercolor=COLORS["line"])
        style.configure("TRadiobutton",background="white",font=(self.ui_font,10),foreground=COLORS["ink"])
        style.configure("Mode.TRadiobutton",background="white",font=(self.ui_font,10),foreground=COLORS["ink"],padding=(4,5))
        style.configure("TCheckbutton",background="white",font=(self.ui_font,10),foreground=COLORS["ink"])
        style.configure("Treeview",font=(self.ui_font,9),rowheight=29,background="white",fieldbackground="white",foreground=COLORS["ink"],bordercolor=COLORS["line"])
        style.configure("Treeview.Heading",font=(self.ui_font,9,"bold"),padding=(6,8),background="#EAF0EC",foreground=COLORS["ink"])
        style.map("Treeview",background=[("selected","#DDEFE3")],foreground=[("selected",COLORS["ink"])])
        style.configure("Work.TNotebook",background=COLORS["bg"],borderwidth=0)
        style.configure("Work.TNotebook.Tab",padding=(20,10),font=(self.ui_font,10),background="#EAF0EC",foreground=COLORS["muted"])
        style.map("Work.TNotebook.Tab",background=[("selected","white")],foreground=[("selected",COLORS["accent"])])
        style.configure("Horizontal.TProgressbar",background=COLORS["accent"],troughcolor="#E5ECE7",borderwidth=0)

    def notify(self,message,error=False):
        if hasattr(self,"status"):self.status.configure(text=message,fg=COLORS["error"] if error else COLORS["muted"])

    def select_stage(self,index):
        if not 0<=index<len(self.stage_pages):raise ValueError("关卡序号须为0~4")
        for page in self.stage_pages:page.pack_forget()
        self.stage_pages[index].pack(fill="both",expand=True)
        self.selected_stage=index
        number,title,subtitle=STAGES[index]
        self.badge.configure(text=f"关卡 {number} / 05")
        self.heading.configure(text=title);self.subtitle.configure(text=subtitle)
        for i,button in enumerate(self.nav_buttons):
            button.configure(bg=COLORS["soft"] if i==index else "white",fg=COLORS["accent"] if i==index else COLORS["muted"],font=(self.ui_font,11,"bold" if i==index else "normal"))
        self.notify("当前关卡的输入会保留；可随时切换回来继续。")

    def start_attack(self):
        self.select_stage(3);self.multiple_book.select(self.attack);self.attack.start()

    def close(self):
        self.attack.shutdown();self.root.destroy()


def main():
    try:root=tk.Tk()
    except tk.TclError as error:
        raise SystemExit(f"无法启动桌面窗口：{error}\nWindows请运行 source/main.py；无桌面环境可使用CLI。")
    SAESApp(root);root.mainloop()
