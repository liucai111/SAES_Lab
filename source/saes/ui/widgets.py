"""Reusable native widgets: validated forms, direct results, scrollable pages."""
import tkinter as tk
from tkinter import ttk

COLORS = {"bg": "#F3F6F4", "card": "#FFFFFF", "ink": "#193932", "muted": "#657B73",
          "line": "#DCE6DF", "accent": "#176B55", "soft": "#E6F2E9", "error": "#AF3737"}


def label(parent, text, *, size=10, bold=False, color=None, bg=None, wrap=0):
    return tk.Label(parent, text=text, font=(parent.winfo_toplevel().ui_font, size, "bold" if bold else "normal"),
                    fg=color or COLORS["ink"], bg=bg or COLORS["card"], anchor="w", justify="left", wraplength=wrap)


def card(parent, title=None, subtitle=None):
    frame = tk.Frame(parent, bg=COLORS["card"], highlightbackground=COLORS["line"], highlightthickness=1, padx=18, pady=16)
    if title:
        label(frame, title, size=12, bold=True).pack(anchor="w", pady=(0, 6))
    if subtitle:
        label(frame, subtitle, size=9, color=COLORS["muted"], wrap=650).pack(anchor="w", pady=(0, 10))
    return frame


class ScrollPage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=COLORS["bg"])
        self.canvas = tk.Canvas(self, bg=COLORS["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.body = tk.Frame(self.canvas, bg=COLORS["bg"])
        self.window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", lambda event: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda event: self.canvas.itemconfigure(self.window, width=event.width))
        self.bind_all("<MouseWheel>", self._wheel, add="+")
        self.bind_all("<Button-4>", lambda event: self._wheel(event, -1), add="+")
        self.bind_all("<Button-5>", lambda event: self._wheel(event, 1), add="+")

    def _wheel(self, event, step=None):
        if not self.winfo_ismapped():
            return
        widget = event.widget
        # Text and tree controls retain their own wheel behavior.
        if isinstance(widget, (tk.Text, ttk.Treeview)):
            return
        node = widget
        while node is not None:
            if node is self:
                delta = step if step is not None else (-1 if event.delta > 0 else 1)
                self.canvas.yview_scroll(delta, "units")
                return
            node = getattr(node, "master", None)


class TextBox(tk.Frame):
    """Preserve text exactly and notify only when its content actually changes."""
    def __init__(self, parent, *, height=3, on_change=None, readonly=False, font_size=10):
        super().__init__(parent, bg=COLORS["card"])
        self.callback = on_change
        self.previous = ""
        self.readonly = readonly
        self.text = tk.Text(self, height=height, width=1, wrap="word", undo=not readonly, relief="flat", borderwidth=0,
                            highlightthickness=1, highlightbackground=COLORS["line"], highlightcolor=COLORS["accent"],
                            padx=10, pady=9, fg=COLORS["ink"], bg="#F9FBFA" if readonly else "white",
                            font=(parent.winfo_toplevel().ui_font, font_size), insertbackground=COLORS["accent"])
        bar = ttk.Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        self.text.bind("<<Modified>>", self._modified)
        if readonly:
            self.text.configure(state="disabled")

    def _modified(self, event=None):
        if not self.text.edit_modified():
            return
        self.text.edit_modified(False)
        value = self.get()
        if value != self.previous:
            self.previous = value
            if self.callback:
                self.callback()

    def get(self):
        return self.text.get("1.0", "end-1c")

    def set(self, value, notify=True):
        changed = value != self.get()
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", value)
        self.previous = value
        self.text.edit_modified(False)
        if self.readonly:
            self.text.configure(state="disabled")
        if changed and notify and self.callback:
            self.callback()


class Field(tk.Frame):
    def __init__(self, parent, title, value="", hint="", on_change=None):
        super().__init__(parent, bg=COLORS["card"])
        self.title = label(self, title, size=10, bold=True)
        self.title.pack(anchor="w", pady=(0, 5))
        self.value = tk.StringVar(value=value)
        self.entry = ttk.Entry(self, textvariable=self.value)
        self.entry.pack(fill="x", ipady=5)
        if hint:
            label(self, hint, size=9, color=COLORS["muted"], wrap=610).pack(anchor="w", pady=(4, 0))
        if on_change:
            self.value.trace_add("write", lambda *_: on_change())

    def get(self):
        return self.value.get()

    def set(self, value):
        self.value.set(value)


class ResultPanel(tk.Frame):
    def __init__(self, parent, on_copy, on_save, on_handoff):
        super().__init__(parent, bg=COLORS["card"])
        label(self, "运算结果", size=12, bold=True).pack(anchor="w")
        self.caption = label(self, "输入参数后，点击左侧按钮开始。", size=9, color=COLORS["muted"], wrap=410)
        self.caption.pack(anchor="w", pady=(5, 10))
        self.value = TextBox(self, height=3, readonly=True, font_size=13)
        self.value.pack(fill="x")
        self.secondary = label(self, "", size=10, color=COLORS["muted"], wrap=410)
        self.secondary.pack(anchor="w", pady=(10, 5))
        self.note = label(self, "", size=9, color=COLORS["muted"], wrap=410)
        self.note.pack(anchor="w", pady=(0, 10))
        self.handoff = ttk.Button(self, text="将结果用于解密", command=on_handoff, style="Accent.TButton", state="disabled")
        self.handoff.pack(anchor="w", pady=(0, 10))
        row = tk.Frame(self, bg=COLORS["card"]);row.pack(fill="x")
        self.copy = ttk.Button(row, text="复制结果", command=on_copy, state="disabled")
        self.copy.pack(side="left")
        self.save = ttk.Button(row, text="保存记录", command=on_save, state="disabled")
        self.save.pack(side="left", padx=8)
        self.detail_button = ttk.Button(self, text="展开计算过程", command=self.toggle, state="disabled")
        self.detail_button.pack(anchor="w", pady=(14, 0))
        self.details = tk.Frame(self, bg=COLORS["card"])
        self.detail_text = TextBox(self.details, height=14, readonly=True, font_size=9)
        self.detail_text.pack(fill="both", expand=True, pady=(8, 0))
        self.opened = False

    def reset(self):
        self.value.set("", notify=False)
        self.caption.configure(text="输入参数后，点击左侧按钮开始。")
        self.secondary.configure(text="")
        self.note.configure(text="")
        self.detail_text.set("", notify=False)
        for button in (self.copy, self.save, self.handoff, self.detail_button):
            button.configure(state="disabled")
        self.details.pack_forget();self.opened=False
        self.detail_button.configure(text="展开计算过程")

    def show(self, value, secondary, note, details, decrypt):
        self.value.set(value, notify=False)
        self.caption.configure(text="解密完成 · 明文" if decrypt else "加密完成 · 密文")
        self.secondary.configure(text=secondary)
        self.note.configure(text=note)
        self.detail_text.set(details, notify=False)
        self.handoff.configure(text="将明文用于加密" if decrypt else "将密文用于解密")
        for button in (self.copy, self.save, self.handoff):button.configure(state="normal")
        self.detail_button.configure(state="normal" if details else "disabled")
        self.details.pack_forget();self.opened=False
        self.detail_button.configure(text="展开计算过程")

    def toggle(self):
        if self.opened:
            self.details.pack_forget();self.detail_button.configure(text="展开计算过程")
        else:
            self.details.pack(fill="both", expand=True);self.detail_button.configure(text="收起计算过程")
        self.opened=not self.opened
