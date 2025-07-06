import os
import sv_ttk
import threading
import tkinter as tk
from pathlib import Path
from typing import Callable
from PIL import Image, ImageTk
from tkinter import filedialog, ttk

from .utils import Cfg


class PlaceholderEntry(ttk.Entry):
    def __init__(self, master=None, placeholder="PLACEHOLDER", color='grey', **kwargs):
        super().__init__(master, **kwargs)

        self.placeholder = placeholder
        self.placeholder_color = color
        self.default_fg_color = self['foreground']

        self.is_placeholder_active = False

        self.bind("<FocusIn>", self._on_focus_in)
        self.bind("<FocusOut>", self._on_focus_out)

        self._put_placeholder()

    def _put_placeholder(self):
        """插入占位符，设置颜色，并更新状态标志"""
        self.insert(0, self.placeholder)
        self['foreground'] = self.placeholder_color
        self.is_placeholder_active = True

    # 清除逻辑
    def _remove_placeholder(self):
        """如果占位符是激活的，则清除它，并恢复正常状态"""
        if self.is_placeholder_active:
            self.delete(0, "end")
            self['foreground'] = self.default_fg_color
            self.is_placeholder_active = False

    def _on_focus_in(self, event):
        """获取焦点时，清除占位符"""
        self._remove_placeholder()

    def _on_focus_out(self, event):
        """失去焦点时，如果为空则恢复占位符"""
        if not self.get():
            self._put_placeholder()

    def get(self):
        """如果占位符是激活状态，则返回空字符串"""
        return "" if self.is_placeholder_active else super().get()

    # 重写 insert 方法以供外部使用
    def insert(self, index, text):
        """
        在插入文本前，先清除占位符（如果存在）。
        """
        self._remove_placeholder()
        super().insert(index, text)


class MainWindow(tk.Tk):
    def __init__(self, parse: Callable):
        super().__init__()
        self.parse = parse  # 解析函数
        self.__cfg = Cfg()
        self.title(self.__cfg.exe_title)
        icon = _load_icon(self.__cfg.ICONS.LOGO)
        self.iconphoto(False, icon)  # 设置窗口图标
        self.resizable(False, False)
        # 启用 Sun Valley 主题
        sv_ttk.set_theme("light")
        # 初始化 Style
        style = ttk.Style()
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Icon.TButton", padding=4)
        # 线程
        self.__worker = None
        # 主容器 Frame
        self.__frame = ttk.Frame(self, padding=15)
        self.__frame.pack(expand=True, fill="both")
        self.__widget_init()

    def __widget_init(self):
        folder_icon = _load_icon(self.__cfg.ICONS.FOLDER)  # 加载文件夹图标
        # 输入项目
        self.__entry1 = PlaceholderEntry(self.__frame, placeholder="待解析ZIP压缩包路径", width=45)
        self.__entry1.grid(row=0, column=0, pady=12, padx=(0, 8), sticky="ew")
        btn1 = ttk.Button(
            self.__frame,
            image=folder_icon,
            style="Icon.TButton",  # 使用仅图标的样式
            command=lambda: _select_file(
                self.__entry1, True, Path(self.__entry1.get()).name if self.__entry1.get() else ""
            )
        )
        btn1.image = folder_icon  # 防止图标被垃圾回收
        btn1.grid(row=0, column=1, pady=12)

        # 输出项目
        self.__entry2 = PlaceholderEntry(self.__frame, placeholder='解析结果XLSX保存路径', width=45)
        self.__entry2.grid(row=1, column=0, pady=6, padx=(0, 8), sticky="ew")
        btn2 = ttk.Button(
            self.__frame,
            image=folder_icon,
            style="Icon.TButton",  # 使用仅图标的样式
            command=lambda: _select_file(
                self.__entry2,
                False,
                Path(self.__entry1.get()).stem+'.xlsx' if self.__entry1.get() else "output.xlsx")
            )
        btn2.image = folder_icon  # 防止图标被垃圾回收
        btn2.grid(row=1, column=1, pady=12)

        # 让输入框列随窗口拉伸
        self.__frame.grid_columnconfigure(0, weight=1)

        # --- 执行按钮 ---
        self.__exec_btn = ttk.Button(
            self.__frame,
            text="转换",
            style="Accent.TButton",
            command=lambda: self.execute()
        )
        # 使用 sticky="ew" 让按钮横向填满
        self.__exec_btn.grid(row=2, column=0, columnspan=2, pady=(20, 0), sticky="ew")

    def get_inputs(self) -> tuple[Path | None, Path | None]:
        return (Path(self.__entry1.get()) if self.__entry1.get() else None,
                Path(self.__entry2.get()) if self.__entry2.get() else None)

    def show(self):
        """ 窗口显示在屏幕中央 """
        self.update_idletasks()  # 更新窗口以获取正确的大小
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() - width) // 2
        y = (self.winfo_screenheight() - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.mainloop()

    def execute(self):
        inputs = self.get_inputs()
        if not all(inputs):
            tk.messagebox.showerror("请确保所有输入框都已填写！")
            return

        if not inputs[0].is_file():
            tk.messagebox.showerror(f"输入文件 '{inputs[0]}' 不存在！")
            return

        if not inputs[1].parent.exists():
            tk.messagebox.showerror(f"输出目录 '{inputs[1].parent}' 不存在！")
            return
        # 禁用按钮，防止重复启动
        self.__exec_btn.config(state="disabled", text="处理中…")

        # 启动后台线程
        self.__worker = threading.Thread(
            target=self.parse,
            args=inputs,
            daemon=True
        )
        self.__worker.start()

        # 启动轮询，检查线程何时结束
        self.after(100, self.__check_worker)

    def __check_worker(self):
        """
        每隔 100ms 检查一次线程状态。
        线程结束后，重新启用按钮，并不再循环。
        """
        if self.__worker and self.__worker.is_alive():
            # 线程还在跑，继续等
            self.after(100, self.__check_worker)
        else:
            # 线程已结束
            self.__exec_btn.config(state="normal", text="转换")
            # （此时 parse_callback 已经被调用来更新 status_label）
            self.__worker = None
            tk.messagebox.showinfo("完成", f"转换已完成！输出文件已保存至: {self.__entry2.get()}")

def _select_file(entry: PlaceholderEntry, is_file: bool, filename: str = ""):
    if is_file:
        file_path = filedialog.askopenfilename(
            title="选择文件",
            initialfile=filename,
            filetypes=[('ZIP files', '*.zip')]
        )
    else:
        file_path = filedialog.asksaveasfilename(
            title="保存文件",
            initialfile=filename,
            defaultextension=".xlsx",
            filetypes=[('Excel files', '*.xlsx')]
        )

    if file_path:
        entry.delete(0, tk.END)
        entry.insert(0, file_path)

def _load_icon(path: Path) -> ImageTk.PhotoImage | None:
    # 检查文件是否存在，如果不存在则返回 None
    if not os.path.exists(path):
        print(f"警告: 找不到图标文件 '{path}'")
        return None

    img = Image.open(path)
    # Pillow >= 10.0: Image.Resampling.LANCZOS; 较旧版本使用 Image.LANCZOS
    resample = getattr(Image, "Resampling", Image).LANCZOS
    img = img.resize((20, 20), resample)
    return ImageTk.PhotoImage(img)
