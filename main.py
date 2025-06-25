import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import datetime
import random
import string
import json
import os
import subprocess
import base64
import re

from PIL import Image, ImageTk

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
import sys


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.id = None
        self.x = 0
        self.y = 0
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.widget.bind("<ButtonPress>", self.leave)

    def enter(self, event=None):
        self.schedule()

    def leave(self, event=None):
        self.unschedule()
        self.hidetip()

    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(500, self.showtip)

    def unschedule(self):
        if self.id:
            self.widget.after_cancel(self.id)
            self.id = None

    def showtip(self):
        if self.tip_window or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 25

        self.tip_window = tk.Toplevel(self.widget)
        self.tip_window.wm_overrideredirect(True)
        label = tk.Label(self.tip_window, text=self.text, background="#FFFFCC", relief="solid", borderwidth=1, font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)
        self.tip_window.wm_geometry(f"+{x}+{y}")

    def hidetip(self):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None


class MasterPasswordDialog(tk.Toplevel):
    def __init__(self, parent, title, prompt_text, verify_mode=False):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.title(title)
        self.result_password = None
        self.verify_mode = verify_mode

        self.geometry("350x250")
        self.resizable(False, False)

        main_frame = ttk.Frame(self, padding="15")
        main_frame.pack(expand=True, fill="both")

        ttk.Label(main_frame, text=prompt_text, wraplength=300).pack(pady=10)

        self.password_entry = ttk.Entry(main_frame, show="*", width=30)
        self.password_entry.pack(pady=5)
        self.password_entry.bind("<Return>", lambda event: self.ok_pressed())

        if not self.verify_mode:
            ttk.Label(main_frame, text="Repetir Contraseña:").pack(pady=5)
            self.confirm_password_entry = ttk.Entry(main_frame, show="*", width=30)
            self.confirm_password_entry.pack(pady=5)
            self.confirm_password_entry.bind("<Return>", lambda event: self.ok_pressed())
        else:
            self.confirm_password_entry = None

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="OK", command=self.ok_pressed).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancelar", command=self.cancel_pressed).pack(side="right", padx=5)

        self.parent = parent
        self.wait_window(self)

    def ok_pressed(self):
        password = self.password_entry.get()
        if self.verify_mode:
            self.result_password = password
            self.destroy()
        else:
            confirm_password = self.confirm_password_entry.get()
            if password == confirm_password:
                if password:
                    self.result_password = password
                    self.destroy()
                else:
                    messagebox.showwarning("Advertencia", "La contraseña no puede estar vacía.", parent=self)
            else:
                messagebox.showerror("Error", "Las contraseñas no coinciden.", parent=self)

    def cancel_pressed(self):
        self.result_password = None
        self.destroy()


class BastionPasswordManager:
    DRAG_THRESHOLD = 5

    def __init__(self, root):
        self.root = root
        self.root.title("Bastión")

        # --- Cargar y establecer el icono de la aplicación (usando PNG) ---
        png_file_name = "icono_bastion.png"
        png_path_full = resource_path(os.path.join("Icons", png_file_name))
        
        try:
            original_image = Image.open(png_path_full)
            icon_image_32 = original_image.resize((32, 32), Image.Resampling.LANCZOS)
            icon_image_64 = original_image.resize((64, 64), Image.Resampling.LANCZOS)

            self.tk_icon_32 = ImageTk.PhotoImage(icon_image_32)
            self.tk_icon_64 = ImageTk.PhotoImage(icon_image_64)

            # Usar iconphoto para el icono de la ventana principal con el PNG
            self.root.iconphoto(True, self.tk_icon_32, self.tk_icon_64)
        except FileNotFoundError:
            messagebox.showwarning("Icono no encontrado", f"No se encontró el archivo de icono: {png_path_full}. La aplicación se ejecutará sin icono.")
        except Exception as e:
            messagebox.showwarning("Error de icono (PNG)", f"No se pudo cargar el icono PNG: {e}. La aplicación se ejecutará sin icono.")
        # ----------------------------------------------------

        self.root.geometry("900x600")

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.master_key = None
        self.fernet_cipher = None
        self.current_file_path = None
        self.current_salt = None

        self.entries_data_store = {}
        self.all_entries_data = {}

        self._drag_item = None
        self._drag_item_candidate = None
        self._start_x = 0
        self._start_y = 0
        self._is_dragging = False
        self.db_node_id = None

        self.current_sort_key = "Title"
        self.current_sort_reverse = False

        self.root.grid_rowconfigure(0, weight=0)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_rowconfigure(2, weight=0)
        self.root.grid_columnconfigure(0, weight=1)


        self.create_menu_bar()
        self.create_toolbar()
        self.create_main_panels()
        self.create_status_bar()

        self.populate_group_tree()
        self.update_status_bar(None)

        self.root.after(100, self._prompt_on_startup)

    def _prompt_on_startup(self):
        response = messagebox.askyesno("Bienvenido", "¿Deseas abrir una base de datos existente?")
        if response:
            self.open_database()
        else:
            self.start_new_database()


    def create_menu_bar(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Nuevo...", command=self.start_new_database)
        file_menu.add_command(label="Abrir...", command=self.open_database)
        file_menu.add_command(label="Guardar", command=self.save_database)
        file_menu.add_command(label="Guardar Como...", command=lambda: self.save_database(save_as=True))
        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=self.on_closing)
        menubar.add_cascade(label="Archivo", menu=file_menu)

        group_menu = tk.Menu(menubar, tearoff=0)
        group_menu.add_command(label="Añadir Grupo", command=self.open_add_group_window)
        group_menu.add_command(label="Eliminar Grupo", command=lambda: self.delete_selected_group(None))
        menubar.add_cascade(label="Grupo", menu=group_menu)

        entry_menu = tk.Menu(menubar, tearoff=0)
        entry_menu.add_command(label="Editar Entrada/Grupo", command=self.open_edit_entry_window)
        entry_menu.add_command(label="Eliminar Entrada", command=self.delete_selected_entry)
        entry_menu.add_separator()
        entry_menu.add_command(label="Copiar Usuario", command=lambda: self.copy_entry_detail("User Name"))
        entry_menu.add_command(label="Copiar Contraseña", command=lambda: self.copy_entry_detail("Password"))
        entry_menu.add_command(label="Copiar URL", command=lambda: self.copy_entry_detail("URL"))
        menubar.add_cascade(label="Entrada", menu=entry_menu)

        find_menu = tk.Menu(menubar, tearoff=0)
        find_menu.add_command(label="Buscar...", command=self._activate_search)
        menubar.add_cascade(label="Buscar", menu=find_menu)

        view_menu = tk.Menu(menubar, tearoff=0)

        sort_by_title_menu = tk.Menu(view_menu, tearoff=0)
        sort_by_title_menu.add_command(label="Ascendente", command=lambda: self._sort_entries("Title", False))
        sort_by_title_menu.add_command(label="Descendente", command=lambda: self._sort_entries("Title", True))
        view_menu.add_cascade(label="Ordenar por Título", menu=sort_by_title_menu)

        sort_by_username_menu = tk.Menu(view_menu, tearoff=0)
        sort_by_username_menu.add_command(label="Ascendente", command=lambda: self._sort_entries("User Name", False))
        sort_by_username_menu.add_command(label="Descendente", command=lambda: self._sort_entries("User Name", True))
        view_menu.add_cascade(label="Ordenar por Nombre de Usuario", menu=sort_by_username_menu)

        sort_by_creation_time_menu = tk.Menu(view_menu, tearoff=0)
        sort_by_creation_time_menu.add_command(label="Más Reciente", command=lambda: self._sort_entries("Creation Time", True))
        sort_by_creation_time_menu.add_command(label="Más Antiguo", command=lambda: self._sort_entries("Creation Time", False))
        view_menu.add_cascade(label="Ordenar por Fecha de Creación", menu=sort_by_creation_time_menu)

        sort_by_modification_time_menu = tk.Menu(view_menu, tearoff=0)
        sort_by_modification_time_menu.add_command(label="Más Reciente", command=lambda: self._sort_entries("Last Modification Time", True))
        sort_by_modification_time_menu.add_command(label="Más Antiguo", command=lambda: self._sort_entries("Last Modification Time", False))
        view_menu.add_cascade(label="Ordenar por Última Modificación", menu=sort_by_modification_time_menu)

        menubar.add_cascade(label="Ver", menu=view_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Generador de Contraseñas Avanzado...", command=self._open_advanced_password_generator_window)
        tools_menu.add_command(label="Comprobador de Fortaleza de Contraseñas...", command=self._open_password_strength_checker)
        tools_menu.add_command(label="Limpiar Portapapeles", command=self.clean_clipboard)
        tools_menu.add_separator()
        tools_menu.add_command(label="Cambiar Contraseña Maestra...", command=self.open_change_master_password_window)
        menubar.add_cascade(label="Herramientas", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Acerca de...", command=self.show_about_dialog)
        help_menu.add_command(label="Instrucciones", command=self.open_instructions_file)
        menubar.add_cascade(label="Ayuda", menu=help_menu)

    def create_toolbar(self):
        toolbar_frame = ttk.Frame(self.root, relief="raised", borderwidth=1)
        toolbar_frame.grid(row=0, column=0, sticky="ew")

        toolbar_frame.grid_columnconfigure(0, weight=0)
        toolbar_frame.grid_columnconfigure(1, weight=1)
        toolbar_frame.grid_columnconfigure(2, weight=0)

        button_container = ttk.Frame(toolbar_frame)
        button_container.grid(row=0, column=0, sticky="w", padx=(5,0))

        btn_add_group = ttk.Button(button_container, text="➕G", command=self.open_add_group_window)
        btn_add_group.pack(side="left", padx=2, pady=2)
        ToolTip(btn_add_group, "Añadir Grupo")

        btn_add_entry = ttk.Button(button_container, text="➕E", command=self.open_add_entry_window)
        btn_add_entry.pack(side="left", padx=2, pady=2)
        ToolTip(btn_add_entry, "Añadir Entrada")

        ttk.Separator(button_container, orient="vertical").pack(side="left", fill="y", padx=5, pady=2)

        btn_edit_entry = ttk.Button(button_container, text="✏️", command=self.open_edit_entry_window)
        btn_edit_entry.pack(side="left", padx=2, pady=2)
        ToolTip(btn_edit_entry, "Editar Entrada/Grupo")

        btn_delete_selected = ttk.Button(button_container, text="🗑️", command=self.delete_selected)
        btn_delete_selected.pack(side="left", padx=2, pady=2)
        ToolTip(btn_delete_selected, "Eliminar Seleccionado")

        btn_copy_user = ttk.Button(button_container, text="📋U", command=lambda: self.copy_entry_detail("User Name"))
        btn_copy_user.pack(side="left", padx=2, pady=2)
        ToolTip(btn_copy_user, "Copiar Usuario")

        btn_copy_pwd = ttk.Button(button_container, text="📋P", command=lambda: self.copy_entry_detail("Password"))
        btn_copy_pwd.pack(side="left", padx=2, pady=2)
        ToolTip(btn_copy_pwd, "Copiar Contraseña")

        btn_copy_url = ttk.Button(button_container, text="📋L", command=lambda: self.copy_entry_detail("URL"))
        btn_copy_url.pack(side="left", padx=2, pady=2)
        ToolTip(btn_copy_url, "Copiar URL")

        search_frame = ttk.Frame(toolbar_frame)
        search_frame.grid(row=0, column=2, sticky="e", padx=5)
        ttk.Label(search_frame, text="Buscar:").pack(side="left", padx=5)
        self.search_entry = ttk.Entry(search_frame, width=30)
        self.search_entry.pack(side="left", padx=5, pady=2)
        ttk.Label(search_frame, text="🔍").pack(side="left", padx=2)
        self.search_entry.bind("<KeyRelease>", self._filter_entries)


    def create_main_panels(self):
        self.main_pane = ttk.PanedWindow(self.root, orient="horizontal")
        self.main_pane.grid(row=1, column=0, sticky="nsew")

        group_container_frame = ttk.Frame(self.main_pane, relief="sunken", borderwidth=1)
        group_container_frame.grid_rowconfigure(1, weight=1)
        group_container_frame.grid_columnconfigure(0, weight=1)
        self.main_pane.add(group_container_frame, weight=1)

        ttk.Label(group_container_frame, text="Grupos", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="nw", padx=5, pady=5)
        self.group_tree = ttk.Treeview(group_container_frame, show="tree", selectmode="browse")
        self.group_tree.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.group_tree.bind("<<TreeviewSelect>>", self.on_group_select)
        self.group_tree.bind("<Button-1>", self._start_drag)

        self.group_tree.bind("<B1-Motion>", self._do_drag)
        self.group_tree.bind("<ButtonRelease-1>", self._drop)

        group_scrollbar = ttk.Scrollbar(group_container_frame, orient="vertical", command=self.group_tree.yview)
        group_scrollbar.grid(row=1, column=1, sticky="ns")
        self.group_tree.configure(yscrollcommand=group_scrollbar.set)

        entry_frame = ttk.Frame(self.main_pane, relief="sunken", borderwidth=1)
        entry_frame.grid_rowconfigure(0, weight=1)
        entry_frame.grid_columnconfigure(0, weight=1)
        self.main_pane.add(entry_frame, weight=3)

        columns = ("Title", "User Name", "Password", "URL", "Notes")
        self.entry_tree = ttk.Treeview(entry_frame, columns=columns, show="headings", selectmode="browse")
        self.entry_tree.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        for col in columns:
            self.entry_tree.heading(col, text=col)
            if col == "Password":
                self.entry_tree.column(col, width=80, anchor="center")
            else:
                self.entry_tree.column(col, width=100, anchor="w")

        entry_scrollbar_y = ttk.Scrollbar(entry_frame, orient="vertical", command=self.entry_tree.yview)
        entry_scrollbar_y.grid(row=0, column=1, sticky="ns")
        self.entry_tree.configure(yscrollcommand=entry_scrollbar_y.set)

        entry_scrollbar_x = ttk.Scrollbar(entry_frame, orient="horizontal", command=self.entry_tree.xview)
        entry_scrollbar_x.grid(row=1, column=0, sticky="ew")
        self.entry_tree.configure(xscrollcommand=entry_scrollbar_x.set)

        self.entry_tree.bind("<<TreeviewSelect>>", self.update_status_bar)
        self.entry_tree.bind("<Double-1>", self._on_entry_double_click)

    def get_full_tree_item_path(self, item_id):
        if not item_id:
            return "Database"

        path_parts = []
        current_id = item_id
        while current_id and self.group_tree.parent(current_id) != "":
            item_text = self.group_tree.item(current_id, "text")
            path_parts.insert(0, item_text)
            current_id = self.group_tree.parent(current_id)

        if current_id:
            path_parts.insert(0, self.group_tree.item(current_id, "text"))

        return "/".join(path_parts)

    def populate_group_tree(self):
        for item in self.group_tree.get_children():
            self.group_tree.delete(item)

        path_to_tree_item_id = {"": ""}

        all_actual_group_paths = set()
        for group_path in self.all_entries_data.keys():
            parts = group_path.split('/')
            current_partial_path_list = []
            for part in parts:
                current_partial_path_list.append(part)
                all_actual_group_paths.add("/".join(current_partial_path_list))

        sorted_group_paths = sorted(list(all_actual_group_paths))

        first_group_id = None

        for full_path in sorted_group_paths:
            parts = full_path.split('/')
            current_group_name = parts[-1]

            parent_full_path_for_data = "/".join(parts[:-1])

            parent_tree_item_id = path_to_tree_item_id.get(parent_full_path_for_data, "")

            if parent_tree_item_id is not None:
                new_item_id = self.group_tree.insert(parent_tree_item_id, "end", text=current_group_name, open=True, tags=("group", current_group_name.lower()))
                path_to_tree_item_id[full_path] = new_item_id
                if first_group_id is None:
                    first_group_id = new_item_id
            else:
                print(f"Warning: Parent Treeview item not found for path: {full_path} (Parent: {parent_full_path_for_data})")

        if first_group_id:
            self.group_tree.selection_set(first_group_id)
            self.group_tree.focus(first_group_id)
            self.group_tree.see(first_group_id)
            self._filter_entries()
        else:
            self.group_tree.selection_set("")
            self._filter_entries()


    def _filter_entries(self, event=None):
        search_query = self.search_entry.get().strip().lower()
        for item in self.entry_tree.get_children():
            self.entry_tree.delete(item)
        self.entries_data_store = {}

        selected_group_full_path = self.get_selected_group_full_path()

        entries_to_process = []
        if selected_group_full_path == "Database":
            if search_query:
                for group_path, entries_list in self.all_entries_data.items():
                    for entry in entries_list:
                        entries_to_process.append(entry)

        else:
            entries_to_process = self.all_entries_data.get(selected_group_full_path, [])

        filtered_entries = []
        if search_query:
            for entry in entries_to_process:
                if (search_query in entry.get("Title", "").lower() or
                    search_query in entry.get("User Name", "").lower() or
                    search_query in entry.get("URL", "").lower() or
                    search_query in entry.get("Notes", "").lower()):
                    filtered_entries.append(entry)
        else:
            filtered_entries = entries_to_process

        if self.current_sort_key:
            try:
                if self.current_sort_key in ["Creation Time", "Last Modification Time"]:
                    filtered_entries.sort(key=lambda x: datetime.datetime.strptime(x.get(self.current_sort_key, "01/01/2000 12:00:00 a.m."), "%d/%m/%Y %I:%M:%S %p."), reverse=self.current_sort_reverse)
                else:
                    filtered_entries.sort(key=lambda x: str(x.get(self.current_sort_key, "")).lower(), reverse=self.current_sort_reverse)
            except Exception as e:
                print(f"Error durante el ordenamiento: {e}")

        for entry in filtered_entries:
            displayed_password = "*********" if entry.get("Password") else ""
            item_id = self.entry_tree.insert("", "end", values=(entry.get("Title"), entry.get("User Name"), displayed_password, entry.get("URL"), entry.get("Notes")))
            self.entries_data_store[item_id] = entry

        self.update_status_bar(None)


    def _sort_entries(self, sort_key, reverse):
        self.current_sort_key = sort_key
        self.current_sort_reverse = reverse
        self._filter_entries()


    def on_group_select(self, event):
        self._filter_entries()


    def create_status_bar(self):
        self.status_bar_frame = ttk.Frame(self.root, relief="sunken", borderwidth=1)
        self.status_bar_frame.grid(row=2, column=0, sticky="ew")
        self.status_bar_frame.grid_columnconfigure(0, weight=1)
        self.status_bar_frame.grid_columnconfigure(1, weight=1)
        self.status_bar_frame.grid_columnconfigure(2, weight=0)

        self.details_label = ttk.Label(self.status_bar_frame, text="Listo.", font=("Arial", 9))
        self.details_label.grid(row=0, column=0, sticky="w", padx=10, pady=2)

        self.selection_count_label = ttk.Label(self.status_bar_frame, text="0 de 0 seleccionados", font=("Arial", 9))
        self.selection_count_label.grid(row=0, column=1, sticky="e", padx=10, pady=2)

        self.datetime_label = ttk.Label(self.status_bar_frame, text="", font=("Arial", 9))
        self.datetime_label.grid(row=0, column=2, sticky="e", padx=10, pady=2)

        self.update_datetime_in_status_bar()

    def update_status_bar(self, event):
        selected_items = self.entry_tree.selection()
        num_selected = len(selected_items)
        total_entries = len(self.entry_tree.get_children())

        self.details_label.config(text="Listo.")
        self.selection_count_label.config(text=f"{num_selected} de {total_entries} seleccionados")

        self.update_datetime_in_status_bar()

    def update_datetime_in_status_bar(self):
        now = datetime.datetime.now()

        hour = now.hour
        am_pm = "a.m."
        if hour >= 12:
            am_pm = "p.m."
            if hour > 12:
                hour -= 12
        if hour == 0:
            hour = 12

        minutes = now.minute
        if minutes < 10:
            minutes = f"0{minutes}"

        date_time_str = f"{now.day}/{now.month}/{now.year} {hour}:{minutes}{am_pm}"
        self.datetime_label.config(text=f"ESP LAA {date_time_str}")
        self.root.after(60000, self.update_datetime_in_status_bar)

    def get_selected_group_full_path(self):
        selected_item_id = self.group_tree.selection()
        if selected_item_id:
            return self.get_full_tree_item_path(selected_item_id[0])
        return "Database"

    def on_closing(self):
        if self.master_key is not None:
            if messagebox.askyesno("Guardar Cambios", "¿Deseas guardar los cambios antes de salir de Bastión?"):
                self.save_database()

        if messagebox.askyesno("Salir", "¿Estás seguro de que quieres salir de Bastión?"):
            self.root.destroy()

    def _start_drag(self, event):
        self._start_x = event.x
        self._start_y = event.y
        self._drag_item_candidate = self.group_tree.identify_row(event.y)

        if not self._drag_item_candidate:
            self.group_tree.selection_set("")
            self._filter_entries()
            self._reset_drag_state()
            return

        self._is_dragging = False
        self._drag_item = None
        self.root.config(cursor="")

    def _do_drag(self, event):
        if not self._drag_item_candidate:
            return

        dx = abs(event.x - self._start_x)
        dy = abs(event.y - self._start_y)

        if not self._is_dragging and (dx > self.DRAG_THRESHOLD or dy > self.DRAG_THRESHOLD):
            self._is_dragging = True
            self._drag_item = self._drag_item_candidate

            if not self._drag_item or self._drag_item == "":
                self._drag_item = None
                self._is_dragging = False
                self.root.config(cursor="")
                return

            self.root.config(cursor="hand2")

    def _drop(self, event):
        self.root.config(cursor="")

        if not self._is_dragging or self._drag_item is None:
            self._reset_drag_state()
            return

        target_item = self.group_tree.identify_row(event.y)

        if not target_item or target_item == "":
            target_full_path_for_data_update = "Database"
        else:
            target_full_path_for_data_update = self.get_full_tree_item_path(target_item)

        source_full_path = self.get_full_tree_item_path(self._drag_item)

        if source_full_path == target_full_path_for_data_update:
            messagebox.showwarning("Mover Grupo", "No se puede mover un grupo sobre sí mismo.")
            self._reset_drag_state()
            return

        if target_full_path_for_data_update != "Database" and target_full_path_for_data_update.startswith(f"{source_full_path}/"):
             messagebox.showwarning("Mover Grupo", "No se puede mover un grupo a uno de sus subgrupos.")
             self._reset_drag_state()
             return

        self._remap_group_paths_in_data(source_full_path, target_full_path_for_data_update, is_rename_op=False)

        self.populate_group_tree()

        self._reset_drag_state()

    def _reset_drag_state(self):
        self._drag_item = None
        self._drag_item_candidate = None
        self._is_dragging = False
        self._start_x = 0
        self._start_y = 0
        self.root.config(cursor="")

    def _remap_group_paths_in_data(self, old_full_path, new_path_context, is_rename_op=False):
        remapping = {}

        if is_rename_op:
            remapping[old_full_path] = new_path_context
            for current_path in list(self.all_entries_data.keys()):
                if current_path.startswith(f"{old_full_path}/"):
                    suffix = current_path[len(old_full_path):]
                    remapping[current_path] = f"{new_path_context}{suffix}"
        else:
            moved_group_base_name = old_full_path.split('/')[-1]
            if new_path_context == "Database":
                new_full_path_for_moved_group = moved_group_base_name
            else:
                new_full_path_for_moved_group = f"{new_path_context}/{moved_group_base_name}"

            remapping[old_full_path] = new_full_path_for_moved_group
            for current_path in list(self.all_entries_data.keys()):
                if current_path.startswith(f"{old_full_path}/"):
                    suffix = current_path[len(old_full_path):]
                    remapping[current_path] = f"{new_full_path_for_moved_group}{suffix}"

        new_all_entries_data = {}
        for current_path, entries in self.all_entries_data.items():
            if current_path in remapping:
                new_all_entries_data[remapping[current_path]] = entries
            else:
                new_all_entries_data[current_path] = entries

        self.all_entries_data = new_all_entries_data

    def _derive_key(self, master_password, salt=None):
        if salt is None:
            salt = os.urandom(16)

        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(master_password.encode('utf-8'))
        return base64.urlsafe_b64encode(key), salt

    def _encrypt_data(self, data, cipher):
        try:
            json_data = json.dumps(data).encode('utf-8')
            encrypted_bytes = cipher.encrypt(json_data)
            return encrypted_bytes
        except Exception as e:
            print(f"Error al encriptar los datos: {e}")
            return None

    def _decrypt_data(self, encrypted_bytes, cipher):
        try:
            decrypted_bytes = cipher.decrypt(encrypted_bytes)
            decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
            return decrypted_data
        except InvalidToken:
            messagebox.showerror("Error de Desencriptación", "Contraseña maestra incorrecta o datos corruptos.")
            return None
        except Exception as e:
            print(f"Error al desencriptar los datos: {e}")
            messagebox.showerror("Error de Desencriptación", f"Error al desencriptar los datos: {e}")
            return None

    def _load_database_file_internal(self, file_path, master_password):
        try:
            with open(file_path, 'rb') as f:
                salt_b64 = f.read(24)
                if len(salt_b64) < 24:
                    messagebox.showerror("Error de Carga", "Archivo de base de datos corrupto o incompleto (salt faltante).")
                    return None, None, None
                salt = base64.urlsafe_b64decode(salt_b64)

                encrypted_data_bytes = f.read()
                if not encrypted_data_bytes:
                    messagebox.showerror("Error de Carga", "Archivo de base de datos vacío o corrupto (datos encriptados faltantes).")
                    return None, None, None

            derived_key_b64, _ = self._derive_key(master_password, salt=salt)
            fernet_cipher = Fernet(derived_key_b64)

            decrypted_data = self._decrypt_data(encrypted_data_bytes, fernet_cipher)
            if decrypted_data is not None:
                return decrypted_data, derived_key_b64, salt
            else:
                return None, None, None

        except FileNotFoundError:
            messagebox.showerror("Error de Carga", "Archivo no encontrado.")
            return None, None, None
        except Exception as e:
            messagebox.showerror("Error de Carga", f"No se pudo abrir la base de datos: {e}")
            return None, None, None

    def _save_database_file_internal(self, file_path, data_to_save, master_key_b64, salt):
        try:
            fernet_cipher = Fernet(master_key_b64)
            encrypted_data_bytes = self._encrypt_data(data_to_save, fernet_cipher)
            if encrypted_data_bytes is None:
                return False

            with open(file_path, 'wb') as f:
                f.write(base64.urlsafe_b64encode(salt))
                f.write(encrypted_data_bytes)
            return True
        except Exception as e:
            messagebox.showerror("Error de Guardado", f"No se pudo guardar la base de datos: {e}")
            return False

    def start_new_database(self):
        dialog = MasterPasswordDialog(self.root, "Establecer Contraseña Maestra",
                                      "Por favor, introduzca una nueva contraseña maestra para la base de datos:")
        master_password = dialog.result_password

        if master_password:
            derived_key_b64, salt = self._derive_key(master_password)
            self.master_key = derived_key_b64
            self.current_salt = salt
            self.fernet_cipher = Fernet(self.master_key)

            self.all_entries_data = {}
            self.populate_group_tree()
            self.current_file_path = None

            messagebox.showinfo("Base de Datos", "Nueva base de datos creada. Ahora puede añadir grupos y entradas. Por favor, guarde la base de datos.")
            self.save_database(save_as=True)
        else:
            messagebox.showwarning("Base de Datos", "Creación de nueva base de datos cancelada.")

    def open_database(self):
        file_path = filedialog.askopenfilename(
            defaultextension=".bastion",
            filetypes=[("Bastión Database Files", "*.bastion"), ("All Files", "*.*")]
        )
        if not file_path:
            self._reset_app_state()
            messagebox.showwarning("Apertura de Base de Datos", "Selección de archivo cancelada.")
            return

        dialog = MasterPasswordDialog(self.root, "Introducir Contraseña Maestra",
                                      "Por favor, introduzca la contraseña maestra para abrir esta base de datos:", verify_mode=True)
        master_password = dialog.result_password

        if not master_password:
            messagebox.showwarning("Base de Datos", "Apertura de base de datos cancelada.")
            self._reset_app_state()
            return

        loaded_data, derived_key_b64, salt = self._load_database_file_internal(file_path, master_password)

        if loaded_data is not None:
            self.all_entries_data = loaded_data
            self.current_file_path = file_path
            self.master_key = derived_key_b64
            self.current_salt = salt
            self.fernet_cipher = Fernet(self.master_key)
            self.populate_group_tree()
            messagebox.showinfo("Base de Datos", "Base de datos abierta exitosamente.")
        else:
            pass

    def save_database(self, save_as=False):
        if not self.master_key or not self.fernet_cipher:
            messagebox.showwarning("Guardar Base de Datos", "No hay una base de datos abierta o una contraseña maestra establecida.")
            return

        file_path = self.current_file_path
        if save_as or not file_path:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".bastion",
                filetypes=[("Bastión Database Files", "*.bastion"), ("All Files", "*.*")]
            )
            if not file_path:
                messagebox.showwarning("Guardar Base de Datos", "Operación de guardar cancelada.")
                return

        success = self._save_database_file_internal(file_path, self.all_entries_data, self.master_key, self.current_salt)

        if success:
            self.current_file_path = file_path
            messagebox.showinfo("Guardar Base de Datos", "Base de datos guardada exitosamente.")
        else:
            pass

    def _reset_app_state(self):
        self.master_key = None
        self.fernet_cipher = None
        self.current_salt = None
        self.current_file_path = None
        self.all_entries_data = {}
        self.populate_group_tree()

    def open_add_group_window(self):
        if not self.master_key:
            messagebox.showwarning("Advertencia", "Por favor, cree o abra una base de datos primero.")
            return

        add_group_win = tk.Toplevel(self.root)
        add_group_win.title("Añadir Nuevo Grupo")
        add_group_win.geometry("300x180")
        add_group_win.transient(self.root)
        add_group_win.grab_set()

        selected_group_id = self.group_tree.selection()
        parent_group_full_path = self.get_full_tree_item_path(selected_group_id[0]) if selected_group_id else "Database"

        ttk.Label(add_group_win, text=f"Grupo Padre: {parent_group_full_path}").pack(pady=5)
        ttk.Label(add_group_win, text="Nombre del Nuevo Grupo:").pack(pady=5)
        entry_name = ttk.Entry(add_group_win, width=30)
        entry_name.pack(pady=5)

        def save_group():
            new_group_name = entry_name.get().strip()
            if not new_group_name:
                messagebox.showwarning("Advertencia", "El nombre del grupo no puede estar vacío.")
                return

            if parent_group_full_path == "Database":
                new_group_full_path = new_group_name
            else:
                new_group_full_path = f"{parent_group_full_path}/{new_group_name}"

            if new_group_full_path in self.all_entries_data:
                messagebox.showerror("Error", "Ya existe un grupo con esta ruta.")
                return

            self.all_entries_data[new_group_full_path] = []
            messagebox.showinfo("Éxito", f"Grupo '{new_group_full_path}' añadido.")
            add_group_win.destroy()

            self.populate_group_tree()

            self._select_group_by_path(new_group_full_path)


        btn_save = ttk.Button(add_group_win, text="Guardar", command=save_group)
        btn_save.pack(side="left", padx=10, pady=10)
        btn_cancel = ttk.Button(add_group_win, text="Cancelar", command=add_group_win.destroy)
        btn_cancel.pack(side="right", padx=10, pady=10)

        self.root.wait_window(add_group_win)

    def open_edit_entry_window(self):
        if not self.master_key:
            messagebox.showwarning("Advertencia", "Por favor, cree o abra una base de datos primero.")
            return

        selected_group_ids = self.group_tree.selection()
        selected_entry_ids = self.entry_tree.selection()

        if selected_group_ids and not selected_entry_ids:
            self._open_edit_group_window(selected_group_ids[0])
        elif selected_entry_ids:
            item_id = selected_entry_ids[0]
            entry_data = self.entries_data_store.get(item_id)
            if entry_data:
                self.create_entry_form_window("Editar Entrada", entry_data, item_id)
            else:
                messagebox.showerror("Error", "No se encontraron datos para la entrada seleccionada.")
        else:
            messagebox.showwarning("Editar", "Por favor, seleccione un grupo o una entrada para editar.")

    def _open_edit_group_window(self, group_id_to_edit):
        current_group_full_path = self.get_full_tree_item_path(group_id_to_edit)

        if current_group_full_path == "Database":
            messagebox.showerror("Error", "No se puede renombrar el grupo 'Database' (raíz conceptual).")
            return

        current_group_base_name = current_group_full_path.split('/')[-1]
        parent_path = "/".join(current_group_full_path.split('/')[:-1])

        edit_group_win = tk.Toplevel(self.root)
        edit_group_win.title(f"Editar Grupo: {current_group_base_name}")
        edit_group_win.geometry("350x180")
        edit_group_win.transient(self.root)
        edit_group_win.grab_set()

        ttk.Label(edit_group_win, text=f"Grupo Padre: {parent_path if parent_path else 'Base de Datos'}").pack(pady=5)
        ttk.Label(edit_group_win, text="Nuevo Nombre del Grupo:").pack(pady=5)
        new_name_entry = ttk.Entry(edit_group_win, width=30)
        new_name_entry.insert(0, current_group_base_name)
        new_name_entry.pack(pady=5)

        def save_rename():
            new_base_name = new_name_entry.get().strip()
            if not new_base_name:
                messagebox.showwarning("Advertencia", "El nombre del grupo no puede estar vacío.")
                return
            if new_base_name == current_group_base_name:
                messagebox.showinfo("Renombrar Grupo", "El nombre del grupo no ha cambiado.")
                edit_group_win.destroy()
                return

            if parent_path:
                new_full_path = f"{parent_path}/{new_base_name}"
            else:
                new_full_path = new_base_name

            parent_id_in_tree = self.group_tree.parent(group_id_to_edit)
            existing_sibling_names = set()
            for child_id in self.group_tree.get_children(parent_id_in_tree):
                if child_id != group_id_to_edit:
                    existing_sibling_names.add(self.group_tree.item(child_id, "text"))

            if new_base_name in existing_sibling_names:
                messagebox.showerror("Error", "Ya existe un grupo con este nombre en el mismo nivel.")
                return

            self._remap_group_paths_in_data(current_group_full_path, new_full_path, is_rename_op=True)
            messagebox.showinfo("Éxito", f"Grupo renombrado a '{new_base_name}'.")
            edit_group_win.destroy()
            self.populate_group_tree()
            self._select_group_by_path(new_full_path)


        btn_save = ttk.Button(edit_group_win, text="Guardar", command=save_rename)
        btn_save.pack(side="left", padx=10, pady=10)
        btn_cancel = ttk.Button(edit_group_win, text="Cancelar", command=edit_group_win.destroy)
        btn_cancel.pack(side="right", padx=10, pady=10)

        self.root.wait_window(edit_group_win)


    def _select_group_by_path(self, full_path):
        def find_item_id_recursive(current_tree_id, target_parts, current_part_index):
            if current_part_index >= len(target_parts):
                return current_tree_id

            target_name = target_parts[current_part_index]
            for child_id in self.group_tree.get_children(current_tree_id):
                if self.group_tree.item(child_id, "text") == target_name:
                    return find_item_id_recursive(child_id, target_parts, current_part_index + 1)
            return None

        if full_path == "Database":
            self.group_tree.selection_set("")
            self._filter_entries()
            return

        parts = full_path.split('/')
        found_id = find_item_id_recursive("", parts, 0)
        if found_id:
            self.group_tree.selection_set(found_id)
            self.group_tree.focus(found_id)
            self.group_tree.see(found_id)
            self._filter_entries()
        else:
            self.group_tree.selection_set("")
            self._filter_entries()


    def open_add_entry_window(self):
        if not self.master_key:
            messagebox.showwarning("Advertencia", "Por favor, cree o abra una base de datos primero.")
            return

        selected_group_full_path = self.get_selected_group_full_path()
        if selected_group_full_path == "Database":
            messagebox.showwarning("Añadir Entrada", "Por favor, seleccione un grupo específico (ej. 'eMail/Personal') antes de añadir una entrada.")
            return

        if selected_group_full_path not in self.all_entries_data:
             messagebox.showwarning("Añadir Entrada", "El grupo seleccionado no es válido para añadir entradas.")
             return

        self.create_entry_form_window("Añadir Nueva Entrada")


    def _on_entry_double_click(self, event):
        if not self.master_key:
            messagebox.showwarning("Advertencia", "Por favor, cree o abra una base de datos primero.")
            return

        item_id = self.entry_tree.identify_row(event.y)
        if item_id:
            self.entry_tree.selection_set(item_id)
            entry_data = self.entries_data_store.get(item_id)
            if entry_data:
                self.create_entry_form_window("Editar Entrada", entry_data, item_id)
            else:
                messagebox.showerror("Error", "No se encontraron datos para la entrada seleccionada.")


    def create_entry_form_window(self, title, entry_data=None, item_id_to_update=None):
        form_win = tk.Toplevel(self.root)
        form_win.title(title)
        form_win.geometry("550x450")
        form_win.transient(self.root)
        form_win.grab_set()

        form_frame = ttk.Frame(form_win, padding="15")
        form_frame.pack(expand=True, fill="both")

        form_frame.grid_columnconfigure(1, weight=1)
        form_frame.grid_columnconfigure(2, weight=0)

        labels = ["Título:", "Nombre de Usuario:", "Contraseña:", "URL:", "Notas:"]
        entries = {}

        password_visible = tk.BooleanVar(value=False)

        def toggle_password_visibility():
            if password_visible.get():
                entries["contraseña"].config(show="")
                btn_show_hide.config(text="Ocultar")
            else:
                entries["contraseña"].config(show="*")
                btn_show_hide.config(text="Mostrar")
            password_visible.set(not password_visible.get())


        for i, text in enumerate(labels):
            ttk.Label(form_frame, text=text).grid(row=i, column=0, sticky="w", pady=5, padx=5)

            if text == "Notas:":
                notes_entry_widget = tk.Text(form_frame, height=5, width=40)
                notes_entry_widget.grid(row=i, column=1, sticky="ew", pady=5, padx=5, columnspan=2)
                entries["notas"] = notes_entry_widget
            else:
                entry_widget = ttk.Entry(form_frame, width=40)
                entry_widget.grid(row=i, column=1, sticky="ew", pady=5, padx=5)
                entries[text.replace(":", "").strip().replace(" ", "_").lower()] = entry_widget

                if text == "Contraseña:":
                    entry_widget.config(show="*")

                    button_col_frame = ttk.Frame(form_frame)
                    button_col_frame.grid(row=i, column=2, padx=5, sticky="nw")

                    btn_show_hide = ttk.Button(button_col_frame, text="Mostrar", command=toggle_password_visibility)
                    btn_show_hide.pack(pady=2, fill="x")

                    btn_generate_pwd = ttk.Button(button_col_frame, text="Generar", command=lambda: self.generate_password(entries["contraseña"]))
                    btn_generate_pwd.pack(pady=2, fill="x")

        if entry_data:
            entries["título"].insert(0, entry_data.get("Title", ""))
            entries["nombre_de_usuario"].insert(0, entry_data.get("User Name", ""))
            entries["contraseña"].insert(0, entry_data.get("Password", ""))
            entries["url"].insert(0, entry_data.get("URL", ""))
            entries["notas"].delete("1.0", tk.END)
            notes_text = entry_data.get("Notes", "")
            if notes_text:
                entries["notas"].insert("1.0", notes_text)


        def save_entry():
            title_val = entries["título"].get().strip()
            user_val = entries["nombre_de_usuario"].get().strip()
            password_val = entries["contraseña"].get().strip()
            url_val = entries["url"].get().strip()
            notes_val = entries["notas"].get("1.0", tk.END).strip()

            if not title_val or not password_val:
                messagebox.showwarning("Campos Requeridos", "Título y Contraseña son campos obligatorios.")
                return

            current_time = datetime.datetime.now().strftime("%d/%m/%Y %I:%M:%S %p.").replace("AM", "a.m.").replace("PM", "p.m.")

            new_entry = {
                "Title": title_val,
                "User Name": user_val,
                "Password": password_val,
                "URL": url_val,
                "Notes": notes_val,
                "Creation Time": current_time if entry_data is None else entry_data.get("Creation Time", current_time),
                "Last Modification Time": current_time
            }

            selected_group_full_path = self.get_selected_group_full_path()
            if selected_group_full_path == "Database":
                messagebox.showwarning("Advertencia", "Por favor, seleccione un grupo específico (ej. 'eMail/Personal') para añadir la entrada.")
                return

            if selected_group_full_path not in self.all_entries_data:
                messagebox.showerror("Error", "El grupo seleccionado no existe en los datos. Por favor, intente seleccionar un grupo existente.")
                return

            if item_id_to_update:
                if selected_group_full_path in self.all_entries_data:
                    entry_found = False
                    for i, entry in enumerate(self.all_entries_data[selected_group_full_path]):
                        if entry.get("Title") == entry_data.get("Title") and entry.get("User Name") == entry_data.get("User Name"):
                            self.all_entries_data[selected_group_full_path][i] = new_entry
                            entry_found = True
                            break
                    if not entry_found:
                        messagebox.showerror("Error", "No se pudo encontrar la entrada original para actualizar.")
                        return

                self._filter_entries()
                messagebox.showinfo("Éxito", "Entrada actualizada exitosamente.")
            else:
                self.all_entries_data[selected_group_full_path].append(new_entry)

                self._filter_entries()
                messagebox.showinfo("Éxito", "Nueva entrada añadida exitosamente.")

            form_win.destroy()

        button_frame = ttk.Frame(form_win)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Guardar", command=save_entry).pack(side="left", padx=10)
        ttk.Button(button_frame, text="Cancelar", command=form_win.destroy).pack(side="right", padx=10)

        self.root.wait_window(form_win)

    def generate_password(self, password_entry_widget):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for i in range(12))
        password_entry_widget.delete(0, tk.END)
        password_entry_widget.insert(0, password)

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Portapapeles", "Copiado al portapapeles.")

    def copy_entry_detail(self, detail_key):
        if not self.master_key:
            messagebox.showwarning("Advertencia", "Por favor, cree o abra una base de datos primero.")
            return

        selected_items = self.entry_tree.selection()
        if not selected_items:
            messagebox.showwarning("Copiar", "Por favor, seleccione una entrada para copiar.")
            return

        item_id = selected_items[0]
        entry_data = self.entries_data_store.get(item_id)

        if entry_data and detail_key in entry_data:
            value_to_copy = entry_data[detail_key]
            self.copy_to_clipboard(value_to_copy)
        else:
            messagebox.showerror("Error", f"No se pudo copiar el detalle '{detail_key}'.")

    def delete_selected(self):
        if not self.master_key:
            messagebox.showwarning("Advertencia", "Por favor, cree o abra una base de datos primero.")
            return

        selected_group_ids = self.group_tree.selection()
        selected_entry_ids = self.entry_tree.selection()

        if selected_group_ids and not selected_entry_ids:
            self.delete_selected_group(selected_group_ids[0])
        elif selected_entry_ids:
            self.delete_selected_entry()
        else:
            messagebox.showwarning("Eliminar", "Por favor, seleccione un grupo o una entrada para eliminar.")


    def delete_selected_group(self, group_id):
        group_full_path = self.get_full_tree_item_path(group_id)

        if group_full_path == "Database":
            messagebox.showerror("Error", "No se puede eliminar el grupo 'Database' (raíz conceptual).")
            return

        if messagebox.askyesno("Confirmar Eliminación de Grupo",
                               f"¿Estás seguro de que quieres eliminar el grupo '{group_full_path}' y todas sus entradas y subgrupos?"):

            paths_to_delete = [
                path for path in self.all_entries_data.keys()
                if path == group_full_path or path.startswith(f"{group_full_path}/")
            ]

            for path in paths_to_delete:
                if path in self.all_entries_data:
                    del self.all_entries_data[path]

            self.group_tree.delete(group_id)

            messagebox.showinfo("Eliminación Exitosa", f"Grupo '{group_full_path}' y sus contenidos eliminados correctamente.")

            self.populate_group_tree()

            self.update_status_bar(None)


    def delete_selected_entry(self):
        selected_items = self.entry_tree.selection()
        if not selected_items:
            messagebox.showwarning("Eliminar Entrada", "Por favor, seleccione una o más entradas para eliminar.")
            return

        if messagebox.askyesno("Confirmar Eliminación de Entrada", f"¿Estás seguro de que quieres eliminar {len(selected_items)} entrada(s) seleccionada(s)?"):
            selected_group_full_path = self.get_selected_group_full_path()
            if selected_group_full_path == "Database":
                 messagebox.showerror("Error", "No se pueden eliminar entradas desde el grupo 'Database' (raíz conceptual). Por favor, seleccione un grupo específico.")
                 return

            if selected_group_full_path not in self.all_entries_data:
                messagebox.showerror("Error", "Grupo no encontrado en los datos para eliminar entradas.")
                return

            entries_to_delete_from_store = []
            for item_id in selected_items:
                entry_data = self.entries_data_store.get(item_id)
                if entry_data:
                    entries_to_delete_from_store.append(entry_data)
                self.entry_tree.delete(item_id)
                if item_id in self.entries_data_store:
                    del self.entries_data_store[item_id]

            if entries_to_delete_from_store:
                self.all_entries_data[selected_group_full_path] = [
                    entry for entry in self.all_entries_data[selected_group_full_path]
                    if entry not in entries_to_delete_from_store
                ]

            messagebox.showinfo("Eliminación Exitosa", "Entrada(s) eliminada(s) correctamente.")
            self.update_status_bar(None)

    def _activate_search(self):
        self.search_entry.focus_set()
        self._filter_entries()

    def show_about_dialog(self):
        about_win = tk.Toplevel(self.root)
        about_win.title("Acerca de Bastión")
        about_win.geometry("400x200")
        about_win.transient(self.root)
        about_win.grab_set()
        about_win.resizable(False, False)

        about_text = (
            "Bastión v1.0\n\n"
            "Desarrollado por Riso.Inc\n"
            "Fecha: Junio 2025\n\n"
            "Una herramienta segura y fácil de usar para gestionar sus contraseñas."
        )

        ttk.Label(about_win, text=about_text, justify=tk.CENTER, wraplength=380).pack(pady=20, padx=10)
        ttk.Button(about_win, text="Cerrar", command=about_win.destroy).pack(pady=10)
        self.root.wait_window(about_win)

    def open_instructions_file(self):
        instructions_file_path = resource_path("Instrucciones.txt")

        if not os.path.exists(instructions_file_path):
            messagebox.showerror("Error", f"No se encontró el archivo de instrucciones:\n{instructions_file_path}")
            return

        try:
            if os.name == 'nt':
                subprocess.Popen(['start', instructions_file_path], shell=True)
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', instructions_file_path])
            else:
                subprocess.Popen(['xdg-open', instructions_file_path])
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el archivo de instrucciones:\n{e}")

    def _open_advanced_password_generator_window(self):
        gen_win = tk.Toplevel(self.root)
        gen_win.title("Generador de Contraseñas Avanzado")
        gen_win.geometry("400x350")
        gen_win.transient(self.root)
        gen_win.grab_set()

        main_frame = ttk.Frame(gen_win, padding="15")
        main_frame.pack(expand=True, fill="both")

        ttk.Label(main_frame, text="Longitud:").grid(row=0, column=0, sticky="w", pady=5)
        length_var = tk.IntVar(value=16)
        length_spinbox = ttk.Spinbox(main_frame, from_=8, to=64, textvariable=length_var, width=5)
        length_spinbox.grid(row=0, column=1, sticky="ew", pady=5)

        uppercase_var = tk.BooleanVar(value=True)
        lowercase_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        symbols_var = tk.BooleanVar(value=True)
        exclude_ambiguous_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(main_frame, text="Mayúsculas (A-Z)", variable=uppercase_var).grid(row=1, column=0, columnspan=2, sticky="w", pady=2)
        ttk.Checkbutton(main_frame, text="Minúsculas (a-z)", variable=lowercase_var).grid(row=2, column=0, columnspan=2, sticky="w", pady=2)
        ttk.Checkbutton(main_frame, text="Números (0-9)", variable=digits_var).grid(row=3, column=0, columnspan=2, sticky="w", pady=2)
        ttk.Checkbutton(main_frame, text="Símbolos (!@#$...)", variable=symbols_var).grid(row=4, column=0, columnspan=2, sticky="w", pady=2)
        ttk.Checkbutton(main_frame, text="Excluir caracteres ambiguos (i,l,1,o,0,O)", variable=exclude_ambiguous_var).grid(row=5, column=0, columnspan=2, sticky="w", pady=2)

        ttk.Label(main_frame, text="Contraseña Generada:").grid(row=6, column=0, sticky="w", pady=5)
        generated_pwd_entry = ttk.Entry(main_frame, width=30, state="readonly")
        generated_pwd_entry.grid(row=6, column=1, sticky="ew", pady=5)

        def generate_and_display():
            generated_password = self._generate_custom_password(
                length_var.get(),
                uppercase_var.get(),
                lowercase_var.get(),
                digits_var.get(),
                symbols_var.get(),
                exclude_ambiguous_var.get()
            )
            generated_pwd_entry.config(state="normal")
            generated_pwd_entry.delete(0, tk.END)
            generated_pwd_entry.insert(0, generated_password)
            generated_pwd_entry.config(state="readonly")

        def copy_generated_password():
            self.copy_to_clipboard(generated_pwd_entry.get())


        generate_btn = ttk.Button(main_frame, text="Generar", command=generate_and_display)
        generate_btn.grid(row=7, column=0, sticky="w", pady=10)

        copy_btn = ttk.Button(main_frame, text="Copiar", command=copy_generated_password)
        copy_btn.grid(row=7, column=1, sticky="e", pady=10)

        gen_win.wait_window(gen_win)

    def _generate_custom_password(self, length, use_uppercase, use_lowercase, use_digits, use_symbols, exclude_ambiguous):
        characters = ""
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_digits:
            characters += string.digits
        if use_symbols:
            characters += string.punctuation

        if exclude_ambiguous:
            ambiguous_chars = "ilo0O1"
            characters = "".join(c for c in characters if c not in ambiguous_chars)

        if not characters:
            messagebox.showwarning("Advertencia", "Por favor, seleccione al menos un tipo de carácter para generar la contraseña.")
            return ""

        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def _open_password_strength_checker(self):
        strength_win = tk.Toplevel(self.root)
        strength_win.title("Comprobador de Fortaleza de Contraseñas")
        strength_win.geometry("400x200")
        strength_win.transient(self.root)
        strength_win.grab_set()

        main_frame = ttk.Frame(strength_win, padding="15")
        main_frame.pack(expand=True, fill="both")

        ttk.Label(main_frame, text="Introduce una contraseña:").pack(pady=5)
        password_entry = ttk.Entry(main_frame, show="*", width=40)
        password_entry.pack(pady=5)

        strength_label = ttk.Label(main_frame, text="Fortaleza: ", font=("Arial", 10, "bold"))
        strength_label.pack(pady=10)

        def update_strength(event=None):
            password = password_entry.get()
            strength = self._check_password_strength(password)
            strength_label.config(text=f"Fortaleza: {strength}")
            if strength == "Muy Débil" or strength == "Débil":
                strength_label.config(foreground="red")
            elif strength == "Moderada":
                strength_label.config(foreground="orange")
            else:
                strength_label.config(foreground="green")

        password_entry.bind("<KeyRelease>", update_strength)

        strength_win.wait_window(strength_win)

    def _check_password_strength(self, password):
        length = len(password)
        score = 0

        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if length >= 16:
            score += 1

        if re.search(r"[A-Z]", password):
            score += 1
        if re.search(r"[a-z]", password):
            score += 1
        if re.search(r"\d", password):
            score += 1
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1

        if score < 3:
            return "Muy Débil"
        elif score == 3:
            return "Débil"
        elif score == 4:
            return "Moderada"
        elif score == 5:
            return "Fuerte"
        else:
            return "Muy Fuerte"

    def clean_clipboard(self):
        try:
            self.root.clipboard_clear()
            messagebox.showinfo("Portapapeles", "El portapapeles ha sido limpiado.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo limpiar el portapapeles: {e}")

    def open_change_master_password_window(self):
        if not self.master_key:
            messagebox.showwarning("Advertencia", "Por favor, cree o abra una base de datos primero.")
            return

        current_password_dialog = MasterPasswordDialog(self.root, "Verificar Contraseña Maestra Actual",
                                                       "Por favor, introduzca su contraseña maestra actual:", verify_mode=True)
        current_master_password = current_password_dialog.result_password

        if not current_master_password:
            messagebox.showwarning("Cambiar Contraseña Maestra", "Cambio de contraseña maestra cancelado.")
            return

        try:
            verified_key_b64, _ = self._derive_key(current_master_password, salt=self.current_salt)
            if verified_key_b64 != self.master_key:
                messagebox.showerror("Error", "Contraseña maestra actual incorrecta.")
                return
        except Exception as e:
            messagebox.showerror("Error de Verificación", f"Error al verificar la contraseña actual: {e}")
            return

        new_password_dialog = MasterPasswordDialog(self.root, "Establecer Nueva Contraseña Maestra",
                                                   "Por favor, introduzca su NUEVA contraseña maestra:")
        new_master_password = new_password_dialog.result_password

        if not new_master_password:
            messagebox.showwarning("Cambiar Contraseña Maestra", "Cambio de contraseña maestra cancelado.")
            return

        new_derived_key_b64, new_salt = self._derive_key(new_master_password)
        new_fernet_cipher = Fernet(new_derived_key_b64)

        try:
            success = self._save_database_file_internal(self.current_file_path, self.all_entries_data, new_derived_key_b64, new_salt)
            if success:
                self.master_key = new_derived_key_b64
                self.current_salt = new_salt
                self.fernet_cipher = new_fernet_cipher
                messagebox.showinfo("Éxito", "La contraseña maestra ha sido cambiada exitosamente.")
            else:
                messagebox.showerror("Error", "No se pudo re-encriptar y guardar la base de datos con la nueva contraseña maestra.")
        except Exception as e:
            messagebox.showerror("Error de Cambio de Contraseña", f"Ocurrió un error al cambiar la contraseña maestra: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = BastionPasswordManager(root)
    root.mainloop()
