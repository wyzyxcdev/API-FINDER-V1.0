#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API-HUNTER GUI v4.0 - Aplicación de Escritorio
COLIN | INTERFAZ VISUAL COMPLETA
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import asyncio
import aiohttp
import json
import re
import time
import random
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import webbrowser
import queue
import sys
import os

# ============================================================================
# CLASE PRINCIPAL DEL ESCÁNER
# ============================================================================

class APIScanner:
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        
        self.session = None
        self.is_scanning = False
        
    async def init_session(self):
        connector = aiohttp.TCPConnector(limit=20, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        )
    
    def normalize_url(self, url: str, base_url: str):
        try:
            url = url.strip().replace('\\/', '/')
            if url.startswith('/'):
                parsed = urlparse(base_url)
                return f"{parsed.scheme}://{parsed.netloc}{url}"
            elif not url.startswith('http'):
                return urljoin(base_url, url)
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                return url
        except:
            pass
        return None
    
    async def fetch_page(self, url: str):
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.text()
        except:
            pass
        return None
    
    async def scan_website(self, url: str, progress_callback=None, result_callback=None):
        try:
            await self.init_session()
            
            results = {
                'apis': [],
                'working': [],
                'auth_required': [],
                'tokens': [],
                'stats': {},
                'status': 'scanning'
            }
            
            # Paso 1: Obtener página principal
            if progress_callback:
                progress_callback(10, "Obteniendo página principal...")
            
            html = await self.fetch_page(url)
            if not html:
                results['status'] = 'error'
                results['error'] = 'No se pudo acceder al sitio'
                await self.session.close()
                if result_callback:
                    result_callback(results)
                return results
            
            # Paso 2: Analizar HTML
            if progress_callback:
                progress_callback(30, "Analizando código HTML...")
            
            soup = BeautifulSoup(html, 'html.parser')
            apis = set()
            tokens = []
            
            # Buscar en scripts
            scripts_found = 0
            for script in soup.find_all('script'):
                if script.get('src'):
                    script_url = urljoin(url, script['src'])
                    if script_url.endswith('.js'):
                        if progress_callback:
                            progress_callback(30 + scripts_found, f"Analizando script: {script_url}")
                        
                        script_content = await self.fetch_page(script_url)
                        if script_content:
                            # Buscar APIs
                            api_patterns = [
                                r'https?://[^"\']+api[^"\']*',
                                r'https?://[^"\']+/api/v\d+/[^"\']*',
                                r'fetch\(["\']([^"\']+)["\']\)',
                                r'axios\.(get|post)\(["\']([^"\']+)["\']\)',
                                r'baseURL:\s*["\']([^"\']+)["\']'
                            ]
                            
                            for pattern in api_patterns:
                                matches = re.finditer(pattern, script_content, re.IGNORECASE)
                                for match in matches:
                                    found_url = match.group(1) if match.groups() else match.group(0)
                                    normalized = self.normalize_url(found_url, script_url)
                                    if normalized and ('api' in normalized.lower() or 'v1' in normalized.lower() or 'v2' in normalized.lower()):
                                        apis.add(normalized)
                            
                            # Buscar tokens
                            token_patterns = [
                                r'"token"\s*:\s*"([^"]+)"',
                                r'"accessToken"\s*:\s*"([^"]+)"',
                                r'Bearer\s+([a-zA-Z0-9._-]+)'
                            ]
                            
                            for pattern in token_patterns:
                                matches = re.findall(pattern, script_content)
                                for token in matches:
                                    if len(token) > 10:
                                        tokens.append({
                                            'source': script_url,
                                            'token': token[:50] + '...' if len(token) > 50 else token,
                                            'type': 'JWT' if 'bearer' in token.lower() else 'API Token'
                                        })
                        
                        scripts_found += 1
                        if scripts_found >= 5:  # Limitar a 5 scripts para velocidad
                            break
            
            # Buscar en atributos HTML
            for tag in soup.find_all():
                for attr in ['href', 'src', 'data-url', 'data-api']:
                    if tag.get(attr):
                        value = tag[attr]
                        if 'http' in value.lower():
                            normalized = self.normalize_url(value, url)
                            if normalized and ('api' in normalized.lower()):
                                apis.add(normalized)
            
            results['apis'] = list(apis)[:50]  # Limitar a 50 APIs
            results['tokens'] = tokens
            
            # Paso 3: Testear endpoints
            if progress_callback:
                progress_callback(60, f"Testeando {len(results['apis'])} endpoints...")
            
            tested = 0
            total = min(len(results['apis']), 20)
            
            for api in results['apis'][:20]:
                try:
                    headers = {'User-Agent': random.choice(self.user_agents)}
                    async with self.session.get(api, headers=headers) as response:
                        result = {
                            'url': api,
                            'status': response.status,
                            'working': response.status == 200,
                            'requires_auth': response.status in [401, 403]
                        }
                        
                        if response.status == 200:
                            results['working'].append(result)
                        elif response.status in [401, 403]:
                            results['auth_required'].append(result)
                
                except:
                    pass
                
                tested += 1
                progress = 60 + (tested / total * 30)
                if progress_callback:
                    progress_callback(int(progress), f"Testeando endpoint {tested}/{total}")
            
            # Paso 4: Finalizar
            results['stats'] = {
                'total_apis': len(results['apis']),
                'working_apis': len(results['working']),
                'auth_required': len(results['auth_required']),
                'tokens_found': len(results['tokens']),
                'scan_time': time.strftime('%H:%M:%S')
            }
            
            results['status'] = 'completed'
            
            if progress_callback:
                progress_callback(100, "Escaneo completado!")
            
            await self.session.close()
            
            if result_callback:
                result_callback(results)
            
            return results
            
        except Exception as e:
            results = {
                'status': 'error',
                'error': str(e)
            }
            if result_callback:
                result_callback(results)
            return results

# ============================================================================
# INTERFAZ GRÁFICA PRINCIPAL
# ============================================================================

class APIHunterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("API-HUNTER GUI v4.0")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Estilo personalizado
        self.setup_styles()
        
        # Scanner
        self.scanner = APIScanner()
        self.is_scanning = False
        
        # Variables de estado
        self.progress_var = tk.IntVar()
        self.status_var = tk.StringVar(value="Listo para escanear")
        
        # Construir interfaz
        self.build_gui()
        
        # Configurar cierre seguro
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_styles(self):
        """Configurar estilos personalizados"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Colores principales
        self.bg_color = '#1e1e1e'
        self.fg_color = '#ffffff'
        self.accent_color = '#00ff88'
        self.secondary_color = '#00ccff'
        self.error_color = '#ff5555'
        self.warning_color = '#ffaa00'
        
        # Configurar estilos ttk
        style.configure('TLabel', background=self.bg_color, foreground=self.fg_color)
        style.configure('TButton', padding=10)
        style.configure('TFrame', background=self.bg_color)
        style.configure('TProgressbar', troughcolor='#2d2d2d', background=self.accent_color)
        
    def build_gui(self):
        """Construir interfaz gráfica completa"""
        
        # Frame principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # ========== HEADER ==========
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Título y logo
        title_frame = ttk.Frame(header_frame)
        title_frame.pack()
        
        # Logo ASCII
        logo_label = tk.Label(title_frame, text="""
╔═╗┌─┐┬ ┬  ╦ ╦┌─┐┌┬┐┌─┐
╠═╣│ ││ │  ║ ║├─┘ ││├┤ 
╩ ╩└─┘└─┘  ╚═╝┴  ─┴┘└─┘
        """, font=('Courier', 16), bg=self.bg_color, fg=self.accent_color)
        logo_label.pack(side=tk.LEFT, padx=(0, 20))
        
        title_text = tk.Label(title_frame, text="API-HUNTER GUI v4.0", 
                            font=('Arial', 24, 'bold'), bg=self.bg_color, fg=self.fg_color)
        title_text.pack(side=tk.LEFT)
        
        version_label = tk.Label(title_frame, text="by COLIN", 
                               font=('Arial', 12), bg=self.bg_color, fg=self.secondary_color)
        version_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Separador
        ttk.Separator(main_frame, orient='horizontal').pack(fill=tk.X, pady=10)
        
        # ========== SCANNER SECTION ==========
        scanner_frame = ttk.LabelFrame(main_frame, text=" ESCÁNER DE APIS ", padding=20)
        scanner_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Input URL
        url_frame = ttk.Frame(scanner_frame)
        url_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(url_frame, text="URL del sitio:", font=('Arial', 11)).pack(side=tk.LEFT, padx=(0, 10))
        
        self.url_entry = ttk.Entry(url_frame, width=60, font=('Arial', 11))
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.url_entry.insert(0, "https://github.com")
        
        # Botones de control
        button_frame = ttk.Frame(scanner_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.scan_button = ttk.Button(button_frame, text="🚀 INICIAR ESCANEO", 
                                     command=self.start_scan, style='Accent.TButton')
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="🔄 LIMPIAR", command=self.clear_results).pack(side=tk.LEFT)
        
        # Barra de progreso
        self.progress_frame = ttk.Frame(scanner_frame)
        self.progress_frame.pack(fill=tk.X, pady=(15, 5))
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var, 
                                          maximum=100, mode='determinate')
        self.progress_bar.pack(fill=tk.X)
        
        self.progress_label = ttk.Label(self.progress_frame, textvariable=self.status_var, 
                                      font=('Arial', 10))
        self.progress_label.pack()
        
        # Ocultar progreso inicialmente
        self.progress_frame.pack_forget()
        
        # ========== RESULTS SECTION ==========
        results_frame = ttk.LabelFrame(main_frame, text=" RESULTADOS ", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Notebook (pestañas)
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Pestaña 1: APIs encontradas
        self.apis_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.apis_frame, text="📡 APIs ENCONTRADAS")
        
        # Toolbar para APIs
        apis_toolbar = ttk.Frame(self.apis_frame)
        apis_toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(apis_toolbar, text="Filtrar:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_entry = ttk.Entry(apis_toolbar, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.filter_entry.bind('<KeyRelease>', self.filter_apis)
        
        ttk.Button(apis_toolbar, text="📋 Copiar seleccionados", command=self.copy_selected_apis).pack(side=tk.LEFT)
        ttk.Button(apis_toolbar, text="💾 Guardar lista", command=self.save_apis_list).pack(side=tk.LEFT, padx=(5, 0))
        
        # Lista de APIs
        apis_list_frame = ttk.Frame(self.apis_frame)
        apis_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Treeview para APIs
        columns = ('#', 'URL', 'Estado')
        self.apis_tree = ttk.Treeview(apis_list_frame, columns=columns, show='headings', height=15)
        
        # Configurar columnas
        self.apis_tree.heading('#', text='#')
        self.apis_tree.heading('URL', text='URL')
        self.apis_tree.heading('Estado', text='Estado')
        
        self.apis_tree.column('#', width=50, anchor='center')
        self.apis_tree.column('URL', width=800)
        self.apis_tree.column('Estado', width=100, anchor='center')
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(apis_list_frame, orient=tk.VERTICAL, command=self.apis_tree.yview)
        self.apis_tree.configure(yscrollcommand=scrollbar.set)
        
        self.apis_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Pestaña 2: Endpoints funcionando
        self.working_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.working_frame, text="✅ ENDPOINTS FUNCIONANDO")
        
        working_text_frame = ttk.Frame(self.working_frame)
        working_text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.working_text = scrolledtext.ScrolledText(working_text_frame, height=15, 
                                                     font=('Consolas', 10), bg='#2d2d2d', fg='#00ff88')
        self.working_text.pack(fill=tk.BOTH, expand=True)
        
        # Pestaña 3: Tokens encontrados
        self.tokens_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.tokens_frame, text="🔑 TOKENS")
        
        tokens_text_frame = ttk.Frame(self.tokens_frame)
        tokens_text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.tokens_text = scrolledtext.ScrolledText(tokens_text_frame, height=15,
                                                   font=('Consolas', 10), bg='#2d2d2d', fg='#ffaa00')
        self.tokens_text.pack(fill=tk.BOTH, expand=True)
        
        # Pestaña 4: Estadísticas
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="📊 ESTADÍSTICAS")
        
        # Widgets de estadísticas
        self.stats_canvas = tk.Canvas(self.stats_frame, bg=self.bg_color, highlightthickness=0)
        self.stats_canvas.pack(fill=tk.BOTH, expand=True)
        
        # ========== FOOTER ==========
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(20, 0))
        
        ttk.Label(footer_frame, text="🔒 Solo para uso ético | 🚫 No escanear sitios sin permiso", 
                 font=('Arial', 9), foreground='#888888').pack()
        
        # Inicializar datos
        self.current_results = None
        
    def start_scan(self):
        """Iniciar escaneo en segundo plano"""
        if self.is_scanning:
            messagebox.showwarning("Escaneo en curso", "Ya hay un escaneo en progreso.")
            return
        
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Por favor ingresa una URL.")
            return
        
        if not url.startswith('http'):
            url = 'https://' + url
        
        # Mostrar barra de progreso
        self.progress_frame.pack(fill=tk.X, pady=(15, 5))
        self.progress_var.set(0)
        self.status_var.set("Preparando escaneo...")
        
        # Deshabilitar botón
        self.scan_button.config(state='disabled')
        self.is_scanning = True
        
        # Limpiar resultados anteriores
        self.clear_results()
        
        # Iniciar escaneo en thread separado
        scan_thread = threading.Thread(target=self.run_scan_thread, args=(url,), daemon=True)
        scan_thread.start()
    
    def run_scan_thread(self, url):
        """Ejecutar escaneo en thread separado"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(
                self.scanner.scan_website(
                    url,
                    progress_callback=self.update_progress,
                    result_callback=self.on_scan_complete
                )
            )
        except Exception as e:
            self.root.after(0, lambda: self.on_scan_error(str(e)))
        finally:
            loop.close()
    
    def update_progress(self, value, message):
        """Actualizar barra de progreso desde thread"""
        self.root.after(0, lambda: self._update_progress_ui(value, message))
    
    def _update_progress_ui(self, value, message):
        """Actualizar UI del progreso"""
        self.progress_var.set(value)
        self.status_var.set(message)
    
    def on_scan_complete(self, results):
        """Manejar finalización del escaneo"""
        self.root.after(0, lambda: self._display_results(results))
    
    def _display_results(self, results):
        """Mostrar resultados en la interfaz"""
        self.is_scanning = False
        self.scan_button.config(state='normal')
        self.current_results = results
        
        if results['status'] == 'error':
            messagebox.showerror("Error", f"Error durante el escaneo: {results.get('error', 'Desconocido')}")
            self.progress_frame.pack_forget()
            return
        
        # Actualizar lista de APIs
        self.apis_tree.delete(*self.apis_tree.get_children())
        for i, api in enumerate(results['apis'], 1):
            self.apis_tree.insert('', 'end', values=(i, api, "No probado"))
        
        # Actualizar endpoints funcionando
        self.working_text.delete(1.0, tk.END)
        for endpoint in results['working']:
            self.working_text.insert(tk.END, f"✅ {endpoint['url']}\n")
            self.working_text.insert(tk.END, f"   Status: {endpoint['status']}\n\n")
        
        # Actualizar tokens
        self.tokens_text.delete(1.0, tk.END)
        for token in results['tokens']:
            self.tokens_text.insert(tk.END, f"🔑 {token['type']}\n")
            self.tokens_text.insert(tk.END, f"   Token: {token['token']}\n")
            self.tokens_text.insert(tk.END, f"   Fuente: {token.get('source', 'N/A')}\n\n")
        
        # Actualizar estadísticas
        self.update_stats_display(results['stats'])
        
        # Mostrar mensaje de éxito
        messagebox.showinfo("Escaneo completado", 
                          f"¡Escaneo completado!\n\n"
                          f"APIs encontradas: {results['stats']['total_apis']}\n"
                          f"Endpoints funcionando: {results['stats']['working_apis']}\n"
                          f"Tokens encontrados: {results['stats']['tokens_found']}")
        
        # Ocultar barra de progreso
        self.progress_frame.pack_forget()
    
    def update_stats_display(self, stats):
        """Actualizar visualización de estadísticas"""
        self.stats_canvas.delete("all")
        
        # Configuración
        canvas_width = 800
        canvas_height = 400
        margin = 50
        
        # Dibujar título
        self.stats_canvas.create_text(canvas_width//2, 30, 
                                    text="ESTADÍSTICAS DEL ESCANEO",
                                    font=('Arial', 16, 'bold'),
                                    fill=self.fg_color)
        
        # Dibujar estadísticas como tarjetas
        cards_data = [
            ("APIs Encontradas", stats['total_apis'], self.accent_color),
            ("Endpoints Funcionando", stats['working_apis'], '#00ccff'),
            ("Requieren Auth", stats['auth_required'], self.warning_color),
            ("Tokens", stats['tokens_found'], '#ff55ff')
        ]
        
        card_width = 150
        card_height = 100
        spacing = 50
        
        for i, (title, value, color) in enumerate(cards_data):
            x = margin + i * (card_width + spacing)
            y = 100
            
            # Dibujar tarjeta
            self.stats_canvas.create_rectangle(x, y, x + card_width, y + card_height,
                                             fill='#2d2d2d', outline=color, width=2)
            
            # Título
            self.stats_canvas.create_text(x + card_width//2, y + 30,
                                        text=title, fill=self.fg_color,
                                        font=('Arial', 10))
            
            # Valor
            self.stats_canvas.create_text(x + card_width//2, y + 65,
                                        text=str(value), fill=color,
                                        font=('Arial', 20, 'bold'))
        
        # Dibujar tiempo
        time_y = 250
        self.stats_canvas.create_text(canvas_width//2, time_y,
                                    text=f"Hora del escaneo: {stats['scan_time']}",
                                    fill=self.secondary_color,
                                    font=('Arial', 12))
    
    def on_scan_error(self, error_msg):
        """Manejar error del escaneo"""
        self.is_scanning = False
        self.scan_button.config(state='normal')
        self.progress_frame.pack_forget()
        messagebox.showerror("Error", f"Error durante el escaneo:\n{error_msg}")
    
    def clear_results(self):
        """Limpiar todos los resultados"""
        self.apis_tree.delete(*self.apis_tree.get_children())
        self.working_text.delete(1.0, tk.END)
        self.tokens_text.delete(1.0, tk.END)
        self.stats_canvas.delete("all")
        self.filter_entry.delete(0, tk.END)
        self.current_results = None
    
    def filter_apis(self, event=None):
        """Filtrar lista de APIs"""
        filter_text = self.filter_entry.get().lower()
        
        # Si no hay resultados, no hacer nada
        if not self.current_results or not self.current_results.get('apis'):
            return
        
        self.apis_tree.delete(*self.apis_tree.get_children())
        
        for i, api in enumerate(self.current_results['apis'], 1):
            if filter_text in api.lower():
                self.apis_tree.insert('', 'end', values=(i, api, "No probado"))
    
    def copy_selected_apis(self):
        """Copiar APIs seleccionadas al portapapeles"""
        selected_items = self.apis_tree.selection()
        if not selected_items:
            messagebox.showwarning("Sin selección", "Selecciona APIs para copiar.")
            return
        
        urls = []
        for item in selected_items:
            values = self.apis_tree.item(item, 'values')
            if values and len(values) > 1:
                urls.append(values[1])
        
        if urls:
            self.root.clipboard_clear()
            self.root.clipboard_append('\n'.join(urls))
            messagebox.showinfo("Copiado", f"{len(urls)} URLs copiadas al portapapeles.")
    
    def save_apis_list(self):
        """Guardar lista de APIs en archivo"""
        if not self.current_results or not self.current_results.get('apis'):
            messagebox.showwarning("Sin datos", "No hay datos para guardar.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(self.current_results, f, indent=2)
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write("API-HUNTER REPORT\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(f"URL: {self.url_entry.get()}\n")
                        f.write(f"Fecha: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        
                        f.write("APIs ENCONTRADAS:\n")
                        f.write("-" * 30 + "\n")
                        for i, api in enumerate(self.current_results['apis'], 1):
                            f.write(f"{i:3}. {api}\n")
                
                messagebox.showinfo("Guardado", f"Resultados guardados en:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar el archivo:\n{str(e)}")
    
    def on_closing(self):
        """Manejar cierre de la aplicación"""
        if self.is_scanning:
            if messagebox.askyesno("Escaneo en curso", 
                                 "Hay un escaneo en progreso. ¿Seguro que quieres salir?"):
                self.root.destroy()
        else:
            self.root.destroy()

# ============================================================================
# ESTILOS PERSONALIZADOS PARA TKINTER
# ============================================================================

def configure_styles():
    """Configurar estilos adicionales"""
    style = ttk.Style()
    
    # Botón de acento
    style.configure('Accent.TButton', 
                   background='#00ff88',
                   foreground='black',
                   borderwidth=2,
                   font=('Arial', 11, 'bold'))
    
    style.map('Accent.TButton',
             background=[('active', '#00cc77'), ('disabled', '#555555')])

# ============================================================================
# EJECUCIÓN PRINCIPAL
# ============================================================================

if __name__ == "__main__":
    # Crear ventana principal
    root = tk.Tk()
    
    # Configurar estilos
    configure_styles()
    
    # Crear aplicación
    app = APIHunterGUI(root)
    
    # Ejecutar aplicación
    root.mainloop()