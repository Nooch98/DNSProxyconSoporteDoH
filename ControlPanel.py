import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading

# Configuración del panel
SERVER_IP = "127.0.0.1" # USA LA IP DE TU SERVIDOR DNS EN CASO DE SER OTRO EQUIPO USE SU IP EJ: 10.10.10.23
CONTROL_PORT = 5001  # NO USAR EL PUERTO 5000 YA QUE ES EL QUE USA FLASK Y PROVOCA CONFLICTOS

class DNSServerControlPanel:
    def __init__(self, root):
        self.root = root
        self.root.title("Panel de Control DNS - Enhanced")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # Estilo visual
        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 10, "bold"))
        style.configure("TLabel", font=("Helvetica", 11))
        style.configure("Green.TLabel", foreground="green")
        style.configure("Red.TLabel", foreground="red")

        # Pestañas
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, fill="both", expand=True)

        self.control_tab = ttk.Frame(self.notebook)
        self.stats_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)
        self.blacklist_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.control_tab, text="Control")
        self.notebook.add(self.stats_tab, text="Estadísticas")
        self.notebook.add(self.logs_tab, text="Logs")
        self.notebook.add(self.blacklist_tab, text="Lista Negra")

        # --- Pestaña de Control ---
        self.control_frame = ttk.LabelFrame(self.control_tab, text="Controles del Servidor")
        self.control_frame.pack(pady=10, padx=10, fill="x")

        self.start_button = ttk.Button(self.control_frame, text="Iniciar", command=self.send_start)
        self.start_button.grid(row=0, column=0, padx=5, pady=5)

        self.stop_button = ttk.Button(self.control_frame, text="Detener", command=self.send_stop)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)

        self.restart_button = ttk.Button(self.control_frame, text="Reiniciar", command=self.send_restart)
        self.restart_button.grid(row=0, column=2, padx=5, pady=5)

        self.reload_config_button = ttk.Button(self.control_frame, text="Recargar Configuracion")
        self.reload_config_button.grid(row=0, column=3, padx=5, pady=5)

        # Indicador de estado
        self.status_label = ttk.Label(self.control_frame, text="Estado: Desconocido")
        self.status_label.grid(row=1, column=0, columnspan=2, pady=5)
        self.status_indicator = tk.Canvas(self.control_frame, width=20, height=20)
        self.status_indicator.grid(row=1, column=2, padx=5)
        self.update_status_indicator("gray")

        # Comando personalizado
        ttk.Label(self.control_frame, text="Comando:").grid(row=2, column=0, pady=5)
        self.custom_command_entry = ttk.Entry(self.control_frame)
        self.custom_command_entry.grid(row=2, column=1, columnspan=2, pady=5, sticky="ew")
        self.send_custom_button = ttk.Button(self.control_frame, text="Enviar", command=self.send_custom)
        self.send_custom_button.grid(row=2, column=3, padx=5)

        # --- Pestaña de Estadísticas ---
        self.stats_frame = ttk.LabelFrame(self.stats_tab, text="Estadísticas del Servidor")
        self.stats_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.queries_label = ttk.Label(self.stats_frame, text="Consultas: 0")
        self.queries_label.grid(row=0, column=0, padx=5, pady=5)

        self.ips_label = ttk.Label(self.stats_frame, text="IPs conectadas: 0")
        self.ips_label.grid(row=0, column=1, padx=5, pady=5)

        self.success_label = ttk.Label(self.stats_frame, text="Éxitos: 0", style="Green.TLabel")
        self.success_label.grid(row=1, column=0, padx=5, pady=5)

        self.error_label = ttk.Label(self.stats_frame, text="Errores: 0", style="Red.TLabel")
        self.error_label.grid(row=1, column=1, padx=5, pady=5)

        self.blocked_label = ttk.Label(self.stats_frame, text="Bloqueados: 0")
        self.blocked_label.grid(row=2, column=0, padx=5, pady=5)

        self.avg_time_label = ttk.Label(self.stats_frame, text="Tiempo promedio: N/A")
        self.avg_time_label.grid(row=2, column=1, padx=5, pady=5)

        self.ip_port_label = ttk.Label(self.stats_frame, text="IP: ? Puerto: ?")
        self.ip_port_label.grid(row=3, column=0, columnspan=2, pady=5)

        # Gráfico
        self.fig, self.ax = plt.subplots(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.stats_frame)
        self.canvas.get_tk_widget().grid(row=4, column=0, columnspan=2, pady=10)

        # --- Pestaña de Logs ---
        self.logs_frame = ttk.LabelFrame(self.logs_tab, text="Logs del Servidor")
        self.logs_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.log_area = scrolledtext.ScrolledText(self.logs_frame, width=80, height=20, state='disabled')
        self.log_area.pack(pady=5, fill="both", expand=True)

        self.logs_buttons_frame = ttk.Frame(self.logs_frame)
        self.logs_buttons_frame.pack(pady=5)
        self.clear_logs_button = ttk.Button(self.logs_buttons_frame, text="Limpiar", command=self.clear_logs)
        self.clear_logs_button.grid(row=0, column=0, padx=5)
        self.copy_logs_button = ttk.Button(self.logs_buttons_frame, text="Copiar al Portapapeles", command=self.copy_logs)
        self.copy_logs_button.grid(row=0, column=1, padx=5)

        # --- Pestaña de Lista Negra ---
        self.blacklist_frame = ttk.LabelFrame(self.blacklist_tab, text="Gestión de Lista Negra")
        self.blacklist_frame.pack(pady=10, padx=10, fill="both", expand=True)

        ttk.Label(self.blacklist_frame, text="Dominio:").grid(row=0, column=0, padx=5, pady=5)
        self.blacklist_entry = ttk.Entry(self.blacklist_frame)
        self.blacklist_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.add_blacklist_button = ttk.Button(self.blacklist_frame, text="Añadir", command=self.add_to_blacklist)
        self.add_blacklist_button.grid(row=0, column=2, padx=5, pady=5)
        self.remove_blacklist_button = ttk.Button(self.blacklist_frame, text="Eliminar", command=self.remove_from_blacklist)
        self.remove_blacklist_button.grid(row=0, column=3, padx=5, pady=5)

        self.blacklist_listbox = tk.Listbox(self.blacklist_frame, height=15)
        self.blacklist_listbox.grid(row=1, column=0, columnspan=4, pady=5, sticky="nsew")
        self.blacklist_frame.grid_columnconfigure(1, weight=1)

        # Iniciar actualización
        self.update_gui()

    def send_command(self, command):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((SERVER_IP, CONTROL_PORT))
                s.send(command.encode('utf-8'))
                response = s.recv(4096).decode('utf-8')
                return response if response else "No response"
        except socket.timeout:
            return "Error: Connection timed out"
        except Exception as e:
            return f"Error: {e}"

    def send_start(self):
        response = self.send_command("start")
        print(response)

    def send_stop(self):
        response = self.send_command("stop")
        print(response)

    def send_restart(self):
        self.send_stop()
        time.sleep(1)
        self.send_start()
        print("Servidor reiniciado")

    def send_reload_config(self):
        response = self.send_command("reload_config")
        print(response)

    def send_custom(self):
        command = self.custom_command_entry.get().strip()
        if command:
            response = self.send_command(command)
            messagebox.showinfo("Respuesta", response)
            self.custom_command_entry.delete(0, tk.END)

    def remove_from_blacklist(self):
        domain = self.blacklist_entry.get().strip()
        if domain:
            response = self.send_command(f"blacklist_remove:{domain}")
            if "Error" not in response:
                messagebox.showinfo("Éxito", f"Dominio {domain} eliminado")
            self.blacklist_entry.delete(0, tk.END)
            self.update_blacklist()
        else:
            messagebox.showerror("Error", response)
    
    def add_to_blacklist(self):
        domain = self.blacklist_entry.get().strip()
        if domain:
            response = self.send_command(f"blacklist_add:{domain}")
            if "Error" not in response:
                messagebox.showinfo("Éxito", f"Dominio {domain} añadido")
            self.blacklist_entry.delete(0, tk.END)
            self.update_blacklist()
        else:
            messagebox.showerror("Error", response)
    
    def update_blacklist(self):
        response = self.send_command("get_blacklist")
        if not response.startswith("Error:"):
            try:
                blacklist = json.loads(response)
                self.blacklist_listbox.delete(0, tk.END)
                for domain in blacklist:
                    self.blacklist_listbox.insert(tk.END, domain)
            except json.JSONDecodeError:
                print("Error al parsear lista negra")
    
    def clear_logs(self):
        self.log_area.config(state='normal')
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state='disabled')

    def copy_logs(self):
        self.log_area.config(state='normal')
        logs = self.log_area.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(logs)
        self.log_area.config(state='disabled')
        messagebox.showinfo("Éxito", "Logs copiados al portapapeles")

    def update_status_indicator(self, color):
        self.status_indicator.delete("all")
        self.status_indicator.create_oval(2, 2, 18, 18, fill=color, outline="")

    def update_gui(self):
        response = self.send_command("stats")
        if response.startswith("Error:"):
            self.status_label.config(text=f"Estado: {response}")
            self.update_status_indicator("gray")
            self.queries_label.config(text="Consultas: N/A")
            self.ips_label.config(text="IPs conectadas: N/A")
            self.success_label.config(text="Éxitos: N/A")
            self.error_label.config(text="Errores: N/A")
            self.blocked_label.config(text="Bloqueados: N/A")
            self.avg_time_label.config(text="Tiempo promedio: N/A")
            self.ip_port_label.config(text="IP: ? Puerto: ?")
            self.log_area.config(state='normal')
            self.log_area.delete(1.0, tk.END)
            self.log_area.insert(tk.END, f"{response}\n")
            self.log_area.config(state='disabled')
            self.ax.clear()
            self.canvas.draw()
        else:
            try:
                stats = json.loads(response)
                self.status_label.config(text=f"Estado: {stats['status']}")
                self.update_status_indicator("green" if stats['status'] == "Corriendo" else "red")
                self.queries_label.config(text=f"Consultas: {stats['queries']}")
                self.ips_label.config(text=f"IPs conectadas: {stats['connected_ips']}")
                self.success_label.config(text=f"Éxitos: {stats['success_count']}")
                self.error_label.config(text=f"Errores : {stats['error_count']}")
                self.blocked_label.config(text=f"Bloqueados: {stats['blocked_domains_count']}")
                avg_time = stats['success_count'] and stats.get('total_query_time', 0) / stats['success_count'] or 0
                self.avg_time_label.config(text=f"Tiempo promedio: {avg_time:.4f}s")
                self.ip_port_label.config(text=f"IP: {stats['ip']} Puerto: {stats['port']}")

                self.log_area.config(state='normal')
                self.log_area.delete(1.0, tk.END)
                for log_entry in stats['logs']:
                    self.log_area.insert(tk.END, log_entry + "\n")
                    self.log_area.config(state='disabled')
                    self.log_area.yview(tk.END)

                # Actualizar gráfico
                self.ax.clear()
                self.ax.bar(['Éxitos', 'Errores'], [stats['success_count'], stats['error_count']], color=['green', 'red'])
                self.ax.set_title("Consultas Exitosas vs Fallidas")
                self.canvas.draw()

                # Actualizar lista negra
                self.update_blacklist()
            except json.JSONDecodeError as e:
                print(f"Error al procesar estadísticas: {e}")

        self.root.after(1000, self.update_gui)


def main():
    root = tk.Tk()
    app = DNSServerControlPanel(root)
    root.mainloop()


if __name__ == "__main__":
    main()
