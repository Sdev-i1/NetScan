import tkinter as tk
from tkinter import ttk, messagebox
import threading
import csv
import socket
import ipaddress
import psutil
from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
from mac_vendor_lookup import MacLookup


def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"

def get_mac_vendor(mac):
    try:
        return MacLookup().lookup(mac)
    except Exception:
        return "Unknown"

def list_network_adapters():
    adapters = []
    interfaces = psutil.net_if_addrs()
    for adapter_name, addresses in interfaces.items():
        for addr in addresses:
            if addr.family == socket.AF_INET:
                adapters.append({
                    "name": adapter_name,
                    "ip": addr.address,
                    "netmask": addr.netmask if addr.netmask else "255.255.255.0"
                })
    return adapters

def get_network_from_adapter(adapter):
    ip = adapter["ip"]
    netmask = adapter["netmask"]
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return str(network)

def scan_ip(ip, iface):

    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered = srp(packet, iface=iface, timeout=1, verbose=False)[0]

        if answered:
            for _, received in answered:
                device = [
                    received.psrc,
                    received.hwsrc,
                    get_device_name(received.psrc),
                    get_mac_vendor(received.hwsrc),
                ]
                return device
    except Exception:
        pass
    return None

def discover_devices_concurrent(network, iface):

    ip_list = [str(ip) for ip in ipaddress.IPv4Network(network, strict=False).hosts()]
    devices = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(scan_ip, ip, iface): ip for ip in ip_list}
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                devices.append(result)

    return devices

def write_to_csv(data, filename="scan_result.csv"):     
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "MAC", "Hostname", "Vendor"])  
        writer.writerows(data)


class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetScan")
        self.root.geometry("800x500")


        self.adapters = []
        self.selected_adapter = tk.StringVar()
        self.scanning = False


        self.create_widgets()
        self.load_adapters()

    def create_widgets(self):

        top_frame = ttk.Frame(self.root, padding="5")
        top_frame.pack(fill=tk.X)

        ttk.Label(top_frame, text="Сетевой адаптер:").pack(side=tk.LEFT, padx=5)

        self.adapter_combo = ttk.Combobox(top_frame, textvariable=self.selected_adapter, state="readonly", width=50)
        self.adapter_combo.pack(side=tk.LEFT, padx=5)
        self.adapter_combo.bind('<<ComboboxSelected>>', self.on_adapter_select)

        self.scan_btn = ttk.Button(top_frame, text="Сканировать", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.save_btn = ttk.Button(top_frame, text="Сохранить в CSV", command=self.save_to_csv, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=5)


        self.progress = ttk.Progressbar(top_frame, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)


        columns = ("IP", "MAC", "Hostname", "Vendor")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=20)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)


        scrollbar = ttk.Scrollbar(self.tree, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def load_adapters(self):

        self.adapters = list_network_adapters()
        if not self.adapters:
            messagebox.showerror("Ошибка", "Не найдено ни одного сетевого адаптера с IPv4.")
            return

        names = [f"{a['name']} - {a['ip']}" for a in self.adapters]
        self.adapter_combo['values'] = names
        if names:
            self.adapter_combo.current(0)
            self.selected_adapter.set(names[0])


    def get_current_adapter(self):

        idx = self.adapter_combo.current()
        if idx >= 0:
            return self.adapters[idx]
        return None

    def start_scan(self):

        if self.scanning:
            return

        adapter = self.get_current_adapter()
        if not adapter:
            messagebox.showwarning("Предупреждение", "Выберите сетевой адаптер.")
            return

        for row in self.tree.get_children():
            self.tree.delete(row)
        self.scan_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.DISABLED)
        self.progress.start()
        self.scanning = True

        thread = threading.Thread(target=self.scan_network, args=(adapter,))
        thread.daemon = True
        thread.start()

    def scan_network(self, adapter):

        network = get_network_from_adapter(adapter)
        iface = adapter['name']

        self.root.after(0, lambda: self.update_status(f"Сканирование сети {network}..."))

        try:
            devices = discover_devices_concurrent(network, iface)
        except Exception as e:
            devices = []
            self.root.after(0, lambda: messagebox.showerror("Ошибка", f"Ошибка при сканировании: {e}"))

        self.root.after(0, self.scan_finished, devices)

    def scan_finished(self, devices):

        self.progress.stop()
        self.scan_btn.config(state=tk.NORMAL)
        self.scanning = False

        if not devices:
            messagebox.showinfo("Результат", "В сети не найдено активных устройств.")
            return

        for dev in devices:self.tree.insert("", tk.END, values=dev)

        self.save_btn.config(state=tk.NORMAL)
        self.update_status(f"Найдено устройств: {len(devices)}")

    def update_status(self, text):
        self.root.title(f"Сканер сети (ARP) — {text}")

    def save_to_csv(self):
       
        filename = "scan_result.csv"
        data = []
        for child in self.tree.get_children():
            data.append(self.tree.item(child)['values'])

        if not data:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения.")
            return

        try:
            write_to_csv(data, filename)
            messagebox.showinfo("Сохранение", f"Результаты сохранены в файл {filename}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()