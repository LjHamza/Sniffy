from tkinter import *
from tkinter import ttk
import sqlite3
from scapy.all import *
from datetime import date
import threading


root = Tk()
root.title('Sniffy')

root.geometry("1300x750")



#--------- DATABASE PART ---------#

conn = sqlite3.connect("Sniffy.db")
c = conn.cursor()

c.execute("""
		CREATE TABLE if not exists sniffed (
			Packet_type text,
			Mac_src text,
			Ip_src text,
			Port_src integer,
			Mac_dest text,
			Ip_dest text,
			Port_dest integer,
			date text
		)""")


#--------- NETWORK PART ---------#

pack_info = []

def testing(pkt):
	pack_dmac = pkt[Ether].dst
	pack_smac = pkt[Ether].src
	
	
	today = date.today()

	if TCP in pkt:
		pack_type = "TCP"
		pack_sport = pkt[TCP].sport
		pack_dport = pkt[TCP].dport
		pack_dip = pkt[IP].dst
		pack_sip = pkt[IP].src
		pack_info.append((pack_type, pack_smac, pack_sip, pack_sport, pack_dmac, pack_dip, pack_dport, today))
	elif UDP in pkt:
		pack_type = "UDP"
		pack_sport = pkt[UDP].sport
		pack_dport = pkt[UDP].dport
		pack_dip = pkt[IP].dst
		pack_sip = pkt[IP].src
		pack_info.append((pack_type, pack_smac, pack_sip, pack_sport, pack_dmac, pack_dip, pack_dport, today))
	if ICMP in pkt:
		pack_type = "ICMP"
		pack_dip = pkt[IP].dst
		pack_sip = pkt[IP].src
		pack_sport = 0
		pack_dport = 0
		pack_info.append((pack_type, pack_smac, pack_sip, pack_sport, pack_dmac, pack_dip, pack_dport, today))


def interface_machine():
	interfa = conf.iface
	interface.delete(1.0,END)
	interface.insert(END,interfa)


def mac_machine():
	mac_src = get_if_hwaddr(conf.iface)
	mac.delete(1.0,END)
	mac.insert(END,mac_src)


def ip_machine():
	ip_src = get_if_addr(conf.iface)
	ip.delete(1.0,END)
	ip.insert(END,ip_src)


def query_database():
	# Create a database or connect to one that exists
	conn = sqlite3.connect('Sniffy.db')

	# Create a cursor instance
	c = conn.cursor()

	sniff(iface=conf.iface ,prn=testing, count=50, store=0)

	c.executemany("INSERT INTO sniffed VALUES (?, ?, ?, ?, ?, ?, ?, ?)", pack_info)

	conn.commit()

	c.execute("SELECT rowid, * FROM sniffed")
	records = c.fetchall()
	
	# Add our data to the screen
	global count
	count = 0

	my_tree.ip.delete(1.0,END)

	for record in records:
		if count % 2 == 0:
			my_tree.insert(parent='', index='end', iid=count, text='', values=(record[0], record[1], record[2], record[3], record[4], record[5], record[6], record[7], record[8]), tags=('evenrow',))
		else:
			my_tree.insert(parent='', index='end', iid=count, text='', values=(record[0], record[1], record[2], record[3], record[4], record[5], record[6], record[7], record[8]), tags=('oddrow',))
		# increment counter
		count += 1


	# Commit changes
	conn.commit()

	# Close our connection
	conn.close()


def history_database():
	# Create a database or connect to one that exists
	conn = sqlite3.connect('Sniffy.db')

	# Create a cursor instance
	c = conn.cursor()

	

	c.execute("SELECT rowid, * FROM sniffed")
	records = c.fetchall()
	
	# Add our data to the screen
	global count
	count = 0

	for record in records:
		if count % 2 == 0:
			my_tree.insert(parent='', index='end', iid=count, text='', values=(record[0], record[1], record[2], record[3], record[4], record[5], record[6], record[7], record[8]), tags=('evenrow',))
		else:
			my_tree.insert(parent='', index='end', iid=count, text='', values=(record[0], record[1], record[2], record[3], record[4], record[5], record[6], record[7], record[8]), tags=('oddrow',))
		# increment counter
		count += 1


	# Commit changes
	conn.commit()

	# Close our connection
	conn.close()

##


def nbrtcp():
	# Create a database or connect to one that exists
	conn = sqlite3.connect('Sniffy.db')

	# Create a cursor instance
	c = conn.cursor()

	c.execute("SELECT rowid, * FROM sniffed WHERE Packet_type='TCP' ")
	nbre = len(c.fetchall())

	tcp.delete(1.0,END)
	tcp.insert(END, nbre)


def nbrudp():
	# Create a database or connect to one that exists
	conn = sqlite3.connect('Sniffy.db')

	# Create a cursor instance
	c = conn.cursor()

	c.execute("SELECT rowid, * FROM sniffed WHERE Packet_type='UDP' ")
	nbre = len(c.fetchall())

	udp.delete(1.0,END)

	udp.insert(END, nbre)


def nbricmp():
	# Create a database or connect to one that exists
	conn = sqlite3.connect('Sniffy.db')

	# Create a cursor instance
	c = conn.cursor()

	c.execute("SELECT rowid, * FROM sniffed WHERE Packet_type='ICMP' ")
	nbre = len(c.fetchall())

	icmp.delete(1.0,END)
	icmp.insert(END, nbre)


def remove_tree():
	for e in my_tree.get_children():
		my_tree.delete(e)


#--------- THREAD PART ----------#

thread_sniffer = threading.Thread(target=query_database)
thread_history = threading.Thread(target=history_database)


#--------- Styling PART ---------#

# Add Some Style
style = ttk.Style()

# Pick A Theme
style.theme_use('default')

title= Label(root, text="Sniffy", font=('bold',18))
title.pack(pady=10)

# Configure the Treeview Colors
style.configure("Treeview",
				background="#D3D3D3",
				foreground="black",
				rowheight=25,
				fieldbackground="#D3D3D3")

# Change Selected Color
style.map('Treeview',
		  background=[('selected', "#347083")])



# Create a Treeview Frame
tree_frame = Frame(root)
tree_frame.pack(pady=10)

# Create a Treeview Scrollbar
tree_scroll = Scrollbar(tree_frame)
tree_scroll.pack(side=RIGHT, fill=Y)

# Create The Treeview
my_tree = ttk.Treeview(tree_frame, yscrollcommand=tree_scroll.set, selectmode="extended")
my_tree.pack()

# Configure the Scrollbar
tree_scroll.config(command=my_tree.yview)

# Define Our Columns
my_tree['columns'] = ("Id","packet_type", "mac_source", "ip_source", "port_source", "mac_destination", "ip_destination", "port_destination", "date")

# Format Our Columns
my_tree.column("#0", width=0, stretch=NO)
my_tree.column("Id", anchor=CENTER, width=60)
my_tree.column("packet_type", anchor=CENTER, width=140)
my_tree.column("mac_source", anchor=CENTER, width=160)
my_tree.column("ip_source", anchor=CENTER, width=160)
my_tree.column("port_source", anchor=CENTER, width=160)
my_tree.column("mac_destination", anchor=CENTER, width=160)
my_tree.column("ip_destination", anchor=CENTER, width=160)
my_tree.column("port_destination", anchor=CENTER, width=160)
my_tree.column("date", anchor=CENTER, width=140)



# Create Headings
my_tree.heading("#0", text="", anchor=W)
my_tree.heading("Id", text="Id", anchor=CENTER)
my_tree.heading("packet_type", text="Packet Type", anchor=CENTER)
my_tree.heading("mac_source", text="Mac Source", anchor=CENTER)
my_tree.heading("ip_source", text="Ip Source", anchor=CENTER)
my_tree.heading("port_source", text="Port Source", anchor=CENTER)
my_tree.heading("mac_destination", text="Mac Destination", anchor=CENTER)
my_tree.heading("ip_destination", text="Ip Destination", anchor=CENTER)
my_tree.heading("port_destination", text="Port Destination", anchor=CENTER)
my_tree.heading("date", text="Date", anchor=CENTER)





# Create Striped Row Tags
my_tree.tag_configure('oddrow', background="white")
my_tree.tag_configure('evenrow', background="lightblue")

lf1 = LabelFrame(root, text = 'Machine')
lf1.pack(expand = 'yes', fill = 'x', padx=20)

ip = Text(lf1, width=20, height=1.3)
ip.grid(row=0, column=3, padx=10)
ip_button = Button(lf1, text="Adresse IP", width=40 , height=1, bd=3, cursor='hand2', font='bold',command=ip_machine)
ip_button.grid(row=0, column=0, padx=10, pady=10)

mac = Text(lf1, width=20, height=1.3)
mac.grid(row=1, column=3, padx=10)
mac_button = Button(lf1, text="Adresse MAC", width=40 , height=1, bd=3, cursor='hand2', font='bold',command=mac_machine)
mac_button.grid(row=1, column=0, padx=10, pady=10)

interface = Text(lf1, width=20, height=1.3)
interface.grid(row=2, column=3, padx=10)
interf_button = Button(lf1, text="Interface Réseau ", width=40 , height=1, bd=3, cursor='hand2', font='bold',command=interface_machine)
interf_button.grid(row=2, column=0, padx=10, pady=10)


scan_button = Button(root, text="Scan", width=16 , height=1, bd=5 , cursor='hand2', font='bold', command=thread_sniffer.start)
scan_button.place(x=600, y=650)

history_button = Button(root, text="Show Database", width=16 , height=1, bd=5 , cursor='hand2', font='bold', command=thread_history.start)
history_button.place(x=400, y=650)

remove_button = Button(root, text="Clear ", width=16 , height=1, bd=5 , cursor='hand2', font='bold', command=remove_tree)
remove_button.place(x=800, y=650)

tcp = Text(lf1, width=20, height=1.3)
tcp.grid(row=0, column=7, padx=10)
tcp_button = Button(lf1, text="Nombre de packets TCP", width=30 , height=1, bd=3, cursor='hand2', font='bold',command=nbrtcp)
tcp_button.grid(row=0, column=5, padx=10, pady=10)

udp = Text(lf1, width=20, height=1.3)
udp.grid(row=1, column=7, padx=10)
udp_button = Button(lf1, text="Nombre de packets UDP", width=30 , height=1, bd=3, cursor='hand2', font='bold',command=nbrudp)
udp_button.grid(row=1, column=5, padx=10, pady=10)

icmp = Text(lf1, width=20, height=1.3)
icmp.grid(row=2, column=7, padx=10)
icmp_button = Button(lf1, text="Nombre de packets ICMP", width=30 , height=1, bd=3, cursor='hand2', font='bold',command=nbricmp)
icmp_button.grid(row=2, column=5, padx=10, pady=10)



root.mainloop()
