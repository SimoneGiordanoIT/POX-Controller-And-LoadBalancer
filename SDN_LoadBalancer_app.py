from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()  #stampa nel terminale informazioni che vengono trattate più avanti

class Tutorial (object):

	routingTable = {}  #dizionario associa indirizzo IP a interfaccia di uscita. viceversa l'altro
	routingTable[IPAddr("10.0.0.101")] = 1
	routingTable[IPAddr("10.0.0.102")] = 2
	routingTable[IPAddr("10.0.0.103")] = 3
	routingTable[IPAddr("10.0.0.104")] = 4
	routingTable[IPAddr("79.12.1.10")] = 5
	routingTable[IPAddr("79.12.2.10")] = 6
	routingTable[IPAddr("79.12.3.10")] = 7
	routingTable[IPAddr("79.12.4.10")] = 8


	interfaceIPaddresses = {}
	interfaceIPaddresses[1] = IPAddr("10.0.0.101")
	interfaceIPaddresses[2] = IPAddr("10.0.0.102")
	interfaceIPaddresses[3] = IPAddr("10.0.0.103")
	interfaceIPaddresses[4] = IPAddr("10.0.0.104")
	interfaceIPaddresses[5] = IPAddr("79.12.1.10")
	interfaceIPaddresses[6] = IPAddr("79.12.2.10")
	interfaceIPaddresses[7] = IPAddr("79.12.3.10")
	interfaceIPaddresses[8] = IPAddr("79.12.4.10")


	arpTable = {}
	bufferIPpacket = {} #gestione della coda dei pckt in arrivo allo switch

	semaforo1=0		#gestione del metodo round robin
	semaforo2=0
	arpCount=0		#da chiedere a Calisi

	def __init__ (self, connection): 
		print "_INIT_"
		self.connection = connection
		connection.addListeners(self)

	def resend_packet (self, packet_in, out_port):
		print "RESEND_PACKET"
		msg = of.ofp_packet_out()       #crea un pkt messaggio da mandare in output
		msg.data = packet_in			#con packet_in prendo il pkt in entrata 
		action = of.ofp_action_output(port = out_port)			#indica la porta uscita su cui inviare il msg
		msg.actions.append(action)								#appendo l'azione di mandare in uscita il pkt sulla porta
		self.connection.send(msg)								#invio mex

	def send_arp_reply (self, packet, inPort):
		print "SEND_ARP_REPLY"
		arp_reply = pkt.arp()							#crea un pkt di tipo ARP in cui si inseriranno le info 
		arp_reply.hwsrc = EthAddr("1a:72:4f:e7:0f:46")   #poiche del pkt arp ci interessa solo il mac e l'ip di destinazione, nel mac sorgente si scrive un mac fittizio 
		arp_reply.hwdst = packet.src
		arp_reply.opcode = pkt.arp.REPLY				#definisco la natura del pkt che sto creando. arp reply
		arp_reply.protosrc = packet.payload.protodst		#APPROFONDIRE: l'ip sorgente è l'ip del pkt di destinazione
		arp_reply.protodst = packet.payload.protosrc
		if packet.payload.protosrc not in self.arpTable:     #IP del sorgente del pkt NON dell'arp reply. se non è nell arp table lo inserisco chiave IP e valore MAC sorgente
			self.arpTable[packet.payload.protosrc] = packet.src
		ether = pkt.ethernet()									#creazione pkt ethernet di cui definisco il tipo a riga 63
		ether.type = pkt.ethernet.ARP_TYPE
		ether.dst = packet.src
		ether.src = EthAddr("1a:72:4f:e7:0f:46")
		ether.payload = arp_reply								#nel payload si mette il pkt arp creato prima
		self.resend_packet(ether, inPort)


	def send_arp_request (self, IPdestinationAddress, IPsourceAddress):
		print "SEND_ARP_REQUEST"
		outInterface = self.routingTable[IPdestinationAddress]  #prelevo interfaccia di uscita dalla routing table dato l'ip di destinazione
		arp_request = pkt.arp()
		arp_request.hwsrc = EthAddr("1a:72:4f:e7:0f:46")
		arp_request.opcode = pkt.arp.REQUEST
		arp_request.protosrc = IPsourceAddress	#ip del sorgente 
		arp_request.protodst = IPdestinationAddress
		ether = pkt.ethernet()
		ether.type = pkt.ethernet.ARP_TYPE
		ether.dst = pkt.ETHER_BROADCAST       #il pkt viene inviato in broadcast e solo l'host interessato risponderà
		ether.src = EthAddr("1a:72:4f:e7:0f:46")
		ether.payload = arp_request
		self.resend_packet(ether, outInterface)


	def send_packets_in_queue(self, IP_destination_addr):
		print "SEND_PACKETS_IN_QUEUE"
		out_port = -1
		coda = self.bufferIPpacket.copy()		#prende i pkt in coda e li copia in coda
		for buffID in coda:						#ciclo sugli ID dei pkt. il buffer ha come chiave l'id e valore il pkt
			packet = coda[buffID]				#prelevo il pkt a quel buff id
			del self.bufferIPpacket[buffID]		#elimino il pkt dal buffer visto che si sta parsando

			if packet.payload.dstip == IP_destination_addr:		#prendo il pkt che ha invocato la fne tramite l'ip di destinazione 	
				#log.debug("Installing flow...")
				print "INSTALLING FLOW"
				msg = of.ofp_flow_mod()							#creo il pkt msg in cui inserisco le flow rule. the packet that will eventually be sent to the router to add a flow entry
				if packet.next.protocol==pkt.ipv4.TCP_PROTOCOL:
					msg.match = of.ofp_match(dl_type=0x800, nw_src=packet.payload.srcip, nw_dst=IP_destination_addr, nw_proto=6, tp_src=packet.payload.payload.srcport, tp_dst=packet.payload.payload.dstport) 
					#msg.match la struttura che contiene le regole con cui bisogna matchare il pkt. tpsrc i payload che spacchetto servono per arrivare al lvl di trasporto per la porta
				else:
					msg.match = of.ofp_match(dl_type=0x800, nw_src=packet.payload.srcip, nw_dst=IP_destination_addr)

				msg.idle_timeout = 6
				#msg.hard_timeout = 8
				msg.buffer_id = buffID
				acts = []				#azioni che deve eseguire il pkt prima di essere inviato sulla porta di uscita e dopo che si è fatto le flow table
				if packet.payload.dstip==IPAddr('81.77.12.4'):
					if self.semaforo1==0:
						IP_destination_addr=IPAddr('10.0.0.101')
						self.semaforo1=1
					else:
						IP_destination_addr=IPAddr('10.0.0.102')
						self.semaforo1=0


					action=of.ofp_action_nw_addr.set_dst(IP_destination_addr) 	#imposta destinazione l'ip addr che il round robin gli ha assegnato
					acts.append(action)

				if packet.payload.dstip==IPAddr('81.77.12.5'):
					if self.semaforo2==0:
						IP_destination_addr=IPAddr('10.0.0.103')
						self.semaforo2=1
					else:
						IP_destination_addr=IPAddr('10.0.0.104')
						self.semaforo2=0


					action=of.ofp_action_nw_addr.set_dst(IP_destination_addr)
					acts.append(action)

				#si gestisce il caso da server a client. si fa la conversione da indirizzo privato a ind pubblico

				if packet.payload.srcip==IPAddr('10.0.0.101') or packet.payload.srcip==IPAddr('10.0.0.102'):			
					action=of.ofp_action_nw_addr.set_src(IPAddr('81.77.12.4'))
					acts.append(action)
				elif packet.payload.srcip==IPAddr('10.0.0.103') or packet.payload.srcip==IPAddr('10.0.0.104'):
					action=of.ofp_action_nw_addr.set_src(IPAddr('81.77.12.5'))
					acts.append(action)


				action = of.ofp_action_dl_addr.set_dst(self.arpTable[IP_destination_addr])		#prelevo dall arp table il mac dell'indirizzo ip associato di destinazione 
				acts.append(action)

				out_port = self.routingTable[IP_destination_addr]
				action = of.ofp_action_output(port = out_port)
				acts.append(action)

				msg.actions = acts
				self.connection.send(msg)

	def _handle_PacketIn (self, event):
		print "HANDLE_PACKET_IN"				
		packet = event.parsed			#event è il pacchetto e viene parsato (event.parsed), event.parsed prendo le info sul tipo di pckt
		packet_in = event.ofp			#ofp appartiene alla libreria pox.openflow.libopenflow_01. Prendo il pckt in entrata e lo descrivo tramite la f.ne ofp. In pckt in memorizzo info in più rispetto a packet
		inPort = packet_in.in_port		#memorizzo la porta di input del packt

		if packet.type == packet.ARP_TYPE:													
			if packet.payload.opcode == pkt.arp.REQUEST:		
				self.send_arp_reply(packet, inPort)
			elif packet.payload.opcode == pkt.arp.REPLY:
				self.arpTable[packet.payload.protosrc] = packet.payload.hwsrc
				if (len(self.bufferIPpacket) > 0):     					#si assicura che ci siano uno o più di un pacchetti nel buffer. buffer con i pkt di cui attendo arp reply
					if ((packet.payload.protosrc==IPAddr('10.0.0.101')) or (packet.payload.protosrc==IPAddr('10.0.0.102'))):   #contatore: non sapendo quale server soddisfa la mia richiesta si richiedono entrambre le arp request 
						self.arpCount += 1																						#e quando avrò entrambe le arp reply procederò con lil send packet in queue
						if self.arpCount == 2:
							self.arpCount = 0
							self.send_packets_in_queue(IPAddr('81.77.12.4'))  

					if ((packet.payload.protosrc==IPAddr('10.0.0.103')) or (packet.payload.protosrc==IPAddr('10.0.0.104'))):
						self.arpCount += 1
						if self.arpCount == 2:
							self.arpCount = 0
							self.send_packets_in_queue(IPAddr('81.77.12.5'))

		if packet.type == packet.IP_TYPE: 		#pkt ip sono quelli del ping tra client server e della connessione tcp client server (viceversa)
			ip_packet=packet.payload			#recupero i dati mantenuti nel payload del pkt ip
			self.arpTable[ip_packet.srcip] = str(packet.src)			#casting a stringa del mac della sorgente che è scritto a fuffa

			#FORWARDING
			IP_destination_addr = packet.payload.dstip
			IP_source_addr= packet.payload.srcip
			self.bufferIPpacket[packet_in.buffer_id] = packet    #packet.ofp a riga 152 preleva anche il buffer_id del pkt 

			if IP_destination_addr in self.arpTable:  #fallira' sicuramente se verso il server poiche contiene ip privato del server. Serve quando il server risponde al client
				self.send_packets_in_queue(IP_destination_addr)
			else:
				if IPAddr('81.77.12.4')==IP_destination_addr:
					if ((IPAddr('10.0.0.101') not in self.arpTable) and (IPAddr('10.0.0.102') not in self.arpTable)):
						self.send_arp_request(IPAddr('10.0.0.101'), IP_source_addr)
						self.send_arp_request(IPAddr('10.0.0.102'), IP_source_addr)
					else:
						self.send_packets_in_queue(IP_destination_addr)
				if IPAddr('81.77.12.5')==IP_destination_addr:
					if ((IPAddr('10.0.0.103') not in self.arpTable) and (IPAddr('10.0.0.104') not in self.arpTable)):
						self.send_arp_request(IPAddr('10.0.0.103'), IP_source_addr)
						self.send_arp_request(IPAddr('10.0.0.104'), IP_source_addr)
					else:
						self.send_packets_in_queue(IP_destination_addr)
				if ((IPAddr('81.77.12.4')!=IP_destination_addr) and (IPAddr('81.77.12.5')!=IP_destination_addr)):  #caso di risposta da server a host
					self.send_arp_request(IP_destination_addr, IP_source_addr)   #arp request in cui inserisco ip destinazione e ip sorgente

def launch ():
	def start_switch (event):
		print "START_SWITCH"
		log.debug("Controlling %s" % (event.connection,))  #
		Tutorial(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
