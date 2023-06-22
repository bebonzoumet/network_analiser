import scapy.all as scapy
import time
class Analisador_de_rede:
    def __init__(self):
        self.port_list = []
        temp_list = []
        self.ip_list = []
        with open("netconf.txt") as f:
            self.arquivo = f.readlines()
        for i, lines in enumerate(self.arquivo):
            if i==0:
                split_list = lines.split(": ")
            elif i==1:
                self.periodo = int(lines.split(", ")[0])
                self.subrede = lines.split(", ")[1]
                self.ip_local = lines.split(", ")[2]
        for i, x in enumerate(split_list):
            if i==0:
                self.ip_list.append(x)
            if i==len(split_list)-1:
                self.port_list.append(x.split("\n")[0])
            if ", " in x:
                temp_list = x.split(", ")
                self.port_list.append(temp_list[0])
                self.ip_list.append(temp_list[1])
        while True:
            self.varredura_ip()
            self.varredura_porta()
            time.sleep(self.periodo)

    def varredura_ip(self):
        """Realiza varredura pelos ips da subrede"""
        datagrama = scapy.IP()
        datagrama.src = self.ip_local
        datagrama.ttl = 77
        for i in range(0,17):
            print("i =", i)
            ip_dest = self.ip_local.split(".")
            ip_dest[3] = str(i)
            ip_dest = ".".join(ip_dest)
            datagrama.dst = ip_dest
            pacote1 = datagrama / scapy.ICMP(type = "echo-request")
            tempo_inicio=time.time()
            respostas, nao_respondido = scapy.srp(pacote1, timeout=3)
            tempo_final=time.time()
            tempo = tempo_final - tempo_inicio
            if len(respostas)>0:
                if ip_dest in self.ip_list:
                    anomalia = False
                    rede = True
                    descricao = "Resposta ICMP esperada"
                else:
                    anomalia = True
                    rede = False
                    descricao = "Resposta ICMP inesperada ip nao esta na lista de ativos"
                protocolo = respostas[0].proto
                print("protocolo respondido:",protocolo)
            else:
                if ip_dest in self.ip_list:
                    anomalia = True
                    rede = False
                    descricao = "Resposta ICMP esperada nao ocorreu"
                else:
                    anomalia = False
                    rede = True
                    descricao = "Nao recebeu resposta ICMP e nao era esperada"
                protocolo = nao_respondido[0].proto
                print("protocolo nao respondido:",protocolo)
            if protocolo == 1:
                protocolo = "ICMP"
                camada = "Transporte"
            elif protocolo == 6:
                protocolo = "TCP"
                camada = "Transporte"
            elif protocolo == 17:
                protocolo = "UDP"
                camada = "Transporte"
            elif protocolo == 4:
                protocolo = "IP"
                camada = "Rede"
            elif protocolo == 143:
                protocolo = "Ether"
                camada = "Enlace"
            with open("netlog.txt", "a") as f:
                arquivo_log = f
                arquivo_log.write(f"{tempo}, {camada}, {protocolo}, {self.ip_local}, {self.ip_local}, {ip_dest}, Anomalia: {anomalia}/Rede: {rede}, Descricao: {descricao}\n")

    def varredura_porta(self):
        """realiza varredura pelas portas"""
        datagrama = scapy.IP()
        datagrama.src = self.ip_local
        segmento = scapy.TCP(flags="S")
        for i, ip_dest in enumerate(self.ip_list):
            datagrama.dst = ip_dest
            datagrama.show()
            print("ip_dest:",ip_dest)
            for port in self.port_list[i].split(","):
                segmento.dport = int(port)
                segmento.show()
                pacote1 = datagrama / segmento
                tempo_inicial = time.time()
                respostas, nao_respondido = scapy.srp(pacote1, timeout=3)
                tempo_final = time.time()
                tempo = tempo_final - tempo_inicial
                if len(respostas)>0:
                    if port in self.port_list[i].split(","):
                        anomalia = False
                        rede = True
                        descricao = "Porta na lista de portas ativas, resposta esperada recebida"
                    else:
                        anomalia = True
                        rede = False
                        descricao = "Porta nao esta na lista de portas ativas e uma resposta foi recebida"
                    protocolo = respostas[0].proto
                    print("protocolo:",protocolo)
                else:
                    if port in self.port_list[i].split(","):
                        anomalia = True
                        rede = False
                        descricao = "Porta na lista de portas ativas, resposta esperada nao foi recebida"
                    else:
                        anomalia = False
                        rede = True
                        descricao = "Porta nao esta na lista de portas ativas e nenhuma resposta foi recebida"
                    protocolo = nao_respondido[0].proto
                    print("protocolo:", protocolo)
                if protocolo == 1:
                    protocolo = "ICMP"
                elif protocolo == 6:
                    protocolo = "TCP"
                elif protocolo == 17:
                    protocolo = "UDP"
                elif protocolo == 4:
                    protocolo = "IP"
                elif protocolo == 143:
                    protocolo = "Ether"
                with open("netlog.txt", "a") as f:
                    arquivo_log = f
                    arquivo_log.write(f"{tempo}, rede, {protocolo}, {self.ip_local}, {self.ip_local}, {ip_dest}, Anomalia: {anomalia}/Rede: {rede}, Descricao: {descricao}\n")

analisador_de_rede = Analisador_de_rede()
