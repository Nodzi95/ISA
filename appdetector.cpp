#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <ctype.h>
#include <iostream>
#include <list>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
using namespace std;

/************************************************************************/
/*struktura obsahující informace o spojeni*/
struct spojeni{					
	string name;				//jmeno aplikace
	string sip;					//zdrojová ip adresa
	string dip;					//cílová ip adresa
	string sport;				//zdrojový port
	string dport;				//cílový port
	string protocol;			//protokol
	bool active = false;		//stav pro smazání
	bool printable = false;		//stav pro výpis
};
/************************************************************************/

/************************************************************************/
/*globální list spojení*/
list<spojeni> connections;
/************************************************************************/

/************************************************************************/
/*odeslání logu syslog serveru*/
/**
	Odesílání logu na syslog server

	@param char *address ip adresa serveru
	@param char *msg log 
	@return vrací úspěch(0) nebo neúspěch(1)
*/
int sendLog(const char *msg, char *ip, int sock){
	
	struct sockaddr_in server;
	memset(&server, 0, sizeof(struct sockaddr_in));

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(ip);		//nastaví se adresa serveru
	server.sin_port = htons(514);						//nastaví se port serveru
	
	size_t sending = sendto(sock, msg, strlen(msg), 0, (struct sockaddr*) &server, sizeof(server));		//odešle se zpráva 
	if(sending == -1){
		fprintf(stderr, "Chyba: chyba v odesilani socketu\n");
		close(sock);		//uzavře se socket
		return 1;
	}
	//printf("sent: %d\n", (int) sending);
	//close(sock);		//uzavře se socket
	return 0;
}
/************************************************************************/

/************************************************************************/
/**
	Ověří platnost ip adresy serveru

	@param char *ipaddr ip adresa serveru
	@return úspěch nebo neúspěch
*/
bool checkIP(char *ipaddr){
	struct sockaddr_in sock;
	int check = inet_pton(AF_INET, ipaddr, &(sock.sin_addr));
	if(check != 0) return true;
	else return false;
}
/************************************************************************/

/************************************************************************/
/**
	Kontroluje parametry příkazové řádky

	@param int argc počet parametrů příkazové řádky
	@param char *argv[] všechny parametry příkazové řádky
	@param char **ip získaná ip adresa serveru
	@param int *inv získaný časový interval
	@param char **filter získaný seznam kontrolovaných aplikací
	@return úspěch(0) nebo neúspěch(1)
*/
int parseArgs(int argc, char *argv[], char **ip, int *inv, char **filter){
	if(argc != 7){
		fprintf(stderr,"Chyba: spatny pocet parametru\n");
		return 1;
	}

	int ipCounter = 0;
	int intvCounter = 0;
	int filterCounter = 0;

	for(int i = 0; i < 7; i++){
		if(!strcmp("-s", argv[i]) && ipCounter == 0 && i != 6){
			*ip = argv[++i];
			ipCounter++;
		}
		else if(!strcmp("-i", argv[i]) && intvCounter == 0  && i != 6){
			char *p;
			*inv = strtol(argv[++i], &p, 10);
			if(*p){
				fprintf(stderr, "Chyba: %s neni cislo, za parametrem -i je ocekavano cislo\n",argv[i] );
				return 1;
			}
			if(*inv < 1){
				fprintf(stderr, "Chyba: cislo za parametrem -i musi byt vetsi, nez 1\n");
				return 1;
			}
			intvCounter++;
		}
		else if(!strcmp("-f", argv[i]) && filterCounter == 0  && i != 6){
			*filter = argv[++i];
			filterCounter++;
		}
	}
	if(ipCounter && intvCounter && filterCounter){
		/*printf("ip: %s\n", ip);
		printf("interval: %s\n", intv);
		printf("filter: %s\n", filter);*/
		return 0;	
	}
	else{
		fprintf(stderr, "Chyba: spatne zadane parametry\n" );
	}
	return 1;
}
/************************************************************************/

/************************************************************************/
/**
	Porovná rovnost dvou struktur

	@param spojeni &str1 struktura 1
	@param spojeni &str2 struktura 2
	@return true pokud se rovnají, false pokud ne
*/
bool comp(spojeni &str1, spojeni &str2){
	return str1.name == str2.name && str1.sip == str2.sip && str1.dip == str2.dip
	 && str1.sport == str2.sport && str1.dport == str2.dport && str1.protocol == str2.protocol;
}
/************************************************************************/

/************************************************************************/
/*vytvoří příkaz pro získání všech spojení, kterým odpovíná jméno*/
/**
	Vytvoří příkaz pro získání všech spojení, kterým odpovídá jméno

	@param const char *name jméno aplikace
	@return příkaz
*/
string command(const char *name){
	string result = "lsof -Pnl +M -i | grep ESTABLISHED | grep ";
	result += name;
	return result;
}
/************************************************************************/

/************************************************************************/
/**
	Naplní globální list spojení spojeními, kterým odpovídá jméno

	@param const char *app jméno aplikace 
	@return úspěch(0) nebo neúspěch(1)
*/
int check(const char *app){
	struct spojeni log;		//pomocná struktura
	char line[512];
	int found;
	bool ipv4, ipv6;
	string result;
	string cmnd = command(app);
	FILE *cmd = popen(cmnd.c_str(), "r");			//otevreni prikazove radky a zadani příkazu
	while(fgets(line, 512, cmd)){					//čtení jednotlivých řádků
		result = (string) line;
		ipv4 = false;
		ipv6 = false;
		int ipv = result.find("IPv4");
		if(ipv != string::npos){
			ipv4 = true;
		}
		ipv = result.find("IPv6");
		if(ipv != string::npos){
			ipv6 = true;
		}
		int protocol = result.find("TCP");
		if(protocol == string::npos){
			protocol = result.find("UDP");
		}
		//****************************** Parsování řádku a plnění struktury spojení*****************
		log.name = result.substr(0, result.find(" "));
		if(strcmp(app, log.name.c_str())){
			continue;
		}
		
		/************************************************************************/
		/*získání protokolu*/
		string PROTOCOL = result.substr(protocol, 3);
		log.protocol = PROTOCOL;
		/************************************************************************/

		if(ipv4){

			result = result.substr(protocol + 4);
			/************************************************************************/
			/*získání zdrojové ip adresy*/
			found = result.find(":");
			if(found == string::npos) continue;
			string sip = result.substr(0, found);
			log.sip = sip;
			/************************************************************************/

			result = result.substr(result.find(":") +1);

			/************************************************************************/
			/*získání zdrojového portu*/
			found = result.find("-");
			if(found == string::npos) continue;
			string sport = result.substr(0, found);
			log.sport = sport;

			result = result.substr(result.find("-")+2);
			/************************************************************************/

			/************************************************************************/
			/*získání cílové ip adresy*/
			found = result.find(":");
			if(found == string::npos) continue;
			string dip = result.substr(0, found);
			log.dip = dip;

			result = result.substr(result.find(":") +1);
			/************************************************************************/

			/************************************************************************/
			/*získání cílového portu*/
			found = result.find("(");
			string dport;
			if(found != string::npos){
				dport = result.substr(0, found -1);
			}
			else{
				dport = result.substr(0, result.length() -2);
			}
			log.dport = dport;	
		}
		if(ipv6){
			/************************************************************************/
			result = result.substr(protocol + 5);
			found = result.find("]");
			if(found == string::npos) continue;
			string sip = result.substr(0, found);
			log.sip = sip;
			result = result.substr(result.find("]") +2);

			/************************************************************************/
			/*získání zdrojového portu*/
			found = result.find("-");
			if(found == string::npos) continue;
			string sport = result.substr(0, found);
			log.sport = sport;

			result = result.substr(result.find("-")+3);
			/************************************************************************/

			/************************************************************************/
			/*získání cílové ip adresy*/
			found = result.find("]");
			if(found == string::npos) continue;
			string dip = result.substr(0, found);
			log.dip = dip;

			result = result.substr(result.find("]") +2);
			/************************************************************************/

			/************************************************************************/
			/*získání cílového portu*/
			found = result.find("(");
			string dport;
			if(found != string::npos){
				dport = result.substr(0, found -1);
			}
			else{
				dport = result.substr(0, result.length() -2);
			}
			log.dport = dport;	

		}

		if(!(strcmp(log.sip.c_str(), "127.0.0.1") || strcmp(log.dip.c_str(), "127.0.0.1") || strcmp(log.sip.c_str(), "::1") || strcmp(log.dip.c_str(), "::1"))){
			continue;
		}
		
		/************************************************************************/

 		/************************************************************************/
 		/*projít list, jestli už spojení existuje, pokud ne nastavit printable a active na true a vložit strukturu, 
 		pokud existuje nastavit active na true a pokračovat v procházení listu s novou položkou
 		*/
 		bool added = false;
 		for(list<spojeni>::iterator iter = connections.begin(); iter != connections.end(); iter++){
			spojeni spoj = *iter;
			if(comp(log, spoj)){
				(*iter).active = true;
				(*iter).printable = false;
				added = true;
				break;
			}
 		}
 		/************************************************************************/

 		/************************************************************************/
 		/*nové spojení, vytvoří se záznam v listu*/
 		if(!added){
	 		log.active = true;
			log.printable = true;
			connections.push_back(log); 			
 		}
 		/************************************************************************/
	}
	pclose(cmd);
	return 0;
}
/************************************************************************/

/************************************************************************/
/**
	Prochází seznam spojení, případně je maže/vypisuje

	@param int argc počet parametrů příkazové řádky
	@param char *argv[] všechny parametry příkazové řádky
	@return úspěch(0) nebo neúspěch(1)
*/
int main(int argc, char *argv[]){
	char *ip;
	int inv = 0;
	char *filter;
	int state;
	if(parseArgs(argc, argv, &ip, &inv, &filter)){
		return 1;
	}
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);	//vytvoří se socket
	if (sock < 0){
		fprintf(stderr, "Chyba: spatny socket\n");
		return 1;
	}

	/************************************************************************/
	/*vytvoření seznamu aplikací, které se budou kontrolovat*/
	string fil = filter;
	list<string> filters;
	size_t pos = fil.find(",",0);
	while(pos != string::npos){
		if(fil.substr(0, pos).length() == 0){
			fprintf(stderr, "Chyba: chybne zapsany seznam aplikaci\n" );
			return 1;
		}
		filters.push_back(fil.substr(0, pos));
		fil = fil.substr(pos+1);
		pos = fil.find(",",0);
	}
	if(fil.length() != 0){
		filters.push_back(fil);	
	}
	else{
		fprintf(stderr, "Chyba: chybne zapsany seznam aplikaci\n" );
		return 1;
	}
	if(!checkIP(ip)){
		fprintf(stderr, "Chyba: chybne zadana ip adresa\n");
		return 1;
	}
	/************************************************************************/
	while(1){
		for(list<string>::iterator iter = filters.begin(); iter != filters.end(); iter++){
			check((*iter).c_str());
		}
		
		//**********************************************************************************************************

		//**********************************next**************************************
		//položky, které namají nastavené active na true budou smazány
		//**********************************next**************************************

		//**********************************************************************************************************
		for(list<spojeni>::iterator iter = connections.begin(); iter != connections.end(); ){
			spojeni spoj = *iter;
			if(!spoj.active){
				//printf("mazu: %s aktivita: %d\n",spoj.name.c_str(), spoj.active);
				iter = connections.erase(iter);
				//printf("smazal\n");
			}
			else{
				(*iter).active = false;
				iter++;
			}
	 	}
		//**********************************************************************************************************
		//položky, které mají nastavení printable na true budou vytisknuty
		//**********************************next**************************************
		//po vytisknutí nastavit active a printable na false u všech položek

		//**********************************************************************************************************
		string msg;
		for(list<spojeni>::iterator iter = connections.begin(); iter != connections.end(); iter++){
			spojeni spoj = *iter;
			if(spoj.printable){
				msg = spoj.protocol + " " + spoj.sip + " " + spoj.sport + " " + spoj.dip + " " + spoj.dport + " " + spoj.name;
				cout << msg << endl;
				if(sendLog(msg.c_str(), ip, sock)){
					return 1;
				}
				(*iter).printable = false;
				(*iter).active = false;
			}
	 	}
	 	/************************************************************************/
	 	/*debug*/
	 	/*cout << "************** velikost seznamu bezicich aplikaci: ";
	 	cout <<  connections.size();
	 	cout << " **************" << endl;*/
	 	/************************************************************************/
	 	sleep(inv);
	}
	close(sock);
	return 0;
}
/************************************************************************/
