#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct{
	unsigned char beacon_flag[2];
}Beacon;

typedef struct{
	unsigned char bssid[6];
}Bssid;

typedef struct {
	char* dev_;
} Param;

Param param = {
	//해당 interface명이 들어가게 된다.
	.dev_ = NULL
};

// 사용방법
void usage();
bool parse(Param* param, int argc, char* argv[]);

// // EthernetHeader 나열
// void printEthernetHeader(const u_char * packet);

//ESSID 나열
char * ESSID_Setting(const u_char * packet);

//BSSID 나열
unsigned char * BSSID_Setting(const u_char * packet);

int main(int argc, char* argv[]) {
	//klan0을 argv[]으로 넣었다.
	if (!parse(&param, argc, argv))
		return -1;


	//오류 발생시 생기는 일
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}


	//패킷을 지속적으로 수집
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		// printf("%u bytes captured\n", header->caplen);
		// printEthernetHeader(packet);

		Beacon * bc;
		bc = packet+0x18;
		
		if (bc->beacon_flag[0]==0x80 && bc->beacon_flag[1]==0x00){
			printf("---------Start------------\n");
			char *essid= ESSID_Setting(packet+0x3d);

			Bssid * bs;
			bs = packet+0x28;
			printf("ESSID : %s\n",essid);
			printf("BSSID : %02x:%02x:%02x:%02x:%02x:%02x\n",bs->bssid[0],bs->bssid[1],bs->bssid[2],bs->bssid[3],bs->bssid[4],bs->bssid[5]);
			puts("");
		}


	}
	pcap_close(pcap);
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	//오류문
	if (argc != 2) {
		usage();
		return false;
	}
	//정상문
	param->dev_ = argv[1];
	return true;
}

char* ESSID_Setting(const u_char * packet){
	int name_cnt = *packet;
	char *tmp = (char *)malloc(name_cnt+1);
	if (tmp==NULL) return -1;
	strncpy(tmp,packet+1,name_cnt);
	tmp[name_cnt]=0;
	return tmp;
}
