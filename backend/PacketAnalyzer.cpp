#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

#include "pcap.h"

#define ANOMALY_LOG_FILE "C:\\hpnta\\anomalies.jsonl"

typedef struct {
  unsigned char version_header_length;
  unsigned char dscp_ecn;
  unsigned short total_length;
  unsigned short identification;
  unsigned short flags_fragment_offset;
  unsigned char ttl;
  unsigned char protocol;
  unsigned short header_checksum;
  unsigned int source_address;
  unsigned int destination_address;
} IPHeader;

typedef struct {
  unsigned short source_port;
  unsigned short destination_port;
  unsigned int sequence_number;
  unsigned int acknowledgement_number;
  unsigned char data_offset;
  unsigned char flags;
  unsigned short window;
  unsigned short checksum;
  unsigned short urgent_pointer;
} TCPHeader;

typedef struct {
  unsigned short source_port;
  unsigned short destination_port;
  unsigned short length;
  unsigned short checksum;
} UDPHeader;

void log_anomaly_to_file(const char* source_ip, unsigned short source_port,
                         const char* dest_ip, unsigned short dest_port,
                         const char* protocol, unsigned int packet_length,
                         const char* threat_type, const char* severity) {
  FILE* file = fopen(ANOMALY_LOG_FILE, "a");
  if (!file) {
    fprintf(stderr, "Warning: Could not open anomaly log file\n");
    return;
  }

  time_t now = time(NULL);
  struct tm* timeinfo = localtime(&now);
  char timestamp[30];
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", timeinfo);

  fprintf(file,
          "{\"timestamp\":\"%s\",\"source_ip\":\"%s\",\"source_port\":%u,"
          "\"dest_ip\":\"%s\",\"dest_port\":%u,\"protocol\":\"%s\","
          "\"packet_length\":%u,\"threat_type\":\"%s\",\"severity\":\"%s\"}\n",
          timestamp, source_ip, source_port, dest_ip, dest_port, protocol,
          packet_length, threat_type, severity);

  fclose(file);
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header,
                    const u_char* pkt_data) {
  IPHeader* ip_header;
  TCPHeader* tcp_header;
  UDPHeader* udp_header;
  unsigned short ip_header_len;

  if (header->len < 34) return;

  ip_header = (IPHeader*)(pkt_data + 14);
  ip_header_len = (ip_header->version_header_length & 0x0F) * 4;

  char source_ip[16], dest_ip[16];
  inet_ntop(AF_INET, &ip_header->source_address, source_ip, sizeof(source_ip));
  inet_ntop(AF_INET, &ip_header->destination_address, dest_ip, sizeof(dest_ip));

  const char* protocol = "UNKNOWN";
  unsigned short source_port = 0;
  unsigned short dest_port = 0;
  unsigned int packet_length = header->len;

  if (ip_header->protocol == 6) {
    protocol = "TCP";
    if (header->len >= 14 + ip_header_len + 20) {
      tcp_header = (TCPHeader*)((u_char*)ip_header + ip_header_len);
      source_port = ntohs(tcp_header->source_port);
      dest_port = ntohs(tcp_header->destination_port);

      if (dest_port == 22 || dest_port == 3389) {
        printf("[ANOMALY DETECTED] Suspicious Port Access | Src: %s:%u -> "
               "Dest: %s:%u | Proto: TCP | Len: %u bytes\n",
               source_ip, source_port, dest_ip, dest_port, packet_length);
        log_anomaly_to_file(source_ip, source_port, dest_ip, dest_port, "TCP",
                            packet_length, "Suspicious Port Access", "high");
      }
    }
  } else if (ip_header->protocol == 17) {
    protocol = "UDP";
    if (header->len >= 14 + ip_header_len + 8) {
      udp_header = (UDPHeader*)((u_char*)ip_header + ip_header_len);
      source_port = ntohs(udp_header->source_port);
      dest_port = ntohs(udp_header->destination_port);
    }
  } else if (ip_header->protocol == 1) {
    protocol = "ICMP";
  }
}

int main() {
  pcap_if_t* alldevs;
  pcap_t* adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];
  u_int netmask;
  char packet_filter[] = "ip";
  struct bpf_program fcode;

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    return 1;
  }

  const char* device = "\\Device\\NPF_{629A59C0-9220-4F47-B977-2BCCBAEC7C53}";

  adhandle = pcap_open_live(device, 65536, 1, 1000, errbuf);

  if (adhandle == NULL) {
    fprintf(stderr, "\nUnable to open the adapter. %s is not supported by "
                    "WinPcap\n",
            device);
    pcap_freealldevs(alldevs);
    return 1;
  }

  netmask = 0xffffff;

  if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
    fprintf(stderr, "\nError calling pcap_compile");
    pcap_freealldevs(alldevs);
    return 1;
  }

  if (pcap_setfilter(adhandle, &fcode) < 0) {
    fprintf(stderr, "\nError setting the filter\n");
    pcap_freealldevs(alldevs);
    return 1;
  }

  printf("Starting High-Performance Network Engine on: %s\n", device);
  printf("Engine active. Listening for traffic... (Press Ctrl+C to stop)\n");

  pcap_loop(adhandle, 0, packet_handler, NULL);

  pcap_close(adhandle);
  pcap_freealldevs(alldevs);

  return 0;
}