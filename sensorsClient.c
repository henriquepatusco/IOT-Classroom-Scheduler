/*
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Institute nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   SUCH DAMAGE.

   This file is part of the Contiki operating system.

*/

#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "net/uip.h"
#include "net/uip-ds6.h"
#include "net/uip-udp-packet.h"
#include "sys/ctimer.h"
#ifdef WITH_COMPOWER
#include "powertrace.h"
#endif
#include "dev/uart0.h"
#include <stdio.h>
#include <string.h>
#include "dev/leds.h"

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define UDP_EXAMPLE_ID  190

#define DEBUG DEBUG_PRINT
#include "net/uip-debug.h"

#ifndef PERIOD
#define PERIOD 60
#endif

#define START_INTERVAL    (15 * CLOCK_SECOND)
#define SEND_INTERVAL   (PERIOD * CLOCK_SECOND)
#define SEND_TIME     (random_rand() % (SEND_INTERVAL))
#define MAX_PAYLOAD_LEN   30
#define SERIAL_BUF_SIZE         128
#define CARD_ID_SIZE              8
#define ROOM_SIZE                 6
static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;
char currCard[CARD_ID_SIZE + 1];
char rx_buf[SERIAL_BUF_SIZE];
char room[ROOM_SIZE + 1];
short serialIt = 0;
/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  char *str;

  if (uip_newdata()) {
    str = uip_appdata;
    str[uip_datalen()] = '\0';
    printf("DATA recv '%s'\n", str);
    if(str[0] == '1'){
	leds_off(LEDS_BLUE);
	leds_on(LEDS_GREEN);
    }
    else if(str[0] == 'e'){
	leds_on(LEDS_BLUE);
	leds_off(LEDS_GREEN);
    }
    else if(str[0] == '0'){
	leds_off(LEDS_BLUE);
	leds_off(LEDS_GREEN);
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
send_packet(void *ptr)
{
  static int seq_id;
  char buf[MAX_PAYLOAD_LEN];

  seq_id++;
  char temp[CARD_ID_SIZE + ROOM_SIZE + 1]  = {'\0'};
  strcat(temp , room );
  strcat(temp , currCard );
  PRINTF("DATA send to TV (%d) '%s'\n",
         server_ipaddr.u8[sizeof(server_ipaddr.u8) - 1], temp);
  sprintf(buf, "%s", temp);
  uip_udp_packet_sendto(client_conn, buf, strlen(buf),
                        &server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Client IPv6 addresses: ");
  for (i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if (uip_ds6_if.addr_list[i].isused &&
        (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      int tempr = uip_ds6_if.addr_list[i].ipaddr.u8[sizeof(uip_ds6_if.addr_list[i].ipaddr.u8)-1]+98;
      sprintf(room, "%d", tempr); // room based on MAC
      int j = 0;
      while (tempr >= 1.0){
		  j++;
		  tempr = tempr/10;
	  }
      while (j < ROOM_SIZE){
			room[j++] = ' ';
		}
      PRINTF("\n");
      printf("Room selected: %s\n",room);
      /* hack to make address "final" */
      if (state == ADDR_TENTATIVE) {
        uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  /* The choice of server address determines its 6LoPAN header compression.
     (Our address will be compressed Mode 3 since it is derived from our link-local address)
     Obviously the choice made here must also be selected in udp-server.c.

     For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
     e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
     (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)

     Note the IPCMV6 checksum verification depends on the correct uncompressed addresses.
  */

#if 0
  /* Mode 1 - 64 bits inline */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
#elif 1
  /* Mode 2 - 16 bits inline */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
  /* Mode 3 - derived from server link-local (MAC) address */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0250, 0xc2ff, 0xfea8, 0xcd1a); //redbee-econotag
#endif
}

static int uart_rx_callback(unsigned char c) {
  uint8_t u;
  u = (uint8_t)c;
  if (u == 10 && serialIt != 0) {
//    if (!strncmp(room, "      ", ROOM_SIZE)) {
//		strncpy(room,rx_buf,ROOM_SIZE);
//		while (serialIt < ROOM_SIZE){
//			room[serialIt++] = ' ';
//		}
//		serialIt = 0;
//		printf("\nSelected room: %s\n", room);
//   }
//    else {
      if (serialIt == CARD_ID_SIZE) {
        if (strncmp(rx_buf, "00000000", CARD_ID_SIZE)) {
          strncpy(currCard, rx_buf, CARD_ID_SIZE);
          printf("\nCard inserted: %s\n", currCard);
        }
        else {
          strncpy(currCard, "00000000", CARD_ID_SIZE);
          printf("\nCard removed\n");
      	  leds_off(LEDS_BLUE);
  	      leds_off(LEDS_GREEN);
        }
        send_packet(NULL);
      }
      else {
        printf("\nTry again %i\n", serialIt);
      }
      serialIt = 0;
//    }
  }
  else if (u != 10) {
    rx_buf[serialIt++] = c;
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic;
  static struct ctimer backoff_timer;
#if WITH_COMPOWER
  static int print = 0;
#endif
  uart0_init(BAUD2UBR(115200)); //set the baud rate as necessary
  uart0_set_input(uart_rx_callback); //set the callback function
  PROCESS_BEGIN();
  
  PROCESS_PAUSE();

  set_global_address();
  strncpy(currCard, "00000000",8);
  strncpy(room, "      ",ROOM_SIZE);
  PRINTF("UDP client process started\n");

  print_local_addresses();

  /* new connection with remote host */
  client_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL);
  if (client_conn == NULL) {
    PRINTF("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(client_conn, UIP_HTONS(UDP_CLIENT_PORT));

  PRINTF("Created a connection with the server ");
  PRINT6ADDR(&client_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
         UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

#if WITH_COMPOWER
  powertrace_sniff(POWERTRACE_ON);
#endif
  etimer_set(&periodic, SEND_INTERVAL);
  printf(" Waiting for connection\n");
  while (1) {
    PROCESS_YIELD();
    if(strncmp(room, "      ", ROOM_SIZE)){
		if (ev == tcpip_event) {
		  tcpip_handler();
		}
		if (etimer_expired(&periodic)) {
		  etimer_reset(&periodic);
		  ctimer_set(&backoff_timer, SEND_TIME, send_packet, NULL);

		}
	}
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
