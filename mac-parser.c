#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "header.h"
#include "td-util.h"
#include "pkts.h"
#include "address_table.h"
#include "ctype.h"

int debug_mode=1;
int mgmt_beacon_count =0 ;
#ifdef TRANSPORT_LAYER_CAPTURE
int transport_header_parser(u_int16_t,
			    unsigned char*,
			    unsigned char*,
			    int,
			    int,
			    struct data_layer_header * );
#endif
int parse_beacon(unsigned char* p,
		 u_int length,
		 struct mgmt_beacon_layer_header * mlh);

static void print_mac( u_int8_t * ptr ,const char* type){
  printf("%s; %02x:%02x:%02x:%02x:%02x:%02x\n", type,ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
}


struct data_layer_header dlh ;
struct control_layer_header clh ;
struct mgmt_beacon_layer_header mlh ;

struct data_layer_err_header dlh_t ;
struct mgmt_layer_err_header mlh_t ;
int mac_header_parser(unsigned char * p,
		      int pkt_len,
		      int cap_len,
		      int path_type,
		      int radiotap_len)
{
  unsigned char * p_start ;
  p_start = p;
  p += radiotap_len ; //HOMESAW_RX/TX_FRAME_HEADER;
  if (debug_mode) {
    if (path_type ==1 ) {
      if (*(p+1)==0x0 && *(p) ==0x50)
	return 0; //mgmt frames transmitted by router

      if (*(p+1)==0x0 && *(p) ==0x84)
	return 0; //control frames transmitted by router

      if (*(p+1)==0x42 && *(p) ==0x8)
	return 0; //control frames transmitted by router

      if(*(p)==0xc0 && *(p+1)==0x0 )
	return 0 ; //mgmt type but is 0c (deauth)
      //printf("\nin mp: mac header: %02x %02x %d \n", *p, *(p+1),pkt_len );
    }
  }

  memset(&clh,0,sizeof(struct control_layer_header));
  memset(&mlh,0,sizeof(struct mgmt_beacon_layer_header));
  memset(&mlh_t,0,sizeof(struct mgmt_layer_err_header));
  memset(&dlh,0,sizeof(struct data_layer_header));
  u_int16_t fc =  EXTRACT_LE_16BITS(p);
  struct mgmt_header_t *mgmt_h =NULL;
  struct ctrl_ps_poll_t * c_poll = NULL ;
  struct ctrl_bar_t * c_bar =NULL;
  struct ctrl_rts_t * rts = NULL;
  struct ctrl_cts_t *cts= NULL;

  switch (FC_TYPE(fc)) {
  case MGT_FRAME:
    printf("mgmt frame\n");
    mgmt_h = (struct mgmt_header_t *) p;
    switch(FC_SUBTYPE(fc)){
    case ST_BEACON:
        printf("st beacon\n");
	memcpy(mlh.src_mac,mgmt_h->sa,6);
	mlh.pkt_len=pkt_len;
	mlh.frame_control = fc ;
	mlh.seq_ctrl =  pletohs(&(mgmt_h->seq_ctrl));
	parse_beacon(p+MGT_FRAME_HDR_LEN, (unsigned int)cap_len, &mlh );
	mgmt_beacon_count++;
    default :
      memcpy(mlh_t.src_mac,mgmt_h->sa,6);
      mlh_t.pkt_len=pkt_len;
      mlh_t.frame_control = fc ;
      mlh_t.seq_ctrl =  pletohs(&(mgmt_h->seq_ctrl)); //EXTRACT_LE_16BITS(mgmt_h->seq_ctrl);
      break ;
    }
    break ;
  case CONTROL_FRAME:
    printf("control frame\n");
    clh.pkt_len= pkt_len;
    clh.frame_control =fc ;
    switch(FC_SUBTYPE(fc)){
    case CTRL_BAR:
      printf("bar\n");
      c_bar  = (struct ctrl_bar_t *)p;
      memcpy(clh.src_mac,c_bar->ra,6);
      break ;
    case CTRL_PS_POLL :
      printf("ps poll\n");
      c_poll =  (struct ctrl_ps_poll_t *)p;
      memcpy(clh.src_mac,c_poll->bssid,6);      
      break ;
      
    case  CTRL_RTS :
      printf("rts\n");
      rts =  (struct ctrl_rts_t *) p;
      memcpy(clh.src_mac,rts->ra,6);
      
      if (debug_mode) {
	print_mac(rts->ta,"rts ta ");
      }
      break;
    case CTRL_ACK :
      cts=  (struct ctrl_cts_t * ) p;
      if (debug_mode) {
	print_mac(cts->ra, "ack frames\n ");
      }
      break ;
    case CTRL_END_ACK:
      cts=  (struct ctrl_cts_t * ) p;
      if(debug_mode) {
	print_mac(cts->ra, "end ack\n ");
      }
      break ;
      
    case	CTRL_CF_END:
      cts=  (struct ctrl_cts_t *) p;
      if (debug_mode) {
      print_mac(cts->ra, "cf end ack\n ");
      }
    default : // Use the common structure of rest
      cts=  (struct ctrl_cts_t * ) p;
      memcpy(clh.src_mac,cts->ra,6);     
      if (debug_mode) {
	print_mac(cts->ra, "default control err\n ");
      }
      break;
    }
    break ;
  case DATA_FRAME : {
    struct ieee80211_hdr * sc = (struct ieee80211_hdr *)p;
    //    printf("control sequence = %u \n", pletohs(&(sc->seq_ctrl)) );
    dlh.pkt_len=pkt_len;
    dlh.frame_control =fc ;
    dlh.seq_ctrl =  pletohs(&(sc->seq_ctrl));
    if (debug_mode) {
      if(	DATA_FRAME_IS_NULL(FC_SUBTYPE(fc))){
	printf("null type\n");
      }
      else if (DATA_FRAME_IS_CF_ACK(FC_SUBTYPE(fc))){
	printf("cf-type\n");
      }
      else if (DATA_FRAME_IS_CF_POLL(FC_SUBTYPE(fc))){
	printf("poll type\n");
      }
      else if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc))){
	printf("qos type\n");
      }
      if(IS_DATA_DATA(FC_SUBTYPE(fc))){
	printf(" data-data\n");
      }else if(IS_DATA_DATA_CF_ACK(FC_SUBTYPE(fc))){
	printf("cf-ack\n");
      }else if(IS_DATA_DATA_CF_POLL(FC_SUBTYPE(fc))){
	  printf("cf-poll\n");
      }else if(IS_DATA_DATA_CF_ACK_POLL(FC_SUBTYPE(fc))){
	  printf("cf-poll-ack\n");
      }else if(IS_DATA_NODATA(FC_SUBTYPE(fc))){
	printf("no data\n");
      }else if(IS_DATA_NODATA_CF_ACK(FC_SUBTYPE(fc))){
	printf("nodata cf ack\n");
      }else if(IS_DATA_NODATA_CF_POLL (FC_SUBTYPE(fc))){
	printf("nodata cf poll\n");	  
      }else if(IS_DATA_NODATA_CF_ACK_POLL (FC_SUBTYPE(fc))){
	printf(" cf ack poll\n");
      }
      printf("subtype:%02x \n",FC_SUBTYPE(fc));
      printf("seq ctrl : %d \n", dlh.seq_ctrl );
    }
    int hdrlen  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
    if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
      hdrlen += 2;
    // but there is 8 bytes offset after mac header of 26 bytes, thats for qos data packet
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
    if (!FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
      memcpy(dlh.src_mac,ADDR2,6);
      memcpy(dlh.dest_mac,ADDR1,6);
      if(debug_mode) {
	print_mac(ADDR2,"1 addr2");
	print_mac(ADDR1,"1 addr1");
      }
    } else if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
	if (radiotap_len ==HOMESAW_TX_FRAME_HEADER )
        printf("mac address map \n");//	    mac_address_map(&devices,ADDR1);
      memcpy(dlh.src_mac,ADDR3,6);
      memcpy(dlh.dest_mac,ADDR1,6);
//      printf("f in anon 2 \n");
      if (debug_mode) {
	print_mac(ADDR3,"2 src");
	print_mac(ADDR1,"2 dest");
      }
    } else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
      memcpy(dlh.src_mac,ADDR2,6);
      memcpy(dlh.dest_mac,ADDR3,6);
      if (debug_mode) {
	print_mac(ADDR2,"3 src");
	print_mac(ADDR3,"3 dest");
      }
    } else if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
#define ADDR4  (p + 24)
      memcpy(dlh.src_mac,ADDR4,6);
      memcpy(dlh.dest_mac,ADDR3,6);
      if (debug_mode) {
	print_mac(ADDR4,"4 src");
	print_mac(ADDR3,"4 dest");
      }
#undef ADDR4
    }
#undef ADDR1
#undef ADDR2
#undef ADDR3
//    address_data_table_update(&data_address_table ,p_start, &dlh,path_type, 0); // is_more flag: write tcp/udp headers to file
#ifdef TRANSPORT_LAYER_CAPTURE
	transport_header_parser(fc,p_start,p+hdrlen,pkt_len,path_type,&dlh);
#endif
	break ;
  }
    break;
  default :
    printf("imposs pkt ! pkt len is %d\n ",pkt_len);
    exit(EXIT_FAILURE);
  }
  return 0 ;
}

int mac_header_err_parser(unsigned char *p,
			  int pkt_len,
			  int cap_len)
{

  u_char * p_start = p ;
  p += HOMESAW_RX_FRAME_HEADER;
  struct mgmt_header_t *mgmt_h =NULL;
  memset(&clh,0,sizeof(struct control_layer_header));
  memset(&mlh_t,0,sizeof(struct mgmt_layer_err_header));
  memset(&dlh_t,0,sizeof(struct data_layer_err_header));
  u_int16_t fc =  EXTRACT_LE_16BITS(p);
  struct ctrl_ps_poll_t * c_poll = NULL ;
  struct ctrl_bar_t * c_bar =NULL;
  struct ctrl_rts_t * rts = NULL;
  struct ctrl_cts_t *cts= NULL;
  if (debug_mode) {
    printf("macheader err_parser: %02x %02x\n", *p, *(p+1));
  }
  switch (FC_TYPE(fc)) {
  case MGT_FRAME: {
    mgmt_h = (struct mgmt_header_t *) p;
    memcpy(mlh_t.src_mac,mgmt_h->sa,6);
    mlh_t.frame_control = fc ;
    mlh_t.pkt_len= pkt_len;
    mlh_t.seq_ctrl =  pletohs(&(mgmt_h->seq_ctrl)); //EXTRACT_LE_16BITS(mgmt_h->seq_ctrl);  /*Copied the common portions */
//    address_mgmt_err_table_update(&mgmt_address_table_err, p_start, &mlh_t);
  }
    break ;
  case CONTROL_FRAME:  {
    clh.frame_control = fc ;
    clh.pkt_len=pkt_len;
    switch(FC_SUBTYPE(fc)){
    case CTRL_BAR:
      c_bar  = (struct ctrl_bar_t *)p;
      memcpy(c_bar->ra,clh.src_mac,6);
//      address_control_err_table_update(&control_address_table_err , p_start, &clh);
      break ;

    case CTRL_PS_POLL :
      c_poll =  (struct ctrl_ps_poll_t *)p;
      memcpy(c_poll->bssid,clh.src_mac,6);
//      address_control_err_table_update(&control_address_table_err , p_start, &clh);
      break ;

    case  CTRL_RTS :
      rts =  (struct ctrl_rts_t *) p;
      memcpy(clh.src_mac,rts->ra,6);
//      address_control_err_table_update(&control_address_table_err , p_start, &clh);
#ifdef DEBUG
      print_mac(rts->ra,"rts ra");
      print_mac(rts->ta,"rts ta ");
#endif
      break;
    default : // Use the common structure of rest
      cts=  (struct ctrl_cts_t * ) p;
      memcpy(clh.src_mac,cts->ra,6);
//      address_control_err_table_update(&control_address_table_err , p_start, &clh);
#ifdef DEBUG
      print_mac(cts->ra, "ack ");
#endif
      break;
    }
	}
    break ;
  case DATA_FRAME : {
    struct ieee80211_hdr * sc = (struct ieee80211_hdr *)p;
//    printf("control sequence = %u \n", pletohs(&(sc->seq_ctrl)) );
    dlh_t.frame_control =fc ;
    dlh_t.pkt_len=pkt_len;
    dlh_t.seq_ctrl =  pletohs(&(sc->seq_ctrl));
    int hdrlen  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
    if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
      hdrlen += 2;
        // but there is 8 bytes offset after mac header of 26 bytes, thats for qos data packet
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
    if (!FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
      memcpy(dlh_t.src_mac,ADDR2,6);
      memcpy(dlh_t.dest_mac,ADDR1,6);
      if (debug_mode ){
	print_mac(ADDR2,"1 addr2");
	print_mac(ADDR1,"1 addr1");
      }
    } else if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
      memcpy(dlh_t.src_mac,ADDR3,6);
      memcpy(dlh_t.dest_mac,ADDR1,6);
//      printf("f in anon 2 \n");
      if (debug_mode ){
	print_mac(ADDR3,"2 src");
	print_mac(dlh_t.src_mac,"anon src");
	print_mac(ADDR1,"2 dest");
	print_mac(dlh_t.dest_mac, " anon dest");
      }
    } else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
      memcpy(dlh_t.src_mac,ADDR2,6);
      memcpy(dlh_t.dest_mac,ADDR3,6);
      if (debug_mode ){
	print_mac(ADDR2,"3 src");
	print_mac(ADDR3,"3 dest");
      }
    } else if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
#define ADDR4  (p + 24)
      memcpy(dlh_t.src_mac,ADDR4,6);
      memcpy(dlh_t.dest_mac,ADDR3,6);
      if (debug_mode ){
	print_mac(ADDR4,"4 src");
	print_mac(ADDR3,"4 dest");
      }
#undef ADDR4
    }
#undef ADDR1
#undef ADDR2
#undef ADDR3
//    address_data_err_table_update(&data_address_table_err ,p_start, &dlh_t);
   break ;
  }
    break;
  default :
    // TODO: XXX classify it as different kinds of packets depending on packet length and other features
    /*
     * CONTROL PKT SIZE : 14 + custom header
     *BEACON PKT SIZE : can be as large as (11n) 320 bytes. Atleast 100 bytes (a/g) 110 bytes
     *LAB BEACONS : 156-231 bytes ; check for fffffffff
     *PROBES SIZE : 101,149,219,225 , 204, 83
     *DATA PKT SIZE : anything greater than 400 bytes is data packet
     *check the fields of FS,DS to get the mac address offset
     *  Can be 55 size packets too !
     */
    if(pkt_len>400 ){ // DATA FRAME 48 byte RADIOTAP header
      struct ieee80211_hdr * sc = (struct ieee80211_hdr *)p;
      //    printf("control sequence = %u \n", pletohs(&(sc->seq_ctrl)) );
      dlh_t.frame_control =fc ;
      dlh_t.pkt_len=pkt_len;
      dlh_t.seq_ctrl =  pletohs(&(sc->seq_ctrl));
      int hdrlen  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
      if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
	hdrlen += 2;
      // but there is 8 bytes offset after mac header of 26 bytes, thats for qos data packet
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
      if (!FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
	memcpy(dlh_t.src_mac,ADDR2,6);
	memcpy(dlh_t.dest_mac,ADDR1,6);
	if (debug_mode) {
	  print_mac(ADDR2,"1 addr2");
	  print_mac(ADDR1,"1 addr1");
	}
      } else if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
	memcpy(dlh_t.src_mac,ADDR3,6);
	memcpy(dlh_t.dest_mac,ADDR1,6);
	//      printf("f in anon 2 \n");
	if (debug_mode) {
	  print_mac(ADDR3,"2 src");
	  print_mac(dlh_t.src_mac,"anon src");
	  print_mac(ADDR1,"2 dest");
	  print_mac(dlh_t.dest_mac, " anon dest");
	}
      } else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
      memcpy(dlh_t.src_mac,ADDR2,6);
      memcpy(dlh_t.dest_mac,ADDR3,6);
      if (debug_mode) {
	print_mac(ADDR2,"3 src");
	print_mac(ADDR3,"3 dest");
      }
      } else if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
#define ADDR4  (p + 24)
	memcpy(dlh_t.src_mac,ADDR4,6);
	memcpy(dlh_t.dest_mac,ADDR3,6);
	if (debug_mode) {
	  print_mac(ADDR4,"4 src");
	  print_mac(ADDR3,"4 dest");
	}
#undef ADDR4
      }
#undef ADDR1
#undef ADDR2
#undef ADDR3
      //TODO: XXX Just update with this much info
      // There is too much guessing on the type of packet based on packet length which doesn't make sense for the software now.
      // Skip it all after discussion with Mingli
    }else if(pkt_len>110 && pkt_len <360){ // MGMT FRAME
      
      mgmt_h = (struct mgmt_header_t *) p;
      memcpy(mlh_t.src_mac,mgmt_h->sa,6);
      mlh_t.pkt_len=pkt_len;
      mlh_t.frame_control =fc ;
      mlh_t.seq_ctrl =  pletohs(&(mgmt_h->seq_ctrl)); // EXTRACT_LE_16BITS(mgmt_h->seq_ctrl);//Copied the common portions
    }
    else if ( pkt_len <72){  //CONTROL FRAME : 48+14 : 62 bytes
      clh.frame_control = fc ;
      clh.pkt_len=pkt_len;
      switch FC_SUBTYPE(fc) {
	  
	case CTRL_BAR:
	  c_bar  = (struct ctrl_bar_t *)p;
	  memcpy(clh.src_mac,c_bar->ra,6);	  
	  break ;
	case CTRL_PS_POLL :
	  c_poll =  (struct ctrl_ps_poll_t *)p;
	  memcpy(clh.src_mac,c_poll->bssid,6);
	  break ;
	  
	case  CTRL_RTS :
	  rts =  (struct ctrl_rts_t *) p;
	  memcpy(clh.src_mac,rts->ra,6);
	  if (debug_mode) {
	    print_mac(rts->ra,"rts ra");
	    print_mac(rts->ta,"rts ta ");
	  }
	  break;
	default : // Use the common structure of rest
	  cts=  (struct ctrl_cts_t * ) p;
	  memcpy(clh.src_mac,cts->ra,6);
	  if (debug_mode) {
	    print_mac(cts->ra, "default control\n");
	  }
	  break;
	}
    }else {
      cts=  (struct ctrl_cts_t * ) p;
      clh.pkt_len=pkt_len;
      clh.frame_control =fc ;
      memcpy(clh.src_mac,cts->ra,6);

    }
  }
  return 0;
}

#ifdef TRANSPORT_LAYER_CAPTURE
int transport_header_parser(u_int16_t fc,unsigned char* p_start,
			    unsigned char* p,
			    int pkt_len,
			    int path_type,
			    struct data_layer_header * dlh)
{
  printf("Transport header works if there is no encryption at the Access Point\n");  
  if( FC_SUBTYPE(fc)== IEEE80211_FTYPE_DATA   ){
    p +=8;
    struct llc_hdr * llc = (struct llc_hdr *) p;
    dlh->eth_type   =  ntohs(llc->snap.ether_type);
	printf("header transport fine \n");
    if ( ntohs(llc->snap.ether_type) == ETHERTYPE_IP  ) {
      struct  iphdr* ih = (struct iphdr*)(llc+1);
      dlh->ip_type = ih->protocol ;
      dlh->ip_src = ih->saddr;
      dlh->ip_dest =  ih->daddr ;
      u_int32_t src= ntohl(ih->saddr) ;
      u_int32_t dst = ntohl(ih->daddr) ;
      u_char* s = &src ;
      u_char* d = &dst ;
      printf("ip source %" PRIx32 " ip dest %" PRIx32  "\n", ntohl(ih->saddr), ntohl(ih->daddr) );
      printf("src: %d:%d:%d:%d\n",*(s),*(s+1),*(s+2),*(s+3));
      printf("dst: %d:%d:%d:%d\n",*(d),*(d+1),*(d+2),*(d+3));
      if (ih->protocol == IPPROTO_TCP){
	struct tcphdr* tcp_header = (struct tcphdr*)((void *)ih + ih->ihl * sizeof(uint32_t));
	  printf("->tcp port_source %u\n", ntohs(tcp_header->source));
	  printf("tcp port_destination  %u <-\n", ntohs(tcp_header->dest));
	u_char * tmp =  (u_char*) tcp_header;
	memcpy(dlh->trans_content.tcp.tcp_hdr, tmp, TCP_HEADER_SIZE);
	const  struct tcphdr* t = (struct tcphdr* )dlh->trans_content.tcp.tcp_hdr;
      }
      else if (ih->protocol == IPPROTO_UDP){
	const struct udphdr* udp_header = (struct udphdr*)((void *)ih + ih->ihl * sizeof(uint32_t));
	printf("udp port_source %u \n",ntohs(udp_header->source));
	printf("udp port_destination %u \n",ntohs(udp_header->dest));
	dlh-> trans_content.udp.src_port = udp_header->source ;
	dlh-> trans_content.udp.dest_port = udp_header->dest ;
      }
    }
    return 0;
  }else {
      printf("probably encrypted and we can't decipher anything above MAC headers \n");
  }
  return 0 ;
}
#endif

/*Functions for parsing management frames */

int
fn_print(register const u_char *s, register const u_char *ep)
{
  printf("SSID:"); 
  register int ret; 
  register u_char c;    
    
  ret = 1;            /* assume truncated */
  while (ep == NULL || s < ep) {
    c = *s++;
    if (c == '\0') {
      ret = 0;
      break;
    }
    if (!isascii(c)) {
      c = toascii(c);
      putchar('M');
      putchar('-');
    }
    if (!isprint(c)) {
      c ^= 0x40;  /* DEL to ?, others to alpha */
      putchar('^');
    }
    putchar(c);
  }       
  return(ret);
} 
int parse_elements(struct mgmt_body_t* pbody,
		   const u_char *p,
		   int offset,
		   u_int length,
		   struct mgmt_beacon_layer_header * mlh)
{
  struct ssid_t ssid;
  struct challenge_t challenge;
  struct rates_t rates;
  struct ds_t ds;
  struct cf_t cf;
  struct tim_t tim;

  pbody->challenge_present = 0;
  pbody->ssid_present = 0;
  pbody->rates_present = 0;
  pbody->ds_present = 0;
  pbody->cf_present = 0;
  pbody->tim_present = 0;
  while (length != 0) {
    if (!TTEST2(*(p + offset), 1))
      return 0;
    if (length < 1)
      return 0;
    switch (*(p + offset)) {
    case E_SSID:
      if (!TTEST2(*(p + offset), 2))
        return 0;
      if (length < 2)
        return 0;
      memcpy(&ssid, p + offset, 2);
      offset += 2;
      length -= 2;
      if (ssid.length != 0) {
        if (ssid.length > sizeof(ssid.ssid) - 1)
          return 0;
        if (!TTEST2(*(p + offset), ssid.length))
          return 0;
        if (length < ssid.length)
          return 0;
	memcpy(&ssid.ssid, p + offset, ssid.length);
        offset += ssid.length;
        length -= ssid.length;
      }
      ssid.ssid[ssid.length] = '\0';
      if (!pbody->ssid_present) {
        pbody->ssid = ssid;
        pbody->ssid_present = 1;
      }      
      break;
    case E_CHALLENGE:
      if (!TTEST2(*(p + offset), 2))
        return 0;
      if (length < 2)
        return 0;
      memcpy(&challenge, p + offset, 2);
      offset += 2;
      length -= 2;
      if (challenge.length != 0) {
        if (challenge.length >
            sizeof(challenge.text) - 1)
          return 0;
        if (!TTEST2(*(p + offset), challenge.length))
          return 0;
        if (length < challenge.length)
          return 0;
        //memcpy(&challenge.text, p + offset, challenge.length);
        offset += challenge.length;
        length -= challenge.length;
      }
      //challenge.text[challenge.length] = '\0';
      /*
      if (!pbody->challenge_present) {
        pbody->challenge = challenge;
        pbody->challenge_present = 1;
      }*/
      break;
    case E_RATES:
      if (!TTEST2(*(p + offset), 2))
        return 0;
      if (length < 2)
        return 0;
      memcpy(&rates, p + offset, 2);
      offset += 2;
      length -= 2;
      if (rates.length != 0) {
        if (rates.length > sizeof rates.rate)
          return 0;
        if (!TTEST2(*(p + offset), rates.length))
          return 0;
        if (length < rates.length)
          return 0;
        memcpy(&rates.rate, p + offset, rates.length);
        offset += rates.length;
        length -= rates.length;
      }
      if (!pbody->rates_present && rates.length != 0) {
        pbody->rates = rates;
        pbody->rates_present = 1;
      }
      break;
    case E_DS:
      if (!TTEST2(*(p + offset), 3))
        return 0;
      if (length < 3)
        return 0;
      memcpy(&ds, p + offset, 3);
      offset += 3;
      length -= 3;
      if (!pbody->ds_present) {
        pbody->ds = ds;
        pbody->ds_present = 1;
      }
      break;
    case E_CF:
      if (!TTEST2(*(p + offset), 8))
        return 0;
      if (length < 8)
        return 0;
      offset += 8;
      length -= 8;
      /*if (!pbody->cf_present) {
        pbody->cf = cf;
        pbody->cf_present = 1;
      }*/
      break;
    case E_TIM:
      if (!TTEST2(*(p + offset), 2))
        return 0;
      if (length < 2)
        return 0;
      memcpy(&tim, p + offset, 2);
      offset += 2;
      length -= 2;
      if (!TTEST2(*(p + offset), 3))
        return 0;
      if (length < 3)
        return 0;
      //memcpy(&tim.count, p + offset, 3);
      offset += 3;
      length -= 3;

      if (tim.length <= 3)
        break;
      if (tim.length - 3 > (int)sizeof tim.bitmap)
        return 0;
      if (!TTEST2(*(p + offset), tim.length - 3))
        return 0;
      if (length < (u_int)(tim.length - 3))
        return 0;
      //memcpy(tim.bitmap, p + (tim.length - 3), (tim.length - 3));
      offset += tim.length - 3;
      length -= tim.length - 3;
      /*      if (!pbody->tim_present) {
        pbody->tim = tim;
        pbody->tim_present = 1;
      }*/
      break;
    default:
      if (*(p + offset)== HT_CAP){
	mlh->ht_support = 1 ;
      }

      if (!TTEST2(*(p + offset), 2))
        return 0;
      if (length < 2)
        return 0;
      if (!TTEST2(*(p + offset + 2), *(p + offset + 1)))
        return 0;
      if (length < (u_int)(*(p + offset + 1) + 2))
        return 0;
      offset += *(p + offset + 1) + 2;
      length -= *(p + offset + 1) + 2;
      break;
    }
  }

  return 1;
}

int parse_beacon(unsigned char* p,
		 u_int length,
		 struct mgmt_beacon_layer_header * mlh )
{

  struct mgmt_body_t pbody;
  int offset = 0;
  int ret;
  snapend = (u_char*)(p+length) ;
  memset(&pbody, 0, sizeof(pbody));
  if (!TTEST2(*p, IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN + IEEE802_11_CAPINFO_LEN))
    return 0;
  if (length < IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN +
      IEEE802_11_CAPINFO_LEN)
    return 0;
  // memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN);
  offset += IEEE802_11_TSTAMP_LEN;
  length -= IEEE802_11_TSTAMP_LEN;
  //pbody.beacon_interval = EXTRACT_LE_16BITS(p+offset);
  offset += IEEE802_11_BCNINT_LEN;
  length -= IEEE802_11_BCNINT_LEN;
  //  pbody.capability_info =  EXTRACT_LE_16BITS(p+offset);
  mlh->cap_info = EXTRACT_LE_16BITS(p+offset);
  offset += IEEE802_11_CAPINFO_LEN;
  length -= IEEE802_11_CAPINFO_LEN;

  ret = parse_elements(&pbody, p, offset, length,mlh);
    if (pbody.ssid_present) {
      fn_print(pbody.ssid.ssid, NULL);
      printf("\n");
    }
  
  //  if (pbody.ds_present) {
  //    printf(" mgmt packet channel = %d\n",pbody.ds.channel);
  //  }
  //paket->p.mgmt_pkt.cap_privacy=  CAPABILITY_PRIVACY(pbody.capability_info) ? 1 :0 ;
  //  printf("%s \n",   CAPABILITY_ESS(pbody.capability_info) ? "ESS" : "IBSS");
  u_int8_t _r;
  if (pbody.rates_present) {
    _r= pbody.rates.rate[pbody.rates.length -1] ;
    mlh->max_rate= _r ; // (float)((.5 * ((_r) & 0x7f)));
    //TODO: XXX check the values   printf("packet rate is %f \n",mlh->max_rate);
  }
  else {
    mlh->max_rate=0; // undefined rate, because of bad fcs (might be a reason)
  }
  return ret;
}

