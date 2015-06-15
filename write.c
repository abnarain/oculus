#include <stdio.h>
#include <zlib.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <time.h>
#include "ieee80211_radiotap.h"
#include "td-util.h"
#include "header.h"
#include "pkts.h"
#include "address_table.h"


#define MODULUS(m, d)  ((((m) % (d)) + (d)) % (d))
#define NORM(m)  (MODULUS(m, MAC_TABLE_ENTRIES))

static int debug_mode;
mgmt_beacon_address_table_t mgmt_beacon_address_table ;
mgmt_common_address_table_t mgmt_common_address_table ;
data_address_table_t data_address_table ;
control_address_table_t control_address_table ;

mgmt_address_err_table_t mgmt_address_table_err ;
data_address_err_table_t data_address_table_err ;
control_address_err_table_t control_address_table_err ;

static void print_mac(u_int8_t* ptr ,const char* type)
{
  printf("%s; %02x:%02x:%02x:%02x:%02x:%02x\n", type,ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
}

static int distance (const u_char* word1,
                     const u_char* word2)
{
	int len1 =6; int len2=6;
 int delete;
 int insert;
 int substitute;
 int minimum;

  int matrix[len1 + 1][len2 + 1];
  int i;
  for (i = 0; i <= len1; i++) {
    matrix[i][0] = i;
  }
  for (i = 0; i <= len2; i++) {
    matrix[0][i] = i;
  }
  for (i = 1; i <= len1; i++) {
    int j;
    char c1;
    c1 = word1[i-1];
    for (j = 1; j <= len2; j++) {
      char c2;
      c2 = word2[j-1];
      if (c1 == c2) {
	matrix[i][j] = matrix[i-1][j-1];
      }
      else {
	delete = matrix[i-1][j] + 1;
	insert = matrix[i][j-1] + 1;
	substitute = matrix[i-1][j-1] + 1;
	minimum = delete;
	if (insert < minimum) {
	  minimum = insert;
	}
	if (substitute < minimum) {
	  minimum = substitute;
	}
	matrix[i][j] = minimum;
      }
    }
  }
  return matrix[len1][len2];
}

static int test_mgmt_buff(u_char* buff){
  struct ieee80211_radiotap_header* hdr;
  hdr = (struct ieee80211_radiotap_header*) buff;
  u_int16_t it_len ;
  it_len = pletohs(&hdr->it_len);
  struct mgmt_beacon_layer_header* mlh ;
  if(it_len == HOMESAW_RX_FRAME_HEADER )
    mlh = (struct mgmt_beacon_layer_header* )  (buff+HOMESAW_RX_FRAME_HEADER);
  else
    mlh = (struct mgmt_beacon_layer_header* )  (buff+HOMESAW_TX_FRAME_HEADER);
  if( FC_TYPE(mlh->frame_control) == MGT_FRAME )
    printf("\nmgmt TYPE FRAME \n");
  else
    printf("\nNOT mgmt TYPE \n");
  print_mac( mlh->src_mac, "mgmt frame ");
  printf("pkt_len=%u\n",mlh->pkt_len);
  printf("fc=%u\n",mlh->frame_control) ;
  printf("seq ctrl=%u\n",mlh->seq_ctrl) ;
  printf("ht=%u\n",mlh->ht_support) ;
  printf("cap_info=%u\n",mlh->cap_info);
  printf("max_rate=%u\n",mlh->max_rate);
  return 0;
}

static int test_mgmt_err_buff(u_char* buff)
{
  struct ieee80211_radiotap_header* hdr;
  hdr = (struct ieee80211_radiotap_header*) buff;
  u_int16_t it_len ;
  it_len = pletohs(&hdr->it_len);
  struct mgmt_layer_err_header* mlh ;
  if(it_len == HOMESAW_RX_FRAME_HEADER )
    mlh = (struct mgmt_layer_err_header* )  (buff+HOMESAW_RX_FRAME_HEADER);
  else
    mlh = (struct mgmt_layer_err_header* )  (buff+HOMESAW_TX_FRAME_HEADER);

  if( FC_TYPE(mlh->frame_control) == MGT_FRAME )
    printf("\nmgmt TYPE FRAME \n");
  else
    printf("\nmgmt DATA TYPE \n");
  printf("pkt_control=%u\n",mlh->pkt_len);
  printf("fc %u=\n",mlh->frame_control) ;
  printf("seq ctrl %u=\n",mlh->seq_ctrl) ;

  return 0;
}

static int test_ctl_buff(u_char* buff)
{
  struct ieee80211_radiotap_header* hdr;
  hdr = (struct ieee80211_radiotap_header*) buff;
  u_int16_t it_len ;
  it_len = pletohs(&hdr->it_len);
  struct control_layer_header* clh ;
  if(it_len == HOMESAW_RX_FRAME_HEADER )
    clh = (struct control_layer_header* )(buff+HOMESAW_RX_FRAME_HEADER);
  else
    clh = (struct control_layer_header* )(buff+HOMESAW_TX_FRAME_HEADER);

 if( FC_TYPE(clh->frame_control) == CONTROL_FRAME )
    printf("\nctrl TYPE FRAME \n");
  else
    printf("\nnon ctrl  TYPE \n");
  printf("pkt_control=%u\n",clh->pkt_len);
  printf("ctrl frame %u=\n",clh->frame_control) ;
  return 0;
}

int test_data_buff (u_char* buff )
{

  struct ieee80211_radiotap_header* hdr;
  hdr = (struct ieee80211_radiotap_header*) buff;
  u_int16_t it_len ;
  it_len = pletohs(&hdr->it_len);
  struct data_layer_header* dlh ;
    dlh = (struct data_layer_header* )  (buff+it_len);

  if( FC_TYPE(dlh->frame_control) == DATA_FRAME ){
    printf("\nDATA TYPE FRAME %d\n", it_len);
	}
  else{
    printf("\nNOT DATA TYPE %d\n",it_len);
	}
    printf("pkt len=%d \n", dlh->pkt_len );
		print_mac(dlh->src_mac,"src mac");
		print_mac(dlh->dest_mac,"dest mac");
#ifdef TRANSPORT_LAYER_CAPTURE
  if (dlh->eth_type == ETHERTYPE_IP){
    printf("IP packet\n");
    if(dlh->ip_type == IPPROTO_UDP){
      printf("UDP \n");
      printf("src port %u \n", ntohs( dlh->trans_content.udp.src_port));
      printf("dest port %u \n", ntohs(dlh->trans_content.udp.src_port));
    }
    else if ( dlh->ip_type == IPPROTO_TCP){
      printf("TCP \n ");
      u_char* t = (u_char*) (dlh->trans_content.tcp.tcp_hdr );
      struct tcphdr* tcp_header = (struct tcphdr*)t ;
      printf("source port %u\n",ntohs(tcp_header->source));
      printf("dest port %u \n",ntohs(tcp_header->dest));
      printf("seq =%u \n",ntohl(tcp_header->seq));
      printf("ack seq %u\n ",ntohl(tcp_header->ack_seq));
    }
  }
  else if( dlh->ip_type == IPPROTO_ICMP)
    printf("icmp\n");
  else
    printf("Unsure what packet \n");
#endif
  return 0;
}

void mac_address_table_init(mac_address_table_t* table) 
{
  memset(table, '\0', sizeof(*table));
}


u_int8_t* access_point_address_table_lookup(mac_address_table_t* table, uint8_t* mac,int mgmt_type)
{
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if ( !memcmp(table->entries[mac_id].mac_address, mac, ETH_ALEN)) {
	return table->entries[mac_id].hashed_mac_address;
      }
    }
  }
  if (mgmt_type) {
    if (table->length == MAC_TABLE_ENTRIES) {
      /* Discard the oldest MAC address. */
      table->first = NORM(table->first + 1);
    } else {
      ++table->length;
    }
    if (table->length > 1) {
      table->last = NORM(table->last + 1);
    }

    memcpy(table->entries[table->last].mac_address,mac,ETH_ALEN);
    anonymize_mac(mac, table->entries[table->last].hashed_mac_address);
    if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
      ++table->added_since_last_update;
    }
    return table->entries[table->last].hashed_mac_address;
  }else{
    return NULL;
  }
}
u_char*  connected_device_address_table_lookup(mac_address_table_t* table,u_char* mac)
{
  if (table->length > 0) {
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if ( !memcmp(table->entries[mac_id].mac_address, mac, ETH_ALEN)) {
	return table->entries[mac_id].hashed_mac_address;
      }else if(distance(table->entries[mac_id].mac_address,mac)<4){
	return table->entries[mac_id].hashed_mac_address;
      }
    }
  }
  return NULL ;
}


u_char* connected_device_address_table_insert(mac_address_table_t* table,u_char* mac)
{
  if(table->length >0){
    int idx;
    for (idx=0; idx <table->length; ++idx){
      int mac_id = NORM(table->last -idx);
      if (!memcmp(table->entries[mac_id].mac_address,mac,ETH_ALEN)){
	return table->entries[mac_id].hashed_mac_address;
      }
    }
  }
  if (table->length == MAC_TABLE_ENTRIES){
    table->first=NORM(table->first +1 );
  }else {
    ++table->length;
  }
  if(table->length > 1){
    table->last = NORM(table->last +1);
  }
  memcpy(table->entries[table->last].mac_address,mac,ETH_ALEN);
  anonymize_mac(table->entries[table->last].mac_address,table->entries[table->last].hashed_mac_address);
  if(table->added_since_last_update <MAC_TABLE_ENTRIES){
    ++table->added_since_last_update;
  }
  return table->entries[table->last].hashed_mac_address ;
}



u_char* device_address_table_lookup(mac_address_table_t* table,u_char* mac,int x) 
{
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if ( !memcmp(table->entries[mac_id].mac_address, mac, ETH_ALEN)) {
	return table->entries[mac_id].hashed_mac_address;
      }
    }
  }
  if (x) {
    if (table->length == MAC_TABLE_ENTRIES) {
      /* Discard the oldest MAC address. */
      table->first = NORM(table->first + 1);
    } else {
      ++table->length;
    }
    if (table->length > 1) {
      table->last = NORM(table->last + 1);
    }

    memcpy(table->entries[table->last].mac_address,mac,ETH_ALEN);
    anonymize_mac(mac, table->entries[table->last].hashed_mac_address);
    if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
      ++table->added_since_last_update;
    }
    return table->entries[table->last].hashed_mac_address;
  }else{
    return NULL;
  }
}

int write_update()
{

  char mgmt_handle_t[FILENAME_MAX];
  char ctrl_handle_t[FILENAME_MAX];
  char data_handle_t[FILENAME_MAX];

  snprintf(mgmt_handle_t,sizeof(mgmt_handle_t),PENDING_UPDATE_MGMT_FILENAME,ifc);
  snprintf(ctrl_handle_t,sizeof(ctrl_handle_t),PENDING_UPDATE_CONTROL_FILENAME,ifc);
  snprintf(data_handle_t,sizeof(data_handle_t),PENDING_UPDATE_DATA_FILENAME,ifc);

  gzFile mgmt_handle = gzopen (mgmt_handle_t/*PENDING_UPDATE_MGMT_FILENAME*/, "wb");
  gzFile control_handle = gzopen (ctrl_handle_t/*PENDING_UPDATE_CONTROL_FILENAME*/, "wb");
  gzFile data_handle = gzopen (data_handle_t/*PENDING_UPDATE_DATA_FILENAME*/, "wb");

  current_timestamp = time(NULL);
  if (!mgmt_handle) {
    perror("Could not open update mgmt file for writing\n");
    exit(EXIT_FAILURE);
  }

  char mgmt_stamp [64];
  snprintf(mgmt_stamp,sizeof(mgmt_stamp), "%s %" PRId64 " %d %" PRId64 "\n",\
	   bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp);
  if(!gzwrite(mgmt_handle,mgmt_stamp, strlen(mgmt_stamp ))){
    perror("Error writing mgmt update\n");
    exit(EXIT_FAILURE);
  }
  //XXX:TODO
  address_mgmt_table_write_update(&mgmt_common_address_table,&mgmt_beacon_address_table,&mgmt_address_table_err,mgmt_handle);
  gzclose(mgmt_handle);
 mgmt_beacon_count =0;
  char update_mgmt_filename[FILENAME_MAX];
  snprintf(update_mgmt_filename,FILENAME_MAX,UPDATE_MGMT_FILENAME,bismark_id,start_timestamp_microseconds,sequence_number,ifc);
  if (rename(mgmt_handle_t/*PENDING_UPDATE_MGMT_FILENAME*/, update_mgmt_filename)) {
    perror("Could not stage mgmt update\n");
    exit(EXIT_FAILURE);
  }

  /*done with mgmt update */
  if (!data_handle) {
    perror("Could not open update data file for writing\n");
    exit(EXIT_FAILURE);
  }
  char data_stamp [64];
  snprintf(data_stamp,sizeof(data_stamp), "%s %" PRId64 " %d %" PRId64 "\n",\
	   bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp);
  if(!gzwrite(data_handle,data_stamp, strlen(data_stamp ))){
    perror("Error writing control update\n");
    exit(EXIT_FAILURE);
  }

  address_data_table_write_update(&data_address_table,&data_address_table_err,data_handle);
  gzclose(data_handle);

  char update_data_filename[FILENAME_MAX];
  snprintf(update_data_filename,FILENAME_MAX,UPDATE_DATA_FILENAME, \
	   bismark_id,start_timestamp_microseconds,sequence_number,ifc);
  if (rename(data_handle_t/*PENDING_UPDATE_DATA_FILENAME*/, update_data_filename)) {
    perror("Could not stage data update\n");
    exit(EXIT_FAILURE);
  }
  /*done with data update */
  if (!control_handle) {
    perror("Could not open update control file for writing\n");
    exit(EXIT_FAILURE);
  }
  char control_stamp [64];
  snprintf(control_stamp,sizeof(control_stamp), "%s %" PRId64 " %d %" PRId64 "\n", \
	   bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp);
  if(!gzwrite(control_handle,control_stamp, strlen(control_stamp ))){
    perror("Error writing control update\n");
    exit(EXIT_FAILURE);
  }
  address_control_table_write_update(&control_address_table,&control_address_table_err,control_handle);
  gzclose(control_handle);

  char update_control_filename[FILENAME_MAX];
  snprintf(update_control_filename,FILENAME_MAX,UPDATE_CONTROL_FILENAME, \
	   bismark_id,start_timestamp_microseconds,sequence_number,ifc);
  if (rename(ctrl_handle_t/*PENDING_UPDATE_CONTROL_FILENAME*/, update_control_filename)) {
    perror("Could not stage control update\n");
    exit(EXIT_FAILURE);
  }

  /*done with control update */

  static int once_ =0;
  if (once_ ==0){
    char digest_handle_t[FILENAME_MAX];
    snprintf(digest_handle_t,sizeof(digest_handle_t),PENDING_UPDATE_FILENAME_DIGEST,ifc);
    gzFile handle_digest = gzopen (digest_handle_t/*PENDING_UPDATE_FILENAME_DIGEST*/, "wb");
    if (!handle_digest) {
      perror("Could not open update file for writing\n");
      exit(EXIT_FAILURE);
    }
    if (anonymization_write_update(handle_digest)) {
      perror("Could not write anonymization update");
	  exit(EXIT_FAILURE);
    }
    gzclose(handle_digest);
    char update_filename_digest[FILENAME_MAX];
    snprintf(update_filename_digest,FILENAME_MAX,UPDATE_FILENAME_DIGEST, \
	     bismark_id,start_timestamp_microseconds,sequence_number);
    if (rename(digest_handle_t/*PENDING_UPDATE_FILENAME_DIGEST*/, update_filename_digest)) {
      perror("Could not stage update for anonymized digest key\n");
      exit(EXIT_FAILURE);
    }
    once_ =1;
  }

  ++sequence_number;
  address_control_table_init(&control_address_table);
  address_data_table_init(&data_address_table);
  address_mgmt_beacon_table_init(&mgmt_beacon_address_table);
  address_mgmt_common_table_init(&mgmt_common_address_table);

  address_control_err_table_init(&control_address_table_err);
  address_data_err_table_init(&data_address_table_err);
  address_mgmt_err_table_init(&mgmt_address_table_err);

  return 0;
}

/*Initializing the tables */

void address_mgmt_beacon_table_init(mgmt_beacon_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}
void address_mgmt_common_table_init(mgmt_common_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

void address_mgmt_err_table_init(mgmt_address_err_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

void address_data_table_init(data_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

void address_data_err_table_init(data_address_err_table_t* table) {
  memset(table, '\0', sizeof(*table));
}


void address_control_table_init(control_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}


void address_control_err_table_init(control_address_err_table_t* table) {
  memset(table, '\0', sizeof(*table));
}
/*Update the records in tables */

int address_data_err_table_update(data_address_err_table_t*  table,
				   unsigned char* pkt ,
				   struct data_layer_err_header* dlh) {
  int idx = table->length;
  if(idx < MAC_TABLE_DATA_ERR_ENTRIES){
    u_char* buffer = table->entries[idx].data_err_content ;
    memcpy(buffer,pkt, HOMESAW_RX_FRAME_HEADER);
    struct data_layer_err_header* t  = (struct data_layer_err_header*)(buffer+HOMESAW_RX_FRAME_HEADER) ;
    t->pkt_len= dlh->pkt_len;
    t->frame_control = dlh->frame_control;
    t->seq_ctrl =  dlh->seq_ctrl;

    memcpy(t->src_mac,dlh->src_mac,ETH_ALEN);
    memcpy(t->dest_mac,dlh->dest_mac,ETH_ALEN);

    table->length++;
  }else {
    table->missed++;
  }
  return 0;
}

int address_data_table_update(data_address_table_t* table,
			       unsigned char* pkt ,
			       struct data_layer_header* dlh,
			       int path_type, int is_more){

  int idx= table->length ;
  if (idx< MAC_TABLE_DATA_ENTRIES){
  if (path_type ==1){ //tx path
    u_char* buffer = table->entries[idx].data_content ;
    memcpy(buffer,pkt, HOMESAW_TX_FRAME_HEADER);

    struct data_layer_header* t  = (struct data_layer_header*)(buffer+HOMESAW_TX_FRAME_HEADER) ;
    memcpy(t->src_mac,dlh->src_mac,ETH_ALEN);
    memcpy(t->dest_mac,dlh->dest_mac,ETH_ALEN);
    t->pkt_len=	dlh->pkt_len;
    t->frame_control = dlh->frame_control;
    t->seq_ctrl =  dlh->seq_ctrl;
#ifdef TRANSPORT_LAYER_CAPTURE
    t->eth_type	= dlh->eth_type;
    t->ip_type=dlh->ip_type;
    t->ip_src=dlh->ip_src;
    t->ip_dest=dlh->ip_dest;

    if(dlh->ip_type == IPPROTO_TCP){
      memcpy(&t->trans_content.tcp.tcp_hdr,(u_char*)&dlh->trans_content.tcp.tcp_hdr, TCP_HEADER_SIZE);
    }
    else if(dlh->ip_type == IPPROTO_UDP){
      t-> trans_content.udp.src_port=dlh-> trans_content.udp.src_port;
      t-> trans_content.udp.dest_port=dlh-> trans_content.udp.dest_port;
    }
#endif
  }else { //rx path
    if (is_more){ /*the data is from the client attached to Bismark and not encrypted data from surrounding traffic*/
#ifdef TRANSPORT_LAYER_CAPTURE
      u_char* buffer = table->entries[idx].data_content ;
      memcpy(buffer,pkt, HOMESAW_RX_FRAME_HEADER);

      struct data_layer_header* t  = (struct data_layer_header*)(buffer+HOMESAW_RX_FRAME_HEADER) ;
      t->pkt_len= dlh->pkt_len;
      t->frame_control =  dlh->frame_control;
      t->seq_ctrl = dlh->seq_ctrl;
      t->eth_type = dlh->eth_type;
      t->ip_type=dlh->ip_type;
      t->ip_src= dlh->ip_src;
      t->ip_dest= dlh->ip_dest;
      if(dlh->ip_type == IPPROTO_TCP){
	memcpy(&t->trans_content.tcp.tcp_hdr,  (u_char*)&dlh->trans_content.tcp.tcp_hdr, TCP_HEADER_SIZE);
      }
      else if(dlh->ip_type == IPPROTO_UDP){
	t-> trans_content.udp.src_port=dlh-> trans_content.udp.src_port;
	t-> trans_content.udp.dest_port=dlh-> trans_content.udp.dest_port;
      }
#endif

    }else {

      u_char* buffer = table->entries[idx].data_content ;
      memcpy(buffer,pkt, HOMESAW_RX_FRAME_HEADER);
      struct data_layer_err_header* t  = (struct data_layer_err_header*)(buffer+HOMESAW_RX_FRAME_HEADER) ;
      memcpy(t->src_mac,dlh->src_mac,ETH_ALEN);
      memcpy(t->dest_mac,dlh->dest_mac,ETH_ALEN);
      t->pkt_len=    dlh->pkt_len;
      t->frame_control = dlh->frame_control;
      t->seq_ctrl = dlh->seq_ctrl;

    }
  }
  if (debug_mode){
    u_char* buff = table->entries[idx].data_content;
    test_data_buff(buff);
  }
  table->length++;
  }else {
    write_update();
  }
	return 0;
}


int address_control_err_table_update(control_address_err_table_t*table ,
				      unsigned char* pkt,
				      struct control_layer_header* clh){
  //  printf("in control err table update \n");
  int idx= table->length ;
  if( idx < MAC_TABLE_CTL_ERR_ENTRIES ){
    u_char* buffer = table->entries[idx].ctl_err_content ;
    memcpy(buffer,pkt, HOMESAW_RX_FRAME_HEADER);
    struct control_layer_header* t  = (struct control_layer_header*)(buffer+HOMESAW_RX_FRAME_HEADER) ;
    memcpy(t->src_mac,clh->src_mac,ETH_ALEN);
    t->pkt_len=	clh->pkt_len;
    t->frame_control = clh->frame_control;
    if (debug_mode) {
      u_char* buff = table->entries[idx].ctl_err_content;
      test_ctl_buff(buff);
      printf("\n--\n");
    }
    table->length++;
  }else {
    table->missed++;
  }
  return 0;
}

int  address_control_table_update(control_address_table_t* table ,
				  unsigned char* pkt,
				  struct control_layer_header* clh){
  int idx= table->length;
  if (idx <  MAC_TABLE_CTL_ENTRIES ){
    u_char* buffer = table->entries[idx].ctl_content ;
    memcpy(buffer,pkt, HOMESAW_RX_FRAME_HEADER);
    struct control_layer_header* t  = (struct control_layer_header*)(buffer+HOMESAW_RX_FRAME_HEADER) ;
    memcpy(t->src_mac,clh->src_mac,ETH_ALEN);
    t->pkt_len=	   clh->pkt_len;
    t->frame_control = clh->frame_control;
    if (debug_mode) {
      u_char* buff = table->entries[idx].ctl_content;
      test_ctl_buff(buff);
      printf("\n--\n");
    }
    table->length++;
  }else {
    table->missed++;
  }
  return 0 ;
}
int address_mgmt_beacon_table_update(mgmt_beacon_address_table_t* table ,
	unsigned char* pkt,
	struct mgmt_beacon_layer_header* mlh){
//	printf("in mgmt  beacon table update \n");
  int idx= table->length ;
  if (idx <  MAC_TABLE_MGT_BEACON_ENTRIES ) {
    u_char* buffer = table->entries[idx].mgt_content;
    memcpy(buffer,pkt, HOMESAW_RX_FRAME_HEADER);
    struct mgmt_beacon_layer_header* t  = (struct mgmt_beacon_layer_header*)(buffer+HOMESAW_RX_FRAME_HEADER) ;
    memcpy(t->src_mac,mlh->src_mac,ETH_ALEN);
    t->pkt_len=	   mlh->pkt_len;
    t->frame_control = mlh->frame_control;
    t->seq_ctrl = mlh->seq_ctrl;
    t->ht_support=   mlh->ht_support ;
    t->cap_info=  mlh->cap_info;
    t->max_rate=mlh->max_rate;
    table->length++;
    if (debug_mode) {
      u_char* buff = table->entries[idx].mgt_content;
      test_mgmt_buff(buff);
      printf("\n--\n");
    }
  }else {
    table->missed++;
  }
	return 0;
}
int address_mgmt_common_table_update(mgmt_common_address_table_t* table ,
				     unsigned char* pkt,
				     struct mgmt_layer_err_header* mlh){
  //	printf("update common table \n");
  int idx= table->length ;
	int16_t it_len ;
  if (idx <  MAC_TABLE_MGT_COMMON_ENTRIES ) {
    u_char* buffer = (table->entries[idx].mgt_content);
    struct ieee80211_radiotap_header* hdr ;
		hdr = (struct ieee80211_radiotap_header*)(pkt);
		it_len = pletohs(&hdr->it_len);
    memcpy(buffer,pkt, it_len);
    struct mgmt_layer_err_header* t  = (struct mgmt_layer_err_header*)(buffer+it_len) ;
    memcpy(t->src_mac,mlh->src_mac,ETH_ALEN);
    t->pkt_len= mlh->pkt_len;
    t->frame_control = mlh->frame_control;
    t->seq_ctrl = mlh->seq_ctrl;
    table->length++;
    if (debug_mode) {
      u_char* buff = table->entries[idx].mgt_content;
      test_mgmt_buff(buff);
      printf("\n--\n");
    }
  }else {
    table->missed++;
  }
  return 0;
}

int address_mgmt_err_table_update(mgmt_address_err_table_t* table ,
	unsigned char* pkt,
	struct mgmt_layer_err_header* mlh){
//  printf("in mgmt err table update \n");
  int idx= table->length;
  if( idx < MAC_TABLE_MGT_ERR_ENTRIES ) {
    u_char* buffer = table->entries[idx].mgt_err_content ;
    memcpy(buffer,pkt, HOMESAW_RX_FRAME_HEADER);
    struct mgmt_layer_err_header* t  = (struct mgmt_layer_err_header*)(buffer+HOMESAW_RX_FRAME_HEADER) ;
    memcpy(t->src_mac,mlh->src_mac,ETH_ALEN);
    t->pkt_len=	mlh->pkt_len;
    t->frame_control = mlh->frame_control;
    t->seq_ctrl = mlh->seq_ctrl;
    if (debug_mode) {
      u_char* buff = table->entries[idx].mgt_err_content;
      test_mgmt_err_buff(buff);
      printf("\n--\n");
    }
    table->length++;
  }else {
    table->missed++;
  }
	return 0;
}

/*Write the records in the table */
int address_mgmt_table_write_update(mgmt_common_address_table_t* common_table,
	mgmt_beacon_address_table_t* table,
	mgmt_address_err_table_t* table_err,
	gzFile  mgmt_handle)
{
  int idx= 0;
  if (debug_mode) {
    printf("in mgmt table write update c=%d err_c=%d \n",\
	   sizeof(table->entries[idx].mgt_content),sizeof(table_err->entries[idx].mgt_err_content) ) ;
  }
  for (idx=0; idx<table->length; idx++){
    struct mgmt_beacon_layer_header* t =(struct mgmt_beacon_layer_header*)
      (table->entries[idx].mgt_content+HOMESAW_RX_FRAME_HEADER);
      memcpy(t->src_mac,access_point_address_table_lookup(&access_point_mac_address_table,t->src_mac,1),ETH_ALEN) ;
    if(!gzwrite(mgmt_handle,table->entries[idx].mgt_content,sizeof(table->entries[idx].mgt_content))){
      fprintf(stderr,"Can't write mgmtframes into handle \n");
      exit(EXIT_FAILURE);
    }
  }
    if(!gzwrite(mgmt_handle, "\n----\n",6)){
      fprintf(stderr,"Can't write -mgmt-beacon frames into handle \n");
      exit(EXIT_FAILURE);
    }

  for (idx=0; idx<common_table->length; idx++){
    struct mgmt_layer_err_header* t =(struct mgmt_layer_err_header*)
      (common_table->entries[idx].mgt_content+HOMESAW_RX_FRAME_HEADER);
    memcpy(t->src_mac,access_point_address_table_lookup(&access_point_mac_address_table,t->src_mac,1),ETH_ALEN);

    if(!gzwrite(mgmt_handle,common_table->entries[idx].mgt_content,sizeof(common_table->entries[idx].mgt_content))){
      fprintf(stderr,"Can't write mgmtframes into handle \n");
      exit(EXIT_FAILURE);
    }
  }

    if(!gzwrite(mgmt_handle, "\n----\n",6)){
      fprintf(stderr,"Can't write -mgmt-common frames into handle \n");
      exit(EXIT_FAILURE);
    }

    //add demarcator
  for (idx=0; idx<table_err->length; idx++){
    struct mgmt_layer_err_header* t =(struct mgmt_layer_err_header*)
      (table_err->entries[idx].mgt_err_content+HOMESAW_RX_FRAME_HEADER);
    u_char* tmp_mgmt_mac =NULL;
    if ( !(table_err->entries[idx].mgt_err_content[2] ==58 || table_err->entries[idx].mgt_err_content[2]==42 ) ){
      printf("There is Err original sin\n");
		}
    tmp_mgmt_mac=access_point_address_table_lookup(&access_point_mac_address_table,t->src_mac,0);
    if (tmp_mgmt_mac !=NULL)
      memcpy((u_char*)t->src_mac,tmp_mgmt_mac,ETH_ALEN);
    else
      memset((u_char*)(t->src_mac)+3,0,3); //tested
    if(!gzwrite(mgmt_handle, table_err->entries[idx].mgt_err_content,sizeof(table_err->entries[idx].mgt_err_content))){
      test_mgmt_err_buff(table_err->entries[idx].mgt_err_content) ;
      fprintf(stderr, "Can't write mgmt err frames into handle \n");
      exit(EXIT_FAILURE);
    }
  }

  if(!gzwrite(mgmt_handle, "\n----\n",6)){
    fprintf(stderr,"Can't write -mgmt-afer-- miss frames into handle \n");
    exit(EXIT_FAILURE);
  }
  //		printf("abhinav : %d  %d \n ", table->missed, sizeof(table->missed));
  if(!gzwrite(mgmt_handle, &table->missed,sizeof(u_int32_t))){
    fprintf(stderr,"Can't write mgmt missed frames into handle \n");
    exit(EXIT_FAILURE);
  }

  if(!gzwrite(mgmt_handle, "\n----\n",6)){
    fprintf(stderr,"Can't write -mgmt-afer-- miss frames into handle \n");
    exit(EXIT_FAILURE);
  }
  //	printf("abhinav : %d  %d \n ", common_table->missed, sizeof(common_table->missed));
  if(!gzwrite(mgmt_handle, &common_table->missed,sizeof(u_int32_t))){
    fprintf(stderr,"Can't write mgmt missed frames into handle \n");
    exit(EXIT_FAILURE);
    }

  if(!gzwrite(mgmt_handle, "\n----\n",6)){
    fprintf(stderr,"Can't write -mgmt-after-2-- frames into handle \n");
    exit(EXIT_FAILURE);
  }
  if(!gzwrite(mgmt_handle,&table_err->missed,sizeof(u_int32_t))){
    fprintf(stderr,"Can't write mgmt err missed frames into handle \n");
    exit(EXIT_FAILURE);
  }
  return 0;
}
int address_control_table_write_update(control_address_table_t* table,
				       control_address_err_table_t* table_err,
				       gzFile control_handle){
  int idx= 0;
  if (debug_mode) {
    printf("int control table write update c=%d err_c=%d\n",\
	   sizeof(table->entries[idx].ctl_content), sizeof(table_err->entries[idx].ctl_err_content) );
  }

  for (idx=0; idx<table->length; idx++){
    struct control_layer_header* t =(struct control_layer_header*)
      (table->entries[idx].ctl_content+HOMESAW_RX_FRAME_HEADER);
    u_char* tmp_mac=NULL;
    tmp_mac=access_point_address_table_lookup(&access_point_mac_address_table,t->src_mac,0);
    if(tmp_mac==NULL){
      memcpy(t->src_mac,device_address_table_lookup(&device_mac_address_table,t->src_mac,1),ETH_ALEN);
    }else{
      memcpy(t->src_mac,tmp_mac,ETH_ALEN);
    }
    if(!gzwrite(control_handle, table->entries[idx].ctl_content,sizeof(table->entries[idx].ctl_content))){
      fprintf(stderr,"Can't write control frames into handle \n");
      exit(EXIT_FAILURE);
    }
  }

  if(!gzwrite(control_handle, "\n----\n",6)){
    fprintf(stderr,"Can't write -control- frames into handle \n");
    exit(EXIT_FAILURE);
  }
  //add demarcator
  for (idx=0; idx<table_err->length; idx++){
    struct control_layer_header* y =(struct control_layer_header*)
      (table_err->entries[idx].ctl_err_content+HOMESAW_RX_FRAME_HEADER);
    u_char* tmp_mac =NULL;
    tmp_mac=connected_device_address_table_lookup(&devices,y->src_mac ) ;
    if(tmp_mac ==NULL){
      u_int8_t* kt = (u_int8_t* ) y->src_mac		;
      memset(kt+3,0,3);
    }else {
      memcpy(y->src_mac,tmp_mac,ETH_ALEN);
    }
    if(!gzwrite(control_handle,table_err->entries[idx].ctl_err_content,
		sizeof(table_err->entries[idx].ctl_err_content))){
      fprintf(stderr,"Can't write control err frames into handle\n");
      exit(EXIT_FAILURE);
    }
  }
  if(!gzwrite(control_handle, "\n----\n",6)){
      fprintf(stderr,"Can't write after-control- frames into handle \n");
      exit(EXIT_FAILURE);
  }
  if(!gzwrite(control_handle, &table->missed,sizeof(u_int32_t))){
    fprintf(stderr,"Can't write control frames missed into handle \n");
    exit(EXIT_FAILURE);
  }

  if(!gzwrite(control_handle, "\n----\n",6)){
    fprintf(stderr,"Can't write after-data-missed frames into handle \n");
    exit(EXIT_FAILURE);
  }

  if(!gzwrite(control_handle, &table_err->missed,sizeof(u_int32_t))){
    fprintf(stderr,"Can't write data err frames missed into handle \n");
    exit(EXIT_FAILURE);
  }
  return 0;
}

int address_data_table_write_update(data_address_table_t* table,
				     data_address_err_table_t* table_err,
				     gzFile data_handle){
  int it_len=0,idx= 0;
  if (debug_mode) {
  printf("int data table write update content=%d  err_content=%d\n", \
	 sizeof(table->entries[idx].data_content), sizeof(table_err->entries[idx].data_err_content));
  }
  struct ieee80211_radiotap_header* hdr;
  for (idx=0; idx<table->length; idx++){
    if (debug_mode) {
    u_char* buff = table->entries[idx].data_content;
    test_data_buff(buff);
    }
    hdr = (struct ieee80211_radiotap_header*)(table->entries[idx].data_content);
    it_len = pletohs(&hdr->it_len);
    struct data_layer_header* t =(struct data_layer_header*)
      (table->entries[idx].data_content+it_len);
    u_char* tmp =NULL;
    tmp=access_point_address_table_lookup(&access_point_mac_address_table,t->src_mac,0);
    if(tmp!=NULL){
      printf("first tmp !NULL\n");
      memcpy(t->dest_mac,device_address_table_lookup(&device_mac_address_table,t->dest_mac,1),ETH_ALEN);
      memcpy(t->src_mac,tmp,ETH_ALEN);
    }else {
      printf("first tmp NULL\n");
      u_char* tmp_tmp =NULL;
      tmp_tmp=access_point_address_table_lookup(&access_point_mac_address_table,t->dest_mac,0);
      if(tmp_tmp==NULL ){
	memcpy(t->src_mac,device_address_table_lookup(&device_mac_address_table,t->src_mac,1),ETH_ALEN);
	memcpy(t->dest_mac,device_address_table_lookup(&device_mac_address_table,t->dest_mac,1),ETH_ALEN);
      }else{
	memcpy(t->dest_mac,device_address_table_lookup(&device_mac_address_table,t->dest_mac,1),ETH_ALEN);
	memcpy(t->src_mac,device_address_table_lookup(&device_mac_address_table,tmp_tmp,1),ETH_ALEN);
      }
    }
    if (debug_mode) {
      u_char* buff = table->entries[idx].data_content;
      test_data_buff(buff);
    }
    if(!gzwrite(data_handle, table->entries[idx].data_content,sizeof(table->entries[idx].data_content))){
      fprintf(stderr,"Can't write data frames into handle \n");
      exit(EXIT_FAILURE);
    }

  }
  if (debug_mode){
    printf("data lost %d\n", table->missed);
  }
  if(!gzwrite(data_handle, "\n----\n",6)){
    fprintf(stderr,"Can't write after-data- frames into handle \n");
    exit(EXIT_FAILURE);
  }

  for (idx=0; idx<table_err->length; idx++){
    hdr = (struct ieee80211_radiotap_header*)(table_err->entries[idx].data_err_content);
    struct data_layer_header* t =(struct data_layer_header*)
      (table_err->entries[idx].data_err_content+pletohs(&hdr->it_len));
    u_char* tmp =NULL;
    tmp=connected_device_address_table_lookup(&devices,t->src_mac ) ;
    if (tmp ==NULL){
      u_int8_t* kt = (u_int8_t* ) t->src_mac;
      memset(kt+3,0,3);
    }else {
      memcpy(t->src_mac, tmp,ETH_ALEN);
    }
    u_char* tmp_d= NULL;
    tmp_d=connected_device_address_table_lookup(&devices,t->dest_mac ) ;
    if (tmp_d ==NULL){
      u_int8_t* kt = (u_int8_t* ) t->dest_mac;
      memset(kt+3,0,3);
    }else {
	memcpy(t->dest_mac, tmp_d,ETH_ALEN);
    }
    if(!gzwrite(data_handle,table_err->entries[idx].data_err_content,sizeof(table_err->entries[idx].data_err_content))){
      fprintf(stderr,"Can't write data err frames into handle \n");
      exit(EXIT_FAILURE);
    }
  }
  if(!gzwrite(data_handle, "\n----\n",6)){
    fprintf(stderr,"Can't write after-data-err frames into handle \n");
      exit(EXIT_FAILURE);
  }
  if(!gzwrite(data_handle, &table->missed,sizeof(u_int32_t))){
    fprintf(stderr,"Can't write data frames missed into handle \n");
    exit(EXIT_FAILURE);
  }
  if(!gzwrite(data_handle, "\n----\n",6)){
    fprintf(stderr,"Can't write after-data-missed frames missedinto handle \n");
    exit(EXIT_FAILURE);
  }
  if(!gzwrite(data_handle, &table_err->missed,sizeof(u_int32_t))){
    fprintf(stderr,"Can't write err data frames missed into handle \n");
    exit(EXIT_FAILURE);
  }
  return 0;
}
