/*
Author : Abhinav Narain
Code Time period for the software : 1 month (including kernel modifications)
*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include "td-util.h"
#include "header.h"
#include "ieee80211_radiotap.h"
#include "pkts.h"
#include "address_table.h"
#define BIT(n)  (1U << n)

int64_t start_timestamp_microseconds;
mac_address_table_t devices;
mac_address_table_t access_point_mac_address_table;
mac_address_table_t device_mac_address_table;
int sequence_number = 0;
time_t current_timestamp;
unsigned char * snapend ;
static unsigned int alarm_count = 0;
static int debug_mode =1;
sigset_t block_set;
char ifc;

static pcap_t* pcap_handle = NULL;
#define DEBUG 1 
#ifdef DEBUG
//Source of rate table:  WireShark
static const float ieee80211_float_htrates[MAX_MCS_INDEX+1][2][2] = {
  /* MCS  0  */
  {       /* 20 Mhz */ {    6.5f,         /* SGI */    7.2f, },
	  /* 40 Mhz */ {   13.5f,         /* SGI */   15.0f, },
  },

  /* MCS  1  */
  {       /* 20 Mhz */ {   13.0f,         /* SGI */   14.4f, },
	  /* 40 Mhz */ {   27.0f,         /* SGI */   30.0f, },
  },

  /* MCS  2  */
  {       /* 20 Mhz */ {   19.5f,         /* SGI */   21.7f, },
	  /* 40 Mhz */ {   40.5f,         /* SGI */   45.0f, },
  },

  /* MCS  3  */
  {       /* 20 Mhz */ {   26.0f,         /* SGI */   28.9f, },
	  /* 40 Mhz */ {   54.0f,         /* SGI */   60.0f, },
  },

  /* MCS  4  */
  {       /* 20 Mhz */ {   39.0f,         /* SGI */   43.3f, },
	  /* 40 Mhz */ {   81.0f,         /* SGI */   90.0f, },
  },

  /* MCS  5  */
  {       /* 20 Mhz */ {   52.0f,         /* SGI */   57.8f, },
	  /* 40 Mhz */ {  108.0f,         /* SGI */  120.0f, },
  },
  /* MCS  6  */
  {       /* 20 Mhz */ {   58.5f,         /* SGI */   65.0f, },
	  /* 40 Mhz */ {  121.5f,         /* SGI */  135.0f, },
  },

  /* MCS  7  */
  {       /* 20 Mhz */ {   65.0f,         /* SGI */   72.2f, },
	  /* 40 Mhz */ {   135.0f,        /* SGI */  150.0f, },
  },

  /* MCS  8  */
  {       /* 20 Mhz */ {   13.0f,         /* SGI */   14.4f, },
	  /* 40 Mhz */ {   27.0f,         /* SGI */   30.0f, },
  },

  /* MCS  9  */
  {       /* 20 Mhz */ {   26.0f,         /* SGI */   28.9f, },
	  /* 40 Mhz */ {   54.0f,         /* SGI */   60.0f, },
  },

  /* MCS 10  */
  {       /* 20 Mhz */ {   39.0f,         /* SGI */   43.3f, },
	  /* 40 Mhz */ {   81.0f,         /* SGI */   90.0f, },
  },

  /* MCS 11  */
  {       /* 20 Mhz */ {   52.0f,         /* SGI */   57.8f, },
	  /* 40 Mhz */ {  108.0f,         /* SGI */  120.0f, },
  },

  /* MCS 12  */
  {       /* 20 Mhz */ {   78.0f,         /* SGI */   86.7f, },
	  /* 40 Mhz */ {  162.0f,         /* SGI */  180.0f, },
  },
  /* MCS 13  */
  {       /* 20 Mhz */ {  104.0f,         /* SGI */  115.6f, },
	  /* 40 Mhz */ {  216.0f,         /* SGI */  240.0f, },
  },

  /* MCS 14  */
  {       /* 20 Mhz */ {  117.0f,         /* SGI */  130.0f, },
	  /* 40 Mhz */ {  243.0f,         /* SGI */  270.0f, },
  },

  /* MCS 15  */
  {       /* 20 Mhz */ {  130.0f,         /* SGI */  144.4f, },
	  /* 40 Mhz */ {  270.0f,         /* SGI */  300.0f, },
  },

  /* MCS 16  */
  {       /* 20 Mhz */ {   19.5f,         /* SGI */   21.7f, },
	  /* 40 Mhz */ {   40.5f,         /* SGI */   45.0f, },
  },

  /* MCS 17  */
  {       /* 20 Mhz */ {   39.0f,         /* SGI */   43.3f, },
	  /* 40 Mhz */ {   81.0f,         /* SGI */   90.0f, },
  },

  /* MCS 18  */
  {       /* 20 Mhz */ {   58.5f,         /* SGI */   65.0f, },
	  /* 40 Mhz */ {  121.5f,         /* SGI */  135.0f, },
  },

  /* MCS 19  */
  {       /* 20 Mhz */ {   78.0f,         /* SGI */   86.7f, },
	  /* 40 Mhz */ {  162.0f,         /* SGI */  180.0f, },
  },
  /* MCS 20  */
  {       /* 20 Mhz */ {  117.0f,         /* SGI */  130.0f, },
	  /* 40 Mhz */ {  243.0f,         /* SGI */  270.0f, },
  },

  /* MCS 21  */
  {       /* 20 Mhz */ {  156.0f,         /* SGI */  173.3f, },
	  /* 40 Mhz */ {  324.0f,         /* SGI */  360.0f, },
  },

  /* MCS 22  */
  {       /* 20 Mhz */ {  175.5f,         /* SGI */  195.0f, },
	  /* 40 Mhz */ {  364.5f,         /* SGI */  405.0f, },
  },

  /* MCS 23  */
  {       /* 20 Mhz */ {  195.0f,         /* SGI */  216.7f, },
	  /* 40 Mhz */ {  405.0f,         /* SGI */  450.0f, },
  },

  /* MCS 24  */
  {       /* 20 Mhz */ {   26.0f,         /* SGI */   28.9f, },
	  /* 40 Mhz */ {   54.0f,         /* SGI */   60.0f, },
  },

  /* MCS 25  */
  {       /* 20 Mhz */ {   52.0f,         /* SGI */   57.8f, },
	  /* 40 Mhz */ {  108.0f,         /* SGI */  120.0f, },
  },

  /* MCS 26  */
  {       /* 20 Mhz */ {   78.0f,         /* SGI */   86.7f, },
	  /* 40 Mhz */ {  162.0f,         /* SGI */  180.0f, },
  },
  /* MCS 27  */
  {       /* 20 Mhz */ {  104.0f,         /* SGI */  115.6f, },
	  /* 40 Mhz */ {  216.0f,         /* SGI */  240.0f, },
  },

  /* MCS 28  */
  {       /* 20 Mhz */ {  156.0f,         /* SGI */  173.3f, },
	  /* 40 Mhz */ {  324.0f,         /* SGI */  360.0f, },
  },

  /* MCS 29  */
  {       /* 20 Mhz */ {  208.0f,         /* SGI */  231.1f, },
	  /* 40 Mhz */ {  432.0f,         /* SGI */  480.0f, },
  },

  /* MCS 30  */
  {       /* 20 Mhz */ {  234.0f,         /* SGI */  260.0f, },
	  /* 40 Mhz */ {  486.0f,         /* SGI */  540.0f, },
  },

  /* MCS 31  */
  {       /* 20 Mhz */ {  260.0f,         /* SGI */  288.9f, },
	  /* 40 Mhz */ {  540.0f,         /* SGI */  600.0f, },
  },

  /* MCS 32  */
  {       /* 20 Mhz */ {    0.0f,         /* SGI */    0.0f, }, /* not valid */
	  /* 40 Mhz */ {    6.0f,         /* SGI */    6.7f, },
  },

  /* MCS 33  */
  {       /* 20 Mhz */ {   39.0f,         /* SGI */   43.3f, },
	  /* 40 Mhz */ {   81.0f,         /* SGI */   90.0f, },
  },
  /* MCS 34  */
  {       /* 20 Mhz */ {   52.0f,         /* SGI */   57.8f, },
	  /* 40 Mhz */ {  108.0f,         /* SGI */  120.0f, },
  },

  /* MCS 35  */
  {       /* 20 Mhz */ {   65.0f,         /* SGI */   72.2f, },
	  /* 40 Mhz */ {  135.0f,         /* SGI */  150.0f, },
  },

  /* MCS 36  */
  {       /* 20 Mhz */ {   58.5f,         /* SGI */   65.0f, },
	  /* 40 Mhz */ {  121.5f,         /* SGI */  135.0f, },
  },

  /* MCS 37  */
  {       /* 20 Mhz */ {   78.0f,         /* SGI */   86.7f, },
	  /* 40 Mhz */ {  162.0f,         /* SGI */  180.0f, },
  },

  /* MCS 38  */
  {       /* 20 Mhz */ {   97.5f,         /* SGI */  108.3f, },
	  /* 40 Mhz */ {  202.5f,         /* SGI */  225.0f, },
  },

  /* MCS 39  */
  {       /* 20 Mhz */ {   52.0f,         /* SGI */   57.8f, },
	  /* 40 Mhz */ {  108.0f,         /* SGI */  120.0f, },
  },

  /* MCS 40  */
  {       /* 20 Mhz */ {   65.0f,         /* SGI */   72.2f, },
	  /* 40 Mhz */ {  135.0f,         /* SGI */  150.0f, },
  },
  /* MCS 41  */
  {       /* 20 Mhz */ {   65.0f,         /* SGI */   72.2f, },
	  /* 40 Mhz */ {  135.0f,         /* SGI */  150.0f, },
  },

  /* MCS 42  */
  {       /* 20 Mhz */ {   78.0f,         /* SGI */   86.7f, },
	  /* 40 Mhz */ {  162.0f,         /* SGI */  180.0f, },
  },

  /* MCS 43  */
  {       /* 20 Mhz */ {   91.0f,         /* SGI */  101.1f, },
	  /* 40 Mhz */ {  189.0f,         /* SGI */  210.0f, },
  },

  /* MCS 44  */
  {       /* 20 Mhz */ {   91.0f,         /* SGI */  101.1f, },
	  /* 40 Mhz */ {  189.0f,         /* SGI */  210.0f, },
  },

  /* MCS 45  */
  {       /* 20 Mhz */ {  104.0f,         /* SGI */  115.6f, },
	  /* 40 Mhz */ {  216.0f,         /* SGI */  240.0f, },
  },

  /* MCS 46  */
  {       /* 20 Mhz */ {   78.0f,         /* SGI */   86.7f, },
	  /* 40 Mhz */ {  162.0f,         /* SGI */  180.0f, },
  },

  /* MCS 47  */
  {       /* 20 Mhz */ {   97.5f,         /* SGI */  108.3f, },
	  /* 40 Mhz */ {  202.5f,         /* SGI */  225.0f, },
  },
  /* MCS 48  */
  {       /* 20 Mhz */ {   97.5f,         /* SGI */  108.3f, },
	  /* 40 Mhz */ {  202.5f,         /* SGI */  225.0f, },
  },

  /* MCS 49  */
  {       /* 20 Mhz */ {  117.0f,         /* SGI */  130.0f, },
	  /* 40 Mhz */ {  243.0f,         /* SGI */  270.0f, },
  },

  /* MCS 50  */
  {       /* 20 Mhz */ {  136.5f,         /* SGI */  151.7f, },
	  /* 40 Mhz */ {  283.5f,         /* SGI */  315.0f, },
  },

  /* MCS 51  */
  {       /* 20 Mhz */ {  136.5f,         /* SGI */  151.7f, },
	  /* 40 Mhz */ {  283.5f,         /* SGI */  315.0f, },
  },

  /* MCS 52  */
  {       /* 20 Mhz */ {  156.0f,         /* SGI */  173.3f, },
	  /* 40 Mhz */ {  324.0f,         /* SGI */  360.0f, },
  },

  /* MCS 53  */
  {       /* 20 Mhz */ {   65.0f,         /* SGI */   72.2f, },
	  /* 40 Mhz */ {  135.0f,         /* SGI */  150.0f, },
  },

  /* MCS 54  */
  {       /* 20 Mhz */ {   78.0f,         /* SGI */   86.7f, },
	  /* 40 Mhz */ {  162.0f,         /* SGI */  180.0f, },
  },
  /* MCS 55  */
  {       /* 20 Mhz */ {   91.0f,         /* SGI */  101.1f, },
	  /* 40 Mhz */ {  189.0f,         /* SGI */  210.0f, },
  },

  /* MCS 56  */
  {       /* 20 Mhz */ {   78.0f,         /* SGI */   86.7f, },
	  /* 40 Mhz */ {  162.0f,         /* SGI */  180.0f, },
  },

  /* MCS 57  */
  {       /* 20 Mhz */ {   91.0f,         /* SGI */  101.1f, },
	  /* 40 Mhz */ {  189.0f,         /* SGI */  210.0f, },
  },

  /* MCS 58  */
  {       /* 20 Mhz */ {  104.0f,         /* SGI */  115.6f, },
	  /* 40 Mhz */ {  216.0f,         /* SGI */  240.0f, },
  },

  /* MCS 59  */
  {       /* 20 Mhz */ {  117.0f,         /* SGI */  130.0f, },
	  /* 40 Mhz */ {  243.0f,         /* SGI */  270.0f, },
  },

  /* MCS 60  */
  {       /* 20 Mhz */ {  104.0f,         /* SGI */  115.6f, },
	  /* 40 Mhz */ {  216.0f,         /* SGI */  240.0f, },
  },

  /* MCS 61  */
  {       /* 20 Mhz */ {  117.0f,         /* SGI */  130.0f, },
	  /* 40 Mhz */ {  243.0f,         /* SGI */  270.0f, },
  },

  /* MCS 62  */
  {       /* 20 Mhz */ {  130.0f,         /* SGI */  144.4f, },
	  /* 40 Mhz */ {  270.0f,         /* SGI */  300.0f, },
  },

  /* MCS 63  */
  {       /* 20 Mhz */ {  130.0f,         /* SGI */  144.4f, },
	  /* 40 Mhz */ {  270.0f,         /* SGI */  300.0f, },
  },

  /* MCS 64  */
  {       /* 20 Mhz */ {  143.0f,         /* SGI */  158.9f, },
	  /* 40 Mhz */ {  297.0f,         /* SGI */  330.0f, },
  },

  /* MCS 65  */
  {       /* 20 Mhz */ {   97.5f,         /* SGI */  108.3f, },
	  /* 40 Mhz */ {  202.5f,         /* SGI */  225.0f, },
  },

  /* MCS 66  */
  {       /* 20 Mhz */ {  117.0f,         /* SGI */  130.0f, },
	  /* 40 Mhz */ {  243.0f,         /* SGI */  270.0f, },
  },

  /* MCS 67  */
  {       /* 20 Mhz */ {  136.5f,         /* SGI */  151.7f, },
	  /* 40 Mhz */ {  283.5f,         /* SGI */  315.0f, },
  },

  /* MCS 68  */
  {       /* 20 Mhz */ {  117.0f,         /* SGI */  130.0f, },
	  /* 40 Mhz */ {  243.0f,         /* SGI */  270.0f, },
  },
  /* MCS 69  */
  {       /* 20 Mhz */ {  136.5f,         /* SGI */  151.7f, },
	  /* 40 Mhz */ {  283.5f,         /* SGI */  315.0f, },
  },

  /* MCS 70  */
  {       /* 20 Mhz */ {  156.0f,         /* SGI */  173.3f, },
	  /* 40 Mhz */ {  324.0f,         /* SGI */  360.0f, },
  },

  /* MCS 71  */
  {       /* 20 Mhz */ {  175.5f,         /* SGI */  195.0f, },
	  /* 40 Mhz */ {  364.5f,         /* SGI */  405.0f, },
  },

  /* MCS 72  */
  {       /* 20 Mhz */ {  156.0f,         /* SGI */  173.3f, },
	  /* 40 Mhz */ {  324.0f,         /* SGI */  360.0f, },
  },

  /* MCS 73  */
  {       /* 20 Mhz */ {  175.5f,         /* SGI */  195.0f, },
	  /* 40 Mhz */ {  364.5f,         /* SGI */  405.0f, },
  },

  /* MCS 74  */
  {       /* 20 Mhz */ {  195.0f,         /* SGI */  216.7f, },
	  /* 40 Mhz */ {  405.0f,         /* SGI */  450.0f, },
  },
  /* MCS 75  */
  {       /* 20 Mhz */ {  195.0f,         /* SGI */  216.7f, },
	  /* 40 Mhz */ {  405.0f,         /* SGI */  450.0f, },
  },

  /* MCS 76  */
  {       /* 20 Mhz */ {  214.5f,         /* SGI */  238.3f, },
	  /* 40 Mhz */ {  445.5f,         /* SGI */  495.0f, },
  },
};
#endif

int tx_path(const unsigned char* p,
	    int pkt_len,
	    int cap_len )
{
  u_int32_t present ;
  u_int16_t it_len;
  int offset=0;
  struct ieee80211_radiotap_header *hdr;
  hdr = (struct ieee80211_radiotap_header *)p;
  it_len = pletohs(&hdr->it_len);
  u_int16_t radiotap_len;
  radiotap_len =it_len;
  present = pletohl(&hdr->it_present);
  offset += sizeof(struct ieee80211_radiotap_header);
  if (present & BIT(IEEE80211_RADIOTAP_TSFT)) {
   printf ("\n tx: tsft %llu \n",  pletoh64(p+offset));
#ifdef DEBUG
    offset += 8;
  }
  if( present & BIT(IEEE80211_RADIOTAP_RATE)){
    int rate =*(p+offset);
    if (rate >= 0x80 && rate <= 0x8f) {
	printf("rate %u \n",rate & 0x7f);
    } else {
	printf("**RATE** %.1f \n", (float)rate / 2);
    }
      offset +=2 ;
  }
  if (present & BIT(IEEE80211_RADIOTAP_TX_FLAGS)){
    u_int16_t tx_flags =pletohs(p+offset);
//  printf("tx_flags: %"PRIu16"\n",tx_flags);
    printf("act_flag=%02x %02x \n",*(p+offset),*(p+offset+1));
    if (tx_flags & IEEE80211_RADIOTAP_F_TX_CTS)
      printf("flag is cts \n");
    if(tx_flags & IEEE80211_RADIOTAP_F_TX_RTS)
      printf("flag is rts \n");
    if(tx_flags & IEEE80211_RADIOTAP_F_TX_NOACK)
      printf("flag is no ack\n");
   	u_int16_t h = 0x40 ; //IEEE80211_RADIOTAP_F_TX_AGG ;
	u_char *t = &h ;
	printf("tx flag  %x = %02x %02x ; \n",h,*t, *(t+1));
	if (tx_flags & h){
	  printf("this is aggregated frame \n");
	}else {
	  printf("this is not aggr frame\n");
	}
	offset +=2;
  }
	//printf("\n%02x\n",*(p+offset));
  if (present & BIT(IEEE80211_RADIOTAP_DATA_RETRIES)){
    if (debug_mode) {
      printf(" data retries %u \n", *(p+offset));
    }
    offset++;
  }
  if( present & BIT(IEEE80211_RADIOTAP_MCS)){
    //printf(" mcs\n ");
    u_int8_t mcs_known, mcs_flags;
    u_int8_t mcs;
    u_int8_t bandwidth;
    u_int8_t gi_length;
    u_int8_t can_calculate_rate = 1 ;
    mcs_known = *(p+offset) ;
    mcs_flags =  *(p+offset+1);
    mcs = *(p +offset+ 2);
    if (debug_mode) {
      printf(" %02x %02x ;mcs_1:%02x mcs_2:%0x mcs_3:%02x \n", *(p+offset-1), *(p+offset-2) ,mcs_known,mcs_flags,mcs);
    }
    if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
      bandwidth = ((mcs_flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_40) ?
        1 : 0;
    } else {
      bandwidth = 0;
      can_calculate_rate = FALSE; //no bandwidth
    }
    if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_GI) {
      gi_length = (mcs_flags & IEEE80211_RADIOTAP_MCS_SGI) ?  1 : 0;
    } else {
      gi_length = 0;
      can_calculate_rate = FALSE; //no GI width
    }
    if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_MCS) {
      can_calculate_rate =1;
    } else{
      can_calculate_rate = FALSE; // no MCS index
    }
    if (can_calculate_rate && mcs <= MAX_MCS_INDEX
        && ieee80211_float_htrates[mcs][bandwidth][gi_length] != 0.0 ) {
      printf("Data Rate: %.1f Mb/s", ieee80211_float_htrates[mcs][bandwidth][gi_length]);
    }

    offset +=3 ;
  }
#endif
mac_header_parser(p,pkt_len,cap_len, 1,radiotap_len);
return 0 ;
}

int rx_path(const unsigned char * p, int pkt_len, int cap_len )
{
  u_int32_t present ;
  u_int16_t it_len;
  int offset=0;
  u_int8_t bad_fcs =0;
  struct ieee80211_radiotap_header *hdr;
  hdr = (struct ieee80211_radiotap_header *)p;
  it_len = pletohs(&hdr->it_len);
  u_int16_t radiotap_len= it_len ;
  present = pletohl(&hdr->it_present);
  offset += sizeof(struct ieee80211_radiotap_header);
  if (present & BIT(IEEE80211_RADIOTAP_TSFT)) {
    printf ("\n rx: tsft %llu \n",  pletoh64(p+offset));
    offset += 8;
  }
  if (present & BIT(IEEE80211_RADIOTAP_FLAGS)) {
    u_int8_t flags= *(p+offset);
    if (flags	& IEEE80211_RADIOTAP_F_BADFCS){
      bad_fcs =1 ;
    }
  }
#ifdef DEBUG
  offset +=1 ;
  // 	}
  
  if( present & BIT(IEEE80211_RADIOTAP_RATE)){
    int rate =*(p+offset);
    if (rate >= 0x80 && rate <= 0x8f) {
      printf("rate %u \n",rate & 0x7f);
    } else {
      printf("**RATE** %.1f \n", (float)rate / 2);
    }
  }
  offset +=1 ;
  
  if (present & BIT(IEEE80211_RADIOTAP_CHANNEL)){
    u_int16_t *ch=(p+offset);
    printf("chan  %u\n", pletohs(ch));
    offset +=2 ;
    offset +=2 ;
  }
  if (present & BIT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL )){
    printf(" dbm sig %d \n", *(p+offset));
    offset++ ;
  }
  
  if (present & BIT(IEEE80211_RADIOTAP_DBM_ANTNOISE )){
    printf(" dbm noise %d \n", *(p+offset));
		offset++ ;
  }
  if (present & BIT(IEEE80211_RADIOTAP_ANTENNA )){
    printf(" antenna %u \n", *(p+offset));
    offset++;
    /*padding*/
    offset++;
  }
  if (present & BIT(IEEE80211_RADIOTAP_RX_FLAGS )){
    offset +=2 ;
  }
  if( present & BIT(IEEE80211_RADIOTAP_MCS )){
    //	offset +=3 ;    
    u_int8_t mcs_known, mcs_flags;
    u_int8_t mcs;
    u_int8_t bandwidth;
    u_int8_t gi_length;
    u_int8_t can_calculate_rate = 1 ;
    mcs_known = *(p+offset) ;
    mcs_flags =  *(p+offset+1);
    mcs = *(p +offset+ 2);
    if (debug_mode) {
      printf(" %02x %02x ;mcs_1:%02x mcs_2:%0x mcs_3:%02x \n", *(p+offset-1), *(p+offset-2) ,mcs_known,mcs_flags,mcs);
    }
    if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
      bandwidth = ((mcs_flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_40) ?
	1 : 0;
      printf("if bw\n");
    } else {
      bandwidth = 0;
     	 can_calculate_rate = FALSE; // no bandwidth
    }
    if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_GI) {
       gi_length = (mcs_flags & IEEE80211_RADIOTAP_MCS_SGI) ?	1 : 0;

    } else {
      gi_length = 0;
      can_calculate_rate = FALSE;     // no GI width
    }
    if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_MCS) {
      printf("have mcs \n");
      can_calculate_rate =1;
    } else{
      can_calculate_rate = FALSE;     // no MCS index
      printf("cannot calrate %d\n", can_calculate_rate);
    }
    printf("mcs=%u, bw=%u, gi=%u \n",mcs,bandwidth,gi_length);
   if (can_calculate_rate && mcs <= MAX_MCS_INDEX
	&& ieee80211_float_htrates[mcs][bandwidth][gi_length] != 0.0 ) {
      printf("Data Rate: %.1f Mb/s", ieee80211_float_htrates[mcs][bandwidth][gi_length]);
    }
   // printf(" mcs \n");
    offset += 3 ;
  }
  printf("\n");
  offset +=6;
  if (present & BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE )){
    printf("vendor namespace \n");
  }

  if (present & BIT(IEEE80211_RADIOTAP_CAPLEN )){
    printf("  CAPlen %u \n", pletohs(p+offset));
    offset +=2 ;
  }
#endif
  if (bad_fcs) {
    printf("bad fcs \n");
   //mac_header_err_parser(p, pkt_len,cap_len);

  }
  else{
   mac_header_parser(p,pkt_len, cap_len,0,radiotap_len);
   }
  return 0 ;
}

int drops(void)
{
  static int ps_drop=0;
  static int ps_recv=0;
  struct pcap_stat statistics;
  pcap_stats(pcap_handle, &statistics);
  if (debug_mode) {
    printf("drops: %d  %d since process creation\n", statistics.ps_drop,statistics.ps_recv);
  }
  ps_drop=statistics.ps_drop - ps_drop;
  if (ps_drop >0){
    if (debug_mode) {
      printf ("There is a drop %u|%u\n",statistics.ps_recv , statistics.ps_drop );
    }
    gzFile drops_handle = gzopen (PENDING_UPDATE_DROPS_FILENAME, "wb");
    if (!drops_handle) {
      perror("Could not open update drops file for writing\n");
      exit(EXIT_FAILURE);
    }
    if(!gzprintf(drops_handle,"%d|%d\n", statistics.ps_recv,statistics.ps_drop)){
      perror("error writing the mac data zip file ");
      exit(EXIT_FAILURE);
    }
    gzclose(drops_handle);
    char update_drops_filename[FILENAME_MAX];
    if (rename(PENDING_UPDATE_DROPS_FILENAME, update_drops_filename)) {
      perror("Could not stage drops update\n");
      exit(EXIT_FAILURE);
    }
    ps_drop= statistics.ps_drop;
    ps_recv= statistics.ps_recv-ps_recv;
  }
  return 0 ;
}

static void pkt_update(u_char* const user,
		       const struct pcap_pkthdr* const header,
		       const u_char* const p)
{
  if (sigprocmask(SIG_BLOCK, &block_set, NULL) < 0) {
    perror("sigprocmask");
    exit(EXIT_FAILURE);
  }
  u_int16_t it_len;
  struct ieee80211_radiotap_header *hdr;
  hdr = (struct ieee80211_radiotap_header *)p;
  it_len = pletohs(&hdr->it_len);
  printf(" length of radiotap is %u \n",it_len) ;
  if (it_len == 14){
  // tx_path(p,header->len,header->caplen);
  }else if (it_len ==26 || it_len ==29 ){
  rx_path(p, header->len,header->caplen);
  }else {
  }
  if (sigprocmask(SIG_UNBLOCK, &block_set, NULL) < 0) {
    perror("sigprocmask");
    exit(EXIT_FAILURE);
  }
}

static void set_next_alarm(void)
{
  alarm(UPDATE_PERIOD_SECONDS);
}

static void handle_signals(int sig)
{
  if (sig == SIGINT || sig == SIGTERM) {
   // write_update();
    exit(0);
  } else if (sig == SIGALRM) {
    alarm_count += 1;
    if (alarm_count % ALARMS_PER_UPDATE == 0) {
      drops();
    }
    printf(" write update \n");
   // write_update();
    set_next_alarm();
  }
}

static void initialize_signal_handler(void)
{
  struct sigaction action;
  action.sa_handler = handle_signals;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_RESTART;
  if (sigaction(SIGINT, &action, NULL) < 0
      || sigaction(SIGTERM, &action, NULL) < 0
      || sigaction(SIGALRM, &action, NULL)) {
    perror("sigaction");
    exit(EXIT_FAILURE);
  }
  sigemptyset(&block_set);
  sigaddset(&block_set, SIGINT);
  sigaddset(&block_set, SIGTERM);
  sigaddset(&block_set, SIGALRM);
}


int main(int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];

  if (argc <2){
    fprintf(stderr,"Usage : %s monitor interface ", argv[0]);
    exit(EXIT_FAILURE);
  }
  printf("argv1 =%s\n", argv[1]);
  ifc = argv[1][3];
  struct timeval start_timeval;
  gettimeofday(&start_timeval, NULL);
  start_timestamp_microseconds   = start_timeval.tv_sec * NUM_MICROS_PER_SECOND + start_timeval.tv_usec;

  initialize_signal_handler();
  set_next_alarm();

  pcap_handle = pcap_open_live(argv[1], BUFSIZ, PCAP_PROMISCUOUS, PCAP_TIMEOUT_MILLISECONDS, errbuf);
  if (!pcap_handle) {
    fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
    return -1;
  }
  printf(" DLT_IEEE802_11_RADIO: %d \n", pcap_datalink(pcap_handle));

  return pcap_loop(pcap_handle, -1, pkt_update, NULL);
}
