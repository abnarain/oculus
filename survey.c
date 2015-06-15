#include<stdio.h>
#include<zlib.h>    
#include<string.h>
#include<stdlib.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include<net/ethernet.h>
#include <sys/stat.h>
#include <errno.h>
#include "header.h"
#include "td-util.h"
#include "pkts.h"
#include "address_table.h"
/*
This file is not used currently.
The data collected using this file corresponds to the iw survey dump.
*/
static int debug_mode ;
static void print_mac(u_int8_t* ptr ,const char* type){
  printf("%s; %02x:%02x:%02x:%02x:%02x:%02x\n", type,ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
} 


int mac_address_map(mac_address_table_t* devices, u_char* mac_addr){
 u_char* c_d;
 c_d= connected_device_address_table_insert(devices,mac_addr);
 return 0 ;
}

#if 0
int mac_address_map(mac_address_table_t* devices)
{
  char station[20];
  char path[1024];
  u_int8_t  mac[ETH_ALEN];
  FILE * fp=NULL;   fp = popen("iw wlan0 station dump", "r");
  if (fp == NULL) {
    perror("Failed to run wlan0 station dump command\n" );
    return -1;
  }
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    if (strncmp(path, "Station",7) == 0) {
      memset(station,'\0',sizeof(station));
      sscanf (path, "Station %s (on wlan0)",station );
      //	printf("station %s\n",station);
      if (station[0]=='\0')
	break ;
      u_int8_t *c_d ;
      char a[3]={0}; char b[3]={0};
      char c[3]={0}; char d[3]={0};
      char e[3]={0}; char f[3]={0};
      a[0]=station[0];a[1]=station[1];
      b[0]=station[3];b[1]=station[4];
      c[0]=station[6];c[1]=station[7];
      d[0]=station[9];d[1]=station[10];
      e[0]=station[12];e[1]=station[13];
      f[0]=station[15];f[1]=station[16];
      int a0,a1,a2,a3,a4,a5;
      sscanf(a, "%x",&a0); sscanf(b, "%x",&a1);
      sscanf(c, "%x",&a2); sscanf(d, "%x",&a3);
      sscanf(e, "%x",&a4); sscanf(f, "%x",&a5);
      //	printf("abhinav :%x %x %x %x %x %x\n",a0,a1,a2,a3,a4,a5);
      mac[0]=a0;mac[1]=a1;
      mac[2]=a2;mac[3]=a3;
      mac[4]=a4;mac[5]=a5;

      c_d= connected_device_address_table_insert(devices,mac );
      if (debug_mode) {
	print_mac(mac,"actual device\n");      
	print_mac(c_d,"actual hashed device\n");
      }
    }
  }
  pclose(fp);
  //	printf("now for wlan1 interface \n");
  fp=NULL; 
  fp = popen("iw wlan1 station dump", "r");
  if (fp == NULL) {
    perror("Failed to run wlan0 station dump command\n" );
    return -1;
  }
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    if (strncmp(path, "Station",7) == 0) {
      memset(station,'\0',sizeof(station));
      sscanf (path, "Station %s (on wlan1)",station );
      if (debug_mode) {
	printf("station %s\n",station);
      }
      if (station[0]=='\0')
	break ;
      u_int8_t *c_d ;
      char a[3]={0}; char b[3]={0};
      char c[3]={0}; char d[3]={0};
      char e[3]={0}; char f[3]={0};
      a[0]=station[0]; a[1]=station[1];
      b[0]=station[3]; b[1]=station[4];
      c[0]=station[6]; c[1]=station[7];
      d[0]=station[9]; d[1]=station[10];
      e[0]=station[12];e[1]=station[13];
      f[0]=station[15];f[1]=station[16];
      int a0,a1,a2,a3,a4,a5;
      sscanf(a, "%x",&a0); sscanf(b, "%x",&a1);
      sscanf(c, "%x",&a2); sscanf(d, "%x",&a3);
      sscanf(e, "%x",&a4); sscanf(f, "%x",&a5);
      
      mac[0]=a0; mac[1]=a1; mac[2]=a2;
      mac[3]=a3; mac[4]=a4; mac[5]=a5;
      if (debug_mode) {
	printf("abhinav :%x %x %x %x %x %x\n",a0,a1,a2,a3,a4,a5);
	print_mac(mac,"actual device\n");
    }
	c_d= connected_device_address_table_insert(devices,mac );
	if (debug_mode) {
	  print_mac(c_d,"actual hashed device\n");
	}
    }
  }
  pclose(fp);
  return 0;
 
}
#endif 

int survey_stats(gzFile handle_counts){
  char path[1024];
  FILE * fp=NULL;
  fp = popen("iw wlan0 survey dump", "r");
  if (fp == NULL) {
    perror("Failed on wlan0 survey command\n" );
		exit(-1);
  }  
  u_int64_t active_time, busy_time, transmit_time,receive_time;
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    if (strncmp(path,"\tfrequency:\t\t\t",14 )==0){
      int k= strlen(path);
      if (k<30)
	continue ;
      if (strncmp(path+k-9,"in use",6)){
	while (fgets(path, sizeof(path)-1, fp) != NULL){
	  if (strncmp(path,"\tchannel active time:",21)==0){             
	    sscanf (path,  "\tchannel active time:\t\t%llu ms\n",&active_time );
	  }            
	  if (strncmp(path,"\tchannel busy time:",19)==0){                       
	    sscanf (path,  "\tchannel busy time:\t\t%llu ms\n",&busy_time );
	  }                                                                                                               
	  if (strncmp(path,"\tchannel receive time:",22)==0){
	    sscanf (path,  "\tchannel receive time:\t\t%llu ms\n",&receive_time );
	  }                                                                                                                
	  if (strncmp(path,"\tchannel transmit time",22)==0){ 
	    sscanf (path,  "\tchannel transmit time:\t\t%llu ms\n",&transmit_time );
	    break;
	  }
	}
      }
    }  // else there is no freq in use
  }
  pclose(fp);
  if(!gzprintf(handle_counts,"wlan0|%llu|%llu|%llu|%llu\n",
	       transmit_time,receive_time,busy_time,active_time)){
    printf("error writing the zip file :from wlan0");
    exit(-1);
    //the command need not give output, hence nothing to be written, but still cannot return/exit
  }
  
  if(!gzprintf(handle_counts,"%s\n","##" )) {
    printf("error writing the zip file :wlan0 survey values");
    exit(-1);
    //the command need not give output, hence  nothing to be written, but still cannot return/exit
  }
  
  //work on wlan1 interface 

  fp=NULL;
  fp = popen("iw wlan1 survey dump", "r");
  if (fp == NULL) {
    perror("Failed on wlan1 survey command\n" );
    exit(-1);
  }
  
  active_time=busy_time=transmit_time =receive_time=0;
  
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    if (strncmp(path,"\tfrequency:\t\t\t",14 )==0){
      int k= strlen(path);
      if (k<30)
	continue ;
      if (strncmp(path+k-9,"in use",6)){
	
	while (fgets(path, sizeof(path)-1, fp) != NULL){
	  if (strncmp(path,"\tchannel active time:",21)==0){             
	    sscanf (path,  "\tchannel active time:\t\t%llu ms\n",&active_time );
	  }            
	  if (strncmp(path,"\tchannel busy time:",19)==0){                       
	    sscanf (path,  "\tchannel busy time:\t\t%llu ms\n",&busy_time );
	  }                                                                                                               
	  if (strncmp(path,"\tchannel receive time:",22)==0){
	    sscanf (path,  "\tchannel receive time:\t\t%llu ms\n",&receive_time );
	  }                                                                                                                
	  if (strncmp(path,"\tchannel transmit time",22)==0){ 
	    sscanf (path,  "\tchannel transmit time:\t\t%llu ms\n",&transmit_time );
	    break;
	  }
	}
      }
    }  // else there is no freq in use
  }
  
  pclose(fp);
  if (debug_mode) {
    printf("transmit time%llu\n", transmit_time);
  }
  if(!gzprintf(handle_counts,"wlan1|%llu|%llu|%llu|%llu\n",
	       transmit_time,receive_time,busy_time,active_time)){
    printf("error writing the zip file :from wlan0");
    exit(-1);
    //the command need not give output, hence nothing to be written, but still cannot return/exit
  }

  return 0;
}
 

#if 1
/* This function was called from the signal handler.
   It was later commented out to reduce the data collection volume.
 */
int scanning(){
  gzFile handle_counts = gzopen(PENDING_UPDATE_COUNTS_FILENAME, "wb");
  if (!handle_counts) {
    perror("Could not open update count file for writing\n");
    exit(EXIT_FAILURE);
  }
  printf("printing things required in scanning \n");
  if (!gzprintf(handle_counts,"%s %" PRId64 " %d %" PRId64 "\n",bismark_id,\
		start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp)) {
    perror("Error writing client update\n");
    exit(EXIT_FAILURE);
  }
  
  FILE *fp=NULL;
  char path[1024];

  char station[20];
  int r=0;
  unsigned int rx_bytes=0;   unsigned int rx_packets=0;
  unsigned int tx_bytes=0;   unsigned int tx_packets=0;
  unsigned int tx_retries =0;
  unsigned int tx_failed=0;
  
  // Open the command for reading. 
  fp = popen("iw wlan0 station dump", "r");
  if (fp == NULL) {
    perror("Failed to run wlan0 station dump command\n" );
    return -1;
  }
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    if (strncmp(path, "Station",7) == 0) {
      sscanf (path, "Station %s (on wlan0)",station );
    }
    if (strncmp(path, "\trx bytes:",7) == 0) {
      sscanf (path, "\trx bytes:%u ",&rx_bytes );
    }
    if (strncmp(path, "\trx packets:", 8) == 0) {
      sscanf (path,  "\trx packets:%u ",&rx_packets );
    }
    
    if (strncmp(path, "\ttx bytes:",7) == 0) {
      sscanf (path, "\ttx bytes:%u ",&tx_bytes );
    }
    
    if (strncmp(path, "\ttx packets:", 8) == 0) {
      sscanf (path,  "\ttx packets:%u ",&tx_packets );
    }
    if (strncmp(path, "\ttx retries:", 8) == 0) {
      sscanf (path,  "\ttx retries:%u ",&tx_retries);
    }
    if (strncmp(path, "\ttx failed:", 8) == 0) {
      sscanf (path,  "\ttx failed:%u ",&tx_failed );
    }
    
    if (strncmp(path, "\trx bytes:",7) == 0) {
      sscanf (path, "\trx bytes:%u ",&rx_bytes );
    }
    if (strncmp(path, "\trx packets:", 8) == 0) {
      sscanf (path,  "\trx packets:%u ",&rx_packets );
    }

    if (strncmp(path, "\ttx bytes:",7) == 0) {
      sscanf (path, "\ttx bytes:%u ",&tx_bytes );
    }

    if (strncmp(path, "\ttx packets:", 8) == 0) {
      sscanf (path,  "\ttx packets:%u ",&tx_packets );
    }
    if (strncmp(path, "\ttx retries:", 8) == 0) {
      sscanf (path,  "\ttx retries:%u ",&tx_retries);
    }
    if (strncmp(path, "\ttx failed:", 8) == 0) {
      sscanf (path,  "\ttx failed:%u ",&tx_failed );
    }
    
    if(r%11==0 && r!=0){
      if (debug_mode) {
	printf("wlan0: %s|%u|%u|%u|%u|%u|%u\n",
	       station,
	       rx_packets,rx_bytes,tx_packets,
	       tx_bytes,tx_retries,tx_failed);
      }
      uint8_t digest_mac[ETH_ALEN];
     /* if(anonymize_mac(station, digest_mac)) {
	fprintf(stderr, "Error anonymizing MAC mapping\n");
	return -1;
      } 
      */    
      if(!gzprintf(handle_counts,"%s|%u|%u|%u|%u|%u|%u|\n",
		   digest_mac,rx_packets,rx_bytes ,
		   tx_packets,tx_bytes,tx_retries,
		   tx_failed)) {
	printf("error writing the zip file :from wlan0");
	exit(EXIT_FAILURE);
	//the command need not give output, hence nothing to be written, but still cannot return/exit
      }      
    }
    r++;
  }  
  pclose(fp);  
  if(!gzprintf(handle_counts,"%s\n","$$ " )) {
    printf("error writing the zip file :wlan0 data over\n");
    //the command need not give output, hence  nothing to be written, but still cannot return/exit
  }
  //-------------------
  
  r=0;
  fp=NULL;
  
  fp = popen("iw wlan1 station dump", "r");
  if (fp == NULL) {
    perror("Failed on wlan1 command\n" );
    exit(EXIT_FAILURE);
  }
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    if (strncmp(path, "Station",7) == 0) {
      sscanf (path, "Station %s (on wlan0)",station );
    }
    if (strncmp(path, "\trx bytes:",7) == 0) {
      sscanf (path, "\trx bytes:%u ",&rx_bytes );
    }
    if (strncmp(path, "\trx packets:", 8) == 0) {
      sscanf (path,  "\trx packets:%u ",&rx_packets );
    }

    if (strncmp(path, "\ttx bytes:",7) == 0) {
      sscanf (path, "\ttx bytes:%u ",&tx_bytes );
    }

    if (strncmp(path, "\ttx packets:", 8) == 0) {
      sscanf (path,  "\ttx packets:%u ",&tx_packets );
    }
    if (strncmp(path, "\ttx retries:", 8) == 0) {
      sscanf (path,  "\ttx retries:%u ",&tx_retries);
    }
    if (strncmp(path, "\ttx failed:", 8) == 0) {
      sscanf (path,  "\ttx failed:%u ",&tx_failed );
    }
    if(r%11==0 && r!=0){
      if (debug_mode) {
	printf("%s|%u|%u|%u|%u|%u|%u\n",
	       station,
	       rx_packets,rx_bytes,tx_packets,
	       tx_bytes,tx_retries,tx_failed);      
      }
      uint8_t digest_mac[ETH_ALEN];
      /*if(anonymize_mac(station, digest_mac)) {
	fprintf(stderr, "Error anonymizing MAC mapping\n");
	return -1;
      }*/
      
      if(!gzprintf(handle_counts,"%s|%u|%u|%u|%u|%u|%|n",
		   station,
		   rx_packets,rx_bytes,tx_packets,
		   tx_bytes,tx_retries,tx_failed)) {
	printf("error writing the zip file :from wlan0");
	exit(EXIT_FAILURE);
	//the command need not give output, hence nothing to be written, but still cannot return/exit
      }      
    }
    r++;
  }
  pclose(fp);
  //----
  if(!gzprintf(handle_counts,"%s\n","^^" )) {
    printf("error writing the zip file :end of set");
    //the command need not give output, hence  nothing to be written, but still cannot return/exit
  }
  
  fp=NULL;
  char p[5];
  int f; int g;
  int tp;
  p[0]='\0';
  static int first =1;
  if (first){
    printf("inside first \n");
    first=0;
    fp = popen("iwconfig wlan0", "r");
    if (fp == NULL) {
      perror("Failed to iwconfig wlan0 \n" );
      exit(EXIT_FAILURE);
    }
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
      if (strncmp(path, "wlan0",5) == 0) {
	sscanf (path, "wlan0\tIEEE 802.11%s  Mode:Master  Frequency:%d.%d GHz  Tx-Power=%d ",p,&f,&g,&tp);
      }
    }
    // printf("wlan0 p=%s f=%d g=%d tp=%d\n",p,f,g,tp);
    if(!gzprintf(handle_counts,"%s|%d|%d|%d\n",p,f,g,tp )) {
      printf("error writing iwconfig wlan0 demarcator\n");
    }
    pclose(fp);
    //-------
    
    if(!gzprintf(handle_counts,"%s\n","@@ " )) {
      printf("error writing iwconfig demarcator\n");
      //the command need not give output, hence  nothing to be written, but still cannot return/exit
    }
    
    fp=NULL;
    p[0]='\0';
    fp = popen("iwconfig wlan1", "r");
    if (fp == NULL) {
      perror("Failed to run iwconfig wlan1 \n" );
      exit(EXIT_FAILURE);
    }
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
      if (strncmp(path, "wlan1",5) == 0) {
	sscanf (path, "wlan1\tIEEE 802.11%s  Mode:Master  Frequency:%d.%d GHz  Tx-Power=%d ",p,&f,&g,&tp);
      }
    }
    //  printf("iwconfig: wlan1 : p=%s f=%d g=%d tp=%d\n",p,f,g,tp); 
    
    if(!gzprintf(handle_counts,"%s|%d|%d|%d\n",p,f,g,tp )) {
      printf("error writing iwconfig wlan1\n");
    }
    pclose(fp);
    
    if(!gzprintf(handle_counts,"%s\n","^^" )) {
      printf("error writing demarcator end of iwconfig");
    //the command need not give output, hence  nothing to be written, but still cannot return/exit
    }
  }
  printf("going to survey stats \n");
  // To write survey dump stats
  survey_stats(handle_counts);
  gzclose(handle_counts);
  char update_filename_for_counts[FILENAME_MAX];
  snprintf(update_filename_for_counts,FILENAME_MAX,UPDATE_FILENAME_COUNTS,bismark_id,start_timestamp_microseconds,sequence_number);
  if (rename(PENDING_UPDATE_COUNTS_FILENAME, update_filename_for_counts)) {
    perror("Could not stage update for counts");
    exit(EXIT_FAILURE);
  }
  
  return 0;
}
#endif
