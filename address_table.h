#ifndef _ADDRESS_TABLE_T
#define _ADDRESS_TABLE_T

#define MAC_TABLE_MGT_BEACON_ENTRIES 512
#define MAC_TABLE_MGT_COMMON_ENTRIES 2048
#define MAC_TABLE_DATA_ENTRIES 8192
#define MAC_TABLE_CTL_ENTRIES 8192
#define MAC_TABLE_ENTRIES 32

#define MAC_TABLE_MGT_ERR_ENTRIES 2048
#define MAC_TABLE_DATA_ERR_ENTRIES 4096
#define MAC_TABLE_CTL_ERR_ENTRIES 2048

#define UPDATE_FILENAME_DIGEST "/tmp/bismark-uploads/mac-analyzer/%s-%" PRIu64 "-digest-%d.gz"
#define UPDATE_MGMT_FILENAME    "/tmp/bismark-uploads/mac-analyzer/%s-%" PRIu64 "-m-%d-%c.gz"
#define UPDATE_CONTROL_FILENAME "/tmp/bismark-uploads/mac-analyzer/%s-%" PRIu64 "-c-%d-%c.gz"
#define UPDATE_DATA_FILENAME    "/tmp/bismark-uploads/mac-analyzer/%s-%" PRIu64 "-d-%d-%c.gz"

#define UPDATE_FILENAME_COUNTS "/tmp/bismark-uploads/mac-analyzer/%s-%" PRIu64 "-co-%d.gz"

#define PENDING_UPDATE_MGMT_FILENAME "/tmp/mac-analyzer/current-mgmt-update-%c.gz"
#define PENDING_UPDATE_CONTROL_FILENAME "/tmp/mac-analyzer/current-control-update-%c.gz"
#define PENDING_UPDATE_DATA_FILENAME "/tmp/mac-analyzer/current-data-update-%c.gz"
#define PENDING_UPDATE_FILENAME_DIGEST "/tmp/mac-analyzer/current-digest-update-%c.gz"

#define PENDING_UPDATE_COUNTS_FILENAME "/tmp/mac-analyzer/current-count-update.gz"

#include <zlib.h>

typedef struct {
  unsigned char mgt_content[HOMESAW_RX_FRAME_HEADER + sizeof( struct mgmt_beacon_layer_header)];
} mgmt_beacon_address_table_entry_t;

typedef struct {
  unsigned char mgt_content[HOMESAW_RX_FRAME_HEADER + sizeof( struct mgmt_layer_err_header)];
} mgmt_common_address_table_entry_t;

typedef struct {
  unsigned char mgt_err_content[HOMESAW_RX_FRAME_HEADER +sizeof(struct mgmt_layer_err_header)];
} mgmt_address_err_table_entry_t;

typedef struct {
  unsigned char ctl_content[HOMESAW_RX_FRAME_HEADER +sizeof(struct control_layer_header )];
} control_address_table_entry_t;

typedef struct {
  unsigned char ctl_err_content[HOMESAW_RX_FRAME_HEADER +sizeof(struct control_layer_header )];
} control_address_err_table_entry_t;

typedef struct {
  unsigned char data_content[HOMESAW_RX_FRAME_HEADER +sizeof(struct data_layer_header)];
} data_address_table_entry_t;

typedef struct {
  unsigned char data_err_content[HOMESAW_RX_FRAME_HEADER +sizeof(struct data_layer_err_header )];
} data_address_err_table_entry_t;

typedef struct {
  data_address_table_entry_t entries[MAC_TABLE_DATA_ENTRIES];
  u_int16_t length;	
	u_int32_t missed ;
} data_address_table_t;

typedef struct {
  mgmt_beacon_address_table_entry_t entries[MAC_TABLE_MGT_BEACON_ENTRIES];
  u_int16_t length;	
	u_int32_t missed ;
} mgmt_beacon_address_table_t;

typedef struct {
  mgmt_common_address_table_entry_t entries[MAC_TABLE_MGT_COMMON_ENTRIES];
  u_int16_t length;	
	u_int32_t missed ;
} mgmt_common_address_table_t;

typedef struct {
  control_address_table_entry_t entries[MAC_TABLE_CTL_ENTRIES];
  u_int16_t length;	
	u_int32_t missed ;
} control_address_table_t;

typedef struct {
  data_address_err_table_entry_t entries[MAC_TABLE_DATA_ERR_ENTRIES];
  u_int16_t length;	
	u_int32_t missed ;
} data_address_err_table_t;

typedef struct {
  mgmt_address_err_table_entry_t entries[MAC_TABLE_MGT_ERR_ENTRIES];
  u_int16_t length;
	u_int32_t missed ;
} mgmt_address_err_table_t;

typedef struct {
  control_address_err_table_entry_t entries[MAC_TABLE_CTL_ERR_ENTRIES];
  u_int16_t length;
	u_int32_t missed ;
} control_address_err_table_t;

extern struct control_layer_header* c  ; 
extern struct data_layer_header* d  ; 
extern struct mgmt_beacon_layer_header* mb ;
extern struct mgmt_layer_err_header* ml; 


extern mgmt_common_address_table_t mgmt_common_address_table;
extern mgmt_beacon_address_table_t mgmt_beacon_address_table;
extern mgmt_address_err_table_t mgmt_address_table_err;


void address_mgmt_beacon_table_init(mgmt_beacon_address_table_t* table);
void address_mgmt_common_table_init(mgmt_common_address_table_t* table);
void address_mgmt_err_table_init(mgmt_address_err_table_t* table);

int address_mgmt_beacon_table_update(mgmt_beacon_address_table_t* table,
				     unsigned char* pkt,
				     struct mgmt_beacon_layer_header* mlh);

int address_mgmt_common_table_update(mgmt_common_address_table_t* table,
				     unsigned char* pkt,
				     struct mgmt_layer_err_header* mlh); 

int address_mgmt_err_table_update(mgmt_address_err_table_t *table,
				  unsigned char* pkt,
				  struct mgmt_layer_err_header *mlh);

int  address_mgmt_table_write_update(mgmt_common_address_table_t *mgmt_common_address_table,
				     mgmt_beacon_address_table_t *mgmt_beacon_address_table,
				     mgmt_address_err_table_t *mgmt_address_table_err,
				     gzFile mgmt_handle);

extern data_address_table_t data_address_table;
extern data_address_err_table_t data_address_table_err;

void address_data_table_init(data_address_table_t* table);
void address_data_err_table_init(data_address_err_table_t* table);

int address_data_table_update(data_address_table_t* table,
			      unsigned char* pkt,
			      struct data_layer_header* dlh,
			      int path_type,
			      int is_more );
int address_data_err_table_update(data_address_err_table_t* table,
				  unsigned char* pkt,
				  struct data_layer_err_header * dlh );

int  address_data_table_write_update(data_address_table_t* data_address_table,
				     data_address_err_table_t * data_address_table_err,
				     gzFile  data_handle);

extern control_address_table_t control_address_table;
extern control_address_err_table_t control_address_table_err;

void address_control_table_init(control_address_table_t* table);
void address_control_err_table_init(control_address_err_table_t* table);

int address_control_table_update(control_address_table_t *table, 
				 unsigned char* pkt,
				 struct control_layer_header *clh);
int address_control_err_table_update(control_address_err_table_t *table, 
				     unsigned char* pkt,
				     struct control_layer_header *clh);

int  address_control_table_write_update(control_address_table_t *control_address_table,
					control_address_err_table_t * control_address_table_err,
					gzFile control_handle);

/* A mapping from IP address to MAC address. */
typedef struct {
  uint8_t hashed_mac_address[ETH_ALEN];  /* In host byte order. */
  uint8_t mac_address[ETH_ALEN];
} address_table_entry_t;

typedef struct {         
  /* A list of MAC mappings. A mapping ID is simply
   * that mapping's index offset into this array. */
  address_table_entry_t entries[MAC_TABLE_ENTRIES];
  int first;
  int last;
  int length;
  int added_since_last_update;
} mac_address_table_t;
void mac_address_table_init(mac_address_table_t*  table);
      
u_int8_t* mac_address_table_lookup(mac_address_table_t* table, uint8_t mac[ETH_ALEN]);

extern mac_address_table_t devices ;
extern mac_address_table_t access_point_mac_address_table ;
extern mac_address_table_t device_mac_address_table;


int mac_address_map(mac_address_table_t* devices,u_char* mac_addr);
u_char * connected_device_address_table_insert(mac_address_table_t * table,u_char *mac);
u_char * connected_device_address_table_lookup(mac_address_table_t * table,u_char *mac);

#ifdef TRANSPORT_LAYER_CAPTURE
typedef struct {
  uint32_t ip_address;  /* In host byte order. */
  uint32_t hashed_ip_address;  /* In host byte order. */
} ip_address_table_entry_t;

typedef struct {
  ip_address_table_entry_t entries[MAC_TABLE_ENTRIES];
  int first;
  int last;
  int length;
  int added_since_last_update;
} ip_address_table_t;

void address_table_init(ip_address_table_t* const table);

int address_table_lookup(ip_address_table_t* const table, 
                         const uint32_t ip_address,
                         const uint32_t hashed_ip_address);
#endif

#endif /*ADDRESS_TABLE_H*/
