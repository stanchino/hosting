#if !defined(APU_HAS_LDAP) && !defined(APR_HAS_LDAP)
#error mod_config_ldap requires APR-util to have LDAP support built in
#endif

// Error Codes

#define CONFIG_LDAP_OK             0
#define CONFIG_LDAP_ERROR          1

// Constance, but not prudence

#define CONFIG_LDAP_SECTION_OBJ    "ApacheSectionObj"
#define CONFIG_LDAP_SECTION_NAME   "ApacheSectionName"
#define CONFIG_LDAP_SECTION_ARG    "ApacheSectionArg"
#define CONFIG_LDAP_DEFAULT_FILTER "ApacheConfigObj"

#define CONFIG_LDAP_PREFIX         "Apache"
#define CONFIG_LDAP_PREFIX_LENGTH  6
#define CONFIG_LDAP_TAB_LENGTH     4

// Debug Levels

#define CONFIG_LDAP_DEBUG_NONE         0
#define CONFIG_LDAP_DEBUG_CFG          1
#define CONFIG_LDAP_DEBUG_LINE         2
#define CONFIG_LDAP_DEBUG_SRCH         4
#define CONFIG_LDAP_DEBUG_CNXN         8
#define CONFIG_LDAP_DEBUG_SASL         16
#define CONFIG_LDAP_DEBUG_CMD          32
#define CONFIG_LDAP_DEBUG_FUNC         64
#define CONFIG_LDAP_DEBUG_TODO         128
#define CONFIG_LDAP_DEBUG_ALL         -1

// #define Debugging Routines

#define ERROR(text, args...) ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, \
        "[mod_config_ldap.c] %s(): " text "%s", \
        __FUNCTION__, ##args, "")

#define LDEBUG(level, text, args...) if (mcl_debug_level & (level)) { \
    if (CONFIG_LDAP_DEBUG_FUNC & (level)) { \
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, \
                "[mod_config_ldap.c] %s(): " text "%s", \
                __FUNCTION__, ##args, ""); \
    } else { \
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, \
                "[mod_config_ldap.c] " text "%s", \
##args, ""); \
    } \
}

#define LDEBUG_PLAIN(level, ... ) if (mcl_debug_level & (level)) { \
    fprintf(stderr, __VA_ARGS__ ); \
    fflush(stderr); \
}

/* Values that the deref member can have */
typedef enum {
    never=LDAP_DEREF_NEVER, 
    searching=LDAP_DEREF_SEARCHING, 
    finding=LDAP_DEREF_FINDING, 
    always=LDAP_DEREF_ALWAYS
} deref_options;

typedef struct mcl_config_t {
//    mcl_status_e enabled;			/* Is vhost_ldap enabled? */

    /* These parameters are all derived from the VhostLDAPURL directive */
    char *url;				/* String representation of LDAP URL */
    char *host;				/* Name of the LDAP server (or space separated list) */
    int port;				/* Port of the LDAP server */
    deref_options deref;	/* how to handle alias dereferening */
    char *binddn;			/* DN to bind to server (can be NULL) */
    char *bindpw;			/* Password to bind to server (can be NULL) */
    int secure;				/* True if SSL connections are requested */
    apr_array_header_t *certificates;  /* Global CA certificates */
    int   verify_server_cert;
    long  timeout;
    int    simple_bind;
    int    use_tls;
    int version;
    char *basedn;		    /* Base DN to do all searches from */
    int scope;			    /* Scope of the search */
    char *filter;		    /* Filter to further limit the search  */
    char **attr_list;
    int  follow_referrals; 
//    char * sasl_authc;
//    char * sasl_authz;
//    char * sasl_realm;
//    char * sasl_props;
//    char * sasl_mech;
//    int    kerberos_auth;
//    int    kerberos_onestep_auth;
    time_t time;
    time_t interval;
} mcl_config_t;

/*
 * mcl_recursive_args is used to hold a number of useful objects
 * and arguments.  Our call stack can be pretty deep and having to pass
 * all the various pieces of data down to that last stack is much
 * easier when it is all bundled up in one structure.
 *
 */

typedef struct 
{
    apr_pool_t *            mem_pool;
    LDAP *                  ldap_rec;
    char **                 attr_list;
    apr_array_header_t *    attr_ah;
    void *                  call_back_data;
    server_rec *            server;
} mcl_parms;

/*
 * mcl_dn_entry_struct is used to hold a single LDAPMessage record
 * as well as it's exploded DN and the number of DN components.
 * Additionally, it has fields for creating a linked list of entries,
 * for use in <Section> management.
 *
 */
struct mcl_dn_entry_struct
{
    char ** ex_dn;
    int dn_count;
    LDAPMessage * msg;
    struct mcl_dn_entry_struct * prev;
    char * section_name;
};

typedef struct mcl_dn_entry_struct mcl_dn_entry;

/*
 * mcl_config_stack is used to create a virtual config file by
 * holding a list of all configuration directives be sent to Apache.
 * These directives will the be read of by ap_srm_command_loop()
 *
 */
typedef struct
{
    // This array will contain (char *) of all the configuration
    // directives we pull from LDAP and will pass to Apache to load
    // <Section> stack management
    apr_array_header_t *        config_ah;
    int                         index;
    mcl_dn_entry * section_stack;
    int                        section_depth;
} mcl_config_stack;

/*
 * Debug level
 *
 */
int mcl_debug_level = 0;

/*
 * The following variables are used to store the search stack
 *
 */
apr_pool_t              * mcl_attr_stack_pool = NULL;
apr_array_header_t      * mcl_attr_stack_ah = NULL;

/*
 * Global module config
 *
 */

mcl_config_t * scfg = NULL;

/*
 * Default cmd_params
 *
 */

static cmd_parms default_parms =
{NULL, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

/*
 *
 * Function Declarations
 *
 */

/*
 *
 * Utility Functions
 *
 */  

static mcl_config_t* mcl_util_get_module_config(cmd_parms * cmd);
void mcl_util_print_offset(int depth, int debug_level);
char * mcl_util_array_pstrcat(apr_pool_t * p, apr_array_header_t * ah);
static const char * mcl_util_parse_url(apr_pool_t *pool, mcl_config_t *conf, const char *url);
static int mcl_util_parse_cert_type(const char *type);
int mcl_util_search_ldap(LDAP *ldc, mcl_config_t *ldap, LDAPMessage ** result);

/*
 *
 * LDAP Connection
 *
 */

static int mcl_connection_init(apr_pool_t *p, mcl_config_t *ldap, LDAP **ld);

/*
 *
 * LDAP Search
 *
 */
int mcl_load(mcl_parms * args, LDAPMessage * res);
int mcl_search(apr_pool_t *p, server_rec *s);
int mcl_sort_entries(apr_pool_t * p, LDAP * ld, LDAPMessage * msg, mcl_dn_entry ** entries_ptr);
int mcl_reverse_dn_cmp(const void * a, const void *b);
int mcl_handle_config_obj(mcl_parms * args, mcl_dn_entry * entry);
int mcl_handle_section_obj(mcl_parms * args, mcl_dn_entry * entry);
int mcl_check_command(const char *cmd);
int mcl_handle_plain_obj(mcl_parms * args, mcl_dn_entry * entry, int section_check);
int mcl_handle_command(mcl_parms * args, const char * config_string);
int mcl_build_config(mcl_parms * args, server_rec *s);
static void * mcl_ah_getstr(char * buf, size_t bufsiz, void * param);

/*
 *
 * Configuration processing support routines
 *
 */

int mcl_is_section_obj(LDAP * ld, LDAPMessage * entry);
int mcl_check_section_stack(mcl_parms * args, mcl_dn_entry * entry);
int mcl_is_sub_dn(mcl_dn_entry * parent, mcl_dn_entry * child);
int mcl_is_apache_dir(const char * dir);
int mcl_is_raw_arg(const char * dir);
int mcl_is_section_attr(const char * dir);

/*
 *
 * Apache module interface specific functions
 *
 */

static void * mcl_create_server_config(apr_pool_t * p, server_rec * s);
static int mcl_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp);
static int mcl_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static int mcl_monitor(apr_pool_t *p);

/*
 *
 * Apache 'ConfigLDAP_*' Commands processing routines
 *
 */

static const char *mcl_set_debug(cmd_parms * cmd, void * mconfig, const char * level);
static const char *mcl_set_url(cmd_parms *cmd, void *mconfig, const char *url);
static const char *mcl_set_binddn(cmd_parms *cmd, void *mconfig, const char *binddn);
static const char *mcl_set_bindpw(cmd_parms *cmd, void *mconfig, const char *bindpw);
static const char *mcl_set_certificates(cmd_parms *cmd, void *mconfig, const char *type, const char *file, const char *password);
static const char *mcl_set_verify_server_cert(cmd_parms *cmd, void *mconfig, int mode);
static const char *mcl_set_connection_timeout(cmd_parms *cmd, void *mconfig, const char *ttl);
static const char *mcl_set_deref(cmd_parms *cmd, void *mconfig, const char *deref);
