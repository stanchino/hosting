#define CORE_PRIVATE

#include "unistd.h"
#include "ctype.h"

#include "httpd.h"
#include "http_log.h"
#include "http_config.h"
#include "http_core.h"
#include "http_vhost.h"
#include "http_request.h"
#include "apr_version.h"
#include "apr_ldap.h"
#include "apr_strings.h"
#include "apr_reslist.h"
#include "mpm_common.h"

#include "mod_config_ldap.h"

module AP_MODULE_DECLARE_DATA config_ldap_module;

/*
 *
 * Utility Functions
 *
 */  

/* 
 * mcl_util_get_module_config()
 *
 * Helper function that returns the module configuration structure
 *
 */

static mcl_config_t* mcl_util_get_module_config( cmd_parms * cmd )
{
    server_rec * s = cmd->server;

    return (mcl_config_t *) ap_get_module_config(s->module_config, &config_ldap_module);
}

/*
 * mcl_util_print_offset()
 *
 * This function will print 'depth' number of spaces using
 * 'debug_level' as the debug level to LDEBUG
 *
 */

void mcl_util_print_offset( int depth, int debug_level )
{
    int index = 0;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    for( ; index < depth; index++ )
    {
        LDEBUG_PLAIN(debug_level, " ");
    }
}

/*
 * mcl_util_array_pstrcat()
 *
 * Kind of a replacement for ap_array_pstrcat().  The basic idea is,
 * given an array of (char *) strings, to concatenate them into a full
 * string.  However, ap_array_pstrcat() wants you to put some text in
 * between each element.  I don't want ANY text, so I wrote my own
 * version.  It just concatentates everything together.
 *
 */

char * mcl_util_array_pstrcat(
        apr_pool_t * p,
        apr_array_header_t * ah )
{
    char * final, ** elts;
    int index = 0;
    int length = 0;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    if( ah->nelts <= 0 || ah->elts == NULL )
    {
        return NULL;
    }

    elts = (char **) ah->elts;

    for( ; index < ah->nelts; index++ )
    {
        char * element;
        element = elts[ index ];
        if( element != NULL )
        {
            length += strlen( element );
        }
    }

    final = apr_pcalloc( p, sizeof( char ) * ( length + 1 ) );
    length = 0;

    for( index = 0; index < ah->nelts; index++ )
    {
        char * element = elts[ index ];
        int sub_len = 0;
        int sub_index = 0;

        if( element != NULL )
        {
            sub_len = strlen( element );
        }

        for( ; sub_index < sub_len; sub_index++ )
        {
            final[ length ] = element[ sub_index ];
            length++;
        }
    }

    return final;
}

/*
 * mcl_util_parse_url()
 *
 * Parses a ldap url string to a mcl_config_t structure
 * that will be used for connecting to the ldap database
 * and searching for values
 *
 */

static const char * mcl_util_parse_url(apr_pool_t *pool, mcl_config_t *conf, const char *url)
{
    int result;
    apr_ldap_url_desc_t *urld;
#if (APR_MAJOR_VERSION >= 1)
    apr_ldap_err_t *result_err;
#endif

    LDEBUG(CONFIG_LDAP_DEBUG_CMD, "parsing url: %s", url);

#if (APR_MAJOR_VERSION >= 1)    /* for apache >= 2.2 */
    result = apr_ldap_url_parse(pool, url, &(urld), &(result_err));
    if (result != LDAP_SUCCESS) {
        return result_err->reason;
    }
#else
    result = apr_ldap_url_parse(url, &(urld));
    if (result != LDAP_SUCCESS) {
        switch (result) {
            case LDAP_URL_ERR_NOTLDAP:
                return "LDAP URL does not begin with ldap://";
            case LDAP_URL_ERR_NODN:
                return "LDAP URL does not have a DN";
            case LDAP_URL_ERR_BADSCOPE:
                return "LDAP URL has an invalid scope";
            case LDAP_URL_ERR_MEM:
                return "Out of memory parsing LDAP URL";
            default:
                return "Could not parse LDAP URL";
        }
    }
#endif
    conf->url = apr_pstrdup(pool, url);

    if (mcl_debug_level & CONFIG_LDAP_DEBUG_CMD) {
        LDEBUG(CONFIG_LDAP_DEBUG_CMD, "url parse: host: %s", urld->lud_host);
        LDEBUG(CONFIG_LDAP_DEBUG_CMD, "url parse: port: %d", urld->lud_port);
        LDEBUG(CONFIG_LDAP_DEBUG_CMD, "url parse: dn: %s", urld->lud_dn);
        LDEBUG(CONFIG_LDAP_DEBUG_CMD, "url parse: attrib: %s", urld->lud_attrs ? urld->lud_attrs[0] : "(null)");
        LDEBUG(CONFIG_LDAP_DEBUG_CMD, "url parse: scope: %s", (urld->lud_scope == LDAP_SCOPE_SUBTREE? "subtree" : 
                    urld->lud_scope == LDAP_SCOPE_BASE? "base" : 
                    urld->lud_scope == LDAP_SCOPE_ONELEVEL? "onelevel" : "unknown"));
        LDEBUG(CONFIG_LDAP_DEBUG_CMD, "url parse: filter: %s", urld->lud_filter);

    }
    /* Set all the values, or at least some sane defaults */
    if (conf->host) 
    {
        char *p = apr_palloc(pool, strlen(conf->host) + strlen(urld->lud_host) + 2);
        strcpy(p, urld->lud_host);
        strcat(p, " ");
        strcat(p, conf->host);
        conf->host = p;
    }
    else 
    {
        conf->host = urld->lud_host ? apr_pstrdup(pool, urld->lud_host) : "localhost";
    }
    conf->basedn = urld->lud_dn ? apr_pstrdup(pool, urld->lud_dn) : "";

    conf->scope = urld->lud_scope == LDAP_SCOPE_ONELEVEL ?
        LDAP_SCOPE_ONELEVEL : LDAP_SCOPE_SUBTREE;

    if (urld->lud_filter) 
    {
        conf->filter = apr_pstrdup(pool, urld->lud_filter);
    }
    else 
    {
        conf->filter = apr_psprintf(pool, "(objectClass=%s)", CONFIG_LDAP_DEFAULT_FILTER);
    }

    /* "ldaps" indicates secure ldap connections desired
     */
    if (strncasecmp(url, "ldaps", 5) == 0)
    {
        conf->secure = APR_LDAP_SSL;
        conf->port = urld->lud_port ? urld->lud_port : LDAPS_PORT;
        LDEBUG(CONFIG_LDAP_DEBUG_CMD, "using SSL connections");
    }
    else
    {
        conf->secure = APR_LDAP_NONE;
        conf->port = urld->lud_port ? urld->lud_port : LDAP_PORT;
        LDEBUG(CONFIG_LDAP_DEBUG_CMD, "not using SSL connections");
    }

#if (APR_MAJOR_VERSION < 1) /* free only required for older apr */
    apr_ldap_free_urldesc(urld);
#endif

    conf->version = 3;
    conf->simple_bind = 1;

    return NULL;
}

/**
 * mcl_util_parse_cert_type()
 *
 * Parse the certificate type.
 *
 * The type can be one of the following:
 * CA_DER, CA_BASE64, CA_CERT7_DB, CA_SECMOD, CERT_DER, CERT_BASE64,
 * CERT_KEY3_DB, CERT_NICKNAME, KEY_DER, KEY_BASE64
 *
 * If no matches are found, APR_LDAP_CA_TYPE_UNKNOWN is returned.
 */

static int mcl_util_parse_cert_type(const char *type)
{
    /* Authority file in binary DER format */
    if (0 == strcasecmp("CA_DER", type)) {
        return APR_LDAP_CA_TYPE_DER;
    }

    /* Authority file in Base64 format */
    else if (0 == strcasecmp("CA_BASE64", type)) {
        return APR_LDAP_CA_TYPE_BASE64;
    }

    /* Netscape certificate database file/directory */
    else if (0 == strcasecmp("CA_CERT7_DB", type)) {
        return APR_LDAP_CA_TYPE_CERT7_DB;
    }

    /* Netscape secmod file/directory */
    else if (0 == strcasecmp("CA_SECMOD", type)) {
        return APR_LDAP_CA_TYPE_SECMOD;
    }

    /* Client cert file in DER format */
    else if (0 == strcasecmp("CERT_DER", type)) {
        return APR_LDAP_CERT_TYPE_DER;
    }

    /* Client cert file in Base64 format */
    else if (0 == strcasecmp("CERT_BASE64", type)) {
        return APR_LDAP_CERT_TYPE_BASE64;
    }

    /* Client cert file in PKCS#12 format */
    else if (0 == strcasecmp("CERT_PFX", type)) {
        return APR_LDAP_CERT_TYPE_PFX;
    }

    /* Netscape client cert database file/directory */
    else if (0 == strcasecmp("CERT_KEY3_DB", type)) {
        return APR_LDAP_CERT_TYPE_KEY3_DB;
    }

    /* Netscape client cert nickname */
    else if (0 == strcasecmp("CERT_NICKNAME", type)) {
        return APR_LDAP_CERT_TYPE_NICKNAME;
    }

    /* Client cert key file in DER format */
    else if (0 == strcasecmp("KEY_DER", type)) {
        return APR_LDAP_KEY_TYPE_DER;
    }

    /* Client cert key file in Base64 format */
    else if (0 == strcasecmp("KEY_BASE64", type)) {
        return APR_LDAP_KEY_TYPE_BASE64;
    }

    /* Client cert key file in PKCS#12 format */
    else if (0 == strcasecmp("KEY_PFX", type)) {
        return APR_LDAP_KEY_TYPE_PFX;
    }

    else {
        return APR_LDAP_CA_TYPE_UNKNOWN;
    }

}

/*
 * mcl_util_search_ldap()
 *
 * Searches the LDAP database
 *
 */

int mcl_util_search_ldap(
        LDAP *ldc,
        mcl_config_t *conf,
        LDAPMessage ** result)
{
    int search_status;
    struct timeval timeout = {10,0};    /* 10 second default */
    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");
    
    search_status = ldap_search_ext_s(
                ldc,                // LDAP object
                conf->basedn,       // Base DN to search against
                conf->scope,        // Scope of search: LDAP_SCOPE_*
                conf->filter,       // Filter
                conf->attr_list,    // List of attrs to return.
                                    // Returns all of them if
                                    // NULL
                0,                  // We don't want Attribute Names only
                NULL,               // LDAPControl **serverctrls
                NULL,               // LDAPControl **clientctrls
                &timeout,               // struct timeval *timeout
                0,                  // int sizelimit
                result);
    if (search_status != LDAP_SUCCESS )
    {
        ERROR("LDAP search failed: %s", ldap_err2string(search_status));
        LDEBUG(CONFIG_LDAP_DEBUG_CNXN, "Unbinding LDAP connection");
        ldap_unbind_ext( ldc, 0, 0 );
        return CONFIG_LDAP_ERROR;
    }

    return CONFIG_LDAP_OK;
}

/*
 *
 * LDAP Connection
 *
 */

/*
 * mcl_connection_init()
 *
 * Initialize LDAP connection and bind to the server
 *
 */

static int mcl_connection_init(
        apr_pool_t *p,
        mcl_config_t *conf,
        LDAP **ldc)
{
    apr_ldap_err_t *result = apr_palloc(p, sizeof (apr_ldap_err_t));
    /*
    int auth_method;
    */
    int bind_status;
    struct timeval timeout = {10,0};    /* 10 second connection timeout */
    struct berval userpw;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    if (conf->secure != APR_LDAP_NONE) { 
        LDEBUG(CONFIG_LDAP_DEBUG_CFG|CONFIG_LDAP_DEBUG_FUNC, "Setting global certificates");
        if ( APR_SUCCESS != apr_ldap_ssl_init(p, NULL, 0, &(result)) 
                || APR_SUCCESS != apr_ldap_set_option(p, NULL, APR_LDAP_OPT_TLS_CERT,
                    (void *) conf->certificates, &(result)) 
           ) {
            ERROR("Unable to initialize SSL connection");
            return CONFIG_LDAP_ERROR;
        }
    }

    apr_ldap_init(p, ldc, conf->host, conf->port, conf->secure, &result);

    if (NULL == result) {
        ERROR("LDAP: ldap initialization failed");
        return CONFIG_LDAP_ERROR;
    }

    if (result->rc != LDAP_SUCCESS) {
        ERROR("Unable to initialize LDAP connection: %s", result->reason);
        return CONFIG_LDAP_ERROR;
    }

/*XXX All of the #ifdef's need to be removed once apr-util 1.2 is released */
#ifdef APR_LDAP_OPT_VERIFY_CERT
    apr_ldap_set_option(p, *ldc,
                        APR_LDAP_OPT_VERIFY_CERT, &(conf->verify_server_cert), &(result));
#else
#if defined(LDAPSSL_VERIFY_SERVER)
    if (conf->verify_server_cert) {
        result->rc = ldapssl_set_verify_mode(LDAPSSL_VERIFY_SERVER);
    }
    else {
        result->rc = ldapssl_set_verify_mode(LDAPSSL_VERIFY_NONE);
    }
#elif defined(LDAP_OPT_X_TLS_REQUIRE_CERT)
    /* This is not a per-connection setting so just pass NULL for the
       Ldap connection handle */
    if (conf->verify_server_cert) {
        int i = LDAP_OPT_X_TLS_DEMAND;
        result->rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &i);
    }
    else {
        int i = LDAP_OPT_X_TLS_NEVER;
        result->rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &i);
    }
#endif
#endif

#ifdef LDAP_OPT_NETWORK_TIMEOUT
    if (conf->timeout > 0) {
        timeout.tv_sec = conf->timeout;
    }

    if (conf->timeout >= 0) {
        if (APR_SUCCESS != apr_ldap_set_option(
                    p, 
                    *ldc, 
                    LDAP_OPT_NETWORK_TIMEOUT,
                    (void *)&timeout, 
                    &(result))) {
            ERROR("LDAP: Could not set the connection timeout");
            return CONFIG_LDAP_ERROR;
        }
    }
#endif

    LDEBUG(CONFIG_LDAP_DEBUG_TODO, "apr_ldap_set_option(p, *ldc, LDAP_OPT_PROTOCOL_VERSION, %d, &result )",
            conf->version );
    if( apr_ldap_set_option(p, *ldc, LDAP_OPT_PROTOCOL_VERSION, &conf->version, &result )
            != LDAP_OPT_SUCCESS )
    {
        ERROR( "Could not set LDAP_OPT_PROTOCOL_VERSION %d", conf->version );
        return CONFIG_LDAP_ERROR;
    }

    LDEBUG(CONFIG_LDAP_DEBUG_TODO, "apr_ldap_set_option(p, *ldc, LDAP_OPT_REFERRALS, follow => %d, &result )",
            conf->follow_referrals );
    if( apr_ldap_set_option( 
                p,
                *ldc,
                LDAP_OPT_REFERRALS,
                conf->follow_referrals ?
                LDAP_OPT_ON :
                LDAP_OPT_OFF,
                &result ) != LDAP_OPT_SUCCESS)

    {
        ERROR( "Could not set LDAP_OPT_REFERRALS" );
        return CONFIG_LDAP_ERROR;
    }

    LDEBUG(CONFIG_LDAP_DEBUG_TODO, "apr_ldap_set_option(p, *ldc, LDAP_OPT_DEREF, %d, &result )",
            conf->deref );
    if( apr_ldap_set_option( p, *ldc, LDAP_OPT_DEREF, &conf->deref, &result)
            != LDAP_OPT_SUCCESS )
    {
        ERROR( "Could not set LDAP_OPT_DEREF" );
        return CONFIG_LDAP_ERROR;
    }

    userpw.bv_val = conf->bindpw;
    userpw.bv_len = (userpw.bv_val != 0) ? strlen (userpw.bv_val) : 0;

    if (LDAP_SUCCESS != (bind_status = ldap_sasl_bind_s (
                *ldc, conf->binddn, NULL,
                &userpw, NULL, 0, NULL)))
    {
        ERROR("Unable to execute ldap_sasl_bind: %s", ldap_err2string(bind_status));
        return CONFIG_LDAP_ERROR;
    }

     return CONFIG_LDAP_OK;
}

/*
 *
 * LDAP Search
 *
 */

/*
 * mcl_load()
 *
 *
 * This results processing call-back handles a result set created by
 * the 'LDAPCfg_Load' command.  It sorts the results by reverse-DN and
 * then sends on any Apache configuration directives it finds.
 *
 */

int mcl_load (
        mcl_parms * args,
        LDAPMessage * res )
{
    mcl_dn_entry * entries;
    mcl_config_stack * config_stack;
    int count, index;


    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    // If this is our first time through, we need to initialize our
    // data structures
    if( args->call_back_data == NULL )
    {
        LDEBUG(CONFIG_LDAP_DEBUG_TODO, "Preparing config stack");
        args->call_back_data = apr_pcalloc( args->mem_pool,
                sizeof( mcl_config_stack ) );
        config_stack = args->call_back_data;
        config_stack->config_ah = apr_array_make( args->mem_pool,
                4,
                sizeof( char * ) );
        config_stack->index = 0;
    }

    // Reset <Section> stack portion of config stack before starting
    config_stack = args->call_back_data;
    config_stack->section_stack = NULL;
    config_stack->section_depth = 0;

    count = mcl_sort_entries( args->mem_pool,
            args->ldap_rec,
            res,
            & entries );

    for( index = 0; index < count; index ++ )
    {
        LDAPMessage * msg = entries[ index ].msg;
        char * dn;

        dn = ldap_get_dn( args->ldap_rec, msg );
        LDEBUG(CONFIG_LDAP_DEBUG_SRCH, "dn: %s", dn );
        ldap_memfree( dn );

        if( mcl_handle_config_obj( args, & entries[ index ] ) )
        {
            return CONFIG_LDAP_ERROR;
        }
    }

    return mcl_check_section_stack( args, NULL );
}

/*
 * mcl_search()
 *
 * Initializes LDAP connection and searches the database
 * for apache directives to be added to the configuration
 *
 */

int mcl_search(
        apr_pool_t *p,
        server_rec *s)
{
    LDAPMessage * res;
    mcl_parms * args = apr_pcalloc(p, sizeof(mcl_parms));

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");
    args->attr_list = NULL;
    args->attr_ah = mcl_attr_stack_ah;
    args->call_back_data = NULL;
    args->server = s;
    args->mem_pool = p;
    if (LDAP_SUCCESS != mcl_connection_init(
                args->mem_pool, 
                scfg,
                &(args->ldap_rec))) {
        return CONFIG_LDAP_ERROR;
    }

    /*
    char * attr_list[2];
    if( attr_name != NULL )
    {
        attr_list[0] = (char *) attr_name;
        attr_list[1] = NULL;
        args.attr_list = attr_list;
    }
    */
    
    LDEBUG(CONFIG_LDAP_DEBUG_SRCH, "searching the database( base => \"%s\", filter => \"%s\", scope => %d )",
            scfg->basedn, scfg->filter, scfg->scope);

    if (CONFIG_LDAP_OK != mcl_util_search_ldap(
                args->ldap_rec,
                scfg,
                &res)) {
        return CONFIG_LDAP_ERROR;
    }

    if (CONFIG_LDAP_OK != mcl_load(args, res)) 
    {
        ERROR("Error loading data from the LDAP server");
        LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Unbinding LDAP connection");
        ldap_unbind_ext( args->ldap_rec, 0, 0 );
        return CONFIG_LDAP_ERROR;
    }
    if (CONFIG_LDAP_OK != mcl_build_config(args, s)) 
    {
        ERROR("Error building apache configuration");
        LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Unbinding LDAP connection");
        ldap_unbind_ext( args->ldap_rec, 0, 0 );
        return CONFIG_LDAP_ERROR;
    }
    // Free LDAPMessage
    LDEBUG(CONFIG_LDAP_DEBUG_TODO, "ldap_msgfree()");
    ldap_msgfree( res );     

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Unbinding LDAP connection");
    ldap_unbind_ext( args->ldap_rec, 0, 0 );
    return CONFIG_LDAP_OK;
}

/*
 * mcl_sort_entries()
 *
 * For processing configuration directives, it is important that they
 * be sorted by DN.  Considering they come back from LDAP in arbitrary
 * order, we sort them here.  For example, if we had the following DN's:
 * 
 * t=a,t=b,t=c
 * t=a,t=c
 * t=b,t=b,t=c  
 * t=c
 * t=b,t=a,t=c
 *
 * We should get something like then when we are done sorting:
 *
 *           t=c
 *      t=a, t=c
 * t=b, t=a, t=c
 * t=a, t=b, t=c
 * t=b, t=b, t=c
 *
 * Basically, the items are sorted into 'depth-first' tree.  This
 * sorting is neccessary for our <Section> functionality, which says
 * that all objects which are children of a <Section> object should be
 * contained within that section.
 *
 * Sorting is performed off of the exploded DN using the stdlib qsort
 * function and the comparison function, CONFIG_LDAP_reverse_dn_cmp().
 *
 * Note that we explode the DN and count the number of entries here,
 * saving it in the CONFIG_LDAP_dn_entry struct for later use when
 * processing <Section> objects and in the comparison function.
 *
 */

int mcl_sort_entries(
        apr_pool_t * p,
        LDAP * ld,
        LDAPMessage * msg,
      mcl_dn_entry ** entries_ptr )
{
    int index, count;
    mcl_dn_entry * entries;
    LDAPMessage * single_entry;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    count = ldap_count_entries( ld, msg );
    LDEBUG(CONFIG_LDAP_DEBUG_SRCH, "Number of entries returned: %d", count );

    LDEBUG(CONFIG_LDAP_DEBUG_TODO, "Allocating mcl_dn_entry array for %d entries...",
            count );
    entries = apr_pcalloc( p, sizeof( mcl_dn_entry ) * count );

    single_entry = ldap_first_entry( ld, msg );

    LDEBUG(CONFIG_LDAP_DEBUG_TODO, "Popluating entries array...");
    for ( index = 0; index < count; index++ )
    {
        int count = 0;
        char * dn = ldap_get_dn( ld, single_entry );

        entries[ index ].msg = single_entry;
        entries[ index ].ex_dn = ldap_explode_dn( dn, 0 );
        while( entries[ index ].ex_dn[ count ] != NULL ) count++;
        entries[ index ].dn_count = count;

        ldap_memfree( dn );	  
        single_entry = ldap_next_entry( ld, single_entry );
    }

    LDEBUG(CONFIG_LDAP_DEBUG_TODO, "qsort()");
    qsort( entries,
            count,
            sizeof( mcl_dn_entry ),
            mcl_reverse_dn_cmp );

    (* entries_ptr ) = entries;
    return count;
}               

/*
 * mcl_reverse_dn_cmp()
 *
 * Given to mcl_dn_entry objects, it determines which object
 * should be sorted first by doing a reverse comparison of their DN's.
 * The entries should be organized that a parent object should come
 * before its child.  See the example listed for mcl_sort_entries
 * for an example.  This function is passed to qsort in
 * mcl_sort_entries.
 *
 */

int mcl_reverse_dn_cmp(const void * a, const void *b)
{
    mcl_dn_entry * msg_a = (mcl_dn_entry *) a;
    mcl_dn_entry * msg_b = (mcl_dn_entry *) b;

    char ** ex_a = msg_a->ex_dn;
    char ** ex_b = msg_b->ex_dn;

    int len_a = msg_a->dn_count;
    int len_b = msg_b->dn_count;
    int retro = 0;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    // If neither DN has any entries then they are the same
    if( ! ( len_a || len_b ) )
    {
        LDEBUG(CONFIG_LDAP_DEBUG_TODO, "Neither A nor B have any entries...");
        retro = 0;
    }
    // If only one has no entries, it goes first
    else if( ( len_a > 0 ) ^ ( len_b > 0 ) )
    {
        LDEBUG(CONFIG_LDAP_DEBUG_TODO, "One of the entries has zero length...");
        retro = ( len_b > 0 ) ? -1 : 1;
    }
    else
    {
        // Loop in reverse order through the DN until we find a
        // difference
        while( ! retro )
        {
            retro = strcmp( ex_a[ --len_a ], ex_b[ --len_b ] );

            // If we have found no difference, but one DN is out of
            // entries, the one that has run out goes first.
            if( ! retro &&
                    ( ( len_a > 0 ) ^ ( len_b > 0 ) ) )
            {
                retro = ( len_b > 0 ) ? -1 : 1;
            }
        }
    }

    return retro;
}

/*
 * mcl_handle_config_obj()
 *
 * This function examines an LDAP record to determine what type of
 * configuration object it is.  If it is an ApacheSectionObj, we handle
 * it differently than a regular configuration object.
 *
 */

int mcl_handle_config_obj (
        mcl_parms * args,
        mcl_dn_entry * entry )
{
    int retro;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    // Do need to close off an old section?
    mcl_check_section_stack( args, entry );

    // Do we have a new section?
    if( mcl_is_section_obj( args->ldap_rec, entry->msg ) )
    {
        mcl_config_stack * config_stack = args->call_back_data;

        // Add entry to the stack
        entry->prev = config_stack->section_stack;
        config_stack->section_stack = entry;

        retro = mcl_handle_section_obj( args, entry );
        config_stack->section_depth++;

        // Process any remaining config directives
        if( retro == CONFIG_LDAP_OK )
        {
            retro = mcl_handle_plain_obj( args, entry, 1 );
        }

    }
    else
    {
        // Handle regular entry
        retro = mcl_handle_plain_obj( args, entry, 0 );
    }

    return retro;
}

/*
 * mcl_handle_section_obj()
 *
 * This function handles "ApacheSectionObj" objects.  These objects are
 * used to model Apache "<Sections></Sections>".  The object has
 * attributes "ApacheSectionName" and "ApacheSectionArg" which will
 * become "<ApacheSectionName ApacheSectionArg></ApacheSectionName>".
 *
 * Another important feature is that all sub-records of the section
 * object will be processed within that section.  That is if you had
 * the following records:
 *
 * dn: tag=a, dc=test
 * objectClass: ApacheSectionObj
 * ApacheSectionName: VirtualHost
 * ApacheSectionArg: 192.168.1.1
 * 
 * dn tag=kid, tag=a, dc=test
 * objectclass: ApacheVirtualHost
 * ApacheServerName: test.com
 * 
 * You would get the following equivalent configuration:
 *
 * <VirtualHost 192.168.1.1 >
 * ServerName test.com
 * </VirtualHost>
 * 
 * We do this by keeping a reverse-linked list of all currently open
 * sections using the 'prev' field of the mcl_dn_entry object
 * representing the section.  The list is actually linked up back in
 * 'mcl_handle_config_obj'.  There are a number of support
 * routines that deal with closing off the sections and what not.
 *
 */

int mcl_handle_section_obj (
        mcl_parms * args,
        mcl_dn_entry * entry )
{
    struct berval * val;
    struct berval ** values;
    char * section_name;
    char config_string[150];
    char * sec_arg = CONFIG_LDAP_SECTION_ARG;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    // Grab Section Name
    values = ldap_get_values_len( args->ldap_rec,
            entry->msg,
            CONFIG_LDAP_SECTION_NAME );

    val = values[0];
    if( ! ldap_count_values_len( values ) )
    {
        ERROR( "You must declare an %s attribute for a %s\n",
                CONFIG_LDAP_SECTION_NAME,
                CONFIG_LDAP_SECTION_OBJ );
        ldap_value_free_len( values );
        return CONFIG_LDAP_ERROR;
    }

    section_name = apr_pstrdup( args->mem_pool, val->bv_val );
    entry->section_name = section_name;

    ldap_value_free_len( values );

    // Grab Section argument

    values = ldap_get_values_len( args->ldap_rec, entry->msg, sec_arg );

    val = values[0];

    if( ldap_count_values_len( values ) )
    {
        snprintf( config_string, 149, "<%s %s >", section_name, val->bv_val );
    }
    else
    {
        snprintf( config_string, 149, "<%s >", section_name );
    }

    ldap_value_free_len( values );

    // Send actual config
    if( mcl_handle_command( args, config_string )
            != CONFIG_LDAP_OK )
    {
        return CONFIG_LDAP_ERROR;
    }

    return CONFIG_LDAP_OK;
}

/*
 * mcl_check_command()
 *
 * Check if the command exists in all loaded modules
 * to prevent sending invalid directives
 *
 */

int mcl_check_command(const char *cmd) {
    int n;
    for (n = 0; ap_loaded_modules[n]; ++n) {
        if (NULL != ap_find_command_in_modules(cmd, &ap_loaded_modules[n])) {
            return 1;
        }

    }
    return 0;
}

/*
 * mcl_handle_plain_obj()
 *
 * This function handle configuration directives in a plain
 * configuration object (aka not a section object).  Processing is
 * pretty simple.  We loop through all the attributes, and if the first
 * letters are "Apache", it's an Apache configuration directive.  We
 * strip the "Apache" and send on "ConfigDir Value".  The only special
 * cases are:
 *
 * ApacheRawArg: So that a user can specify new config directives
 * without having to modify the LDAP schema, we provide this attribute.
 * Instead of stripping Apache from the attribute name and using RawArg
 * as the directive name, we just send the contents of the value as is.
 * That way you can specify anything you want and have it send on to
 * Apache.
 *
 */
   
int mcl_handle_plain_obj(
        mcl_parms * args,
        mcl_dn_entry * entry,
        int section_check )
{
    BerElement * ber;
    char * attr;
    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    // Loop through all of the attributes... 
    for( attr = ldap_first_attribute( args->ldap_rec, entry->msg, & ber );
            attr != NULL;
            attr = ldap_next_attribute( args->ldap_rec, entry->msg, ber ) )
    {
        LDEBUG(CONFIG_LDAP_DEBUG_TODO, "Checking attr \"%s\"...", attr );

        // First make sure that it is an "Apache" directive.
        // Secondly, if "section_check" is set, make sure that it is
        // not a "Section" attribute.
        if( mcl_is_apache_dir( attr ) &&
                ! ( section_check &&
                    mcl_is_section_attr( attr + CONFIG_LDAP_PREFIX_LENGTH )
                  ) )

        {
            char * config_dir = attr + CONFIG_LDAP_PREFIX_LENGTH;
            struct berval ** values = ldap_get_values_len( args->ldap_rec,
                    entry->msg,
                    attr );
            int vi;
            int is_raw_arg = mcl_is_raw_arg( config_dir );

            for (vi = 0 ; values[vi]; vi++) 
            {
                struct berval *val = values[vi];
                char config_string[150];
                char dir[150];
                if( is_raw_arg )
                {
                    snprintf(dir, val->bv_len - strlen(strstr(val->bv_val, " ")) + 1, "%s", val->bv_val);
                    if (NULL != strstr(dir, "#")) {
                        continue;
                    }

                    snprintf(config_string, 149,
                            "%s", val->bv_val );
                }
                else
                {
                    snprintf(dir, strlen(config_dir) + 1, "%s", config_dir);
                    snprintf( config_string, 149,
                            "%s %s",
                            config_dir,
                            val->bv_val );
                }

                if (0 == mcl_check_command(dir)) {
                    ERROR("Command %s not found in any module", dir);
                    continue;
                }

                if( mcl_handle_command( args, config_string )
                        != CONFIG_LDAP_OK )
                {
                    ldap_value_free_len( values );
                    ber_free( ber, 0 );
                    return CONFIG_LDAP_ERROR;
                }
            }

            ldap_value_free_len( values );
        }
    }

    ber_free( ber, 0 );

    return CONFIG_LDAP_OK;
}

/*
 * mcl_hanle_command()
 *
 * Given an actual Apache configuration directive, we push it onto the
 * the config stack, which will all be sent to Apache in a custom
 * configfile_t.  See mcl_build_config for more info.
 *
 */
int mcl_handle_command (
        mcl_parms * args,
        const char * config_string )
{
    mcl_config_stack * config_stack = args->call_back_data;
    char ** word_ptr;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    // Debug Output
    if (mcl_debug_level & (CONFIG_LDAP_DEBUG_CFG | CONFIG_LDAP_DEBUG_LINE)) {
        LDEBUG_PLAIN( CONFIG_LDAP_DEBUG_LINE, "%2d: ", config_stack->config_ah->nelts + 1);
        mcl_util_print_offset( config_stack->section_depth * CONFIG_LDAP_TAB_LENGTH,
                CONFIG_LDAP_DEBUG_CFG | CONFIG_LDAP_DEBUG_LINE );
        LDEBUG_PLAIN(CONFIG_LDAP_DEBUG_CFG | CONFIG_LDAP_DEBUG_LINE, "%s\n", config_string );
    }

    word_ptr = (char **) apr_array_push( config_stack->config_ah );
    (*word_ptr) = apr_pstrdup( args->mem_pool, config_string );

    return CONFIG_LDAP_OK;
}

/*
 * mcl_build_config()
 *
 * Using a custom ap_configfile_t built with ap_pcfg_open_custom
 * to build the configuration tree and process it.
 *
 */

int mcl_build_config (
        mcl_parms * args,
        server_rec *s)
{
    const char * err_msg;
    cmd_parms cmd;
    apr_status_t rv;

    cmd = default_parms;
    cmd.pool = s->process->pool;
    cmd.temp_pool = s->process->pool;
    cmd.server = args->server;
    ap_directive_t *conftree = (ap_directive_t *) apr_palloc(cmd.temp_pool, sizeof (ap_directive_t));

    conftree = NULL;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    cmd.config_file = ap_pcfg_open_custom(args->mem_pool,
            "LDAP Configuration",
            args->call_back_data,
            NULL,
            (void *) mcl_ah_getstr,
            NULL);
    err_msg = ap_build_config( &cmd, cmd.pool, cmd.temp_pool, &conftree );
    ap_cfg_closefile(cmd.config_file);
    if( err_msg == NULL ) {
        LDEBUG(CONFIG_LDAP_DEBUG_CMD|CONFIG_LDAP_DEBUG_FUNC, "Built apache config tree");
        rv = ap_process_config_tree(cmd.server, conftree,
                cmd.pool, cmd.temp_pool);
        if (rv == OK) {
            ap_fixup_virtual_hosts(cmd.pool, cmd.server);
            ap_fini_vhost_config(cmd.pool, cmd.server);
            return CONFIG_LDAP_OK;
        }
    }
    ERROR("Could not build config");
    return CONFIG_LDAP_ERROR;
}

/*
 * mcl_ah_getstr()
 *
 * Reads data from the attribute stack and sends it to ap_build_config
 *
 */

static void * mcl_ah_getstr (
        char * buf,
        size_t bufsiz,
        void * param )
{
    mcl_config_stack * config_stack = param;
    char ** elts = (char **) config_stack->config_ah->elts;
    char * sbuf = buf;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    // Check to see if we're out of directive to send
    if( config_stack->index >= config_stack->config_ah->nelts )
    {
        LDEBUG(CONFIG_LDAP_DEBUG_TODO, "No more directives to send.");
        return NULL;
    }

    strncpy( sbuf, elts[ config_stack->index++ ], bufsiz );

    LDEBUG(CONFIG_LDAP_DEBUG_TODO, "Sending Apache \"%s\" as line %d.", buf, config_stack->index );

    return buf;
}

/*
 *
 * Configuration processing support routines
 *
 */

/*
 * mcl_is_section_obj()
 *
 * This method is used to determine if an LDAP record represents an
 * ApacheSectionObj.  We determine this by looping through the values
 * of 'objectclass' and looking for 'ApacheSectionObj".
 *
 */

int mcl_is_section_obj (
        LDAP * ld,
        LDAPMessage * entry )
{
    struct berval ** values = ldap_get_values_len( ld, entry, "objectclass" );
    int index = 0;
    int retro = 0;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    for ( index = 0; values[index]; index++) 
    {
        struct berval *val = values[index];
        if (!strcmp(val->bv_val, CONFIG_LDAP_SECTION_OBJ)) {
            retro = 1;
            break;
        }
    }

    ldap_value_free_len( values );

    return retro;
}

/*
 * mcl_check_section_stack()
 *
 * As stated in mcl_handle_section_obj(), all sub-entries of a
 * ApacheSectionObj should be processed within the scope of that
 * section.  However, once all these entries have been processed, we
 * need to close of the section and move onto grener pastures.
 *
 * This function checks to see if the current entry is still within the
 * scope of the section.  If not, it closes of the section (
 * "</Section>" ) and adjusts the section stack appropriately.  Passing
 * in a NULL entry will effectively close off all open sections.
 *
 */

int mcl_check_section_stack (
        mcl_parms * args,
        mcl_dn_entry * entry )
{
    mcl_config_stack * config_stack = args->call_back_data;
    mcl_dn_entry * section = config_stack->section_stack;
    char config_string[150];

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    while( section != NULL )
    {
        // We don't close the section unless we have an entry that
        // is a sub-entry of the active section.  However, if we
        // don't have a sub-entry, we close off the current section.
        // Passing a NULL value is a good way to close off all open
        // sections.
        if( entry != NULL &&
                mcl_is_sub_dn( section, entry ) )
        {
            return CONFIG_LDAP_OK;
        }

        // Increment before sending command so DEBUG output will look right
        config_stack->section_depth--;
        snprintf( config_string, 149, "</%s>", section->section_name );

        // Send actual config
        if( mcl_handle_command( args, config_string )
                != CONFIG_LDAP_OK )
        {
            return CONFIG_LDAP_ERROR;
        }

        // Pop one off the stack
        section = section->prev;
        config_stack->section_stack = section;
    }

    return CONFIG_LDAP_OK;
}

/*
 * mcl_is_sub_dn()
 *
 * This function determines whether "child" is a sub-entry of parent.
 * It does this by comparing the exploded DN's of the two entries in
 * reverse order.  If it is a sub-entry, the parent will run out of DN
 * components before the child and all of the parent's components will
 * match the child's.
 *
 */

int mcl_is_sub_dn (
        mcl_dn_entry * parent,
        mcl_dn_entry * child )
{
    int index = 0;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    while( parent->ex_dn[ index ] != NULL )
    {
        if( child->ex_dn[ index ] == NULL ) return 0;
        if( ! strcmp( parent->ex_dn[ index ],
                    child->ex_dn[ index ] ) ) return 0;
        index++;
    }

    return 1;
}

/*
 * mcl_is_apache_dir()
 *
 * This method examines a string to determine if it is naming an Apache
 * configuration directive.  If it is a directive, it will be prefixed
 * with "Apache".
 *
 */

int mcl_is_apache_dir (
        const char * dir )
{
    char * test = CONFIG_LDAP_PREFIX;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    if( dir == NULL ) return 0;

    return ! strncmp( test, dir, CONFIG_LDAP_PREFIX_LENGTH );
}

/*
 * mcl_is_raw_arg()
 *
 * Though the provided Apache LDAP schema provides entries for all
 * configuration directives in the core httpd, the user may sometime
 * wish to supply a custom directive without adding it to the schema.
 * Thus, "ApacheRawArg", which passes the associated value onto Apache
 * no questions asked.  This function determines if a given attribute
 * is "RawArg"
 */
int mcl_is_raw_arg (
        const char * dir )
{
    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    if( dir == NULL ) return 0;

    return ! strncmp( "RawArg", dir, 6 );
}

/*
 * mcl_is_section_attr()
 *
 * This method determines if the supplied string is either
 * "SectionName" or "SectionArg", indicating that it is an attribute
 * used by an "ApacheSectionObj".
 *
 */

int mcl_is_section_attr (
        const char * dir )
{
    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "checking if %s is a section attribute", dir);

    if( dir == NULL ) return 0;

    return  ! ( strncmp( "Section", dir, 7 ) ||
            ( strncmp( "Arg", dir + 7, 3 ) &&
              strncmp( "Name", dir + 7, 4 ) ) );
}

/*
 *
 * Apache module interface specific functions
 *
 */

static int mcl_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    if( mcl_attr_stack_pool == NULL )
    {
        LDEBUG(CONFIG_LDAP_DEBUG_TODO, "Creating attribute-stack memory pool");
        apr_pool_create_ex(&mcl_attr_stack_pool, p, NULL, NULL);

        LDEBUG(CONFIG_LDAP_DEBUG_TODO, "Creating attribute-stack");
        mcl_attr_stack_ah = apr_array_make( mcl_attr_stack_pool,
                4, sizeof( apr_array_header_t * ) );
    }

    ap_add_version_component(p, MOD_CONFIG_LDAP_VERSION);

    return OK;
}

/* 
 * mcl_create_server_config()
 *
 * Initializes the module specific structures
 *
 */

static void * mcl_create_server_config (
        apr_pool_t *p, 
        server_rec *s)
{ 

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    mcl_config_t *cfg;
    cfg = (mcl_config_t *) apr_pcalloc(p, sizeof(mcl_config_t));

    cfg->certificates = apr_array_make(p, 5, sizeof(apr_ldap_opt_tls_cert_t));
    cfg->secure = APR_LDAP_NONE;
    cfg->timeout = 10;
    cfg->verify_server_cert = 1;
    cfg->deref =  never;
    return (void *) cfg;
}

/*
 * mcl_post_config()
 * 
 * Sends the server configuration generated from the LDAP databse
 *
 */

static int mcl_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{

    void *data;
    const char *cfg_key = "mcl_post_config";
    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    /* 
     * This hook is called twice so don't bother going
     * through all of the initialization on the first call
     * because it will just be thrown away.
     */
    apr_pool_userdata_get(&data, cfg_key, s->process->pool);
    if (!data) {
            apr_pool_userdata_set((void *)1, cfg_key,
                                               apr_pool_cleanup_null, s->process->pool);

            return OK;
    }

    scfg = (mcl_config_t *) ap_get_module_config(s->module_config, &config_ldap_module);

    if (CONFIG_LDAP_OK != mcl_search(p, s)) {
        ERROR("Could not load LDAP configuration");
        return DECLINED;
    }

    time_t rawtime;
    const struct tm * timestart;
    char filter[16];
    if (-1 == time(&rawtime)) {
        ERROR("Could not retrieve timestart");
        return DECLINED;
    }

    timestart = gmtime(&rawtime);
    strftime (filter, 16, "%Y%m%d%H%M%SZ", timestart);
    scfg->filter = apr_psprintf(p, "(modifyTimestamp>=%s)", filter); 

    return OK;
}

/*
 :* mcl_monitor()
 *
 *
 * This is added as an apache monitor hook to allow
 * for dynamic reloading of the configuration when the 
 * ConfigureLDP_PingFilter is updated and actually sends
 * a graceful restart signal to the main apache process
 *
 */

static int mcl_monitor(apr_pool_t *p)
{
    if (NULL == scfg) {
        LDEBUG(CONFIG_LDAP_DEBUG_CFG, "No monitor specified");
        return DECLINED;
    }

    int count;
    pid_t otherpid;
    apr_status_t rv;
    LDAP *ldc = apr_palloc(p, sizeof(LDAP *));
    LDAPMessage *res;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    if (0 < scfg->interval) {

        time_t t;

        if ( -1 == time(&t)) {
            ERROR("Could not execute time(): %s", strerror(errno));
            return DECLINED;
        }

        if (0 >= scfg->time) {
            scfg->time = t;
        }

        int last_run_before = (int) t - (int) scfg->time;

        if (last_run_before < (int) scfg->interval) {
            LDEBUG(CONFIG_LDAP_DEBUG_CFG, "Skipping monitor run "
                    "(time since last run:%d, interval:%d)", 
                    last_run_before,
                    (int) scfg->interval);
            return DECLINED;
        }

        scfg->time = t;
    }
    
    if (LDAP_SUCCESS != mcl_connection_init(
                p,
                scfg,
                &ldc)) {
        ERROR("Could not initialize LDAP connection");
        return DECLINED;
    }

    LDEBUG(CONFIG_LDAP_DEBUG_SRCH|CONFIG_LDAP_DEBUG_FUNC, 
            "Searching (basedn: %s, filter: %s)", 
            scfg->basedn,
            scfg->filter);

    if (CONFIG_LDAP_OK != mcl_util_search_ldap(
                ldc,
                scfg, 
                &res)) {
        goto decline;
    }

    if (-1 == ( count = ldap_count_entries(ldc, res))) {
        ERROR("Could not retrieve the modifyTimestamp entries count");
        goto decline;
    }

    if (count <= 0) {
        LDEBUG(CONFIG_LDAP_DEBUG_SRCH, "No changes found");
        goto decline;
    }

    LDEBUG(CONFIG_LDAP_DEBUG_ALL, "A graceful restart requested:%s", ldap_get_dn(ldc, res));

    rv = ap_read_pid(p, ap_pid_fname, &otherpid);
    if (rv != APR_SUCCESS) {
        ERROR("Unable to find apache pid");
        goto decline;
    }

    if (kill(otherpid, AP_SIG_GRACEFUL) < 0) {
        ERROR("Could not send signal to server");
        goto decline;
    }

    return OK;

decline:    
    LDEBUG(CONFIG_LDAP_DEBUG_CNXN, "Unbinding LDAP connection");
    ldap_unbind_ext( ldc, 0, 0 );
    return DECLINED;
}

/*
 *
 * Apache 'ConfigLDAP_*' Commands processing routines
 *
 */

/*
 * mcl_set_debug()
 *
 * Process ConfigLDAP_DebugLevel
 *
 */

static const char *mcl_set_debug ( cmd_parms * cmd, void * mconfig, const char * level )
{
    mcl_debug_level = atoi( level );
    LDEBUG(CONFIG_LDAP_DEBUG_CMD | CONFIG_LDAP_DEBUG_FUNC, "level => \"%s\" (%d)",
            level,
            mcl_debug_level );

    return NULL;
}

/*
 * mcl_set_url()
 *
 * Process ConfigLDAP_Url
 *
 */

static const char *mcl_set_url ( cmd_parms *cmd, void *mconfig, const char *url )
{
    mcl_config_t *conf = mcl_util_get_module_config(cmd);

    return mcl_util_parse_url(cmd->pool, conf, url);
}

/*
 * mcl_set_binddn()
 *
 * Process ConfigLDAP_BindDN
 *
 */

static const char *mcl_set_binddn ( cmd_parms *cmd, void *mconfig, const char *binddn )
{
    mcl_config_t *conf = mcl_util_get_module_config(cmd); 
    conf->binddn = apr_pstrdup(cmd->pool, binddn);
    return NULL;
}

/*
 * mcl_set_bindpw()
 *
 * Process ConfigLDAP_BindPassword
 *
 */

static const char *mcl_set_bindpw ( cmd_parms *cmd, void *mconfig, const char *bindpw )
{
    mcl_config_t *conf = mcl_util_get_module_config(cmd); 
    conf->bindpw = apr_pstrdup(cmd->pool, bindpw);
    return NULL;
}

/*
 * mcl_set_deref()
 *
 * Process ConfigLDAP_DereferenceAliases
 *
 */

static const char *mcl_set_deref ( cmd_parms *cmd, void *mconfig, const char *deref )
{
    mcl_config_t *conf = mcl_util_get_module_config(cmd); 

    if (strcmp(deref, "never") == 0 || strcasecmp(deref, "off") == 0) {
        conf->deref = never;
    }
    else if (strcmp(deref, "searching") == 0) {
        conf->deref = searching;
    }
    else if (strcmp(deref, "finding") == 0) {
        conf->deref = finding;
    }
    else if (strcmp(deref, "always") == 0 || strcasecmp(deref, "on") == 0) {
        conf->deref = always;
    }
    else {
        return "Unrecognized value for ConfigLDAP_AliasDereference directive";
    }
    return NULL;
}

/*
 * mcl_set_certificates();
 *
 * Process ConfigLDAP_Certificates.
 *
 * This directive takes either two or three arguments:
 * - certificate type
 * - certificate file / directory / nickname
 * - certificate password (optional)
 *
 * This directive may only be used globally.
 *
 */

static const char *mcl_set_certificates(cmd_parms *cmd,
        void *mconfig,
        const char *type,
        const char *file,
        const char *password)
{
    mcl_config_t *conf = mcl_util_get_module_config(cmd); 

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    apr_finfo_t finfo;
    apr_status_t rv;
    int cert_type = 0;
    apr_ldap_opt_tls_cert_t *cert;

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    if (err != NULL) {
        return err;
    }

    /* handle the certificate type */
    if (type) {
        cert_type = mcl_util_parse_cert_type(type);
        if (APR_LDAP_CA_TYPE_UNKNOWN == cert_type) {
           return apr_psprintf(cmd->pool, "The certificate type %s is "
                                          "not recognised. It should be one "
                                          "of CA_DER, CA_BASE64, CA_CERT7_DB, "
                                          "CA_SECMOD, CERT_DER, CERT_BASE64, "
                                          "CERT_KEY3_DB, CERT_NICKNAME, "
                                          "KEY_DER, KEY_BASE64", type);
        }
    }
    else {
        return "Certificate type was not specified.";
    }

    LDEBUG(CONFIG_LDAP_DEBUG_CFG|CONFIG_LDAP_DEBUG_FUNC, "Adding SSL certificate %s (type %s)",
            file, type);

    /* add the certificate to the global array */
    cert = (apr_ldap_opt_tls_cert_t *)apr_array_push(conf->certificates);
    cert->type = cert_type;
    cert->path = file;
    cert->password = password;

    /* if file is a file or path, fix the path */
    if (cert_type != APR_LDAP_CA_TYPE_UNKNOWN &&
        cert_type != APR_LDAP_CERT_TYPE_NICKNAME) {

        cert->path = ap_server_root_relative(cmd->pool, file);
        if (cert->path &&
            ((rv = apr_stat (&finfo, cert->path, APR_FINFO_MIN, cmd->pool))
                != APR_SUCCESS))
        {
            ERROR("Could not open SSL certificate file %s", 
                    cert->path == NULL ? file : cert->path);
            return "Invalid global certificate file path";
        }
    }

    return NULL;
}

/*
 * mcl_set_verify_server_cert()
 *
 * Process ConfigLDAP_VerifyServerCert.
 *
 */

static const char *mcl_set_verify_server_cert(cmd_parms *cmd,
                                                 void *mconfig,
                                                 int mode)
{
    mcl_config_t *conf = mcl_util_get_module_config(cmd); 
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    LDEBUG(CONFIG_LDAP_DEBUG_FUNC, "Function entered");

    if (err != NULL) {
        return err;
    }

    LDEBUG(CONFIG_LDAP_DEBUG_CFG|CONFIG_LDAP_DEBUG_FUNC, "SSL verify server certificate %s", mode ? "TRUE" : "FALSE");

    conf->verify_server_cert = mode;

    return NULL;
}

/*
 * mcl_set_connection_timeout()
 *
 * Process ConfigLDAP_Timeout
 *
 */

static const char *mcl_set_connection_timeout ( cmd_parms *cmd, void *mconfig, const char *ttl )
{
    mcl_config_t *conf = mcl_util_get_module_config(cmd); 
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    conf->timeout = atol(ttl);

    LDEBUG(CONFIG_LDAP_DEBUG_CFG, "Connection timeout %ld", conf->timeout);
#else
    return "Connection timeout option not supported by the LDAP SDK in use.";
#endif
    return NULL;
}

/*
 * mcl_set_monitor_interval()
 *
 * Process ConfigLDAP_MonitorInterval
 *
 */

static const char *mcl_set_monitor_interval ( cmd_parms *cmd, void *mconfig, const char *interval )
{
    mcl_config_t *conf = mcl_util_get_module_config(cmd); 
    conf->interval = (time_t) atoi(interval);
    return NULL;
}

/*
 * All module configuration directives
 *
*/

command_rec mcl_cmds[] = {
    AP_INIT_TAKE1("ConfigLDAP_DebugLevel", mcl_set_debug, NULL, RSRC_CONF | ACCESS_CONF, 
            "Numeric debug level"),

    AP_INIT_TAKE1("ConfigLDAP_Url", mcl_set_url, NULL, RSRC_CONF,
            "URL to define LDAP connection. This should be an RFC 2255 compliant\n"
            "URL of the form ldap://host[:port]/basedn[?attrib[?scope[?filter]]].\n"
            "<ul>\n"
            "<li>Host is the name of the LDAP server. Use a space separated list of hosts \n"
            "to specify redundant servers.\n"
            "<li>Port is optional, and specifies the port to connect to.\n"
            "<li>basedn specifies the base DN to start searches from\n"
            "</ul>\n"),

    AP_INIT_TAKE1 ("ConfigLDAP_BindDN", mcl_set_binddn, NULL, RSRC_CONF,
            "DN to use to bind to LDAP server. If not provided, will do an anonymous bind."),

    AP_INIT_TAKE1("ConfigLDAP_BindPassword", mcl_set_bindpw, NULL, RSRC_CONF,
            "Password to use to bind to LDAP server. If not provided, will do an anonymous bind."),

    AP_INIT_TAKE23("ConfigLDAP_Certificates", mcl_set_certificates,
                   NULL, RSRC_CONF,
                   "Takes three args; the file and/or directory containing "
                   "the trusted CA certificates (and global client certs "
                   "for Netware) used to validate the LDAP server.  Second "
                   "arg is the cert type for the first arg, one of CA_DER, "
                   "CA_BASE64, CA_CERT7_DB, CA_SECMOD, CERT_DER, CERT_BASE64, "
                   "CERT_KEY3_DB, CERT_NICKNAME, KEY_DER, or KEY_BASE64. "
                   "Third arg is an optional passphrase if applicable."),

    AP_INIT_FLAG("ConfigLDAP_VerifyServerCert", mcl_set_verify_server_cert,
                  NULL, RSRC_CONF,
                  "Set to 'ON' requires that the server certificate be verified "
                  "before a secure LDAP connection can be establish.  Default 'ON'"),

    AP_INIT_TAKE1("ConfigLDAP_Timeout", mcl_set_connection_timeout,
                  NULL, RSRC_CONF,
                  "Specify the LDAP socket connection timeout in seconds "
                  "(default: 10)"),

    AP_INIT_TAKE1("ConfigLDAP_DereferenceAliases", mcl_set_deref, NULL, RSRC_CONF,
            "Determines how aliases are handled during a search. Can be one of the"
            "values \"never\", \"searching\", \"finding\", or \"always\". "
            "Defaults to always."),

    AP_INIT_TAKE1("ConfigLDAP_MonitorInterval", mcl_set_monitor_interval, NULL, RSRC_CONF,
            "Password to use to bind to LDAP server. If not provided, will do an anonymous bind."),

    {NULL}
};

/*
 * Module hooks
 *
*/

static void mcl_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(mcl_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_post_config(mcl_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_monitor(mcl_monitor, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

/*
 * Module definition
 *
*/

module AP_MODULE_DECLARE_DATA config_ldap_module = {
    STANDARD20_MODULE_STUFF,                /* maj/min,-1,file,0,0,cookie,null. */
    NULL,                                   /* per-directory config creator */
    NULL,                                   /* dir config merger */
    mcl_create_server_config,   /* server config creator */
    NULL,                                   /* server config merger */
    mcl_cmds,                   /* command table */
    mcl_hooks                   /* register-hooks function */
};
