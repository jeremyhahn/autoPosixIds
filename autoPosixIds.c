/**
 * autoPosixIds.c 
 *
 * Copyright (C) 2009 Jeremy Hahn
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * http://www.OpenLDAP.org/license.html.
 *
 * SEE LICENSE FOR MORE INFORMATION
 *
 * Author: Jeremy Hahn
 * Email:  jeremy.hahn@makeabyte.com
 * Version: 0.1
 * Created: 4.24.2008
 * 
 * autoPosixIds
 *
 * This is an OpenLDAP overlay that intercepts ADD requests for posixAccount type
 * entries that do not have a uidNumber/gidNumber. When such ADD requests are found, 
 * the overlay adds the attribute(s) with the next available id.
 */

#include "portable.h" 
#include "slap.h"
#include "config.h"

static int autoPosixIds_search_cb( Operation *op, SlapReply *rs );
static unsigned long autoPosixIds_next_available( Operation *op );

static slap_overinst autoPosixIds;
static ObjectClass *oc_posix_account;
static char *uid_attr_name = "uidNumber";
static char *gid_attr_name = "gidNumber";

typedef struct autoPosixIds_data {
	ldap_pvt_thread_mutex_t mutex;
  	unsigned long max_uid_number;
} autoPosixIds_data;

/**
 * Look for posixAccount adds with no autoPosixIds/gidNumber,
 * and add in the next available autoPosixIds/gidNumber as needed.
 */
static int autoPosixIds_add( Operation *op, SlapReply *rs ) {

	Entry* to_add = NULL;
 	AttributeDescription* ad = NULL;
	AttributeDescription* ad2 = NULL;
	Attribute* attr = NULL;
	char uidstr[64];
	char gidstr[64];
	struct berval uidbv = BER_BVNULL;
	struct berval gidbv = BER_BVNULL;
  	unsigned long uid;
	const char* text;
	const char* text2;
	int rc;
	int rc2;

	to_add = op->oq_add.rs_e;

	// if the user doesn't have access, default through to the normal ADD
	if( !access_allowed( op, to_add, slap_schema.si_ad_entry, NULL, ACL_WRITE, NULL ) )
	    return SLAP_CB_CONTINUE;

	// only interested in posixAccounts
	if( !is_entry_objectclass( (to_add), oc_posix_account, 0) ) {
	    Debug( LDAP_DEBUG_TRACE, "%s: entry %s is not of objectclass posixAccount\n", autoPosixIds.on_bi.bi_type, to_add->e_nname.bv_val, 0 );
	    return SLAP_CB_CONTINUE;
	}

	// if autoPosixIds present, no further processing required
	for( attr = to_add->e_attrs; attr; attr = attr->a_next ) {

	     if( !strcmp( attr->a_desc->ad_cname.bv_val, uid_attr_name ) ) {
		 Debug(LDAP_DEBUG_TRACE, "%s: ignoring %s due to present uidNumber attribute\n", autoPosixIds.on_bi.bi_type, to_add->e_nname.bv_val, 0 );
		 return SLAP_CB_CONTINUE;
	     }
	}

        // get next assignable number
	uid = autoPosixIds_next_available( op );

        // add autoPosixIds
	rc = slap_str2ad( uid_attr_name, &ad, &text );
	if( rc != LDAP_SUCCESS ) {
	    Debug( LDAP_DEBUG_ANY, "%s: failed to add uidNumber attribute to entry\n", autoPosixIds.on_bi.bi_type, 0, 0 );
	    return SLAP_CB_CONTINUE;
	}
	sprintf( uidstr, "%lu", uid );
	ber_str2bv( uidstr, 0, 0, &uidbv );
	attr_merge_one( to_add, ad, &uidbv, 0 );
	Debug( LDAP_DEBUG_ANY, "%s: added uidNumber %s to entry\n", autoPosixIds.on_bi.bi_type, uidstr, 0 );

        // if gidNumber present, no further processing required
	for( attr = to_add->e_attrs; attr; attr = attr->a_next ) {
	     if( !strcmp( attr->a_desc->ad_cname.bv_val, gid_attr_name ) ) {
		 Debug( LDAP_DEBUG_TRACE, "%s: ignoring %s due to present gidNumber attribute\n", autoPosixIds.on_bi.bi_type, to_add->e_nname.bv_val, 0 );
		 return SLAP_CB_CONTINUE;
	     }
	}

	// add gidNumber
	rc2 = slap_str2ad( gid_attr_name, &ad2, &text2 );
	if( rc2 != LDAP_SUCCESS ) {
 	    Debug( LDAP_DEBUG_ANY, "%s: failed to add gidNumber attribute to entry\n", autoPosixIds.on_bi.bi_type, 0, 0 );
	    return SLAP_CB_CONTINUE;
	}
	sprintf( gidstr, "%lu", uid );
	ber_str2bv( gidstr, 0, 0, &gidbv );
	attr_merge_one( to_add, ad2, &gidbv, 0 );
	Debug( LDAP_DEBUG_ANY, "%s: added gidNumber %s to entry\n", autoPosixIds.on_bi.bi_type, gidstr, 0 );

	return SLAP_CB_CONTINUE;
}

static unsigned long autoPosixIds_next_available( Operation *op ) {

	slap_overinst* on = (slap_overinst *)op->o_bd->bd_info;
	autoPosixIds_data* ad = on->on_bi.bi_private;

	Operation nop = *op;
	SlapReply nrs = { REP_RESULT };
	Filter* filter = NULL;
	slap_callback cb = { NULL, autoPosixIds_search_cb, NULL, ad };
	struct berval fstr = BER_BVNULL;
	struct berval rootstr = BER_BVNULL;
  	int rc;

	// if max uid is known don't bother searching the tree
	if( ad->max_uid_number == 0 ) {

	    nop.o_callback = &cb;
	    op->o_bd->bd_info = (BackendInfo *) on->on_info;
	    nop.o_tag = LDAP_REQ_SEARCH;
	    nop.o_ctrls = NULL;
		
	    filter = str2filter( "(uidNumber=*)" );
	    filter2bv( filter, &fstr );

	    nop.ors_scope = LDAP_SCOPE_SUBTREE;
	    nop.ors_deref = LDAP_DEREF_NEVER;
	    nop.ors_slimit = -1;//SLAP_NO_LIMIT;
	    nop.ors_tlimit = -1;//SLAP_NO_LIMIT;
	    nop.ors_attrsonly = 1;
	    nop.ors_attrs = slap_anlist_no_attrs;
	    nop.ors_filter = filter;
	    nop.ors_filterstr = fstr;

	    memset( &nrs, 0, sizeof(nrs) );
	    nrs.sr_type = REP_RESULT;
	    nrs.sr_err = LDAP_SUCCESS;
	    nrs.sr_entry = NULL;
	    nrs.sr_flags |= REP_ENTRY_MUSTBEFREED;
	    nrs.sr_text = NULL;

	    nop.o_req_dn = rootstr;
	    nop.o_req_ndn = rootstr;

	    if( nop.o_bd->be_search ) {
		rc = nop.o_bd->be_search( &nop, &nrs );
		Debug( LDAP_DEBUG_TRACE, "%s: finished searching for entries with uidNumber\n", autoPosixIds.on_bi.bi_type, 0, 0 );
	    }
	    else {
		Debug( LDAP_DEBUG_ANY, "%s: backend missing search function\n", autoPosixIds.on_bi.bi_type, 0, 0 );
	    }

	    if( filter ) filter_free( filter );
	    if( fstr.bv_val ) ch_free( fstr.bv_val );
	}
	return ++(ad->max_uid_number);
}

static int autoPosixIds_search_cb( Operation *op, SlapReply *rs ) {

	autoPosixIds_data* ad = op->o_callback->sc_private;
	Entry *entry = NULL;

	if( rs->sr_type != REP_SEARCH ) return 0;
				
	if( rs->sr_entry ) {
  	    Debug( LDAP_DEBUG_TRACE, "%s: intercepted candidate %s\n", autoPosixIds.on_bi.bi_type, rs->sr_entry->e_nname.bv_val, 0 );

	    entry = rs->sr_entry;

	    Attribute *attr = NULL;
	    for( attr = entry->e_attrs; attr; attr = attr->a_next ) {

		 if( !strcmp( attr->a_desc->ad_cname.bv_val, uid_attr_name ) )	{
		     if( attr->a_numvals > 0 ) {
			 unsigned long tmp = strtoul( attr->a_vals[0].bv_val, 0, 0 );
			 Debug( LDAP_DEBUG_ANY, "%s: found existing uidNumber %lu\n", autoPosixIds.on_bi.bi_type, tmp, 0 );
			 if( tmp >= ad->max_uid_number ) ad->max_uid_number = tmp;
		     }
	         }
	    }
	}
	return 0;
}

static int autoPosixIds_db_init( BackendDB *be, ConfigReply *cr ) {

	slap_overinst *on = (slap_overinst *)be->bd_info;
	autoPosixIds_data *ad = ch_calloc(1, sizeof(autoPosixIds_data));

	on->on_bi.bi_private = ad;
	ldap_pvt_thread_mutex_init( &ad->mutex );
	ad->max_uid_number = 0;

	return 0;
}

static int autoPosixIds_db_destroy( BackendDB *be, ConfigReply *cr ) {

	slap_overinst *on = (slap_overinst *)be->bd_info;
	autoPosixIds_data *ad = on->on_bi.bi_private;

	ldap_pvt_thread_mutex_destroy( &ad->mutex );
	free( ad );

	return 0;
}

int autoPosixIds_init() {

    autoPosixIds.on_bi.bi_type = "autoPosixIds";
    autoPosixIds.on_bi.bi_op_add = autoPosixIds_add;
    autoPosixIds.on_bi.bi_db_init = autoPosixIds_db_init;
    autoPosixIds.on_bi.bi_db_destroy = autoPosixIds_db_destroy;

    oc_posix_account = oc_find( "posixAccount" );
    if( oc_posix_account == NULL ) {
        Debug( LDAP_DEBUG_ANY, "%s: unable to find default ObjectClass \"posixAccount\".\n", autoPosixIds.on_bi.bi_type, 0, 0 );
        return -1;
    }

    return ( overlay_register(&autoPosixIds) );
}

int init_module( int argc, char *argv[] ) {

    return autoPosixIds_init();
}
