/* $OpenBSD: ssl.h,v 1.3 2023/07/08 16:40:14 beck Exp $ */
/*
 * Copyright (c) 2023 Bob Beck <beck@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _LIBSSL_SSL_H
#define _LIBSSL_SSL_H

#ifndef _MSC_VER
#include_next <openssl/ssl.h>
#else
#include "../include/openssl/ssl.h"
#endif
#include "ssl_namespace.h"

LSSL_USED(SSL_CTX_set_msg_callback);
LSSL_USED(SSL_set_msg_callback);
LSSL_USED(SSL_CTX_set_keylog_callback);
LSSL_USED(SSL_CTX_get_keylog_callback);
LSSL_USED(SSL_set_num_tickets);
LSSL_USED(SSL_get_num_tickets);
LSSL_USED(SSL_CTX_set_num_tickets);
LSSL_USED(SSL_CTX_get_num_tickets);
LSSL_USED(SSL_get0_verified_chain);
LSSL_USED(SSL_CTX_sessions);
LSSL_USED(SSL_CTX_sess_set_new_cb);
LSSL_USED(SSL_CTX_sess_get_new_cb);
LSSL_USED(SSL_CTX_sess_set_remove_cb);
LSSL_USED(SSL_CTX_sess_get_remove_cb);
LSSL_USED(SSL_CTX_sess_set_get_cb);
LSSL_USED(SSL_CTX_set_info_callback);
LSSL_USED(SSL_CTX_get_info_callback);
LSSL_USED(SSL_CTX_set_client_cert_cb);
LSSL_USED(SSL_CTX_get_client_cert_cb);
LSSL_USED(SSL_CTX_set_client_cert_engine);
LSSL_USED(SSL_CTX_set_cookie_generate_cb);
LSSL_USED(SSL_CTX_set_cookie_verify_cb);
LSSL_USED(SSL_CTX_set_next_protos_advertised_cb);
LSSL_USED(SSL_CTX_set_next_proto_select_cb);
LSSL_USED(SSL_select_next_proto);
LSSL_USED(SSL_get0_next_proto_negotiated);
LSSL_USED(SSL_CTX_set_alpn_protos);
LSSL_USED(SSL_set_alpn_protos);
LSSL_USED(SSL_CTX_set_alpn_select_cb);
LSSL_USED(SSL_get0_alpn_selected);
LSSL_USED(SSL_set_psk_use_session_callback);
LSSL_USED(SSL_get_finished);
LSSL_USED(SSL_get_peer_finished);
LSSL_USED(SSL_verify_client_post_handshake);
LSSL_USED(SSL_CTX_set_post_handshake_auth);
LSSL_USED(SSL_set_post_handshake_auth);
LSSL_USED(PEM_read_bio_SSL_SESSION);
LSSL_USED(PEM_read_SSL_SESSION);
LSSL_USED(PEM_write_bio_SSL_SESSION);
LSSL_USED(PEM_write_SSL_SESSION);
LSSL_USED(SSL_CTX_set0_chain);
LSSL_USED(SSL_CTX_set1_chain);
LSSL_USED(SSL_CTX_add0_chain_cert);
LSSL_USED(SSL_CTX_add1_chain_cert);
LSSL_USED(SSL_CTX_get0_chain_certs);
LSSL_USED(SSL_CTX_clear_chain_certs);
LSSL_USED(SSL_set0_chain);
LSSL_USED(SSL_set1_chain);
LSSL_USED(SSL_add0_chain_cert);
LSSL_USED(SSL_add1_chain_cert);
LSSL_USED(SSL_get0_chain_certs);
LSSL_USED(SSL_clear_chain_certs);
LSSL_USED(SSL_CTX_set1_groups);
LSSL_USED(SSL_CTX_set1_groups_list);
LSSL_USED(SSL_set1_groups);
LSSL_USED(SSL_set1_groups_list);
LSSL_USED(SSL_CTX_get_min_proto_version);
LSSL_USED(SSL_CTX_get_max_proto_version);
LSSL_USED(SSL_CTX_set_min_proto_version);
LSSL_USED(SSL_CTX_set_max_proto_version);
LSSL_USED(SSL_get_min_proto_version);
LSSL_USED(SSL_get_max_proto_version);
LSSL_USED(SSL_set_min_proto_version);
LSSL_USED(SSL_set_max_proto_version);
LSSL_USED(SSL_CTX_get_ssl_method);
LSSL_USED(BIO_f_ssl);
LSSL_USED(BIO_new_ssl);
LSSL_USED(BIO_new_ssl_connect);
LSSL_USED(BIO_new_buffer_ssl_connect);
LSSL_USED(BIO_ssl_copy_session_id);
LSSL_USED(BIO_ssl_shutdown);
LSSL_USED(SSL_CTX_get_ciphers);
LSSL_USED(SSL_CTX_set_cipher_list);
LSSL_USED(SSL_CTX_set_ciphersuites);
LSSL_USED(SSL_CTX_new);
LSSL_USED(SSL_CTX_free);
LSSL_USED(SSL_CTX_up_ref);
LSSL_USED(SSL_CTX_set_timeout);
LSSL_USED(SSL_CTX_get_timeout);
LSSL_USED(SSL_CTX_get_cert_store);
LSSL_USED(SSL_CTX_set_cert_store);
LSSL_USED(SSL_CTX_get0_certificate);
LSSL_USED(SSL_CTX_get0_privatekey);
LSSL_USED(SSL_want);
LSSL_USED(SSL_clear);
LSSL_USED(SSL_CTX_flush_sessions);
LSSL_USED(SSL_get_current_cipher);
LSSL_USED(SSL_CIPHER_get_by_id);
LSSL_USED(SSL_CIPHER_get_by_value);
LSSL_USED(SSL_CIPHER_get_bits);
LSSL_USED(SSL_CIPHER_get_version);
LSSL_USED(SSL_CIPHER_get_name);
LSSL_USED(SSL_CIPHER_get_id);
LSSL_USED(SSL_CIPHER_get_value);
LSSL_USED(SSL_CIPHER_find);
LSSL_USED(SSL_CIPHER_get_cipher_nid);
LSSL_USED(SSL_CIPHER_get_digest_nid);
LSSL_USED(SSL_CIPHER_get_kx_nid);
LSSL_USED(SSL_CIPHER_get_auth_nid);
LSSL_USED(SSL_CIPHER_is_aead);
LSSL_USED(SSL_get_fd);
LSSL_USED(SSL_get_rfd);
LSSL_USED(SSL_get_wfd);
LSSL_USED(SSL_get_cipher_list);
LSSL_USED(SSL_get_shared_ciphers);
LSSL_USED(SSL_get_read_ahead);
LSSL_USED(SSL_pending);
LSSL_USED(SSL_set_fd);
LSSL_USED(SSL_set_rfd);
LSSL_USED(SSL_set_wfd);
LSSL_USED(SSL_set_bio);
LSSL_USED(SSL_get_rbio);
LSSL_USED(SSL_set0_rbio);
LSSL_USED(SSL_get_wbio);
LSSL_USED(SSL_set_cipher_list);
LSSL_USED(SSL_set_ciphersuites);
LSSL_USED(SSL_set_read_ahead);
LSSL_USED(SSL_get_verify_mode);
LSSL_USED(SSL_get_verify_depth);
LSSL_USED(SSL_get_verify_callback);
LSSL_USED(SSL_set_verify);
LSSL_USED(SSL_set_verify_depth);
LSSL_USED(SSL_use_RSAPrivateKey);
LSSL_USED(SSL_use_RSAPrivateKey_ASN1);
LSSL_USED(SSL_use_PrivateKey);
LSSL_USED(SSL_use_PrivateKey_ASN1);
LSSL_USED(SSL_use_certificate);
LSSL_USED(SSL_use_certificate_ASN1);
LSSL_USED(SSL_use_RSAPrivateKey_file);
LSSL_USED(SSL_use_PrivateKey_file);
LSSL_USED(SSL_use_certificate_file);
LSSL_USED(SSL_use_certificate_chain_file);
LSSL_USED(SSL_CTX_use_RSAPrivateKey_file);
LSSL_USED(SSL_CTX_use_PrivateKey_file);
LSSL_USED(SSL_CTX_use_certificate_file);
LSSL_USED(SSL_CTX_use_certificate_chain_file);
LSSL_USED(SSL_CTX_use_certificate_chain_mem);
LSSL_USED(SSL_load_client_CA_file);
LSSL_USED(SSL_add_file_cert_subjects_to_stack);
LSSL_USED(SSL_add_dir_cert_subjects_to_stack);
LSSL_USED(SSL_load_error_strings);
LSSL_USED(SSL_state_string);
LSSL_USED(SSL_rstate_string);
LSSL_USED(SSL_state_string_long);
LSSL_USED(SSL_rstate_string_long);
LSSL_USED(SSL_SESSION_get0_cipher);
LSSL_USED(SSL_SESSION_get_master_key);
LSSL_USED(SSL_SESSION_get_protocol_version);
LSSL_USED(SSL_SESSION_get_time);
LSSL_USED(SSL_SESSION_set_time);
LSSL_USED(SSL_SESSION_get_timeout);
LSSL_USED(SSL_SESSION_set_timeout);
LSSL_USED(SSL_copy_session_id);
LSSL_USED(SSL_SESSION_get0_peer);
LSSL_USED(SSL_SESSION_set1_id);
LSSL_USED(SSL_SESSION_set1_id_context);
LSSL_USED(SSL_SESSION_is_resumable);
LSSL_USED(SSL_SESSION_new);
LSSL_USED(SSL_SESSION_free);
LSSL_USED(SSL_SESSION_up_ref);
LSSL_USED(SSL_SESSION_get_id);
LSSL_USED(SSL_SESSION_get0_id_context);
LSSL_USED(SSL_SESSION_get_max_early_data);
LSSL_USED(SSL_SESSION_set_max_early_data);
LSSL_USED(SSL_SESSION_get_ticket_lifetime_hint);
LSSL_USED(SSL_SESSION_has_ticket);
LSSL_USED(SSL_SESSION_get_compress_id);
LSSL_USED(SSL_SESSION_print_fp);
LSSL_USED(SSL_SESSION_print);
LSSL_USED(i2d_SSL_SESSION);
LSSL_USED(SSL_set_session);
LSSL_USED(SSL_CTX_add_session);
LSSL_USED(SSL_CTX_remove_session);
LSSL_USED(SSL_CTX_set_generate_session_id);
LSSL_USED(SSL_set_generate_session_id);
LSSL_USED(SSL_has_matching_session_id);
LSSL_USED(d2i_SSL_SESSION);
LSSL_USED(SSL_get_peer_cert_chain);
LSSL_USED(SSL_CTX_get_verify_mode);
LSSL_USED(SSL_CTX_get_verify_depth);
LSSL_USED(SSL_CTX_get_verify_callback);
LSSL_USED(SSL_CTX_set_verify);
LSSL_USED(SSL_CTX_set_verify_depth);
LSSL_USED(SSL_CTX_set_cert_verify_callback);
LSSL_USED(SSL_CTX_use_RSAPrivateKey);
LSSL_USED(SSL_CTX_use_RSAPrivateKey_ASN1);
LSSL_USED(SSL_CTX_use_PrivateKey);
LSSL_USED(SSL_CTX_use_PrivateKey_ASN1);
LSSL_USED(SSL_CTX_use_certificate);
LSSL_USED(SSL_CTX_use_certificate_ASN1);
LSSL_USED(SSL_CTX_get_default_passwd_cb);
LSSL_USED(SSL_CTX_set_default_passwd_cb);
LSSL_USED(SSL_CTX_get_default_passwd_cb_userdata);
LSSL_USED(SSL_CTX_set_default_passwd_cb_userdata);
LSSL_USED(SSL_CTX_check_private_key);
LSSL_USED(SSL_check_private_key);
LSSL_USED(SSL_CTX_set_session_id_context);
LSSL_USED(SSL_set_session_id_context);
LSSL_USED(SSL_CTX_set_purpose);
LSSL_USED(SSL_set_purpose);
LSSL_USED(SSL_CTX_set_trust);
LSSL_USED(SSL_set_trust);
LSSL_USED(SSL_set1_host);
LSSL_USED(SSL_set_hostflags);
LSSL_USED(SSL_get0_peername);
LSSL_USED(SSL_CTX_get0_param);
LSSL_USED(SSL_CTX_set1_param);
LSSL_USED(SSL_get0_param);
LSSL_USED(SSL_set1_param);
LSSL_USED(SSL_new);
LSSL_USED(SSL_free);
LSSL_USED(SSL_up_ref);
LSSL_USED(SSL_accept);
LSSL_USED(SSL_connect);
LSSL_USED(SSL_is_dtls);
LSSL_USED(SSL_is_server);
LSSL_USED(SSL_read);
LSSL_USED(SSL_peek);
LSSL_USED(SSL_write);
LSSL_USED(SSL_read_ex);
LSSL_USED(SSL_peek_ex);
LSSL_USED(SSL_write_ex);
LSSL_USED(SSL_CTX_get_max_early_data);
LSSL_USED(SSL_CTX_set_max_early_data);
LSSL_USED(SSL_get_max_early_data);
LSSL_USED(SSL_set_max_early_data);
LSSL_USED(SSL_get_early_data_status);
LSSL_USED(SSL_read_early_data);
LSSL_USED(SSL_write_early_data);
LSSL_USED(SSL_ctrl);
LSSL_USED(SSL_callback_ctrl);
LSSL_USED(SSL_CTX_ctrl);
LSSL_USED(SSL_CTX_callback_ctrl);
LSSL_USED(SSL_get_error);
LSSL_USED(SSL_get_version);
LSSL_USED(SSL_CTX_set_ssl_version);
LSSL_USED(SSLv23_method);
LSSL_USED(SSLv23_server_method);
LSSL_USED(SSLv23_client_method);
LSSL_USED(TLSv1_method);
LSSL_USED(TLSv1_server_method);
LSSL_USED(TLSv1_client_method);
LSSL_USED(TLSv1_1_method);
LSSL_USED(TLSv1_1_server_method);
LSSL_USED(TLSv1_1_client_method);
LSSL_USED(TLSv1_2_method);
LSSL_USED(TLSv1_2_server_method);
LSSL_USED(TLSv1_2_client_method);
LSSL_USED(TLS_method);
LSSL_USED(TLS_server_method);
LSSL_USED(TLS_client_method);
LSSL_USED(DTLSv1_method);
LSSL_USED(DTLSv1_server_method);
LSSL_USED(DTLSv1_client_method);
LSSL_USED(DTLSv1_2_method);
LSSL_USED(DTLSv1_2_server_method);
LSSL_USED(DTLSv1_2_client_method);
LSSL_USED(DTLS_method);
LSSL_USED(DTLS_server_method);
LSSL_USED(DTLS_client_method);
LSSL_USED(SSL_get_ciphers);
LSSL_USED(SSL_get_client_ciphers);
LSSL_USED(SSL_get1_supported_ciphers);
LSSL_USED(SSL_do_handshake);
LSSL_USED(SSL_renegotiate);
LSSL_USED(SSL_renegotiate_abbreviated);
LSSL_USED(SSL_renegotiate_pending);
LSSL_USED(SSL_shutdown);
LSSL_USED(SSL_get_ssl_method);
LSSL_USED(SSL_set_ssl_method);
LSSL_USED(SSL_alert_type_string_long);
LSSL_USED(SSL_alert_type_string);
LSSL_USED(SSL_alert_desc_string_long);
LSSL_USED(SSL_alert_desc_string);
LSSL_USED(SSL_set_client_CA_list);
LSSL_USED(SSL_CTX_set_client_CA_list);
LSSL_USED(SSL_get_client_CA_list);
LSSL_USED(SSL_CTX_get_client_CA_list);
LSSL_USED(SSL_add_client_CA);
LSSL_USED(SSL_CTX_add_client_CA);
LSSL_USED(SSL_set_connect_state);
LSSL_USED(SSL_set_accept_state);
LSSL_USED(SSL_get_default_timeout);
LSSL_USED(SSL_library_init);
LSSL_USED(SSL_CIPHER_description);
LSSL_USED(SSL_dup_CA_list);
LSSL_USED(SSL_dup);
LSSL_USED(SSL_get_certificate);
LSSL_USED(SSL_get_privatekey);
LSSL_USED(SSL_CTX_set_quiet_shutdown);
LSSL_USED(SSL_CTX_get_quiet_shutdown);
LSSL_USED(SSL_set_quiet_shutdown);
LSSL_USED(SSL_get_quiet_shutdown);
LSSL_USED(SSL_set_shutdown);
LSSL_USED(SSL_get_shutdown);
LSSL_USED(SSL_version);
LSSL_USED(SSL_CTX_set_default_verify_paths);
LSSL_USED(SSL_CTX_load_verify_locations);
LSSL_USED(SSL_CTX_load_verify_mem);
LSSL_USED(SSL_get_session);
LSSL_USED(SSL_get1_session);
LSSL_USED(SSL_get_SSL_CTX);
LSSL_USED(SSL_set_SSL_CTX);
LSSL_USED(SSL_set_info_callback);
LSSL_USED(SSL_get_info_callback);
LSSL_USED(SSL_state);
LSSL_USED(SSL_set_state);
LSSL_USED(SSL_set_verify_result);
LSSL_USED(SSL_get_verify_result);
LSSL_USED(SSL_set_ex_data);
LSSL_USED(SSL_get_ex_data);
LSSL_USED(SSL_get_ex_new_index);
LSSL_USED(SSL_SESSION_set_ex_data);
LSSL_USED(SSL_SESSION_get_ex_data);
LSSL_USED(SSL_SESSION_get_ex_new_index);
LSSL_USED(SSL_CTX_set_ex_data);
LSSL_USED(SSL_CTX_get_ex_data);
LSSL_USED(SSL_CTX_get_ex_new_index);
LSSL_USED(SSL_get_ex_data_X509_STORE_CTX_idx);
LSSL_USED(SSL_CTX_set_tmp_rsa_callback);
LSSL_USED(SSL_set_tmp_rsa_callback);
LSSL_USED(SSL_CTX_set_tmp_dh_callback);
LSSL_USED(SSL_set_tmp_dh_callback);
LSSL_USED(SSL_CTX_set_tmp_ecdh_callback);
LSSL_USED(SSL_set_tmp_ecdh_callback);
LSSL_USED(SSL_get_client_random);
LSSL_USED(SSL_get_server_random);
LSSL_USED(SSL_get_current_compression);
LSSL_USED(SSL_get_current_expansion);
LSSL_USED(SSL_get_peer_certificate);
LSSL_USED(SSL_COMP_get_name);
LSSL_USED(SSL_COMP_get_compression_methods);
LSSL_USED(SSL_COMP_add_compression_method);
LSSL_USED(SSL_set_session_ticket_ext);
LSSL_USED(SSL_set_session_ticket_ext_cb);
LSSL_USED(SSL_set_session_secret_cb);
LSSL_USED(SSL_set_debug);
LSSL_USED(SSL_cache_hit);
LSSL_USED(SSL_set_security_level);
LSSL_USED(SSL_get_security_level);
LSSL_USED(SSL_CTX_set_security_level);
LSSL_USED(SSL_CTX_get_security_level);
LSSL_USED(SSL_CTX_set_quic_method);
LSSL_USED(SSL_CTX_sess_get_get_cb);
LSSL_USED(SSL_set_quic_method);
LSSL_USED(SSL_is_quic);
LSSL_USED(SSL_quic_max_handshake_flight_len);
LSSL_USED(SSL_quic_read_level);
LSSL_USED(SSL_quic_write_level);
LSSL_USED(SSL_provide_quic_data);
LSSL_USED(SSL_process_quic_post_handshake);
LSSL_USED(SSL_set_quic_transport_params);
LSSL_USED(SSL_get_peer_quic_transport_params);
LSSL_USED(SSL_set_quic_use_legacy_codepoint);
LSSL_USED(ERR_load_SSL_strings);
LSSL_USED(OPENSSL_init_ssl);

#endif /* _LIBSSL_SSL_H */
