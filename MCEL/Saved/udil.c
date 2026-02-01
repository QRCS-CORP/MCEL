#include "udil.h"
#include "dilithium.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

//void be16(uint8_t out[2], uint16_t x) { out[0] = (uint8_t)(x >> 8); out[1] = (uint8_t)x; }
//void be32(uint8_t out[4], uint32_t x) { out[0] = x >> 24; out[1] = x >> 16; out[2] = x >> 8; out[3] = x; }
//void be64(uint8_t out[8], uint64_t x) {
//    out[0] = x >> 56; out[1] = x >> 48; out[2] = x >> 40; out[3] = x >> 32;
//    out[4] = x >> 24; out[5] = x >> 16; out[6] = x >> 8;  out[7] = x;
//}
//
//static void hash_shake(uint8_t out[UDIL_HASHLEN], const uint8_t* in, size_t inlen)
//{
//    qsc_shake256_compute(out, UDIL_HASHLEN, in, inlen);
//}
//
//static void hash_tagged(uint8_t out[UDIL_HASHLEN], const uint8_t* tag, size_t taglen, const uint8_t* msg, size_t msglen)
//{
//    uint8_t* buf = (uint8_t*)malloc(taglen + msglen);
//    qsc_memutils_copy(buf, tag, taglen);
//    qsc_memutils_copy(buf + taglen, msg, msglen);
//    hash_shake(out, buf, taglen + msglen);
//    free(buf);
//}
//
//
//int32_t udil_audit_detect_equivocation(const udil_checkpoint_body* a, const uint8_t a_commit[UDIL_HASHLEN], const udil_checkpoint_body* b, const uint8_t b_commit[UDIL_HASHLEN])
//{
//    // Same ledger and epoch, overlapping sequence ranges, different root or commit
//    if (memcmp(a->ledger_id, b->ledger_id, UDIL_HASHLEN) != 0) return 0;
//    if (a->epoch != b->epoch) return 0;
//
//    uint64_t s = (a->start_seq > b->start_seq) ? a->start_seq : b->start_seq;
//    uint64_t e = (a->end_seq < b->end_seq) ? a->end_seq : b->end_seq;
//
//    if (s <= e) {
//        if (memcmp(a->batch_root, b->batch_root, UDIL_HASHLEN) != 0) return 1; // equivocation evidence
//        if (memcmp(a_commit, b_commit, UDIL_HASHLEN) != 0) return 1;
//    }
//
//    return 0;
//}
//
//int32_t udil_audit_sample_inclusion(const uint8_t checkpoint_root[UDIL_HASHLEN], const uint8_t rec_commit[UDIL_HASHLEN], const udil_merkle_proof* proof)
//{
//    uint8_t r[UDIL_HASHLEN];
//    udil_merkle_verify(r, rec_commit, proof);
//    return (memcmp(r, checkpoint_root, UDIL_HASHLEN) == 0) ? 0 : -1;
//}
//
//void udil_compute_checkpoint_commit(uint8_t out[UDIL_HASHLEN], const udil_checkpoint_body* c)
//{
//    size_t blen = 0;
//    uint8_t* b = udil_serialize_checkpoint_body(c, &blen);
//    hash_tagged(out, TAG_CHK, sizeof(TAG_CHK) - 1, b, blen);
//    free(b);
//}
//
//void udil_compute_env_hash(uint8_t out[UDIL_HASHLEN], const uint8_t* env_bytes, size_t env_len)
//{
//    hash_tagged(out, TAG_ENV, sizeof(TAG_ENV) - 1, env_bytes, env_len);
//}
//
//void udil_compute_payload_hash(uint8_t out[UDIL_HASHLEN], const uint8_t* pay_bytes, size_t pay_len)
//{
//    hash_tagged(out, TAG_PAY, sizeof(TAG_PAY) - 1, pay_bytes, pay_len);
//}
//
//void udil_compute_record_commit(uint8_t out[UDIL_HASHLEN], const udil_record_hdr* h)
//{
//    size_t blen = 0;
//    uint8_t* b = udil_serialize_record_header(h, &blen);
//    hash_tagged(out, TAG_REC, sizeof(TAG_REC) - 1, b, blen);
//    free(b);
//}
//
//int32_t udil_ledger_admin_reset(udil_ledger_state* st, const uint8_t* reset_reason, size_t reason_len)
//{
//    // Append ADMIN record that includes reset_reason and references last checkpoint commit.
//    // Then bump epoch and reinitialize storage if required.
//    // Exact policy depends on governance.
//    return 0;
//}
//
//int32_t udil_ledger_append(udil_ledger_state* st, udil_record_type rtype, const uint8_t env_hash[UDIL_HASHLEN], const uint8_t pay_hash[UDIL_HASHLEN], 
//    const uint8_t corr_id[16], const uint8_t* body, size_t body_len, uint8_t* out_rec_commit)
//{
//    uint8_t rec_commit[UDIL_HASHLEN] = { 0U };
//    udil_record_hdr h;
//
//    memset(&h, 0, sizeof(h));
//    h.version = 1;
//    h.rtype = (uint16_t)rtype;
//    qsc_memutils_copy(h.ledger_id, st->ledger_id, UDIL_HASHLEN);
//    h.epoch = st->epoch;
//
//    h.seq = st->head_seq + 1;
//    h.time = now_unix_ms();
//    qsc_memutils_copy(h.prev_hash, st->head_hash, UDIL_HASHLEN);
//
//    if (env_hash) // TODO: are any of these ever null?
//        qsc_memutils_copy(h.env_hash, env_hash, UDIL_HASHLEN);
//    if (pay_hash) 
//        qsc_memutils_copy(h.pay_hash, pay_hash, UDIL_HASHLEN);
//    if (corr_id)  
//        qsc_memutils_copy(h.corr_id, corr_id, 16);
//
//
//    udil_compute_record_commit(rec_commit, &h);
//
//    uint8_t sig[2048];
//    size_t siglen = 0;
//    udil_sign_record(sig, &siglen, st->udif_signing_key, rec_commit);
//
//    // Container serialization: [hdr_len|hdr|body_len|body|sig_len|sig]
//    // Define this format once and keep it stable.
//    size_t hdr_len = 0;
//    uint8_t* hdr_bytes = udil_serialize_record_header(&h, &hdr_len);
//
//    uint8_t lenbuf[4];
//    size_t total = 4 + hdr_len + 4 + body_len + 4 + siglen;
//    uint8_t* blob = (uint8_t*)malloc(total);
//    size_t o = 0;
//
//    be32(lenbuf, (uint32_t)hdr_len); qsc_memutils_copy(blob + o, lenbuf, 4); o += 4;
//    qsc_memutils_copy(blob + o, hdr_bytes, hdr_len); o += hdr_len;
//
//    be32(lenbuf, (uint32_t)body_len); qsc_memutils_copy(blob + o, lenbuf, 4); o += 4;
//    if (body_len) { qsc_memutils_copy(blob + o, body, body_len); o += body_len; }
//
//    be32(lenbuf, (uint32_t)siglen); qsc_memutils_copy(blob + o, lenbuf, 4); o += 4;
//    qsc_memutils_copy(blob + o, sig, siglen); o += siglen;
//
//    int32_t rc = store_append(st->store, blob, total);
//
//    free(hdr_bytes);
//    free(blob);
//
//    if (rc != 0) return rc;
//
//    st->head_seq = h.seq;
//    qsc_memutils_copy(st->head_hash, rec_commit, UDIL_HASHLEN);
//    store_set_head(st->store, st->head_seq, st->head_hash);
//
//    if (out_rec_commit) 
//        qsc_memutils_copy(out_rec_commit, rec_commit, UDIL_HASHLEN);
//
//    return 0;
//}
//
//int32_t udil_ledger_append_anchor_reference(udil_ledger_state* st, const udil_anchor_ref* a)
//{
//    size_t blen = 0;
//    uint8_t* b = udil_serialize_anchor_reference(a, &blen);
//    int32_t rc = udil_ledger_append(st, RTYPE_ANCHOR_REF, NULL, NULL, NULL, b, blen, NULL);
//    free(b);
//    return rc;
//}
//
//int32_t udil_ledger_build_checkpoint_body(udil_ledger_state* st, uint64_t start_seq, uint64_t end_seq, udil_checkpoint_body* out_body)
//{
//    if (start_seq == 0 || end_seq < start_seq || end_seq > st->head_seq)
//        return -1;
//
//    size_t count = (size_t)(end_seq - start_seq + 1);
//
//    // Read records and compute their rec_commit values
//    uint8_t* commits = (uint8_t*)malloc(count * UDIL_HASHLEN);
//
//    for (size_t i = 0; i < count; i++) {
//        uint64_t seq = start_seq + (uint64_t)i;
//        uint8_t* blob = NULL; size_t blen = 0;
//
//        if (store_read_by_seq(st->store, seq, &blob, &blen) != 0) { free(commits); return -2; }
//
//        // Parse hdr, recompute commitment (no need to verify signature for local checkpointing)
//        udil_record_hdr h;
//        uint8_t* body = NULL; size_t body_len = 0;
//        uint8_t* sig = NULL; size_t sig_len = 0;
//        if (udil_ledger_parse_record(blob, blen, &h, &body, &body_len, &sig, &sig_len) != 0) {
//            free(blob); free(commits); return -3;
//        }
//
//        uint8_t rc[UDIL_HASHLEN];
//        udil_compute_record_commit(rc, &h);
//        qsc_memutils_copy(commits + i * UDIL_HASHLEN, rc, UDIL_HASHLEN);
//
//        free(body); free(sig); free(blob);
//    }
//
//    uint8_t root[UDIL_HASHLEN];
//    udil_merkle_root(root, commits, count);
//    free(commits);
//
//    memset(out_body, 0, sizeof(*out_body));
//    out_body->body_version = 1;
//    qsc_memutils_copy(out_body->ledger_id, st->ledger_id, UDIL_HASHLEN);
//    out_body->epoch = st->epoch;
//    out_body->start_seq = start_seq;
//    out_body->end_seq = end_seq;
//    out_body->record_count = (uint32_t)count;
//    qsc_memutils_copy(out_body->batch_root, root, UDIL_HASHLEN);
//    qsc_memutils_copy(out_body->prev_checkpoint_commit, st->last_checkpoint_commit, UDIL_HASHLEN);
//    out_body->created_time = now_unix_ms();
//    out_body->flags = 0;
//    memset(out_body->reserved, 0, 16);
//
//    return 0;
//}
//
//int32_t udil_ledger_build_inclusion_proof(udil_ledger_state* st, uint64_t start_seq, uint64_t end_seq, uint64_t target_seq, udil_merkle_proof* out_proof,
//    uint8_t out_rec_commit[UDIL_HASHLEN], uint8_t out_root[UDIL_HASHLEN])
//{
//    if (target_seq < start_seq || target_seq > end_seq) return -1;
//
//    size_t count = (size_t)(end_seq - start_seq + 1);
//    size_t idx = (size_t)(target_seq - start_seq);
//
//    // Compute leaf hashes for each record in range
//    uint8_t* level = (uint8_t*)malloc(count * UDIL_HASHLEN);
//
//    for (size_t i = 0; i < count; i++) {
//        uint64_t seq = start_seq + (uint64_t)i;
//        uint8_t* blob = NULL; size_t blen = 0;
//        if (store_read_by_seq(st->store, seq, &blob, &blen) != 0) { free(level); return -2; }
//
//        udil_record_hdr h;
//        uint8_t* body = NULL; size_t body_len = 0;
//        uint8_t* sig = NULL; size_t sig_len = 0;
//        if (udil_ledger_parse_record(blob, blen, &h, &body, &body_len, &sig, &sig_len) != 0) {
//            free(blob); free(level); return -3;
//        }
//
//        uint8_t rc[UDIL_HASHLEN];
//        udil_compute_record_commit(rc, &h);
//
//        if (i == idx) qsc_memutils_copy(out_rec_commit, rc, UDIL_HASHLEN);
//
//        udil_merkle_leaf(level + i * UDIL_HASHLEN, rc);
//
//        free(body); free(sig); free(blob);
//    }
//
//    // Build proof up the tree
//    out_proof->depth = 0;
//    size_t level_count = count;
//    size_t pos = idx;
//
//    while (level_count > 1) {
//        size_t sibling_pos = (pos ^ 1);
//
//        if (sibling_pos < level_count) {
//            qsc_memutils_copy(out_proof->siblings[out_proof->depth], level + sibling_pos * UDIL_HASHLEN, UDIL_HASHLEN);
//        }
//        else {
//            // sibling is itself in odd duplication
//            qsc_memutils_copy(out_proof->siblings[out_proof->depth], level + pos * UDIL_HASHLEN, UDIL_HASHLEN);
//        }
//
//        // direction indicates where sibling sits relative to current node
//        // If pos is even, current is left, sibling on right => directions=0
//        // If pos is odd, current is right, sibling on left => directions=1
//        out_proof->directions[out_proof->depth] = (pos & 1) ? 1 : 0;
//        out_proof->depth++;
//
//        // Compute next level
//        size_t next_count = (level_count + 1) / 2;
//        uint8_t* next = (uint8_t*)malloc(next_count * UDIL_HASHLEN);
//
//        for (size_t i = 0; i < next_count; i++) {
//            uint8_t* L = level + (2 * i) * UDIL_HASHLEN;
//            uint8_t* R = ((2 * i + 1) < level_count) ? (level + (2 * i + 1) * UDIL_HASHLEN) : L;
//            udil_merkle_parent(next + i * UDIL_HASHLEN, L, R);
//        }
//
//        free(level);
//        level = next;
//
//        pos /= 2;
//        level_count = next_count;
//    }
//
//    qsc_memutils_copy(out_root, level, UDIL_HASHLEN);
//    free(level);
//    return 0;
//}
//
//int32_t udil_ledger_initialize(udil_ledger_state* st, const uint8_t ledger_id[UDIL_HASHLEN], uint32_t epoch, void* udif_signing_key, void* store)
//{
//    memset(st, 0, sizeof(*st));
//    qsc_memutils_copy(st->ledger_id, ledger_id, UDIL_HASHLEN);
//    st->epoch = epoch;
//    st->udif_signing_key = udif_signing_key;
//    st->store = store;
//
//    // Load head from storage, or set genesis
//    if (store_get_head(store, &st->head_seq, st->head_hash) != 0) 
//    {
//        st->head_seq = 0;
//        memset(st->head_hash, 0, UDIL_HASHLEN);
//        store_set_head(store, st->head_seq, st->head_hash);
//    }
//
//    // Load last checkpoint reference if present
//    store_find_last_checkpoint(store, st->last_checkpoint_commit, &st->last_checkpoint_end_seq);
//
//    return 0; // Todo: fix this
//}
//
//int32_t udil_ledger_issue_checkpoint(udil_ledger_state* st, uint64_t start_seq, uint64_t end_seq, uint8_t out_chk_commit[UDIL_HASHLEN])
//{
//    udil_checkpoint_body body;
//    int32_t rc = udil_ledger_build_checkpoint_body(st, start_seq, end_seq, &body);
//    if (rc != 0) return rc;
//
//    udil_compute_checkpoint_commit(out_chk_commit, &body);
//
//    // Optional: store a checkpoint signature inside the body blob, or store it as part of the record body.
//    // Here we store (body || chk_sig || signer_id) as the checkpoint record body.
//
//    uint8_t chk_sig[2048]; size_t chk_siglen = 0;
//    udil_sign_checkpoint(chk_sig, &chk_siglen, st->udif_signing_key, out_chk_commit);
//
//    // signer_id = H("UDIL/ID" || signer_cert_pubbytes) or similar.
//    // For now, store a placeholder 32 bytes, or omit if you store cert elsewhere.
//    uint8_t signer_id[UDIL_HASHLEN]; memset(signer_id, 0, UDIL_HASHLEN);
//
//    size_t body_bytes_len = 0;
//    uint8_t* body_bytes = udil_serialize_checkpoint_body(&body, &body_bytes_len);
//
//    uint8_t lenbuf[4];
//    size_t packed_len = body_bytes_len + 4 + chk_siglen + UDIL_HASHLEN;
//    uint8_t* packed = (uint8_t*)malloc(packed_len);
//    size_t o = 0;
//
//    qsc_memutils_copy(packed + o, body_bytes, body_bytes_len); o += body_bytes_len;
//    be32(lenbuf, (uint32_t)chk_siglen); qsc_memutils_copy(packed + o, lenbuf, 4); o += 4;
//    qsc_memutils_copy(packed + o, chk_sig, chk_siglen); o += chk_siglen;
//    qsc_memutils_copy(packed + o, signer_id, UDIL_HASHLEN); o += UDIL_HASHLEN;
//
//    // Append checkpoint record, env_hash/pay_hash not used
//    rc = udil_ledger_append(st, RTYPE_CHECKPOINT, NULL, NULL, NULL, packed, packed_len, NULL);
//
//    free(body_bytes);
//    free(packed);
//
//    if (rc != 0) return rc;
//
//    // Update local state
//    st->last_checkpoint_end_seq = end_seq;
//    qsc_memutils_copy(st->last_checkpoint_commit, out_chk_commit, UDIL_HASHLEN);
//
//    return 0;
//}
//
//int32_t udil_ledger_parse_record(const uint8_t* blob, size_t blob_len, udil_record_hdr* out_hdr, uint8_t** out_body, size_t* out_body_len, uint8_t** out_sig, size_t* out_sig_len)
//{
//    // Implement parsing of [hdr_len|hdr|body_len|body|sig_len|sig]
//    // Validate lengths, allocate body and sig for caller, fill out_hdr from hdr bytes
//    // Also needed: deserialize_record_hdr() (inverse of udil_serialize_record_header)
//    return 0;
//}
//
//int32_t udil_ledger_rotate_key(udil_ledger_state* st, void* new_udif_signing_key)
//{
//    st->udif_signing_key = new_udif_signing_key;
//    st->epoch += 1;
//
//    // Immediately issue a checkpoint that chains from previous checkpoint commit
//    // Typically from last_checkpoint_end_seq+1 to head_seq, if there are pending records
//    if (st->last_checkpoint_end_seq < st->head_seq) {
//        uint64_t start = st->last_checkpoint_end_seq + 1;
//        uint64_t end = st->head_seq;
//        uint8_t chk_commit[UDIL_HASHLEN];
//        return udil_ledger_issue_checkpoint(st, start, end, chk_commit);
//    }
//    return 0;
//}
//
//int32_t udil_ledger_verify_record_blob(const uint8_t* blob, size_t blob_len, const uint8_t* signer_cert, size_t cert_len, uint8_t out_rec_commit[UDIL_HASHLEN])
//{
//    udil_record_hdr h;
//    uint8_t* body = NULL; size_t body_len = 0;
//    uint8_t* sig = NULL; size_t sig_len = 0;
//
//    if (udil_ledger_parse_record(blob, blob_len, &h, &body, &body_len, &sig, &sig_len) != 0)
//        return -1;
//
//    udil_compute_record_commit(out_rec_commit, &h);
//
//    int32_t ok = udil_verify_record_signature(signer_cert, cert_len, out_rec_commit, sig, sig_len);
//
//    free(body);
//    free(sig);
//    return ok ? 0 : -2;
//}
//
//void udil_merkle_leaf(uint8_t out[UDIL_HASHLEN], const uint8_t rec_commit[UDIL_HASHLEN])
//{
//    uint8_t buf[sizeof(TAG_LEAF) - 1 + UDIL_HASHLEN];
//
//    qsc_memutils_copy(buf, TAG_LEAF, sizeof(TAG_LEAF) - 1);
//    qsc_memutils_copy(buf + sizeof(TAG_LEAF) - 1, rec_commit, UDIL_HASHLEN);
//
//    hash_shake(out, buf, sizeof(buf));
//}
//
//void udil_merkle_parent(uint8_t out[UDIL_HASHLEN], const uint8_t left[UDIL_HASHLEN], const uint8_t right[UDIL_HASHLEN])
//{
//    uint8_t buf[sizeof(TAG_NODE) - 1 + 2 * UDIL_HASHLEN];
//
//    qsc_memutils_copy(buf, TAG_NODE, sizeof(TAG_NODE) - 1);
//    qsc_memutils_copy(buf + sizeof(TAG_NODE) - 1, left, UDIL_HASHLEN);
//    qsc_memutils_copy(buf + sizeof(TAG_NODE) - 1 + UDIL_HASHLEN, right, UDIL_HASHLEN);
//
//    hash_shake(out, buf, sizeof(buf));
//}
//
//void udil_merkle_root(uint8_t root[UDIL_HASHLEN], const uint8_t* rec_commits, size_t count)
//{
//    if (count == 0) {
//        memset(root, 0, UDIL_HASHLEN);
//        return;
//    }
//
//    size_t level_count = count;
//    uint8_t* level = malloc(level_count * UDIL_HASHLEN);
//
//    // Compute leaf level
//    for (size_t i = 0; i < count; i++) {
//        udil_merkle_leaf(level + i * UDIL_HASHLEN,
//            rec_commits + i * UDIL_HASHLEN);
//    }
//
//    // Build tree upward
//    while (level_count > 1) {
//        size_t next_count = (level_count + 1) / 2;
//        uint8_t* next = malloc(next_count * UDIL_HASHLEN);
//
//        for (size_t i = 0; i < next_count; i++) {
//            const uint8_t* left = level + (2 * i) * UDIL_HASHLEN;
//            const uint8_t* right;
//
//            if (2 * i + 1 < level_count) {
//                right = level + (2 * i + 1) * UDIL_HASHLEN;
//            }
//            else {
//                // duplicate last node if odd
//                right = left;
//            }
//
//            udil_merkle_parent(next + i * UDIL_HASHLEN, left, right);
//        }
//
//        free(level);
//        level = next;
//        level_count = next_count;
//    }
//
//    qsc_memutils_copy(root, level, UDIL_HASHLEN);
//    free(level);
//}
//
//void udil_merkle_verify(uint8_t out_root[UDIL_HASHLEN], const uint8_t rec_commit[UDIL_HASHLEN], const udil_merkle_proof* proof)
//{
//    uint8_t h[UDIL_HASHLEN];
//    udil_merkle_leaf(h, rec_commit);
//
//    for (size_t i = 0; i < proof->depth; i++) {
//        uint8_t tmp[UDIL_HASHLEN];
//        if (proof->directions[i] == 0) udil_merkle_parent(tmp, h, proof->siblings[i]);
//        else                          udil_merkle_parent(tmp, proof->siblings[i], h);
//        qsc_memutils_copy(h, tmp, UDIL_HASHLEN);
//    }
//    qsc_memutils_copy(out_root, h, UDIL_HASHLEN);
//}
//
//uint8_t* udil_serialize_anchor_reference(const udil_anchor_ref* a, size_t* out_len)
//{
//    const size_t L = 2 + UDIL_HASHLEN + 2 + 32 + 8 + 16;
//    uint8_t* b = (uint8_t*)malloc(L);
//    size_t o = 0;
//    be16(b + o, a->version); o += 2;
//    qsc_memutils_copy(b + o, a->chk_commit, UDIL_HASHLEN); o += UDIL_HASHLEN;
//    be16(b + o, a->anchor_type); o += 2;
//    qsc_memutils_copy(b + o, a->anchor_id, 32); o += 32;
//    be64(b + o, a->anchored_time); o += 8;
//    qsc_memutils_copy(b + o, a->reserved, 16); o += 16;
//    *out_len = L;
//    return b;
//}
//
//uint8_t* udil_serialize_checkpoint_body(const udil_checkpoint_body* c, size_t* out_len)
//{
//    // Fixed size 150 bytes as specified
//    const size_t L = 150;
//    uint8_t* b = (uint8_t*)malloc(L);
//    size_t o = 0;
//
//    be16(b + o, c->body_version); 
//    o += 2;
//    qsc_memutils_copy(b + o, c->ledger_id, UDIL_HASHLEN); o += UDIL_HASHLEN;
//    be32(b + o, c->epoch); 
//    o += 4;
//    be64(b + o, c->start_seq); 
//    o += 8;
//    be64(b + o, c->end_seq); 
//    o += 8;
//    be32(b + o, c->record_count);
//    o += 4;
//    qsc_memutils_copy(b + o, c->batch_root, UDIL_HASHLEN); 
//    o += UDIL_HASHLEN;
//    qsc_memutils_copy(b + o, c->prev_checkpoint_commit, UDIL_HASHLEN); 
//    o += UDIL_HASHLEN;
//    be64(b + o, c->created_time); 
//    o += 8;
//    be32(b + o, c->flags); 
//    o += 4;
//    qsc_memutils_copy(b + o, c->reserved, 16); 
//    o += 16;
//
//    *out_len = L;
//    return b;
//}
//
//uint8_t* udil_serialize_record_header(const udil_record_hdr* h, size_t* out_len)
//{
//    // Fixed size: 2+2 +32 +4 +8+8 +32 +32 +32 +16 +4 = 172 bytes
//    const size_t L = 172U;
//    uint8_t* b = (uint8_t*)malloc(L); // TODO: fix this
//    size_t o = 0U;
//
//    be16(b + o, h->version); 
//    o += 2;
//    be16(b + o, h->rtype);   
//    o += 2;
//
//    qsc_memutils_copy(b + o, h->ledger_id, UDIL_HASHLEN); 
//    o += UDIL_HASHLEN;
//    be32(b + o, h->epoch); 
//    o += 4;
//
//    be64(b + o, h->seq);  
//    o += 8;
//    be64(b + o, h->time); 
//    o += 8;
//
//    qsc_memutils_copy(b + o, h->prev_hash, UDIL_HASHLEN); 
//    o += UDIL_HASHLEN;
//
//    qsc_memutils_copy(b + o, h->env_hash, UDIL_HASHLEN); 
//    o += UDIL_HASHLEN;
//    qsc_memutils_copy(b + o, h->pay_hash, UDIL_HASHLEN); 
//    o += UDIL_HASHLEN;
//
//    qsc_memutils_copy(b + o, h->corr_id, 16); 
//    o += 16;
//
//    be32(b + o, h->flags);
//    o += 4;
//    *out_len = L;
//
//    return b;
//}
//
//void udil_sign_checkpoint(uint8_t* out_sig, size_t* out_siglen, void* udif_key, const uint8_t chk_commit[UDIL_HASHLEN])
//{
//    uint8_t sig_input[UDIL_HASHLEN];
//    hash_tagged(sig_input, TAG_SIG_CHK, sizeof(TAG_SIG_CHK) - 1, chk_commit, UDIL_HASHLEN);
//    udif_sign(udif_key, sig_input, UDIL_HASHLEN, out_sig, out_siglen);
//}
//
//void udil_sign_record(uint8_t out_sig[], size_t* out_siglen, void* udif_key, const uint8_t rec_commit[UDIL_HASHLEN])
//{
//    uint8_t sig_input[UDIL_HASHLEN];
//    hash_tagged(sig_input, TAG_SIG_REC, sizeof(TAG_SIG_REC) - 1, rec_commit, UDIL_HASHLEN);
//
//    // UDIF signing primitive (placeholder):
//    // udif_sign(udif_key, sig_input, UDIL_HASHLEN, out_sig, out_siglen);
//    udif_sign(udif_key, sig_input, UDIL_HASHLEN, out_sig, out_siglen);
//}
//
////int32_t udil_verify_checkpoint_signature(const uint8_t* cert, size_t cert_len, const uint8_t chk_commit[UDIL_HASHLEN], const uint8_t* sig, size_t siglen)
////{
////    uint8_t sig_input[UDIL_HASHLEN];
////    hash_tagged(sig_input, TAG_SIG_CHK, sizeof(TAG_SIG_CHK) - 1, chk_commit, UDIL_HASHLEN);
////    return udil_verify(cert, cert_len, sig_input, UDIL_HASHLEN, sig, siglen);
////}
//
//int32_t udil_verify_record_signature(const uint8_t* cert, size_t cert_len, const uint8_t rec_commit[UDIL_HASHLEN], const uint8_t* sig, size_t siglen)
//{
//    uint8_t sig_input[UDIL_HASHLEN];
//    hash_tagged(sig_input, TAG_SIG_REC, sizeof(TAG_SIG_REC) - 1, rec_commit, UDIL_HASHLEN);
//    return udif_verify(cert, cert_len, sig_input, UDIL_HASHLEN, sig, siglen);
//}
//
//bool udil_ledger_selftest()
//{
//
//}

//int32_t udil_ledger_basic_selftest(udil_ledger_state* st, const uint8_t ledger_id[UDIL_HASHLEN], void* udif_signing_key, void* store, const uint8_t* signer_cert, size_t cert_len)
//{
//    int32_t rc;
//    udil_ledger_state ledger;
//    uint8_t ledger_id[UDIL_HASHLEN];
//
//    memset(ledger_id, 0x01, sizeof(ledger_id));
//
//    void* signing_key = udif_load_signing_key();
//    void* store = udil_store_create();
//
//    size_t cert_len = 0;
//    const uint8_t* signer_cert = udif_load_signer_cert(&cert_len);
//
//    /* ------------------------------------------------------------------
//     * 1. Initialize ledger
//     * ------------------------------------------------------------------ */
//    rc = udil_ledger_initialize(st, ledger_id, 1, udif_signing_key, store);
//    if (rc != 0) {
//        return rc;
//    }
//
//    /* ------------------------------------------------------------------
//     * 2. Prepare dummy envelope and payload hashes
//     * ------------------------------------------------------------------ */
//    uint8_t env_hash[UDIL_HASHLEN];
//    uint8_t pay_hash[UDIL_HASHLEN];
//    uint8_t corr_id[16];
//
//    memset(env_hash, 0xA1, UDIL_HASHLEN);
//    memset(pay_hash, 0xB2, UDIL_HASHLEN);
//    memset(corr_id, 0xC3, sizeof(corr_id));
//
//    /* ------------------------------------------------------------------
//     * 3. Append a single MESSAGE record
//     * ------------------------------------------------------------------ */
//    const uint8_t body[] = "test-record";
//    uint8_t rec_commit[UDIL_HASHLEN];
//
//    rc = udil_ledger_append(st,
//        UDIL_RTYPE_MESSAGE,
//        env_hash,
//        pay_hash,
//        corr_id,
//        body,
//        sizeof(body),
//        rec_commit);
//    if (rc != 0) {
//        return rc;
//    }
//
//    /* ------------------------------------------------------------------
//     * 4. Read the stored record blob back
//     * ------------------------------------------------------------------ */
//    uint8_t* blob = NULL;
//    size_t blob_len = 0;
//
//    rc = store_read_by_seq(store, 1, &blob, &blob_len);
//    if (rc != 0) {
//        return rc;
//    }
//
//    /* ------------------------------------------------------------------
//     * 5. Parse the record blob
//     * ------------------------------------------------------------------ */
//    udil_record_hdr hdr;
//    uint8_t* out_body = NULL;
//    size_t out_body_len = 0;
//    uint8_t* out_sig = NULL;
//    size_t out_sig_len = 0;
//
//    rc = udil_ledger_parse_record(blob,
//        blob_len,
//        &hdr,
//        &out_body,
//        &out_body_len,
//        &out_sig,
//        &out_sig_len);
//    if (rc != 0) {
//        free(blob);
//        return rc;
//    }
//
//    /* ------------------------------------------------------------------
//     * 6. Verify record signature and recompute commitment
//     * ------------------------------------------------------------------ */
//    uint8_t verify_commit[UDIL_HASHLEN];
//
//    rc = udil_ledger_verify_record_blob(blob,
//        blob_len,
//        signer_cert,
//        cert_len,
//        verify_commit);
//    if (rc != 0) {
//        free(blob);
//        free(out_body);
//        free(out_sig);
//        return rc;
//    }
//
//    /* ------------------------------------------------------------------
//     * 7. Compare commitments
//     * ------------------------------------------------------------------ */
//    if (memcmp(rec_commit, verify_commit, UDIL_HASHLEN) != 0) {
//        free(blob);
//        free(out_body);
//        free(out_sig);
//        return -1;
//    }
//
//    /* ------------------------------------------------------------------
//     * 8. Cleanup
//     * ------------------------------------------------------------------ */
//    free(blob);
//    free(out_body);
//    free(out_sig);
//
//    return 0;
//}
