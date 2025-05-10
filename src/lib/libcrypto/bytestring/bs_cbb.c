/*	$OpenBSD: bs_cbb.c,v 1.30 2024/06/22 15:25:06 jsing Exp $	*/
/*
 * Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "bytestring.h"

#define CBB_INITIAL_SIZE 64

// TODO
void CBB_zero(CBB *cbb) { memset(cbb, 0, sizeof(CBB)); }

static int
cbb_init(CBB *cbb, uint8_t *buf, size_t cap, int can_resize)
{
	cbb->is_child = 0;
	cbb->child = NULL;
	cbb->u.base.buf = buf;
	cbb->u.base.len = 0;
	cbb->u.base.cap = cap;
	cbb->u.base.can_resize = can_resize;
	cbb->u.base.error = 0;

	return 1;
}

int
CBB_init(CBB *cbb, size_t initial_capacity)
{
	uint8_t *buf = NULL;

	memset(cbb, 0, sizeof(*cbb));

	if (initial_capacity == 0)
		initial_capacity = CBB_INITIAL_SIZE;

	if ((buf = calloc(1, initial_capacity)) == NULL)
		return 0;

	cbb_init(cbb, buf, initial_capacity, /*can_resize=*/1);

	return 1;
}

int
CBB_init_fixed(CBB *cbb, uint8_t *buf, size_t len)
{
	CBB_zero(cbb);
	cbb_init(cbb, buf, len, 0);
	return 1;
}

void
CBB_cleanup(CBB *cbb)
{
	// Child |CBB|s are non-owning. They are implicitly discarded and should not
	// be used with |CBB_cleanup| or |ScopedCBB|.
	//
	assert(!cbb->is_child);
	if (cbb->is_child) {
		return;
	}

	if (cbb->u.base.can_resize) {
		free(cbb->u.base.buf);
	}
}

static int cbb_buffer_reserve(struct cbb_buffer_st *base, uint8_t **out,
                              size_t len) {
	if (base == NULL) {
		return 0;
	}

	size_t newlen = base->len + len;
	if (newlen < base->len) {
		// Overflow
		goto err;
	}

	if (newlen > base->cap) {
		if (!base->can_resize) {
			// XXX:
			goto err;
		}

		size_t newcap = base->cap * 2;
		if (newcap < base->cap || newcap < newlen) {
			newcap = newlen;
		}

		uint8_t *newbuf = recallocarray(base->buf, base->cap, newcap, 1);
		if (newbuf == NULL) {
			goto err;
		}

		base->buf = newbuf;
		base->cap = newcap;
	}

	if (out) {
		*out = base->buf + base->len;
	}

	return 1;

  err:
	base->error = 1;
	return 0;
}




static int
cbb_buffer_add(struct cbb_buffer_st *base, uint8_t **out, size_t len)
{
	if (!cbb_buffer_reserve(base, out, len)) {
		return 0;
	}
	// This will not overflow or |cbb_buffer_reserve| would have failed.
	base->len += len;
	return 1;
}

int CBB_finish(CBB *cbb, uint8_t **out_data, size_t *out_len) {
	if (cbb->is_child) {
//    OPENSSL_PUT_ERROR(CRYPTO, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}

	if (!CBB_flush(cbb)) {
		return 0;
	}

	if (cbb->u.base.can_resize && (out_data == NULL || out_len == NULL)) {
		// |out_data| and |out_len| can only be NULL if the CBB is fixed.
		return 0;
	}

	if (out_data != NULL) {
		*out_data = cbb->u.base.buf;
	}
	if (out_len != NULL) {
		*out_len = cbb->u.base.len;
	}
	cbb->u.base.buf = NULL;
	CBB_cleanup(cbb);
	return 1;
}

static struct cbb_buffer_st *cbb_get_base(CBB *cbb) {
	if (cbb->is_child) {
		return cbb->u.child.base;
	}
	return &cbb->u.base;
}

// TODO
static void cbb_on_error(CBB *cbb) {
  // Due to C's lack of destructors and |CBB|'s auto-flushing API, a failing
  // |CBB|-taking function may leave a dangling pointer to a child |CBB|. As a
  // result, the convention is callers may not write to |CBB|s that have failed.
  // But, as a safety measure, we lock the |CBB| into an error state. Once the
  // error bit is set, |cbb->child| will not be read.
  //
  // TODO(davidben): This still isn't quite ideal. A |CBB| function *outside*
  // this file may originate an error while the |CBB| points to a local child.
  // In that case we don't set the error bit and are reliant on the error
  // convention. Perhaps we allow |CBB_cleanup| on child |CBB|s and make every
  // child's |CBB_cleanup| set the error bit if unflushed. That will be
  // convenient for C++ callers, but very tedious for C callers. So C callers
  // perhaps should get a |CBB_on_error| function that can be, less tediously,
  // stuck in a |goto err| block.
  cbb_get_base(cbb)->error = 1;

  // Clearing the pointer is not strictly necessary, but GCC's dangling pointer
  // warning does not know |cbb->child| will not be read once |error| is set
  // above.
  cbb->child = NULL;
}



/*
 * CBB_flush recurses and then writes out any pending length prefix. The current
 * length of the underlying base is taken to be the length of the
 * length-prefixed data.
 */
int
CBB_flush(CBB *cbb)
{
	size_t child_start, i, len;
	struct cbb_buffer_st *base;

	// If |base| has hit an error, the buffer is in an undefined state, so
	// fail all following calls. In particular, |cbb->child| may point to invalid
	// memory.
	base = cbb_get_base(cbb);
	if (base == NULL || base->error)
		return 0;

	if (cbb->child == NULL)
		return 1;

	// TODO: nak3
	assert(cbb->child->is_child);
	struct cbb_child_st *child = &cbb->child->u.child;
	assert(child->base == base);
	child_start = child->offset + child->pending_len_len;

	if (!CBB_flush(cbb->child) || child_start < child->offset ||
	    base->len < child_start) {
		goto err;
	}

	len = base->len - child_start;

	if (child->pending_is_asn1) {
		/*
		 * For ASN.1, we assumed that we were using short form which
		 * only requires a single byte for the length octet.
		 *
		 * If it turns out that we need long form, we have to move
		 * the contents along in order to make space for more length
		 * octets.
		 */
		size_t len_len = 1;  /* total number of length octets */
		uint8_t initial_length_byte;

		assert(child->pending_len_len == 1);

		/* Check for long form */
		if (len > 0xfffffffe) {
			goto err;
		} else if (len > 0xffffff) {
			len_len = 5;
			initial_length_byte = 0x80 | 4;
		} else if (len > 0xffff) {
			len_len = 4;
			initial_length_byte = 0x80 | 3;
		} else if (len > 0xff) {
			len_len = 3;
			initial_length_byte = 0x80 | 2;
		} else if (len > 0x7f) {
			len_len = 2;
			initial_length_byte = 0x80 | 1;
		} else {
			len_len = 1;
			initial_length_byte = (uint8_t)len;
			len = 0;
		}

		if (len_len != 1) {
			// We need to move the contents along in order to make space.
			size_t extra_bytes = len_len - 1;
			if (!cbb_buffer_add(base, NULL, extra_bytes)) {
				goto err;
			}
			memmove(base->buf + child_start + extra_bytes,
			    base->buf + child_start, len);
		}
		base->buf[child->offset++] = initial_length_byte;
		child->pending_len_len = len_len - 1;
	}

	for (i = child->pending_len_len - 1; i < child->pending_len_len; i--) {
		base->buf[child->offset + i] = len;
		len >>= 8;
	}
	if (len != 0)
		return 0;

	child->base = NULL;
	cbb->child = NULL;

	/* cbb->pending_len_len = 0; */
	/* cbb->pending_is_asn1 = 0; */
	/* cbb->offset = 0; */

	return 1;
 err:
	cbb_on_error(cbb);
	return 0;
}

static int cbb_add_u(CBB *cbb, uint64_t v, size_t len_len) {
	uint8_t *buf;
	if (!CBB_add_space(cbb, &buf, len_len)) {
		return 0;
	}

	for (size_t i = len_len - 1; i < len_len; i--) {
		buf[i] = v;
		v >>= 8;
	}

	// |v| must fit in |len_len| bytes.
	if (v != 0) {
		cbb_on_error(cbb);
		return 0;
	}

	return 1;
}

void
CBB_discard_child(CBB *cbb)
{
	if (cbb->child == NULL)
		return;

	struct cbb_buffer_st *base = cbb_get_base(cbb);
	// TODO: nak3
//	assert(cbb->child->is_child);
	base->len = cbb->child->u.child.offset;

	cbb->child->u.child.base = NULL;
	cbb->child = NULL;
}

static int cbb_add_child(CBB *cbb, CBB *out_child, uint8_t len_len,
                         int is_asn1) {
  /* assert(cbb->child == NULL); */
  /* assert(!is_asn1 || len_len == 1); */
  struct cbb_buffer_st *base = cbb_get_base(cbb);
  size_t offset = base->len;

  // Reserve space for the length prefix.
  uint8_t *prefix_bytes;
  if (!cbb_buffer_add(base, &prefix_bytes, len_len)) {
    return 0;
  }

  // TODO
  //OPENSSL_memset(prefix_bytes, 0, len_len);
  memset(prefix_bytes, 0, len_len);

  CBB_zero(out_child);
  out_child->is_child = 1;
  out_child->u.child.base = base;
  out_child->u.child.offset = offset;
  out_child->u.child.pending_len_len = len_len;
  out_child->u.child.pending_is_asn1 = is_asn1;
  cbb->child = out_child;
  return 1;
}


static int
cbb_add_length_prefixed(CBB *cbb, CBB *out_contents, size_t len_len)
{
	if (!CBB_flush(cbb)) {
		return 0;
	}

	return cbb_add_child(cbb, out_contents, len_len, /*is_asn1=*/0);
}

int
CBB_add_u8_length_prefixed(CBB *cbb, CBB *out_contents)
{
	return cbb_add_length_prefixed(cbb, out_contents, 1);
}

int
CBB_add_u16_length_prefixed(CBB *cbb, CBB *out_contents)
{
	return cbb_add_length_prefixed(cbb, out_contents, 2);
}

int
CBB_add_u24_length_prefixed(CBB *cbb, CBB *out_contents)
{
	return cbb_add_length_prefixed(cbb, out_contents, 3);
}

int
CBB_add_u32_length_prefixed(CBB *cbb, CBB *out_contents)
{
	return cbb_add_length_prefixed(cbb, out_contents, 4);
}

// add_base128_integer encodes |v| as a big-endian base-128 integer where the
// high bit of each byte indicates where there is more data. This is the
// encoding used in DER for both high tag number form and OID components.
static int add_base128_integer(CBB *cbb, uint64_t v) {
  unsigned len_len = 0;
  uint64_t copy = v;
  while (copy > 0) {
    len_len++;
    copy >>= 7;
  }
  if (len_len == 0) {
    len_len = 1;  // Zero is encoded with one byte.
  }
  for (unsigned i = len_len - 1; i < len_len; i--) {
    uint8_t byte = (v >> (7 * i)) & 0x7f;
    if (i != 0) {
      // The high bit denotes whether there is more data.
      byte |= 0x80;
    }
    if (!CBB_add_u8(cbb, byte)) {
      return 0;
    }
  }
  return 1;
}


// TODO: nak3 move to base.h

// CBS_ASN1_TAG is the type used by |CBS| and |CBB| for ASN.1 tags. See that
// header for details. This type is defined in base.h as a forward declaration.
typedef uint32_t CBS_ASN1_TAG;



int
CBB_add_asn1(CBB *cbb, CBB *out_contents, unsigned int tag)
{
	/* if (tag > UINT8_MAX) */
	/* 	return 0; */

	/* /\* Long form identifier octets are not supported. *\/ */
	/* if ((tag & 0x1f) == 0x1f) */
	/* 	return 0; */

	/* /\* Short-form identifier octet only needs a single byte *\/ */
	/* if (!CBB_flush(cbb) || !CBB_add_u8(cbb, tag)) */
	/* 	return 0; */

	/* /\* */
	/*  * Add 1 byte to cover the short-form length octet case.  If it turns */
	/*  * out we need long-form, it will be extended later. */
	/*  *\/ */
	/* cbb->offset = cbb->base->len; */
	/* if (!CBB_add_u8(cbb, 0)) */
	/* 	return 0; */

	/* memset(out_contents, 0, sizeof(CBB)); */
	/* out_contents->base = cbb->base; */
	/* cbb->child = out_contents; */
	/* cbb->pending_len_len = 1; */
	/* cbb->pending_is_asn1 = 1; */

  if (!CBB_flush(cbb)) {
    return 0;
  }

  // Split the tag into leading bits and tag number.
  uint8_t tag_bits = (tag >> CBS_ASN1_TAG_SHIFT) & 0xe0;
  CBS_ASN1_TAG tag_number = tag & CBS_ASN1_TAG_NUMBER_MASK;
  if (tag_number >= 0x1f) {
    // Set all the bits in the tag number to signal high tag number form.
    if (!CBB_add_u8(cbb, tag_bits | 0x1f) ||
        !add_base128_integer(cbb, tag_number)) {
      return 0;
    }
  } else if (!CBB_add_u8(cbb, tag_bits | tag_number)) {
    return 0;
  }

  // Reserve one byte of length prefix. |CBB_flush| will finish it later.
  return cbb_add_child(cbb, out_contents, /*len_len=*/1, /*is_asn1=*/1);

	return 1;
}

int
CBB_add_bytes(CBB *cbb, const uint8_t *data, size_t len)
{
	uint8_t *out;
	if (!CBB_add_space(cbb, &out, len)) {
		return 0;
	}

	memcpy(out, data, len);
	return 1;
}

int
CBB_add_space(CBB *cbb, uint8_t **out_data, size_t len)
{
	if (!CBB_flush(cbb) || !cbb_buffer_add(cbb_get_base(cbb), out_data, len))
		return 0;

	memset(*out_data, 0, len);
	return 1;
}

int
CBB_add_u8(CBB *cbb, size_t value)
{
	if (value > UINT8_MAX)
		return 0;

	return cbb_add_u(cbb, (uint32_t)value, 1);
}

int
CBB_add_u16(CBB *cbb, size_t value)
{
	if (value > UINT16_MAX)
		return 0;

	return cbb_add_u(cbb, (uint32_t)value, 2);
}

int
CBB_add_u24(CBB *cbb, size_t value)
{
	if (value > 0xffffffUL)
		return 0;

	return cbb_add_u(cbb, (uint32_t)value, 3);
}

int
CBB_add_u32(CBB *cbb, size_t value)
{
	if (value > 0xffffffffUL)
		return 0;

	return cbb_add_u(cbb, (uint32_t)value, 4);
}

int
CBB_add_u64(CBB *cbb, uint64_t value)
{
	uint32_t a, b;

	a = value >> 32;
	b = value & 0xffffffff;

	if (!CBB_add_u32(cbb, a))
		return 0;
	return CBB_add_u32(cbb, b);
}

int
CBB_add_asn1_uint64(CBB *cbb, uint64_t value)
{
	CBB child;
	size_t i;
	int started = 0;

	if (!CBB_add_asn1(cbb, &child, CBS_ASN1_INTEGER))
		return 0;

	for (i = 0; i < 8; i++) {
		uint8_t byte = (value >> 8 * (7 - i)) & 0xff;

		/*
		 * ASN.1 restriction: first 9 bits cannot be all zeroes or
		 * all ones.  Since this function only encodes unsigned
		 * integers, the only concerns are not encoding leading
		 * zeros and adding a padding byte if necessary.
		 *
		 * In practice, this means:
		 * 1) Skip leading octets of all zero bits in the value
		 * 2) After skipping the leading zero octets, if the next 9
		 *    bits are all ones, add an all zero prefix octet (and
		 *    set the high bit of the prefix octet if negative).
		 *
		 * Additionally, for an unsigned value, add an all zero
		 * prefix if the high bit of the first octet would be one.
		 */
		if (!started) {
			if (byte == 0)
				/* Don't encode leading zeros. */
				continue;

			/*
			 * If the high bit is set, add a padding byte to make it
			 * unsigned.
			 */
			if ((byte & 0x80) && !CBB_add_u8(&child, 0))
				return 0;

			started = 1;
		}
		if (!CBB_add_u8(&child, byte))
			return 0;
	}

	/* 0 is encoded as a single 0, not the empty string. */
	if (!started && !CBB_add_u8(&child, 0))
		return 0;

	return CBB_flush(cbb);
}
