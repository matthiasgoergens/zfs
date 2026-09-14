#!/bin/ksh -p
# SPDX-License-Identifier: CDDL-1.0

#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# https://opensource.org/license/CDDL-1.0.
#

. $STF_SUITE/tests/functional/zstream/zstream.kshlib

#
# Description:
# Verify that zstream rejects payload sizes which cannot be checksummed as
# 32-bit words.
#
# Strategy:
# 1. Change a valid BEGIN payload size from 64 to 65 in both byte orders
# 2. Confirm zstream dump rejects each stream before checksumming its payload
# 3. Confirm zstream rejects an unaligned payload produced by decompression
#

verify_runnable "both"

log_assert "unaligned zstream payload sizes are rejected"

typeset bad=$BACKDIR/unaligned-payload.zsend
typeset err=$BACKDIR/unaligned-payload.err
typeset ret

for endian in little big; do
	typeset name="${endian}-endian-all-drr-types-base-XDR.zsend.bz2"
	typeset src="$ZSTREAM_DATADIR/$name"
	log_must eval "bzcat $src >$bad"

	if [[ $endian == little ]]; then
		log_must eval "printf '\\101\\000\\000\\000' | " \
		    "dd of=$bad bs=1 seek=4 conv=notrunc 2>/dev/null"
	else
		log_must eval "printf '\\000\\000\\000\\101' | " \
		    "dd of=$bad bs=1 seek=4 conv=notrunc 2>/dev/null"
	fi

	zstream dump "$bad" >/dev/null 2>"$err"
	ret=$?
	log_must test "$ret" -eq 1
	log_must grep -q \
	    "stated packet size 65 is not aligned to 4 bytes at offset 0" "$err"
done

typeset src="$ZSTREAM_DATADIR/unaligned-decompressed-payload.zsend.bz2"
log_must eval "bzcat $src >$bad"
zstream decompress 2,0 <"$bad" >/dev/null 2>"$err"
ret=$?
log_must test "$ret" -eq 1
log_must grep -q \
    "packet payload size 4097 is not aligned to 4 bytes" "$err"

log_pass "unaligned zstream payload sizes are rejected"
