/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package applicationpb

import (
	"bytes"
)

// QuickASN1Marshal marshals a transactions.
// It uses the schema described in tx_schema.asn.
func (ns *TxNamespace) QuickASN1Marshal(txID string, metadata [][]byte) ([]byte, error) {
	// Build the metadata sequence (optional).
	var metadataSequence []byte
	if len(metadata) > 0 {
		metadataBuf := bytes.NewBuffer(nil)
		for _, m := range metadata {
			writeTLVBytes(metadataBuf, m)
		}
		metadataSequence = metadataBuf.Bytes()
	}

	// Build the read only sequence.
	readOnlyBuf := bytes.NewBuffer(nil)
	for _, r := range ns.ReadsOnly {
		writeReadSequence(readOnlyBuf, r)
	}
	readonlySequence := readOnlyBuf.Bytes()

	// Build the read write sequence.
	readWriteBuf := bytes.NewBuffer(nil)
	for _, rw := range ns.ReadWrites {
		writeReadWriteSequence(readWriteBuf, rw)
	}
	readWriteSequence := readWriteBuf.Bytes()

	// Build the blind write sequence.
	blindWriteBuf := bytes.NewBuffer(nil)
	for _, w := range ns.BlindWrites {
		writeBlindWriteSequence(blindWriteBuf, w)
	}
	blindWriteSequence := blindWriteBuf.Bytes()

	// Encode namespace version
	nsVersionEncoded := encodePositiveInteger(ns.NsVersion)

	// Build the main sequence.
	mainSequenceBuf := bytes.NewBuffer(nil)
	mainSequenceBuf.Grow(7*tlvPreGrowHeaderSize +
		len(txID) + len(metadataSequence) + len(ns.NsId) + len(nsVersionEncoded) +
		len(readonlySequence) + len(readWriteSequence) + len(blindWriteSequence))
	writeTLVString(mainSequenceBuf, txID)
	// Write metadata sequence only if present (optional field)
	if len(metadataSequence) > 0 {
		writeTLVSequence(mainSequenceBuf, metadataSequence)
	}
	writeTLVString(mainSequenceBuf, ns.NsId)
	writeEncodedTLVPositiveInteger(mainSequenceBuf, nsVersionEncoded)
	writeTLVSequence(mainSequenceBuf, readonlySequence)
	writeTLVSequence(mainSequenceBuf, readWriteSequence)
	writeTLVSequence(mainSequenceBuf, blindWriteSequence)
	mainSequence := mainSequenceBuf.Bytes()

	// Wrap the main sequence.
	b := bytes.NewBuffer(nil)
	writeTLVSequence(b, mainSequence)
	return b.Bytes(), nil
}

const (
	// maxLengthEncodingSize limits the length to 2^64 - 1.
	maxLengthEncodingSize = 8

	// tlvPreGrowHeaderSize reserves 1 byte for the tag, 1 for the size of the length encoding, and 8 for the length.
	tlvPreGrowHeaderSize = 1 + 1 + maxLengthEncodingSize
)

// writeBlindWriteSequence optimized to write a TLV sequence of two bytes items.
func writeBlindWriteSequence(b *bytes.Buffer, w *Write) {
	tmpBuf := bytes.NewBuffer(nil)
	tmpBuf.Grow(2*tlvPreGrowHeaderSize + len(w.Key) + len(w.Value))
	writeTLVBytes(tmpBuf, w.Key)
	writeTLVBytes(tmpBuf, w.Value)
	writeTLVSequence(b, tmpBuf.Bytes())
}

// writeReadSequence writes a TLV sequence for a Read (key + optional version).
func writeReadSequence(b *bytes.Buffer, r *Read) {
	tmpBuf := bytes.NewBuffer(nil)
	writeTLVBytes(tmpBuf, r.Key)
	// Only write version if it's not nil (default -1 is omitted in ASN.1)
	if r.Version != nil {
		writeTLVPositiveInteger(tmpBuf, *r.Version)
	}
	writeTLVSequence(b, tmpBuf.Bytes())
}

// writeReadWriteSequence writes a TLV sequence for a ReadWrite (key + value + optional version).
func writeReadWriteSequence(b *bytes.Buffer, rw *ReadWrite) {
	tmpBuf := bytes.NewBuffer(nil)
	writeTLVBytes(tmpBuf, rw.Key)
	writeTLVBytes(tmpBuf, rw.Value)
	// Only write version if it's not nil (default -1 is omitted in ASN.1)
	if rw.Version != nil {
		writeTLVPositiveInteger(tmpBuf, *rw.Version)
	}
	writeTLVSequence(b, tmpBuf.Bytes())
}

// writeTLVSequence writes a TLV with a SEQUENCE tag (0x30).
func writeTLVSequence(b *bytes.Buffer, sequence []byte) {
	writeTLVHeader(b, 0x30, len(sequence))
	b.Write(sequence) //nolint:revive,nolintlint // Buffer write never fail.
}

// writeTLVBytes writes a TLV with an OCTET STRING tag (0x04).
func writeTLVBytes(b *bytes.Buffer, data []byte) {
	writeTLVHeader(b, 0x04, len(data))
	b.Write(data) //nolint:revive,nolintlint // Buffer write never fail.
}

// writeTLVString writes a TLV with a UTF8String tag (0x0c).
func writeTLVString(b *bytes.Buffer, value string) {
	writeTLVHeader(b, 0x0c, len(value))
	b.WriteString(value) //nolint:revive,nolintlint // Buffer write never fail.
}

// writeTLVPositiveInteger writes a TLV with an INTEGER tag (0x02).
// The integer is encoded in big-endian format for positive values only.
func writeTLVPositiveInteger(b *bytes.Buffer, value uint64) {
	writeEncodedTLVPositiveInteger(b, encodePositiveInteger(value))
}

// writeTLVPositiveInteger writes a TLV with an INTEGER tag (0x02).
// The integer is encoded in big-endian format for positive values only.
func writeEncodedTLVPositiveInteger(b *bytes.Buffer, value []byte) {
	writeTLVHeader(b, 0x02, len(value))
	b.Write(value) //nolint:revive,nolintlint // Buffer write never fail.
}

// writeTLVHeader writes the header (tag and length) of the ASN.1 TLV schema:
// - tag (byte).
// - length (variable size length of the value).
// - value (the value's bytes).
func writeTLVHeader(b *bytes.Buffer, tag byte, valueSize int) {
	b.Grow(tlvPreGrowHeaderSize + valueSize)
	b.WriteByte(tag) //nolint:revive,nolintlint // Buffer write never fail.
	writeLength(b, valueSize)
}

// writeLength uses a variable size number according to the ASN.1 scheme.
// The MSB indicate if we use the short or long format.
//   - [0] short  Single byte where the remaining bits encode the length (max 127).
//   - [1] long   The remaining bits of the first byte encode the size of the encoded the length,
//     followed by the said number of bytes encoding the length in big-endian.
func writeLength(b *bytes.Buffer, l int) {
	if l < 128 {
		// [0] short - MSB is already zero.
		b.WriteByte(byte(l)) //nolint:revive,gosec,nolintlint // Buffer write never fail.
		return
	}

	var tmp [maxLengthEncodingSize + 1]byte
	i := maxLengthEncodingSize
	for l != 0 {
		tmp[i] = byte(l & 0xff)
		l >>= 8
		i--
	}
	// [1] long - We add the encoding size and mark the MSB to indicate we use the long format.
	tmp[i] = 0x80 | byte(maxLengthEncodingSize-i)
	b.Write(tmp[i:]) //nolint:revive,nolintlint // Buffer write never fail.
}

// writeTLVPositiveInteger writes a TLV with an INTEGER tag (0x02).
// The integer is encoded in big-endian format for positive values only.
func encodePositiveInteger(value uint64) []byte {
	if value == 0 {
		return []byte{0} // ASN.1 encoding of zero is a single byte with value 0.
	}

	// Encode the positive integer in big-endian format
	var tmp [maxLengthEncodingSize]byte
	i := maxLengthEncodingSize - 1
	for value != 0 {
		tmp[i] = byte(value & 0xff)
		value >>= 8
		i--
	}

	// If MSB is set, we need a leading zero byte to indicate positive
	if i < maxLengthEncodingSize-1 && tmp[i+1]&0x80 != 0 {
		tmp[i] = 0
	} else {
		i++
	}

	return tmp[i:]
}
