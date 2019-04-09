#ifndef __GEN_LABELSET_H__
#define __GEN_LABELSET_H__

extern const unsigned char B_bytes[];

unsigned char* REF10_buffer_add(unsigned char* bufptr, const unsigned char* bufend,
                          const unsigned char* in, const unsigned long in_len);

unsigned char* REF10_buffer_pad(const unsigned char* buf, unsigned char* bufptr, const unsigned char* bufend);


int REF10_labelset_new(unsigned char* labelset, unsigned long* labelset_len, const unsigned long labelset_maxlen,
                 const unsigned char* protocol_name, const unsigned char protocol_name_len,
                 const unsigned char* customization_label, const unsigned char customization_label_len);

int REF10_labelset_add(unsigned char* labelset, unsigned long* labelset_len, const unsigned long labelset_maxlen,
              const unsigned char* label, const unsigned char label_len);

int REF10_labelset_validate(const unsigned char* labelset, const unsigned long labelset_len);

int REF10_labelset_is_empty(const unsigned char* labelset, const unsigned long labelset_len);

#endif
