#ifndef _TEECHAIN_H_
#define _TEECHAIN_H_

typedef unsigned char byte;

extern char in_benchmark;

void send_buffer(byte* buffer, size_t len);
byte* recv_buffer(size_t* len);

#endif /* _TEECHAIN_H_ */
