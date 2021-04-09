#ifndef _CMD_H_
#define _CMD_H_

void send_buffer(byte* buffer, size_t len);
byte* recv_buffer(size_t* len);

#endif /* _CMD_H_ */
