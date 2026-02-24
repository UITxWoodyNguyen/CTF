#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Các cấu trúc dữ liệu và biến toàn cục giả định
uint32_t session_id;     // sess
uint64_t session_state;  // qword_40E4
void (*cb_enc)(void);    // encrypted callback

int main(int argc, const char **argv) {
    char header_buf[8];        // v11, v12, v13
    uint64_t init_packet[7];   // v14
    
    // Khởi tạo môi trường
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);

    // 1. Bước bắt tay (Handshake)
    // Kiểm tra magic bytes của gói tin khởi tạo
    readn(init_packet, 56); 
    // Kiểm tra chuỗi "relay" hoặc magic tương tự trong packet
    if (LODWORD(init_packet[0]) == 0x43504F53 && *((int*)((char*)init_packet + 3)) == 0x3F333F23) {
        
        // Khởi tạo session và token
        session_id = 0x44414441; // "DADA"
        session_state = 0x28242824; 
        
        // Tạo mã kiểm tra (checksum) ban đầu và mã hóa callback
        uint32_t mix_val = mix32(991242259, &session_id);
        cb_enc = (void (*)(void))enc_cb(noop);
        
        // Gửi Session ID cho Client
        write(1, &session_id, 4);

        while (1) {
            // 2. Nhận Header gói tin (8 bytes)
            // v11[0]: Type, v11[1]: Subtype, v12: Length, v13: MAC/Checksum
            if (readn(header_buf, 8) <= 0) break;

            uint8_t cmd_type = header_buf[0];
            uint16_t data_len = *(uint16_t*)(header_buf + 2);
            uint32_t expected_mac = *(uint32_t*)(header_buf + 4);

            if (data_len > 0x500) break; // Giới hạn kích thước gói tin

            // 3. Nhận Data gói tin
            void *payload = malloc(data_len ? data_len : 1);
            if (!payload) break;
            if (data_len) readn(payload, data_len);

            // 4. Kiểm tra tính toàn vẹn (MAC Check)
            uint32_t calculated_mac = mac32(payload, data_len, header_buf[0], header_buf[1], header_buf[0]);
            
            if (expected_mac == calculated_mac) {
                // 5. Xử lý câu lệnh (Dispatcher)
                switch (cmd_type) {
                    case 3: // Authenticate/Update State
                        if (data_len == 4) {
                            uint32_t key = (session_id ^ (uint32_t)session_state);
                            if (((uint32_t)mix32(key, data_len) ^ 0x31C3B7A9) == *(uint32_t*)payload) {
                                // Cập nhật trạng thái session (vùng byte 4-5 của qword_40E4)
                                *(uint16_t*)((char*)&session_state + 4) = 0x0101; 
                            }
                        }
                        break;

                    case 1: // Diagnostic
                        handle_diag(payload, data_len);
                        break;

                    case 2: // Ticketing
                        handle_ticket(payload, data_len);
                        break;

                    case 9: // Execute Encrypted Callback (Trùng khớp với mục tiêu khai thác)
                        if ((session_state >> 40) & 0xFF && ((session_state >> 32) & 0xFF) > 2) {
                            void (*dispatch)(void) = (void (*)(void))enc_cb(cb_enc);
                            dispatch(); // Gọi hàm đã được giải mã
                        }
                        free(payload);
                        return 0;
                }
            }
            free(payload);
        }
    }
    return 0;
}