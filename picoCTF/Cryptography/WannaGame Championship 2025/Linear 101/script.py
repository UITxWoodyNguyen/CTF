from pwn import *
import random
import ast

# --- CẤU HÌNH KẾT NỐI (SỬA Ở ĐÂY) ---
# Điền IP và Port mà đề bài cấp cho bạn vào đây
HOST = 'challenge.cnsc.com.vn'  # Ví dụ: '103.123.x.x'
PORT = 31419         # Ví dụ: 30001

# --- LOGIC GIẢI ---
def solve():
    # 1. Kết nối tới server
    try:
        r = remote(HOST, PORT)
    except:
        print("Lỗi kết nối! Hãy kiểm tra lại IP và Port.")
        return

    # 2. Đồng bộ Random Seed (Quan trọng nhất)
    # Seed này phải GIỐNG HỆT trong đề bài
    random.seed("Wanna Win?")
    n = 128

    print("Đang kết nối và giải 64 vòng...")

    # Vòng lặp 64 Round
    for round_num in range(1, 65):
        try:
            # Tái tạo ma trận A (phải làm mỗi vòng để đồng bộ với server)
            A = [random.randbytes(n) for _ in range(n)]

            # Đọc dữ liệu từ Server
            # Server in: "Round x/64" -> chờ đọc xong dòng này
            r.recvuntil(b'/64')
            
            # Server in: "b = [....]" -> đọc dòng này để lấy b
            r.recvuntil(b'b = ')
            b_str = r.recvline().strip().decode()
            
            # Chuyển chuỗi "[1, 2, 3]" thành list Python thực sự
            b = ast.literal_eval(b_str)

            # --- GIẢI TOÁN (Max-Plus Algebra) ---
            # Tìm x sao cho: b[i] = max(A[i][j] + x[j])
            # Suy ra: x[j] <= b[i] - A[i][j] với mọi i
            # => x[j] = min(b[i] - A[i][j]) trên tất cả các hàng i
            
            sol = []
            for j in range(n):
                min_diff = float('inf')
                for i in range(n):
                    # A[i][j] là byte, nên là số nguyên
                    diff = b[i] - A[i][j]
                    if diff < min_diff:
                        min_diff = diff
                
                # Giới hạn giá trị trong khoảng byte (0-255)
                # Vì x gốc là bytes nên không thể âm hoặc lớn hơn 255
                val = max(0, min(255, int(min_diff)))
                sol.append(val)

            # Gửi kết quả
            # Chuyển list số thành bytes -> hex string
            sol_bytes = bytes(sol)
            r.sendline(sol_bytes.hex().encode())
            
            print(f"Round {round_num}/64: Done")

        except Exception as e:
            print(f"Lỗi tại vòng {round_num}: {e}")
            r.close()
            return

    # Sau 64 vòng, nhận Flag
    print("\n" + "="*30)
    print("Đang chờ Flag...")
    # Đọc tất cả những gì còn lại (chứa Flag)
    print(r.recvall().decode())
    print("="*30)

if __name__ == "__main__":
    solve()
