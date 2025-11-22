import ast

def hex_list_to_text(hex_list):
    result = ''
    for pair in hex_list:
        # Đảm bảo pair là list hoặc tuple
        if not isinstance(pair, (list, tuple)):
            continue
        for hx in pair:
            try:
                # Chuyển hex string sang số, rồi sang ký tự
                result += chr(int(hx, 16))
            except (ValueError, TypeError):
                # Bỏ qua nếu không chuyển được
                pass
    return result

def main():
    try:
        with open('raw.txt', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Chuyển chuỗi đọc được thành list Python
        hex_list = ast.literal_eval(content)
    except Exception as e:
        print(f"Error reading or parsing file: {e}")
        return

    text = hex_list_to_text(hex_list)
    print("Decoded text:")
    print(text)

if __name__ == '__main__':
    main()

