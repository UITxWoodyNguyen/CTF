# File `.htaccess`

## File `.htaccess` là gì ?
- `.htaccess` (Hypertext Access) là một file có ở thư mục gốc của các hostting và do apache quản lý, cấp quyền. File `.htaccess` có thể điều khiển, cấu hình được nhiều thứ với đa dạng các thông số, nó có thể thay đổi được các giá trị được set mặc định của apache (tức bạn có thể quản lý, thay đổi, điều chỉnh cài đặt máy chủ mà **không cần** truy cập vào cấu hình máy chủ chính).

## Ứng dụng phổ biến
### URL Rewrite
```apache
RewriteEngine On
RewriteRule ^blog/(.*)$ blog.php?slug=$1
```
Ví dụ:
```apache=
# topic_1.html thành index.php?topic=1
RewriteRule ^topic_([0-9]*).html index.php?topic=$1
```

### Password Protection
```apache
#Protect Directory
AuthName "Dialog prompt"
AuthType Basic
AuthUserFile /home/username/example.com/.htpasswd
Require valid-user
```
Ví dụ:
```apache
# This example password protects a single file named admin.php:

# Protecting single file:
<Files admin.php>
AuthName "Dialog prompt"
AuthType Basic
AuthUserFile /home/username/example.com/.htpasswd
Require valid-user
</Files>

# Protecting multiple files such as admin.php and staff.php:
<FilesMatch "^(admin|staff).php$">
AuthName "Dialog prompt"
AuthType Basic
AuthUserFile /home/username/example.com/.htpasswd
Require valid-user
</FilesMatch>
```

### Tạo Custom Error Pages
```apache=
ErrorDocument 404 /errors/not-found.html
```

### MIME Type Configuration
- Việc này cho phép máy chủ nhận diện và xử lý nhiều loại định dạng khác nhau.
```apache
AddType application/pdf .pdf
AddType application/x-httpd-php .jpg .html .txt
```
