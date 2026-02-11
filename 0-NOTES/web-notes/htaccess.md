# File `.htaccess`

## What is `.htaccess` file ?
- `.htaccess` (Hypertext Access) is a file located in the root directory of hosting environments and is managed by Apache. The `.htaccess` file can control and configure many aspects using various parameters; it can modify the default values set by Apache (meaning you can manage, change, or adjust server settings **without** needing access to the main server configuration).

## Common Usage
### URL Rewrite
```apache
RewriteEngine On
RewriteRule ^blog/(.*)$ blog.php?slug=$1
```
For example:
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
For example:
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

### Create Custom Error Pages
```apache
ErrorDocument 404 /errors/not-found.html
```

### MIME Type Configuration
- This allows the server to recognize and handle various types of file formats.
```apache
AddType application/pdf .pdf
AddType application/x-httpd-php .jpg .html .txt
```
