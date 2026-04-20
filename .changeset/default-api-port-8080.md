---
"@vex-chat/spire": major
---

The default HTTP listen port is now **8080** (was **16777**). Set `API_PORT` if you need the old port. Docker Compose publishes **8080:8080** directly (the separate Compose `nginx` service was removed); `npm start` and Compose now match for host reverse proxies targeting `http://127.0.0.1:8080`.
