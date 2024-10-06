## EDGAR-2-point-O-Trailer-1
### To set up everything locally

```bash
docker-compose up -d --build (docker-compose config --services | Where-Object { $_ -ne "app" })


docker-compose up -d --build app
```