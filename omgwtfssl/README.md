# OMGWTFSSL
El levantar este contenedor tiene como finalidad la creación de certificados, es importante que los nombres de dominios tengan un certificado, debido a que Wazuh se comunica a traves del puerto 443.

El comando para levantar el contenedor es el siguiente:
```bash
docker run -v /var/containers/omgwtfssl/certs:/certs \
  -e SSL_SUBJECT=test.example.com   \
  paulczar/omgwtfssl
```

Donde:
* SSL_SUBJECT: son los dominios a los cuales se les aplicara el certificado.

Para este caso en concreto utilizaremos el comando:

```bash
docker run -v /var/containers/omgwtfssl/certs:/certs \
  -e SSL_SUBJECT=wazuh.azure.net   \
  -e SSL_SUBJECT=spacewalk.azure.net \
  paulczar/omgwtfssl
```

En este sentido, es necesario modificar la creación del contenedor de nginx, a la cual añadiremos un volumen, quedando el **docker run** de la siguiente manera:

```bash
docker run -td --name=nginx --privileged=false -p 80:80 -p 443:443 \
                    --volume=/var/containers/shared/var/www/sites:/var/www/sites:z \
                    --volume=/var/containers/nginx/var/log/nginx:/var/log/nginx:z \
                    --volume=/var/containers/nginx/etc/nginx/vhosts:/etc/nginx/vhosts:z \
                    --volume=/var/containers/nginx/etc/nginx/keys:/etc/nginx/keys:z \
                    --volume=/var/containers/nginx/etc/nginx/conf.d:/etc/nginx/conf.d:z \
                    --volume=/var/containers/nginx/var/cache/nginx:/var/cache/nginx:z  \
                    --volume=/var/containers/nginx/var/backups:/var/backups:z \
                    --volume=/etc/localtime:/etc/localtime:ro \
                    --volume=/var/containers/omgwtfssl/certs:/tmp/certs \
                    --hostname=nginx.service \
                    docker.io/berryrreb/nginxmodsec
```

De igual forma necesitamos cambiar el archivo de configuración de **/var/containers/nginx/etc/nginx/vhosts/wazuh.conf** con el siguiente contenido:

```bash
server {
    listen 443 ssl;
    server_name wazuh.azure.net;

    location / {
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Scheme $scheme;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://172.17.0.5:5601/;
    }
    # location /.well-known {
    #    root /var/www/acme;
    # }

    # Improve HTTPS performance with session resumption
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 5m;
    # Disable SSLv3
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

    ssl_certificate /tmp/certs/ca.pem; # managed by Certbot
    ssl_certificate_key /tmp/certs/ca-key.pem; # managed by Certbot
}

server {
    if ($host = wazuh.azure.net) {
        return 301 https://$host$request_uri;
    }
    listen 80;
    server_name wazuh.azure.net;
    return 404; # managed by Certbot

}
```
**NOTA:** En la parte *proxy_pass* hay que apuntar a la IP donde esta ubicado el servicio.

Enseguida ejecutamos el siguiente comando:

```bash
docker exec -it nginx bash -c "nginx -s reload"
```
