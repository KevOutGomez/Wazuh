# Nginx

Para levantar un contenedor con nginx, ejecutamos los siguientes comandos:

Creación de directorios
```bash
mkdir -p /var/containers/shared/var/www/sites \
              /var/containers/nginx/{var/log/nginx,etc/nginx/vhosts,etc/nginx/conf.d,var/cache/nginx,var/backups,etc/nginx/keys}
```

```bash
ln -s /var/containers/nginx/var/log/nginx/ /var/log/
```

```bash
mkdir -p /etc/logrotate.d/c
echo 'L3Zhci9sb2cvbmdpbngvKi5sb2cgewogICAgICAgIGRhaWx5CiAgICAgICAgbWlzc2luZ29rCiAgICAgICAgcm90YXRlIDYwCiAgICAgICAgY29tcHJlc3MKICAgICAgICBkZWxheWNvbXByZXNzCiAgICAgICAgbm90aWZlbXB0eQogICAgICAgIGNyZWF0ZSA2NDQKICAgICAgICBzaGFyZWRzY3JpcHRzCiAgICAgICAgcG9zdHJvdGF0ZQogICAgICAgICAgICBuZ2lueCAtcyByZWxvYWQKICAgICAgICBlbmRzY3JpcHQKfQovdmFyL2xvZy9uZ2lueC8qLyoubG9nIHsKICAgICAgICBkYWlseQogICAgICAgIG1pc3NpbmdvawogICAgICAgIHJvdGF0ZSA2MAogICAgICAgIGNvbXByZXNzCiAgICAgICAgZGVsYXljb21wcmVzcwogICAgICAgIG5vdGlmZW1wdHkKICAgICAgICBjcmVhdGUgNjQ0CiAgICAgICAgc2hhcmVkc2NyaXB0cwogICAgICAgIHBvc3Ryb3RhdGUKICAgICAgICAgICAgbmdpbnggLXMgcmVsb2FkCiAgICAgICAgZW5kc2NyaXB0Cn0KCg==' | base64 -w0 -d > /etc/logrotate.d/nginx
```
Creación del contenedor
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
                    --hostname=nginx.service \
                    docker.io/berryrreb/nginxmodsec
```

Después de levantar el contenedor de nginx, es necesario crear el archivo (en el servidor, No en el contenedor) **/var/containers/nginx/etc/nginx/vhosts/wazuh.conf**, con el contenido del archivo con el mismo nombre ubicado en este repositorio.
