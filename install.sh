#!/bin/bash

setenforce 0
echo "SELinux en modo permisivo"

sysctl -w vm.max_map_count=262144
echo "Memoria virtual modificada"

#Creación y configuración de directorios para elasticsearch
mkdir -p /var/containers/elk/elasticsearch/
echo "IyA9PT09PT09PT09PT09PT09PT09IEVTTEFTVElDU0VBUkNIOiBlbGFzdGljc2VhcmNoLnltbCA9PT09PT09PT09PT09PT09PT09PT09ICMKY2x1c3Rlci5uYW1lOiAiZG9ja2VyLWNsdXN0ZXIiCm5ldHdvcmsuaG9zdDogMC4wLjAuMAojIG1pbmltdW1fbWFzdGVyX25vZGVzIG5lZWQgdG8gYmUgZXhwbGljaXRseSBzZXQgd2hlbiBib3VuZCBvbiBhIHB1YmxpYyBJUAojIHNldCB0byAxIHRvIGFsbG93IHNpbmdsZSBub2RlIGNsdXN0ZXJzCiMgRGV0YWlsczogaHR0cHM6Ly9naXRodWIuY29tL2VsYXN0aWMvZWxhc3RpY3NlYXJjaC9wdWxsLzE3Mjg4CmRpc2NvdmVyeS56ZW4ubWluaW11bV9tYXN0ZXJfbm9kZXM6IDE=" | base64 -w0 -d > /var/containers/elk/elasticsearch/elasticsearch.yml
docker run --name=elasticsearch_wazuh_1 -p 9200:9200 -p 9300:9300 -d -e "discovery.type=single-node" -v /var/containers/elk/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:z docker.elastic.co/elasticsearch/elasticsearch-oss:6.2.2
echo "Elasticsearch creado"

#Creación y configuración de directorios para logstash
mkdir -p /var/containers/logstash/pipeline/
echo "IyA9PT09PT09PT09PT09PT09PT09IExvZ3N0YXNoOiBwaXBlbGluZS55bWwgPT09PT09PT09PT09PT09PT09PT09PSAjCmlucHV0eyAgCiAgICBiZWF0c3sKICAgICAgICBwb3J0ID0+ICI1MDAwIiAgfQp9Cm91dHB1dHsgIAogICAgZWxhc3RpY3NlYXJjaCB7CiAgICAgICAgaG9zdHMgPT4gWydodHRwOi8vZWxhc3RpY3NlYXJjaDo5MjAwJ10gI0lQIHkgcHVlcnRvIGRlbCBjb250ZW5lZG9yIGRlIEVsYXN0aWNzZWFyY2gKICAgICAgICBpbmRleCA9PiAibG9nc3Rhc2gtJXsrWVlZWS5NTS5kZH0iICNOb21icmUgZGVsIGluZGljZSAgCiAgICAgICAgfQp9Cg==" | base64 -w0 -d > /var/containers/logstash/pipeline/pipeline.conf
#Creación de contenedor de logstash
docker run --rm -d --name=logstash_wazuh_1 --link=elasticsearch_wazuh_1:elasticsearch -v /var/containers/logstash/pipeline/:/usr/share/logstash/pipeline/bin:z docker.elastic.co/logstash/logstash-oss:6.2.1
echo "Logstash creado"

#Creación y configuración de directorios para filebeat
#mkdir -p /var/containers/logstash/filebeat/
#mkdir -p /var/containers/logstash/filebeat/prospectors.d
#echo "IyA9PT09PT09PT09PT09PT09PT09IEZpbGViZWF0OiBmaWxlYmVhdC55bWwgPT09PT09PT09PT09PT09PT09PT09PSAjCmZpbGViZWF0LmNvbmZpZzogIAogIHByb3NwZWN0b3JzOgogICAgcGF0aDogJHtwYXRoLmNvbmZpZ30vcHJvc3BlY3RvcnMuZC8qLnltbCAgICAgIAogICAgcmVsb2FkLmVuYWJsZWQ6IGZhbHNlICAKICBtb2R1bGVzOgogICAgcGF0aDogJHtwYXRoLmNvbmZpZ30vbW9kdWxlcy5kLyoueW1sCiAgICByZWxvYWQuZW5hYmxlZDogZmFsc2UKICAKcHJvY2Vzc29yczoKLSBhZGRfY2xvdWRfbWV0YWRhdGE6CgpvdXRwdXQubG9nc3Rhc2g6ICAKICBob3N0czogWydodHRwOi8vbG9nc3Rhc2g6NTA0NCddICNpcCBvIG5vbWJyZSBkZSBkb21pbmlvIGRlIGxvZ3N0YXNo" | base64 -w0 -d > /var/containers/logstash/filebeat/filebeat.yml
#echo "IyA9PT09PT09PT09PT09PT09PT09IEZpbGViZWF0OiBwcnVlYmEueW1sID09PT09PT09PT09PT09PT09PT09PT0gIwotIHR5cGU6IGxvZyAgCiAgcGF0aHM6ICAgCiAgLSAvdmFyL2xvZy9kYXRhLmxvZw==" | base64 -w0 -d > /var/containers/logstash/filebeat/prospectors.d/prueba.yml
#Creación de contenedor de filebeat
#docker run -d --name=filebeat_wazuh_1 --link=logstash_wazuh_1:logstash -v /var/containers/logstash/filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml -v /var/containers/logstash/filebeat/prospectors.d:/usr/share/filebeat/prospectors.d -v /var/containers/logstash/filebeat/data.log:/var/log/data.log docker.elastic.co/beats/filebeat:6.2.1
#echo "Filebeat creado"

#Creación y configuración de directorios para wazuh
mkdir -p /var/containers/wazuh/wazuh-config-mount/etc/
echo "PCEtLQogIFdhenVoIC0gTWFuYWdlciAtIERlZmF1bHQgY29uZmlndXJhdGlvbi4KICBNb3JlIGluZm8gYXQ6IGh0dHBzOi8vZG9jdW1lbnRhdGlvbi53YXp1aC5jb20KICBNYWlsaW5nIGxpc3Q6IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZm9ydW0vIyFmb3J1bS93YXp1aAotLT4KCjxvc3NlY19jb25maWc+CiAgPGdsb2JhbD4KICAgIDxqc29ub3V0X291dHB1dD55ZXM8L2pzb25vdXRfb3V0cHV0PgogICAgPGFsZXJ0c19sb2c+eWVzPC9hbGVydHNfbG9nPgogICAgPGxvZ2FsbD5ubzwvbG9nYWxsPgogICAgPGxvZ2FsbF9qc29uPm5vPC9sb2dhbGxfanNvbj4KICAgIDxlbWFpbF9ub3RpZmljYXRpb24+bm88L2VtYWlsX25vdGlmaWNhdGlvbj4KICAgIDxzbXRwX3NlcnZlcj5zbXRwLmV4YW1wbGUud2F6dWguY29tPC9zbXRwX3NlcnZlcj4KICAgIDxlbWFpbF9mcm9tPm9zc2VjbUBleGFtcGxlLndhenVoLmNvbTwvZW1haWxfZnJvbT4KICAgIDxlbWFpbF90bz5yZWNpcGllbnRAZXhhbXBsZS53YXp1aC5jb208L2VtYWlsX3RvPgogICAgPGVtYWlsX21heHBlcmhvdXI+MTI8L2VtYWlsX21heHBlcmhvdXI+CiAgPC9nbG9iYWw+CgogIDwhLS0gQ2hvb3NlIGJldHdlZW4gcGxhaW4gb3IganNvbiBmb3JtYXQgKG9yIGJvdGgpIGZvciBpbnRlcm5hbCBsb2dzIC0tPgogIDxsb2dnaW5nPgogICAgPGxvZ19mb3JtYXQ+cGxhaW48L2xvZ19mb3JtYXQ+CiAgPC9sb2dnaW5nPgoKICA8YWxlcnRzPgogICAgPGxvZ19hbGVydF9sZXZlbD4zPC9sb2dfYWxlcnRfbGV2ZWw+CiAgICA8ZW1haWxfYWxlcnRfbGV2ZWw+MTI8L2VtYWlsX2FsZXJ0X2xldmVsPgogIDwvYWxlcnRzPgoKICA8cmVtb3RlPgogICAgPGNvbm5lY3Rpb24+c2VjdXJlPC9jb25uZWN0aW9uPgogICAgPHBvcnQ+MTUxNDwvcG9ydD4KICAgIDxwcm90b2NvbD51ZHA8L3Byb3RvY29sPgogIDwvcmVtb3RlPgoKICA8IS0tIFBvbGljeSBtb25pdG9yaW5nIC0tPgogIDxyb290Y2hlY2s+CiAgICA8ZGlzYWJsZWQ+bm88L2Rpc2FibGVkPgoKICAgIDwhLS0gRnJlcXVlbmN5IHRoYXQgcm9vdGNoZWNrIGlzIGV4ZWN1dGVkIC0gZXZlcnkgMTIgaG91cnMgLS0+CiAgICA8ZnJlcXVlbmN5PjQzMjAwPC9mcmVxdWVuY3k+CgogICAgPHJvb3RraXRfZmlsZXM+L3Zhci9vc3NlYy9ldGMvc2hhcmVkL3Jvb3RraXRfZmlsZXMudHh0PC9yb290a2l0X2ZpbGVzPgogICAgPHJvb3RraXRfdHJvamFucz4vdmFyL29zc2VjL2V0Yy9zaGFyZWQvcm9vdGtpdF90cm9qYW5zLnR4dDwvcm9vdGtpdF90cm9qYW5zPgoKICAgIDxzeXN0ZW1fYXVkaXQ+L3Zhci9vc3NlYy9ldGMvc2hhcmVkL3N5c3RlbV9hdWRpdF9yY2wudHh0PC9zeXN0ZW1fYXVkaXQ+CiAgICA8c3lzdGVtX2F1ZGl0Pi92YXIvb3NzZWMvZXRjL3NoYXJlZC9zeXN0ZW1fYXVkaXRfc3NoLnR4dDwvc3lzdGVtX2F1ZGl0PgogICAgPHN5c3RlbV9hdWRpdD4vdmFyL29zc2VjL2V0Yy9zaGFyZWQvY2lzX2RlYmlhbl9saW51eF9yY2wudHh0PC9zeXN0ZW1fYXVkaXQ+CgogICAgPHNraXBfbmZzPnllczwvc2tpcF9uZnM+CiAgPC9yb290Y2hlY2s+CgogIDx3b2RsZSBuYW1lPSJvcGVuLXNjYXAiPgogICAgPGRpc2FibGVkPnllczwvZGlzYWJsZWQ+CiAgICA8dGltZW91dD4xODAwPC90aW1lb3V0PgogICAgPGludGVydmFsPjFkPC9pbnRlcnZhbD4KICAgIDxzY2FuLW9uLXN0YXJ0Pnllczwvc2Nhbi1vbi1zdGFydD4KCiAgICA8Y29udGVudCB0eXBlPSJ4Y2NkZiIgcGF0aD0ic3NnLWRlYmlhbi04LWRzLnhtbCI+CiAgICAgIDxwcm9maWxlPnhjY2RmX29yZy5zc2dwcm9qZWN0LmNvbnRlbnRfcHJvZmlsZV9jb21tb248L3Byb2ZpbGU+CiAgICA8L2NvbnRlbnQ+CiAgICA8Y29udGVudCB0eXBlPSJvdmFsIiBwYXRoPSJjdmUtZGViaWFuLW92YWwueG1sIi8+CiAgPC93b2RsZT4KCiAgPHdvZGxlIG5hbWU9InN5c2NvbGxlY3RvciI+CiAgICA8ZGlzYWJsZWQ+bm88L2Rpc2FibGVkPgogICAgPGludGVydmFsPjFoPC9pbnRlcnZhbD4KICAgIDxzY2FuX29uX3N0YXJ0Pnllczwvc2Nhbl9vbl9zdGFydD4KICAgIDxoYXJkd2FyZT55ZXM8L2hhcmR3YXJlPgogICAgPG9zPnllczwvb3M+CiAgICA8bmV0d29yaz55ZXM8L25ldHdvcms+CiAgPC93b2RsZT4KCiAgPHdvZGxlIG5hbWU9InZ1bG5lcmFiaWxpdHktZGV0ZWN0b3IiPgogICAgPGRpc2FibGVkPm5vPC9kaXNhYmxlZD4KICAgIDxpbnRlcnZhbD4xZDwvaW50ZXJ2YWw+CiAgICA8cnVuX29uX3N0YXJ0PnllczwvcnVuX29uX3N0YXJ0PgogICAgPHVwZGF0ZV91YnVudHVfb3ZhbCBpbnRlcnZhbD0iNjBtIiB2ZXJzaW9uPSIxNiwxNCwxMiI+eWVzPC91cGRhdGVfdWJ1bnR1X292YWw+CiAgICA8dXBkYXRlX3JlZGhhdF9vdmFsIGludGVydmFsPSI2MG0iIHZlcnNpb249IjcsNiw1Ij55ZXM8L3VwZGF0ZV9yZWRoYXRfb3ZhbD4KICA8L3dvZGxlPgoKICA8IS0tIEZpbGUgaW50ZWdyaXR5IG1vbml0b3JpbmcgLS0+CiAgPHN5c2NoZWNrPgogICAgPGRpc2FibGVkPm5vPC9kaXNhYmxlZD4KCiAgICA8IS0tIEZyZXF1ZW5jeSB0aGF0IHN5c2NoZWNrIGlzIGV4ZWN1dGVkIGRlZmF1bHQgZXZlcnkgMTIgaG91cnMgLS0+CiAgICA8ZnJlcXVlbmN5PjQzMjAwPC9mcmVxdWVuY3k+CgogICAgPHNjYW5fb25fc3RhcnQ+eWVzPC9zY2FuX29uX3N0YXJ0PgoKICAgIDwhLS0gR2VuZXJhdGUgYWxlcnQgd2hlbiBuZXcgZmlsZSBkZXRlY3RlZCAtLT4KICAgIDxhbGVydF9uZXdfZmlsZXM+eWVzPC9hbGVydF9uZXdfZmlsZXM+CgogICAgPCEtLSBEb24ndCBpZ25vcmUgZmlsZXMgdGhhdCBjaGFuZ2UgbW9yZSB0aGFuIDMgdGltZXMgLS0+CiAgICA8YXV0b19pZ25vcmU+bm88L2F1dG9faWdub3JlPgoKICAgIDwhLS0gRGlyZWN0b3JpZXMgdG8gY2hlY2sgIChwZXJmb3JtIGFsbCBwb3NzaWJsZSB2ZXJpZmljYXRpb25zKSAtLT4KICAgIDxkaXJlY3RvcmllcyBjaGVja19hbGw9InllcyI+L2V0YywvdXNyL2JpbiwvdXNyL3NiaW48L2RpcmVjdG9yaWVzPgogICAgPGRpcmVjdG9yaWVzIGNoZWNrX2FsbD0ieWVzIj4vYmluLC9zYmluLC9ib290PC9kaXJlY3Rvcmllcz4KCiAgICA8IS0tIEZpbGVzL2RpcmVjdG9yaWVzIHRvIGlnbm9yZSAtLT4KICAgIDxpZ25vcmU+L2V0Yy9tdGFiPC9pZ25vcmU+CiAgICA8aWdub3JlPi9ldGMvaG9zdHMuZGVueTwvaWdub3JlPgogICAgPGlnbm9yZT4vZXRjL21haWwvc3RhdGlzdGljczwvaWdub3JlPgogICAgPGlnbm9yZT4vZXRjL3JhbmRvbS1zZWVkPC9pZ25vcmU+CiAgICA8aWdub3JlPi9ldGMvcmFuZG9tLnNlZWQ8L2lnbm9yZT4KICAgIDxpZ25vcmU+L2V0Yy9hZGp0aW1lPC9pZ25vcmU+CiAgICA8aWdub3JlPi9ldGMvaHR0cGQvbG9nczwvaWdub3JlPgogICAgPGlnbm9yZT4vZXRjL3V0bXB4PC9pZ25vcmU+CiAgICA8aWdub3JlPi9ldGMvd3RtcHg8L2lnbm9yZT4KICAgIDxpZ25vcmU+L2V0Yy9jdXBzL2NlcnRzPC9pZ25vcmU+CiAgICA8aWdub3JlPi9ldGMvZHVtcGRhdGVzPC9pZ25vcmU+CiAgICA8aWdub3JlPi9ldGMvc3ZjL3ZvbGF0aWxlPC9pZ25vcmU+CiAgICA8aWdub3JlPi9zeXMva2VybmVsL3NlY3VyaXR5PC9pZ25vcmU+CiAgICA8aWdub3JlPi9zeXMva2VybmVsL2RlYnVnPC9pZ25vcmU+CgogICAgPCEtLSBDaGVjayB0aGUgZmlsZSwgYnV0IG5ldmVyIGNvbXB1dGUgdGhlIGRpZmYgLS0+CiAgICA8bm9kaWZmPi9ldGMvc3NsL3ByaXZhdGUua2V5PC9ub2RpZmY+CgogICAgPHNraXBfbmZzPnllczwvc2tpcF9uZnM+CiAgPC9zeXNjaGVjaz4KCiAgPCEtLSBBY3RpdmUgcmVzcG9uc2UgLS0+CiAgPGdsb2JhbD4KICAgIDx3aGl0ZV9saXN0PjEyNy4wLjAuMTwvd2hpdGVfbGlzdD4KICAgIDx3aGl0ZV9saXN0Pl5sb2NhbGhvc3QubG9jYWxkb21haW4kPC93aGl0ZV9saXN0PgogICAgPHdoaXRlX2xpc3Q+MTAuMC4wLjI8L3doaXRlX2xpc3Q+CiAgPC9nbG9iYWw+CgogIDxjb21tYW5kPgogICAgPG5hbWU+ZGlzYWJsZS1hY2NvdW50PC9uYW1lPgogICAgPGV4ZWN1dGFibGU+ZGlzYWJsZS1hY2NvdW50LnNoPC9leGVjdXRhYmxlPgogICAgPGV4cGVjdD51c2VyPC9leHBlY3Q+CiAgICA8dGltZW91dF9hbGxvd2VkPnllczwvdGltZW91dF9hbGxvd2VkPgogIDwvY29tbWFuZD4KCiAgPGNvbW1hbmQ+CiAgICA8bmFtZT5yZXN0YXJ0LW9zc2VjPC9uYW1lPgogICAgPGV4ZWN1dGFibGU+cmVzdGFydC1vc3NlYy5zaDwvZXhlY3V0YWJsZT4KICAgIDxleHBlY3Q+PC9leHBlY3Q+CiAgPC9jb21tYW5kPgoKICA8Y29tbWFuZD4KICAgIDxuYW1lPmZpcmV3YWxsLWRyb3A8L25hbWU+CiAgICA8ZXhlY3V0YWJsZT5maXJld2FsbC1kcm9wLnNoPC9leGVjdXRhYmxlPgogICAgPGV4cGVjdD5zcmNpcDwvZXhwZWN0PgogICAgPHRpbWVvdXRfYWxsb3dlZD55ZXM8L3RpbWVvdXRfYWxsb3dlZD4KICA8L2NvbW1hbmQ+CgogIDxjb21tYW5kPgogICAgPG5hbWU+aG9zdC1kZW55PC9uYW1lPgogICAgPGV4ZWN1dGFibGU+aG9zdC1kZW55LnNoPC9leGVjdXRhYmxlPgogICAgPGV4cGVjdD5zcmNpcDwvZXhwZWN0PgogICAgPHRpbWVvdXRfYWxsb3dlZD55ZXM8L3RpbWVvdXRfYWxsb3dlZD4KICA8L2NvbW1hbmQ+CgogIDxjb21tYW5kPgogICAgPG5hbWU+cm91dGUtbnVsbDwvbmFtZT4KICAgIDxleGVjdXRhYmxlPnJvdXRlLW51bGwuc2g8L2V4ZWN1dGFibGU+CiAgICA8ZXhwZWN0PnNyY2lwPC9leHBlY3Q+CiAgICA8dGltZW91dF9hbGxvd2VkPnllczwvdGltZW91dF9hbGxvd2VkPgogIDwvY29tbWFuZD4KCiAgPGNvbW1hbmQ+CiAgICA8bmFtZT53aW5fcm91dGUtbnVsbDwvbmFtZT4KICAgIDxleGVjdXRhYmxlPnJvdXRlLW51bGwuY21kPC9leGVjdXRhYmxlPgogICAgPGV4cGVjdD5zcmNpcDwvZXhwZWN0PgogICAgPHRpbWVvdXRfYWxsb3dlZD55ZXM8L3RpbWVvdXRfYWxsb3dlZD4KICA8L2NvbW1hbmQ+CgogIDwhLS0KICA8YWN0aXZlLXJlc3BvbnNlPgogICAgYWN0aXZlLXJlc3BvbnNlIG9wdGlvbnMgaGVyZQogIDwvYWN0aXZlLXJlc3BvbnNlPgogIC0tPgoKICA8IS0tIExvZyBhbmFseXNpcyAtLT4KICA8bG9jYWxmaWxlPgogICAgPGxvZ19mb3JtYXQ+c3lzbG9nPC9sb2dfZm9ybWF0PgogICAgPGxvY2F0aW9uPi92YXIvb3NzZWMvbG9ncy9hY3RpdmUtcmVzcG9uc2VzLmxvZzwvbG9jYXRpb24+CiAgPC9sb2NhbGZpbGU+CgogIDxsb2NhbGZpbGU+CiAgICA8bG9nX2Zvcm1hdD5zeXNsb2c8L2xvZ19mb3JtYXQ+CiAgICA8bG9jYXRpb24+L3Zhci9sb2cvbWVzc2FnZXM8L2xvY2F0aW9uPgogIDwvbG9jYWxmaWxlPgoKICA8bG9jYWxmaWxlPgogICAgPGxvZ19mb3JtYXQ+c3lzbG9nPC9sb2dfZm9ybWF0PgogICAgPGxvY2F0aW9uPi92YXIvbG9nL2F1dGgubG9nPC9sb2NhdGlvbj4KICA8L2xvY2FsZmlsZT4KCiAgPGxvY2FsZmlsZT4KICAgIDxsb2dfZm9ybWF0PnN5c2xvZzwvbG9nX2Zvcm1hdD4KICAgIDxsb2NhdGlvbj4vdmFyL2xvZy9zeXNsb2c8L2xvY2F0aW9uPgogIDwvbG9jYWxmaWxlPgoKICA8bG9jYWxmaWxlPgogICAgPGxvZ19mb3JtYXQ+Y29tbWFuZDwvbG9nX2Zvcm1hdD4KICAgIDxjb21tYW5kPmRmIC1QPC9jb21tYW5kPgogICAgPGZyZXF1ZW5jeT4zNjA8L2ZyZXF1ZW5jeT4KICA8L2xvY2FsZmlsZT4KCiAgPGxvY2FsZmlsZT4KICAgIDxsb2dfZm9ybWF0PmZ1bGxfY29tbWFuZDwvbG9nX2Zvcm1hdD4KICAgIDxjb21tYW5kPm5ldHN0YXQgLXRhbiB8Z3JlcCBMSVNURU4gfGdyZXAgLXYgMTI3LjAuMC4xIHwgc29ydDwvY29tbWFuZD4KICAgIDxmcmVxdWVuY3k+MzYwPC9mcmVxdWVuY3k+CiAgPC9sb2NhbGZpbGU+CgogIDxsb2NhbGZpbGU+CiAgICA8bG9nX2Zvcm1hdD5mdWxsX2NvbW1hbmQ8L2xvZ19mb3JtYXQ+CiAgICA8Y29tbWFuZD5sYXN0IC1uIDU8L2NvbW1hbmQ+CiAgICA8ZnJlcXVlbmN5PjM2MDwvZnJlcXVlbmN5PgogIDwvbG9jYWxmaWxlPgoKICA8cnVsZXNldD4KICAgIDwhLS0gRGVmYXVsdCBydWxlc2V0IC0tPgogICAgPGRlY29kZXJfZGlyPnJ1bGVzZXQvZGVjb2RlcnM8L2RlY29kZXJfZGlyPgogICAgPHJ1bGVfZGlyPnJ1bGVzZXQvcnVsZXM8L3J1bGVfZGlyPgogICAgPHJ1bGVfZXhjbHVkZT4wMjE1LXBvbGljeV9ydWxlcy54bWw8L3J1bGVfZXhjbHVkZT4KICAgIDxsaXN0PmV0Yy9saXN0cy9hdWRpdC1rZXlzPC9saXN0PgoKICAgIDwhLS0gVXNlci1kZWZpbmVkIHJ1bGVzZXQgLS0+CiAgICA8ZGVjb2Rlcl9kaXI+ZXRjL2RlY29kZXJzPC9kZWNvZGVyX2Rpcj4KICAgIDxydWxlX2Rpcj5ldGMvcnVsZXM8L3J1bGVfZGlyPgogIDwvcnVsZXNldD4KCiAgPCEtLSBDb25maWd1cmF0aW9uIGZvciBvc3NlYy1hdXRoZAogICAgICAgVG8gZW5hYmxlIHRoaXMgc2VydmljZSwgcnVuOgogICAgICAgb3NzZWMtY29udHJvbCBlbmFibGUgYXV0aAogIC0tPgogIDxhdXRoPgogICAgPGRpc2FibGVkPm5vPC9kaXNhYmxlZD4KICAgIDxwb3J0PjE1MTU8L3BvcnQ+CiAgICA8dXNlX3NvdXJjZV9pcD55ZXM8L3VzZV9zb3VyY2VfaXA+CiAgICA8Zm9yY2VfaW5zZXJ0PnllczwvZm9yY2VfaW5zZXJ0PgogICAgPGZvcmNlX3RpbWU+MDwvZm9yY2VfdGltZT4KICAgIDxwdXJnZT55ZXM8L3B1cmdlPgogICAgPHVzZV9wYXNzd29yZD5ubzwvdXNlX3Bhc3N3b3JkPgogICAgPCEtLSA8c3NsX2FnZW50X2NhPjwvc3NsX2FnZW50X2NhPiAtLT4KICAgIDxzc2xfdmVyaWZ5X2hvc3Q+bm88L3NzbF92ZXJpZnlfaG9zdD4KICAgIDxzc2xfbWFuYWdlcl9jZXJ0Pi92YXIvb3NzZWMvZXRjL3NzbG1hbmFnZXIuY2VydDwvc3NsX21hbmFnZXJfY2VydD4KICAgIDxzc2xfbWFuYWdlcl9rZXk+L3Zhci9vc3NlYy9ldGMvc3NsbWFuYWdlci5rZXk8L3NzbF9tYW5hZ2VyX2tleT4KICAgIDxzc2xfYXV0b19uZWdvdGlhdGU+bm88L3NzbF9hdXRvX25lZ290aWF0ZT4KICA8L2F1dGg+Cgo8L29zc2VjX2NvbmZpZz4K" | base64 -w0 -d > /var/containers/wazuh/wazuh-config-mount/etc/ossec.conf
docker run --name=wazuh_1 --link=logstash_wazuh_1:logstash -p 1514:1514/udp -p 1515:1515 -p 514:514/udp -p 55000:55000 -v /var/containers/wazuh/var/ossec/data:/var/ossec/data:Z -v /var/containers/wazuh/etc/postfix:/etc/postfix:Z -v /var/containers/wazuh/etc/filebeat:/etc/filebeat:Z -v /var/containers/wazuh/wazuh-config-mount/etc/ossec.conf:/wazuh-config-mount/etc/ossec.conf wazuh/wazuh:3.6.1_6.4.2

#Creación y configuración de directorios para kibana
mkdir -p /var/containers/elk/kibana/
echo "IyA9PT09PT09PT09PT09PT09PT09IGtpYmFuYToga2liYW5hLnltbCA9PT09PT09PT09PT09PT09PT09PT09ICMKI2tpYmFuYSBjb25maWd1cmF0aW9uIGZyb20ga2liYW5hLWRvY2tlci4Kc2VydmVyLm5hbWU6IGtpYmFuYQpzZXJ2ZXIuaG9zdDogIjAiCmVsYXN0aWNzZWFyY2gudXJsOiBodHRwOi8vZWxhc3RpY3NlYXJjaDo5MjAwICNEaXJlY2NpT24gSVAgZGVsIGNvbnRlbmVkb3IgZGUgZWxhc3RpY3NlYXJjaA==" | base64 -w0 -d > /var/containers/elk/kibana/kibana.yml
docker run --name=kibana_wazuh_1 --link=elasticsearch_wazuh_1:elasticsearch -p 5601:5601 -d -v /var/containers/elk/kibana/kibana.yml:/usr/share/kibana/config/kibana.yml:z docker.elastic.co/kibana/kibana-oss:6.2.2
echo "Kibana creado"

echo "Consulta la ruta http://localhost:5601"