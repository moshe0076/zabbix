This Python script will remove an EC2 instance from a Zabbix server.
The script uses the Zabbix API, so make sure the instance can access port 80/tcp on the Zabbix server.
The script uses the zabbix_sender binary to send messages to the Zabbix server. I have created a dummy host called zabbix_web_master on the Zabbix server that the zabbix_sender sends error messages to incase something goes wrong.
