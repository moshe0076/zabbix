#! /usr/bin/python

import argparse
import logging
import logging.handlers
import traceback
import socket
import sys
import time
import os.path
import subprocess
from pyzabbix import ZabbixAPI

class remove_host_from_zabbix:
    def __init__(self, zabbix_server, zabbix_user, zabbix_password, region, zabbix_web_master):
        """Class constructor"""
        self.zabbix_web_master=zabbix_web_master
        self.zabbix_server = zabbix_server
        self.zabbix_user = zabbix_user
        self.zabbix_password = zabbix_password
        self.server_ip_address=self._get_server_ip_address()
        self.zabbix_host_name = "ip-" + self.server_ip_address.replace(".", "-")
        self.zabbix_conn=self._connect_to_zabbix_server_api()
        self.region=region
        self.zabbix_host_id=self._get_zabbix_host_id(self.zabbix_host_name)


    def _get_server_ip_address(self):
        """This function will retrieve the ip address of the server"""
        logging.info("Retrieving IP address of server... ")
        p = subprocess.Popen('curl -s http://169.254.169.254/latest/meta-data/local-ipv4', shell=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        exit_code = p.wait()
        if exit_code != 0:
            logging.critical('There was a problem retrieving the IP address:')
            logging.critical('Will update the Zabbix web master and exit...')
            error_msg="Error:Web Server: failed retrieving the IP address of instance %s" %(self._get_instance_id())
            self._send_to_zabbix(self.zabbix_web_master,error_msg, "Web_Server_Error")
            logging.critical('Script will be terminated....')
            sys.exit(1)
        else:
            logging.info('The IP address of the server is: "%s"' %(out))
            return out

    def _get_instance_id(self):
        """This function will retrieve the instance id of the server"""
        logging.info("Retrieving instance id of the server... ")
        p = subprocess.Popen('curl -s http://169.254.169.254/latest/meta-data/instance-id', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        exit_code = p.wait()
        if exit_code != 0:
            logging.critical('There was a problem retrieving the instance id, will update Zabbix server and exit...')
            self._send_to_zabbix(self.zabbix_host_name, "Error:Web Server: failed retrieving instance id", "Web_Server_Error")
            logging.critical('Script will be terminated....')
            sys.exit(1)
        else:
            logging.info('The instance id of the server is: "%s"' % (out))
            return out

    def _send_to_zabbix(self,zabbix_host_name, massage, key):
        "This function will send a massage to Zabbix using the zabbix_sender binary"
        zabbix_sender_command = "/usr/bin/zabbix_sender -z %s -s %s -k %s -o '%s'" % (self.zabbix_server, zabbix_host_name, key, massage)
        logging.info('Sending massage to Zabbix server "%s"' % (self.zabbix_server))
        logging.info("Executing %s" % (zabbix_sender_command))
        p = subprocess.Popen(zabbix_sender_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        output = p.stdout.read()
        logging.info('Result of zabbix_sender was: "%s"' % (output))


    def _connect_to_zabbix_server_api(self):
        """This function will connect to the zabbix server API"""
        logging.info('Connecting to Zabbix server "%s" API...' % (self.zabbix_server))
        try:
            zapi = ZabbixAPI("http://%s/zabbix" % (self.zabbix_server))
            zapi.login(self.zabbix_user, self.zabbix_password)
        except:
            logging.critical('There was a problem connecting to the Zabbix server "%s" API \n' % (self.zabbix_server) + str(traceback.format_exc()))
            logging.critical('Will update Zabbix server and exit...')
            self._send_to_zabbix(self.zabbix_host_name, "Error:Web Server: failed connecting to Zabbix server API", "Web_Server_Error")
            logging.critical('Script will be terminated....')
            sys.exit(1)
        logging.info("Connected to Zabbix API Version %s" % zapi.api_version())
        return zapi

    def _get_zabbix_host_id(self, zabbix_host_name):
        """This function will retrieve the host id for the zabbix host"""
        logging.info('Retrieving host id for host "%s" from Zabbix server' % (zabbix_host_name))
        try:
            zhost = self.zabbix_conn.host.get(filter={"host": str(zabbix_host_name)})
            zabbix_hostid = zhost[0]["hostid"]
            logging.info('Host id "%s" was retrieved for hostname "%s"' % (zabbix_hostid, zabbix_host_name))
            return zabbix_hostid
        except:
            logging.critical('There was a problem retrieving host id of host "%s from Zabbix server "%s"\n' % (zabbix_host_name, self.zabbix_server) + str(traceback.format_exc()))
            logging.critical('Will update Zabbix server and exit...')
            self._send_to_zabbix(self.zabbix_web_master, 'Error:Web Server: failed retrieving host id for host "%s" from Zabbix server' %(self.server_ip_address), "Web_Server_Error")
            logging.critical('Script will be terminated....')
            sys.exit(1)

    def _remove_host_from_zabbix_api(self, zabbix_host_name, zabbix_host_id):
        """This function will connect to the Zabbix server API"""
        logging.info('Removing host "%s" with host id "%s" from Zabbix server' % (zabbix_host_name, zabbix_host_id))
        try:
            self.zabbix_conn.host.delete(zabbix_host_id)
            logging.info('The host "%s" with host id "%s" was removed from Zabbix server' % (zabbix_host_name, zabbix_host_id))
        except:
            logging.critical('There was a problem removing host "%s" with host id "%s" from Zabbix server "%s"\n' % (
                zabbix_host_name, zabbix_host_id, self.zabbix_server) + str(traceback.format_exc()))
            logging.critical('Will update Zabbix server and exit...')
            self._send_to_zabbix(self.zabbix_host_name, "Error:Web Server: failed removing host from Zabbix server", "Web_Server_Error")
            logging.critical('Script will be terminated....')
            sys.exit(1)

    def execute_remove_host_from_zabbix_server(self):
        """This function will remove the host from the Zabbix server"""
        self._remove_host_from_zabbix_api(self.zabbix_host_name,self.zabbix_host_id)

def main(zabbix_server, zabbix_user, zabbix_password, region, zabbix_web_master):
    try:
        LOG_FILENAME = '/var/log/remove-host-from-zabbix.log'
        filehndlr = logging.handlers.RotatingFileHandler(filename=LOG_FILENAME, mode='a', maxBytes=10000000,
                                                         backupCount=3, encoding=None)

        consolehndlr = logging.StreamHandler()
        hostname = socket.gethostname()
        formatter = logging.Formatter("%(asctime)s " + hostname + " %(name)-10s %(levelname)-8s %(message)s")
        filehndlr.setFormatter(formatter)
        consolehndlr.setFormatter(formatter)
        rootlogger = logging.getLogger()
        rootlogger.setLevel(logging.INFO)
        rootlogger.addHandler(filehndlr)
        rootlogger.addHandler(consolehndlr)
        logging.info("-" * 100)
        logging.info("Hi")
        logging.info("remove-host-from-zabbix.py")
        logging.info("-" * 100)
    except:
        exit("Unable to start logging. Script will exit.....\n" + str(traceback.format_exc()))

    remove_host_from_zabbix_obj = remove_host_from_zabbix(zabbix_server, zabbix_user, zabbix_password, region, zabbix_web_master)
    remove_host_from_zabbix_obj.execute_remove_host_from_zabbix_server()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
    description='This script will remove a host from the Zabbix server')
    parser.add_argument('-R', '--region', help='AWS region name', default="eu-west-1")
    parser.add_argument('-Z', '--zabbix_server', help='IP address or FQDN of the Zabbix server',
                        default="172.31.48.10")
    parser.add_argument('-U', '--zabbix_user', help='Zabbix user name for API connection', default="user")
    parser.add_argument('-P', '--zabbix_password', help='Zabbix password for API connection', default="password")
    parser.add_argument('-ZWM', '--zabbix_web_master', help='Zabbix web master', default="1.2.1.2")
    args = vars(parser.parse_args())
    zabbix_server = args['zabbix_server']
    zabbix_user = args['zabbix_user']
    zabbix_password = args['zabbix_password']
    region = args['region']
    zabbix_web_master=args['zabbix_web_master']

    main(zabbix_server, zabbix_user, zabbix_password, region, zabbix_web_master)


