#!/usr/bin/env python
# encoding: utf-8
import click
import boto3
from boto3.exceptions import botocore
import os.path
import logging
import yaml
import sys

PROFILE = 'default'
REGION = 'us-east-1'
USERNAME = 'centos'
PORT = 22
STATES = ['running']
logger = logging.getLogger(__name__)

def get_instances(profile, region, states):
    """
    get instances by `states` with special aws config `profile_name`.
    the default will get all `running` instances with default aws config.
    """

    session = None
    try:
        if region:
            session = boto3.Session(profile_name=profile, region_name=region)
        else:
            session = boto3.Session(profile_name=profile)
    except botocore.exceptions.ProfileNotFound as e:
        logger.error(e)
        sys.exit()

    ec2 = session.resource('ec2')
    instances = ec2.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': states}])

    return instances


def get_instances_data(profile, region, states):
    instances = get_instances(profile, region, states)
    instances_data = []

    try:
        for instance in instances:
            key_name = instance.key_name
            ip = instance.public_ip_address or instance.private_ip_address

            tags = instance.tags[0]
            if 'Hostname' in tags:
                hostname = tags['Hostname']
            else:
                hostname = tags['Value']

            # remove '[', ']' and replace '--' with '-'
            # hostname should be lowercase
            hostname = hostname and hostname.replace('[', '').replace(']', '-')\
                .replace(' ', '').replace('--', '-')

            # hostname should start with `profile`
            hostname = '{}-{}'.format(profile, hostname).lower()

            # hostname[-1] = ip.split('.')[-1]
            ip_prefix = ip and ip.split('.')[-1]
            hostname = '{}-{}'.format(hostname, ip_prefix)

            instances_data.append({
                'hostname': hostname,
                'ip': ip,
                'key_name': key_name
            })
    # wrong region value will throw this exception.
    except botocore.vendored.requests.exceptions.SSLError as e:
        logger.error(e)
        logger.warning('maybe you give a wrong region?')
        sys.exit()

    return instances_data

def get_ssh_private_key_path(key_name):
    if os.path.exists(os.path.expanduser('~/.ssh/{}'.format(key_name))):
        key_path = '~/.ssh/{}'.format(key_name)
    elif os.path.exists(os.path.expanduser('~/.ssh/id_rsa')):
        logger.debug('can not find ssh private key: ~/.ssh/{}'.format(key_name))
        key_path = '~/.ssh/id_rsa'
    else:
        key_path = ''
        logger.warning('can not find ssh private key: <{}>'.format(key_path))

    return key_path


@click.group()
def cli():
    pass


def generate_ssh_config(profile, region, username, port, states, output):
    hosts = get_instances_data(profile, region, states)
    res = ''
    for host in hosts:
        hostname = host['hostname']
        ip = host['ip']
        key_path = get_ssh_private_key_path(host['key_name'])
        res = ('{res}Host {hostname}{linesep}'
               '\tHostname {ip}{linesep}'
               '\tUser {username}{linesep}'
               '\tPort {port}{linesep}'
               '\tIdentityFile {key_path}{linesep}'
               #'\tProxyCommand ssh -q -W %h:%p {}'.format('jumpserver')
               ).format(res=res, linesep=os.linesep, hostname=hostname, ip=ip,
                        username=username, port=port, key_path=key_path)

    # write result to stdout or output file
    if output == sys.stdout:
        print(res)
    else:
        with open(output, 'w') as fd:
            fd.write(res)


def generate_assh_config(profile, region, username, port, states, output):
    hosts = get_instances_data(profile, region, states)
    data = {}
    template_name = '{}-template'.format(profile)
    data['hosts'] = {}
    data['templates'] = {
        template_name: {
            "User": username,
            "Port": port,
            #"Gateways": '{}-jumpserver'.format(profile),
        }
    }

    for host in hosts:
        key_path = get_ssh_private_key_path(host['key_name'])
        curr_hostname = host['hostname']
        data['hosts'][curr_hostname] = {
            'Hostname': host['ip'],
            'IdentityFile': key_path,
            'Inherits': template_name
        }

    # write result to stdout or output file
    if output == sys.stdout:
        yaml.dump(data, output, default_flow_style=False)
    else:
        with open(output, 'w') as fd:
            yaml.dump(data, fd, default_flow_style=False)

@click.command()
@click.option('--kind', default='assh', help='Generate assh config or ssh config. Default value: assh')
@click.option('--profile', default=PROFILE, help='aws profile name. Default value: {}'.format(PROFILE))
@click.option('--region', default=REGION, help='aws region name. Default value: {}'.format(REGION))
@click.option('--username', default=USERNAME, help='ec2 instance login username. Default value: {}'.format(USERNAME))
@click.option('--port', default=PORT, help='ec2 instance sshd listening port. Default value: {}'.format(PORT))
@click.option('--states', default=['running'], help='ec2 instance run state list. Default value: {}'.format(STATES))
@click.option('--output', default=sys.stdout, help='display result to stdout, or write to output file. Default value: stdout')
def generate_config(kind, profile, region, username, port, states, output):
    if kind == 'assh':
        generate_assh_config(profile, region, username, port, states, output)
    elif kind == 'ssh':
        generate_ssh_config(profile, region, username, port, states, output)
    else:
        logger.error('option, --kind [assh|ssh]')
        sys.exit()

cli.add_command(generate_assh_config, name='assh')
cli.add_command(generate_ssh_config, name='ssh')

if __name__ == '__main__':
    generate_config()
