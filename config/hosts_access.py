import click
import ipaddress

import utilities_common.cli as clicommon
from .validated_config_db_connector import ValidatedConfigDBConnector

#
#   config hosts_access
#
@click.group()
def hosts_access():
    """hosts_access command line"""
    pass

def validate_client_list(clients_list):
    """Validate client list and ensure network addresses have zero host bits"""
    validated_list = []
    for client in clients_list:
        try:
            # Check if client equals "ALL"
            if client == "ALL":
                validated_list.append(client)
            elif '/' in client:
                # Parse as a network and ensure host bits are zero
                network = ipaddress.ip_network(client, strict=False)
                validated_list.append(str(network))
            else:
                # Parse as an individual address
                ip = ipaddress.ip_address(client)
                validated_list.append(str(ip))
        except ValueError:
            # Invalid client
            click.echo(f"Invalid client: {client}")
            return None
    return validated_list


#
#   config hosts_access add
#
@hosts_access.command('add')
@click.argument('access_type', metavar='<allow|deny>', required=True, type=click.Choice(['allow', 'deny']))
@click.argument('daemon', metavar='<daemon_name>',required=True, type=click.Choice(['sshd']))
@click.argument('clients', metavar='<clients_list>', required=True, nargs=-1)
@clicommon.pass_db
def client_add(db, access_type, daemon, clients):
    """Add <daemon,clients> to host access control file\n
       <daemon_name>: daemon process name. currently,only "sshd" is supported\n
       <clients_list>: ipv4/ipv6 host address, network address(net/mask | net/prefixlen), string:"ALL" """

    ctx = click.get_current_context()
    config_db = ValidatedConfigDBConnector(db.cfgdb)
    clients_list = list(clients)

    validated_list = validate_client_list(clients_list)
    if validated_list is None:
        return
    
    # get existing list
    clients_entry = []
    hs_table = config_db.get_entry('HOSTS_ACCESS', access_type)
    if hs_table is not None and daemon in hs_table:
        clients_entry = hs_table[daemon]

    # remove existing clients from the list, and add new clients to the list
    clients_entry = list(set(clients_entry) - set(validated_list))
    clients_entry.extend(validated_list)
    clients_entry = list(set(clients_entry))

    if "ALL" in clients_entry:
        clients_entry = ["ALL"]

    # Update ConfigDB
    fvs = {daemon: clients_entry}
    try:
        config_db.mod_entry('HOSTS_ACCESS', access_type, fvs)
    except ValueError as e:
        ctx.fail("Invalid ConfigDB. Error: {}".format(e))


#
#   config hosts_access remove
#
@hosts_access.command('remove')
@click.argument('access_type', metavar='<allow|deny>', required=True, type=click.Choice(['allow', 'deny']))
@click.argument('daemon', metavar='<daemon_name>',required=True, type=click.Choice(['sshd']))
@click.argument('clients', metavar='<clients_list>', required=True, nargs=-1)
@clicommon.pass_db
def client_remove(db, access_type, daemon, clients):
    """Remove <daemon,clients> from host access control file\n
       <daemon_name>: daemon process name. currently,only "sshd" is supported\n
       <clients_list>: ipv4/ipv6 host address, network address(net/mask | net/prefixlen), string:"ALL" """

    ctx = click.get_current_context()
    config_db = ValidatedConfigDBConnector(db.cfgdb)

    clients_list = list(clients)
    validated_list = validate_client_list(clients_list)
    if validated_list is None:
        return
    
    # get existing list
    clients_entry = []
    hs_table = config_db.get_entry('HOSTS_ACCESS', access_type)
    if hs_table is not None and daemon in hs_table:
        clients_entry = hs_table[daemon]

    if len(clients_entry) == 0:
        return

    # Remove clients from existing list
    clients_entry = list(set(clients_entry) - set(validated_list))
    # Update ConfigDB
    if len(clients_entry) == 0:
        hs_table.pop(daemon)
    else:
        hs_table[daemon] = clients_entry
    try:
        if len(hs_table) == 0:
            config_db.set_entry('HOSTS_ACCESS', access_type, None)
        else:
            config_db.set_entry('HOSTS_ACCESS', access_type, hs_table)
    except ValueError as e:
        ctx.fail("Invalid ConfigDB. Error: {}".format(e))