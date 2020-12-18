#!/usr/bin/env python

"""
ldap_graph.py - Walk an LDAP tree to generate a data structure that can be used to
generate a graph showing the relationships between discovered LDAP objects.
"""

import argparse
import confuse
import getpass
import json
import ldap

from graphviz import Digraph

# Global declarations
#USER_DN="cn=users,cn=accounts"
#GROUP_DN="cn=groups,cn=accounts"
DEFAULT_CONFIG_FILE_PATH="conf/default.yml"

class PasswordPromptAction(argparse.Action):
    """An argparse action to securely prompt
    the user for a password.
    """
    def __init__(self,
             option_strings,
             dest=None,
             nargs=0,
             default=None,
             required=False,
             type=None,
             metavar=None,
             help=None):
        super(PasswordPromptAction, self).__init__(
             option_strings=option_strings,
             dest=dest,
             nargs=nargs,
             default=default,
             required=required,
             metavar=metavar,
             type=type,
             help=help)

    def __call__(self, parser, args, values, option_string=None):
        password = getpass.getpass()
        setattr(args, self.dest, password)

def parse_args():
    """Parse command-line arguments
    """
    parser = argparse.ArgumentParser("Walk an LDAP tree to generate a data structure that can be used to generate a graph showing the relationships between discovered LDAP objects")
    parser.add_argument(
        "-b",
        "--base-dn",
        type=str,
        dest="base_dn",
        required=True,
        help="The base DN of the LDAP tree to search from"
    )
    parser.add_argument(
        "-H",
        "--bind-host",
        type=str,
        dest="bind_host",
        required=True,
        help="The hostname of the LDAP server to bind to"
    )
    parser.add_argument(
        "-s",
        "--secure",
        action="store_true",
        dest="use_ssl",
        help="Use SSL (LDAPS)"
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="ldap_port",
        type=int,
        help="Specify a non-standard port to connect to the LDAP server on"
    )
    parser.add_argument(
        "-f",
        "--filter",
        type=str,
        dest="search_filter",
        default="(objectClass=*)",
        help="Filter string to limit the results"
    )
    parser.add_argument(
        "-D",
        "--bind-dn",
        type=str,
        dest="bind_dn",
        help="The user DN to bind to the LDAP directory with"
    )
    passwd = parser.add_mutually_exclusive_group()
    passwd.add_argument(
        "-w",
        "--bind-passwd",
        type=str,
        dest="bind_passwd",
        help="Specify a bind password on the CLI. Use -W to prompt for one"
    )
    passwd.add_argument(
        "-W",
        "--prompt-passwd",
        action=PasswordPromptAction,
        dest="bind_passwd",
        help="Prompts the user for a password to bind to the LDAP server with"
    )

    # Add sub-parsers for the different graphing frameworks this app supports.
    # TODO: Uncomment anything to do with these subparsers when they're properly implemented
    #subparser = parser.add_subparsers()
    #sp_graphviz = subparser.add_parser("graphviz", help="Generate a GraphViz diagram of the LDAP tree")
    #sp_neo4j = subparser.add_parser("neo4j", help="Generate a Neo4J diagram of the LDAP tree")

    args = parser.parse_args()

    if args.gssapi and (args.bind_dn is not None or args.bind_passwd is not None):
        parser.error("Option to use GSSAPI authentication specified (-Y). Using -D and/or -w/-W while trying to use GSSAPI authenticaton is not allowed.")

    if args.use_ssl:
        if args.ldap_port:
            args.bind_url = f'ldaps://{args.bind_host}:{args.ldap_port}'
        else:
            args.bind_url = f'ldaps://{args.bind_host}:636'
    else:
        if args.ldap_port:
            args.bind_url = f'ldap://{args.bind_host}:{args.ldap_port}'
        else:
            args.bind_url = f'ldap://{args.bind_host}:389'

    return args

def parse_config(config_file_path=None):
    """Parse user-defined YAML config file
    """
    config = confuse.Configuration("ldap_graph", __name__)
    # Read in default configurations
    config.set_file(DEFAULT_CONFIG_FILE_PATH)
    # Read in user-defined configurations (will overwrite any defaults)
    if config_file_path:
        config.set_file(config_file_path)

    return config

def dedup_config(parsed_args, parsed_config):
    """Compare command-line options with configurations
    parsed from config file.
    Command-line options will override options defined in
    any config files.

    Params:
      parsed_args   (namespace)
        Output of argparse.parse_args()

      parsed_config (object)
        YAML configuration parsed by Confuse library

    Returns:
      config        (dict)
        Dictionary of deduplicated configuration
    """
    config = {}

    


if __name__ == "__main__":

    args = parse_args()
    yaml_conf = parse_config()
    config = dedup_config(args, yaml_conf)

    con = ldap.initialize(args.bind_url, bytes_mode=False)
    if args.gssapi:
        con.sasl_gssapi_bind_s()
    else:
        con.simple_bind_s(args.bind_dn, args.bind_passwd)

    results = con.search_s(args.base_dn, ldap.SCOPE_SUBTREE, args.search_filter)
    #print(results)
    #print(json.dumps(results, indent=4))
    #for obj in results:
    #    print(obj)
    dot = Digraph(comment="LDAP relationship graph")
    for key, val in results:
        #out = "{" + key + "}: {" + val + "}"
        #print(json.dumps(out, indent=4))
        print(key)
        print(val)
        print()
        dot.node(key, key)

    dot.render("output/dot/ldap_graph.gv")
