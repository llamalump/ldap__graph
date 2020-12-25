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
import logging

from graphviz import Digraph

# Global declarations
DEFAULT_CONFIG_FILE_PATH="./conf/default.yml"

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
        "-c",
        "--config",
        type=str,
        dest="config_file_path",
        default="DEFAULT_CONFIG_FILE_PATH",
        help="Path to a configuration file. If unspecified, '{0}' is used".format(
            DEFAULT_CONFIG_FILE_PATH
        )
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print verbose output"
    )

    # Add sub-parsers for the different graphing frameworks this app supports.
    # TODO: Uncomment anything to do with these subparsers when they're properly implemented
    #subparser = parser.add_subparsers()
    #sp_graphviz = subparser.add_parser("graphviz", help="Generate a GraphViz diagram of the LDAP tree")
    #sp_neo4j = subparser.add_parser("neo4j", help="Generate a Neo4J diagram of the LDAP tree")

    args = parser.parse_args()

    return args

def configure_logging(verbose=False):
    """Configures the logging module for this script
    """
    logger = logging.getLogger("ldap_graph")
    formatter = logging.Formatter(fmt='{"time": "%(asctime)s.%(msecs)03d", "type": "log", "module": "%(name)s", "level": "%(levelname)s", "msg": "%(message)s"}', datefmt="%Y-%m-%d %H:%M:%S")
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    if verbose:
        logger.setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        console_handler.setLevel(logging.INFO)

    logger.addHandler(console_handler)

    return logger



class Configuration():

    def __init__(self, config_file_path=None):
        """Constructor

        Params:
          config_file_path  (str)
            Path to a configuration file (optional)
        """
        self.config_file_path = config_file_path
        self.raw_config = self.read_config(self.config_file_path)
        self.load_config(self.raw_config)

    def read_config(self, config_file_path):
        """Parse user-defined YAML config file

        Params:
          config_file_path  (str)
            Path to a configuration file
        """
        config = confuse.Configuration("ldap_graph", __name__)
        # Read in default configurations
        config.set_file(DEFAULT_CONFIG_FILE_PATH)
        # Read in user-defined configurations (will overwrite any defaults)
        if config_file_path:
            config.set_file(config_file_path)

        return config

    def load_config(self, config):
        """Load configuration from Confuse object

        Params:
          config   (confuse.core.Configuration)
            Object returned by confuse.Configuration()
        """
        ### Bind configuration
        self.ldap_host = config["bind"]["ldap_host"].get()
        self.ldap_port = config["bind"]["ldap_port"].get()
        self.use_ssl = config["bind"]["use_ssl"].get()
        self.bind_dn = config["bind"]["bind_dn"].get()
        if bool(config["bind"]["prompt_passwd"].get()):
            logger.info("prompt_passwd set to 'True' - prompting for password")
            self.bind_passwd = getpass.getpass("LDAP bind password: ")
        else:
            self.bind_passwd = config["bind"]["bind_passwd"].get()
        self.bind_url = f"{'ldaps' if self.use_ssl else 'ldap'}://{self.ldap_host}:{self.ldap_port}"

        ### Search configuration
        self.base_dn = config["search"]["base_dn"].get()
        # Users
        self.user_dn = config["search"]["users"]["user_dn"].get()
        self.user_obj_class = config["search"]["users"]["user_obj_class"].get()
        self.user_filter = config["search"]["users"]["user_filter"].get()
        self.username_attr = config["search"]["users"]["username_attr"].get()
        self.user_member_attr = config["search"]["users"]["user_member_attr"].get()
        # Groups
        self.group_dn = config["search"]["groups"]["group_dn"].get()
        self.group_obj_class = config["search"]["groups"]["group_obj_class"].get()
        self.group_filter = config["search"]["groups"]["group_filter"].get()
        self.group_name_attr = config["search"]["groups"]["group_name_attr"].get()
        self.group_desc_attr = config["search"]["groups"]["group_desc_attr"].get()
        self.group_member_attr = config["search"]["groups"]["group_member_attr"].get()
        # HBAC rules
        self.hbacrule_dn = config["search"]["hbac_rules"]["hbacrule_dn"].get()
        self.hbacrule_obj_class = config["search"]["hbac_rules"]["hbacrule_obj_class"].get()
        self.hbacrule_filter = config["search"]["hbac_rules"]["hbacrule_filter"].get()
        self.hbacrule_name_attr = config["search"]["hbac_rules"]["hbacrule_name_attr"].get()
        self.hbacrule_member_attr = config["search"]["hbac_rules"]["hbacrule_member_attr"].get()
        # Sudo rules
        self.sudorule_dn = config["search"]["sudo_rules"]["sudorule_dn"].get()
        self.sudorule_obj_class = config["search"]["sudo_rules"]["sudorule_obj_class"].get()
        self.sudorule_filter = config["search"]["sudo_rules"]["sudorule_filter"].get()
        self.sudorule_name_attr = config["search"]["sudo_rules"]["sudorule_name_attr"].get()
        self.sudorule_member_attr = config["search"]["sudo_rules"]["sudorule_member_attr"].get()
        # Hosts
        self.host_dn = config["search"]["hosts"]["host_dn"].get()
        self.host_obj_class = config["search"]["hosts"]["host_obj_class"].get()
        self.host_filter = config["search"]["hosts"]["host_filter"].get()
        self.host_name_attr = config["search"]["hosts"]["host_name_attr"].get()
        self.host_member_attr = config["search"]["hosts"]["host_member_attr"].get()
        # Host groups
        self.hostgroup_dn = config["search"]["host_groups"]["hostgroup_dn"].get()
        self.hostgroup_obj_class = config["search"]["host_groups"]["hostgroup_obj_class"].get()
        self.hostgroup_filter = config["search"]["host_groups"]["hostgroup_filter"].get()
        self.hostgroup_name_attr = config["search"]["host_groups"]["hostgroup_name_attr"].get()
        self.hostgroup_member_attr = config["search"]["host_groups"]["hostgroup_member_attr"].get()
        self.hostgroup_memberof_attr = config["search"]["host_groups"]["hostgroup_memberof_attr"].get()


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

if __name__ == "__main__":

    args = parse_args()

    logger = configure_logging(args.verbose)

    logger.info("Loading configuration")
    #config = parse_config(args.config_file_path)
    config = Configuration(args.config_file_path)
    logger.info("Configuration loaded")
    logger.debug(config.raw_config)

    logger.info("Initializing LDAP connection")
    con = ldap.initialize(config.bind_url, bytes_mode=False)
    con.simple_bind_s(config.bind_dn, config.bind_passwd)

    results = {}

    user_dn = f"{config.user_dn},{config.base_dn}"
    results["users"] = con.search_s(user_dn, ldap.SCOPE_SUBTREE, config.user_filter)
    #users = con.search_s(user_dn, ldap.SCOPE_SUBTREE, config.user_filter)

    group_dn = f"{config.group_dn},{config.base_dn}"
    results["groups"] = con.search_s(group_dn, ldap.SCOPE_SUBTREE, config.group_filter)
    #groups = con.search_s(group_dn, ldap.SCOPE_SUBTREE, config.group_filter)

    hbacrule_dn = f"{config.hbacrule_dn},{config.base_dn}"
    results["hbacrules"] = con.search_s(hbacrule_dn, ldap.SCOPE_SUBTREE, config.hbacrule_filter)
    #hbacrules = con.search_s(hbacrule_dn, ldap.SCOPE_SUBTREE, config.hbacrule_filter)

    sudorule_dn = f"{config.sudorule_dn},{config.base_dn}"
    results["sudorules"] = con.search_s(sudorule_dn, ldap.SCOPE_SUBTREE, config.sudorule_filter)
    #sudorules = con.search_s(sudorule_dn, ldap.SCOPE_SUBTREE, config.sudorule_filter)

    host_dn = f"{config.host_dn},{config.base_dn}"
    results["hosts"] = con.search_s(host_dn, ldap.SCOPE_SUBTREE, config.host_filter)
    #hosts = con.search_s(host_dn, ldap.SCOPE_SUBTREE, config.host_filter)

    hostgroup_dn = f"{config.hostgroup_dn},{config.base_dn}"
    results["hostgroups"] = con.search_s(hostgroup_dn, ldap.SCOPE_SUBTREE, config.hostgroup_filter)
    #hostgroups = con.search_s(hostgroup_dn, ldap.SCOPE_SUBTREE, config.hostgroup_filter)

    tree = {}
    for obj_type in results:
        #print(obj_type)
        for obj_dn, attrs in results[obj_type]:
            #print(obj, val)
            tree[obj_type][obj_dn]

# TODO: Implement generation of relationship data structure

## TODO: Implement Graphviz rendering
#    dot = Digraph(comment="LDAP relationship graph")
#    for key, val in results:
#        #out = "{" + key + "}: {" + val + "}"
#        #print(json.dumps(out, indent=4))
#        print(key)
#        print(val)
#        print()
#        dot.node(key, key)
#
#    dot.render("output/dot/ldap_graph.gv")
