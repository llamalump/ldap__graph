# ldap_graph

Walk an LDAP tree to generate a data structure that can be used to generate a graph showing the relationships between discovered LDAP objects

## Prerequisites

### Package dependencies

`ldap_graph` requires the `python-ldap` package, which is dependent on the following non-Python packages:

***Debian/Ubuntu***

```
sudo apt install libsasl2-dev python-dev libldap2-dev libssl-dev
```

***RedHat/CentOS***

```
sudo yum install python-devel openldap-devel
```

#### Graphviz Output

To output the graph in Graphviz format, you need to install Graphviz on your machine:

***Debian/Ubuntu***

```
sudo apt install graphviz
```

***RedHat/CentOS***

```
sudo yum install graphviz
```
