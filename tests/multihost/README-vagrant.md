Multihost testing with Vagrant
==============================

To test ipaserver role and ipabackup restore options, it is required that a target node without IPA installed is provided. To test ipareplica and ipaclient roles, it is required that a multihost environvent is available, and at least one target node does not have IPA installed. This environment must have proper networking configuration and some isolation for the tarkget nodes that is not provided by containers.

By using Vagrant along with Github Workflows we can have nested virtualization, allowing the creation of virtual machine nodes that will play the roles of primary server, replicas and clients. The use of Vagrant also allows the use of a similar environment to run the tests in a developer's local machine, if desired.

Github workflows only allows nested vintualization within _macOS_ runners \[[1]\]\[[2]\]. A nice side effect of using macOS runners is that there is some more available memory for the VMs \[[3]\], which might allow the use of a Windows node, or more replicas/clients in the future.

The Ansible controller is the runner, a macOS host with the latest `ansible-core` version, installed through `pip`. Connection to the hosts is done through Vagrant `ssh-config` setup.

To execute a playbook, use `ansible-playbook -i vagrant-inventory.yml --ssh-extra-args "-F vagrant-ssh" <path/to/playbook>`. The current directory is `<repo_root>/tests/multihost`.


VM Configuration
----------------

Currently, only three VMs are used, and the hostnames and memory sizes cannot be changed.

* Server:
    * hostname: server.ipa.test
    * RAM: 2500 MB
* Replica:
    * hostname: rep-01.ipa.test
    * private network ip: 192.168.56.102
    * RAM: 2500 MB
* Client:
    * hostname: cli-01.ipa.test
    * private network ip: 192.168.56.110
    * RAM: 768 MB


BASE Variables
----------------

| Name | Description | Type | Default
| `ipadm_password` | The password for the Directory Manager.| str | SomeDMpassword |
| `ipaadmin_password` | The password for the IPA admin user.| str | SomeADMINpassword |


Server Variables
----------------

| Name | Description | Type | Default
| `ipaserver_setup_kra`| Install and configure a KRA on this server. | bool | false |
| `ipaserver_setup_adtrust` | Configure AD Trust capability. | bool | false |
| `ipaserver_netbios_name` | The NetBIOS name for the IPA domain. | str | None |
| `ipaserver_setup_dns` | Configure an integrated DNS server, create DNS zone specified by domain. | bool | true |
| `ipaserver_auto_forwarders` | Add DNS forwarders configured in /etc/resolv.conf to the list of forwarders used by IPA DNS. | bool | true |
| `ipaserver_no_forwarders` | Do not add any DNS forwarders. Root DNS servers will be used instead. | bool | false |
| `ipaserver_forwarders` | Add DNS forwarders to the DNS configuration. | list of strings | \[\] |
| `ipaserver_auto_reverse` | Try to resolve reverse records and reverse zones for server IP addresses. | bool | true |
| `ipaserver_random_serial_numbers` | Enable use of random serial numbers for certificates. | bool | true |

Also the following variables are always set:
```yaml
ipaserver_allow_zone_overlap: true
ipaserver_no_dnssec_validation: true
ipaserver_no_hbac_allow: true
```


Replica Variables
----------------

| Name | Description | Type | Default
| `ipareplica_setup_kra`| Install and configure a KRA on this server. | bool | false |
| `ipareplica_setup_adtrust` | Configure AD Trust capability. | bool | false |
| `ipareplica_netbios_name` | The NetBIOS name for the IPA domain. | str | None |
| `ipareplica_setup_dns` | Configure an integrated DNS server, create DNS zone specified by domain. | bool | false |
| `ipareplica_auto_forwarders` | Add DNS forwarders configured in /etc/resolv.conf to the list of forwarders used by IPA DNS. | bool | true |
| `ipareplica_no_forwarders` | Do not add any DNS forwarders. Root DNS servers will be used instead. | bool | false |
| `ipareplica_forwarders` | Add DNS forwarders to the DNS configuration. | list of strings | \[\] |
| `ipareplica_auto_reverse` | Try to resolve reverse records and reverse zones for server IP addresses. | bool | true |
| `ipareplica_random_serial_numbers` | Enable use of random serial numbers for certificates. | bool | true |


Client Variables
----------------

Currently, no variables can be configured for the `ipaclient` role.


Caveats
-------

As of this writing, there were some issues running Vagrant on `macos-latest`, and as it is transitioning from `macos-11` to `macos-12`, it was decided that the runner used will be pinned to `macos-12`.


<!-- References  -->
[1]: https://github.com/actions/runner-images/issues/183
[2]: https://github.com/actions/runner-images/issues/433
[3]: https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners#supported-runners-and-hardware-resources
