# Copyright (C) 2020 Red Hat, Inc., Jan Jansky <jjansky@redhat.com>

# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

from sos.plugins import Plugin, RedHatPlugin, DebianPlugin, UbuntuPlugin,\
                        SCLPlugin
from pipes import quote
from re import match


class Foreman_proxy(Plugin):
    """Foreman Proxy/Capsule 6 systems management
    """

    plugin_name = 'foreman-proxy'
    plugin_timeout = 1800
    profiles = ('sysmgmt',)
    packages = ('foreman-proxy')
    option_list = []

    def setup(self):
        self.add_forbidden_path("/etc/foreman*/*key.pem")

        _hostname = self.exec_cmd('hostname')['output']
        _hostname = _hostname.strip()
        _host_f = self.exec_cmd('hostname -f')['output']
        _host_f = _host_f.strip()

        # Collect these completely everytime
        self.add_copy_spec("/var/log/{}*/foreman-ssl_*_ssl.log"
                           .format(self.apachepkg), sizelimit=0)

        # Allow limiting these
        self.add_copy_spec([
            "/etc/foreman-proxy/",
            "/etc/foreman-installer/",
            "/var/log/foreman-proxy/cron*log*",
            "/var/log/foreman-proxy/migrate_settings*log*",
            "/var/log/foreman-proxy/proxy*log*",
            "/var/log/foreman-proxy/smart_proxy_dynflow_core*log*",
            "/var/log/foreman-selinux-install.log",
            "/var/log/foreman-maintain/",
            "/etc/puppetlabs/puppet/ssl/certs/ca.pem",
            "/etc/puppetlabs/puppet/ssl/certs/{}.pem".format(_hostname),
            "/var/log/{}*/katello-reverse-proxy_access_ssl.log*".format(
                self.apachepkg),
            "/var/log/{}*/katello-reverse-proxy_error_ssl.log*".format(
                self.apachepkg),
            "/var/log/{}*/error_log*".format(self.apachepkg),
            "/etc/{}*/conf/".format(self.apachepkg),
            "/etc/{}*/conf.d/".format(self.apachepkg)
        ])

        # Limit foreman-installer
        self.add_copy_spec("/var/log/foreman-installer/", sizelimit=50)

        self.add_cmd_output([
            'foreman-selinux-relabel -nv',
            'foreman-maintain service status',
            'ls -lanR /root/ssl-build',
            'ping -c1 -W1 %s' % _hostname,
            'ping -c1 -W1 %s' % _host_f,
            'ping -c1 -W1 localhost'
        ])

        # collect http[|s]_proxy env.variables
        self.add_env_var(["http_proxy", "https_proxy"])

    def postproc(self):
        satreg = r"((foreman.*)?(\"::(foreman(.*?)|katello).*)?((::(.*)::.*" \
              r"(passw|cred|token|secret|key).*(\")?:)|(storepass )))(.*)"
        self.do_path_regex_sub(
            "/var/log/foreman-installer/sat*",
            satreg,
            r"\1 ********")
        # need to do two passes here, debug output has different formatting
        sat_debug_reg = (r"(\s)* (Found key: (\"(foreman(.*?)|katello)"
                         r"::(.*(token|secret|key|passw).*)\") value:) "
                         r"(.*)")
        self.do_path_regex_sub(
            "/var/log/foreman-installer/sat*",
            sat_debug_reg,
            r"\1 \2 ********")
        self.do_path_regex_sub(
            "/var/log/foreman-installer/foreman-proxy*",
            r"(\s*proxy_password\s=) (.*)",
            r"\1 ********")
        # yaml values should be alphanumeric
        self.do_path_regex_sub(
            "/etc/foreman(.*)((yaml|yml)(.*)?)",
            r"((\:|\s*)(passw|cred|token|secret|key).*(\:\s|=))(.*)",
            r'\1"********"')
        self.do_path_regex_sub(
            "/etc/foreman(.*)((conf)(.*)?)",
            r"((\:|\s*)(passw|cred|token|secret|key).*(\:\s|=))(.*)",
            r"\1********")
        self.do_path_regex_sub(
            "/var/log/foreman-maintain/foreman-maintain.log*",
            r"(((passw|cred|token|secret)=)|(password ))(.*)",
            r"\1********")

# Let the base Foreman-proxy class handle the string substitution of the
# apachepkg attr so we can keep all log definitions centralized
# in the main class


class RedHatForeman_proxy(Foreman_proxy, SCLPlugin, RedHatPlugin):

    apachepkg = 'httpd'

    def setup(self):
        super(RedHatForeman_proxy, self).setup()
        self.add_cmd_output_scl('tfm', 'gem list',
                                suggest_filename='scl enable tfm gem list')


class DebianForeman_proxy(Foreman_proxy, DebianPlugin, UbuntuPlugin):

    apachepkg = 'apache'

# vim: set et ts=4 sw=4 :
