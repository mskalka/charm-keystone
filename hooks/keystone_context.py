# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import json

from charmhelpers.contrib.openstack import context

from charmhelpers.contrib.hahelpers.cluster import (
    DC_RESOURCE_NAME,
    determine_apache_port,
    determine_api_port,
    is_elected_leader,
    https,
)

from charmhelpers.core.hookenv import (
    config,
    log,
    leader_get,
    related_units,
    relation_ids,
    relation_get,
)


class ICOContext(context.OSContextGenerator):
    interfaces = ['keystone-ico']

    def __call__(self):
        ctxt = {}
        for rid in relation_ids('keystone-ico'):
            if related_units(rid):
                for unit in related_units(rid):
                    rdata = relation_get(rid=rid, unit=unit)
                    token = str(rdata.get('token-secret'))
                    if token:
                        ctxt['enable_ico'] = True
                        ctxt['ico_token_secret'] = token

        return ctxt

class ApacheSSLContext(context.ApacheSSLContext):
    interfaces = ['https']
    external_ports = []
    service_namespace = 'keystone'
    ssl_dir = os.path.join('/etc/apache2/ssl/', service_namespace)

    def __call__(self):
        # late import to work around circular dependency
        from keystone_utils import (
            determine_ports,
        )

        self.external_ports = determine_ports()
        return super(ApacheSSLContext, self).__call__()


class NginxSSLContext(context.ApacheSSLContext):
    interfaces = ['https']
    external_ports = []
    service_namespace = 'keystone'
    ssl_dir = ('/var/snap/{}/common/lib/juju_ssl/{}/'
               ''.format(service_namespace, service_namespace))

    def __call__(self):
        # late import to work around circular dependency
        from keystone_utils import (
            determine_ports,
        )

        self.external_ports = determine_ports()
        ret = super(NginxSSLContext, self).__call__()
        if not ret:
            log("SSL not used", level='DEBUG')
            return {}

        # Transform for use by Nginx
        """
        {'endpoints': [(u'10.5.0.30', u'10.5.0.30', 4990, 4980),
                       (u'10.5.0.30', u'10.5.0.30', 35347, 35337)],
         'ext_ports': [4990, 35347],
         'namespace': 'keystone'}
        """

        nginx_ret = {}
        nginx_ret['ssl'] = https()
        nginx_ret['namespace'] = self.service_namespace
        endpoints = {}
        for ep in ret['endpoints']:
            int_address, address, ext, internal = ep
            if ext <= 5000:
                endpoints['public'] = {
                    'socket': 'public',
                    'address': address,
                    'ext': ext}
            elif ext >= 35337:
                endpoints['admin'] = {
                    'socket': 'admin',
                    'address': address,
                    'ext': ext}
            else:
                log("Unrecognized internal port", level='ERROR')
        nginx_ret['endpoints'] = endpoints

        return nginx_ret

    def enable_modules(self):
        return


class HAProxyContext(context.HAProxyContext):
    interfaces = []

    def __call__(self):
        '''
        Extends the main charmhelpers HAProxyContext with a port mapping
        specific to this charm.
        Also used to extend nova.conf context with correct api_listening_ports
        '''
        from keystone_utils import api_port
        ctxt = super(HAProxyContext, self).__call__()

        # determine which port api processes should bind to, depending
        # on existence of haproxy + apache frontends
        listen_ports = {}
        listen_ports['admin_port'] = api_port('keystone-admin')
        listen_ports['public_port'] = api_port('keystone-public')

        # Apache ports
        a_admin_port = determine_apache_port(api_port('keystone-admin'),
                                             singlenode_mode=True)
        a_public_port = determine_apache_port(api_port('keystone-public'),
                                              singlenode_mode=True)

        port_mapping = {
            'admin-port': [
                api_port('keystone-admin'), a_admin_port],
            'public-port': [
                api_port('keystone-public'), a_public_port],
        }

        # for haproxy.conf
        ctxt['service_ports'] = port_mapping
        # for keystone.conf
        ctxt['listen_ports'] = listen_ports
        return ctxt


class KeystoneContext(context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        from keystone_utils import (
            api_port, set_admin_token, endpoint_url, resolve_address,
            PUBLIC, ADMIN, ADMIN_DOMAIN,
            snap_install_requested, get_api_version,
        )
        ctxt = {}
        ctxt['token'] = set_admin_token(config('admin-token'))
        ctxt['api_version'] = get_api_version()
        ctxt['admin_role'] = config('admin-role')
        if ctxt['api_version'] > 2:
            ctxt['service_tenant_id'] = \
                leader_get(attribute='service_tenant_id')
            ctxt['admin_domain_name'] = ADMIN_DOMAIN
            ctxt['admin_domain_id'] = \
                leader_get(attribute='admin_domain_id')
            ctxt['default_domain_id'] = \
                leader_get(attribute='default_domain_id')
        ctxt['admin_port'] = determine_api_port(api_port('keystone-admin'),
                                                singlenode_mode=True)
        ctxt['public_port'] = determine_api_port(api_port('keystone-public'),
                                                 singlenode_mode=True)

        ctxt['debug'] = config('debug')
        ctxt['verbose'] = config('verbose')
        ctxt['token_expiration'] = config('token-expiration')

        ctxt['identity_backend'] = config('identity-backend')
        ctxt['assignment_backend'] = config('assignment-backend')
        if config('identity-backend') == 'ldap':
            ctxt['ldap_server'] = config('ldap-server')
            ctxt['ldap_user'] = config('ldap-user')
            ctxt['ldap_password'] = config('ldap-password')
            ctxt['ldap_suffix'] = config('ldap-suffix')
            ctxt['ldap_readonly'] = config('ldap-readonly')
            ldap_flags = config('ldap-config-flags')
            if ldap_flags:
                flags = context.config_flags_parser(ldap_flags)
                ctxt['ldap_config_flags'] = flags

        # Base endpoint URL's which are used in keystone responses
        # to unauthenticated requests to redirect clients to the
        # correct auth URL.
        ctxt['public_endpoint'] = endpoint_url(
            resolve_address(PUBLIC),
            api_port('keystone-public')).replace('v2.0', '')
        ctxt['admin_endpoint'] = endpoint_url(
            resolve_address(ADMIN),
            api_port('keystone-admin')).replace('v2.0', '')

        if snap_install_requested():
            ctxt['domain_config_dir'] = (
                '/var/snap/keystone/common/etc/keystone/domains')
            ctxt['log_config'] = (
                '/var/snap/keystone/common/etc/keystone/logging.conf')
            ctxt['paste_config_file'] = (
                '/var/snap/keystone/common/etc/keystone/keystone-paste.ini')
        else:
            ctxt['domain_config_dir'] = '/etc/keystone/domains'
            ctxt['log_config'] = ('/etc/keystone/logging.conf')
            ctxt['paste_config_file'] = '/etc/keystone/keystone-paste.ini'

        return ctxt


class KeystoneLoggingContext(context.OSContextGenerator):

    def __call__(self):
        from keystone_utils import (
            snap_install_requested,
        )
        ctxt = {}
        debug = config('debug')
        if debug:
            ctxt['root_level'] = 'DEBUG'
        log_level = config('log-level')
        log_level_accepted_params = ['WARNING', 'INFO', 'DEBUG', 'ERROR']
        if log_level in log_level_accepted_params:
            ctxt['log_level'] = config('log-level')
        else:
            log("log-level must be one of the following states "
                "(WARNING, INFO, DEBUG, ERROR) keeping the current state.")
            ctxt['log_level'] = None
        if snap_install_requested():
            ctxt['log_file'] = (
                '/var/snap/keystone/common/log/keystone.log')
        else:
            ctxt['log_file'] = '/var/log/keystone/keystone.log'

        return ctxt


class TokenFlushContext(context.OSContextGenerator):

    def __call__(self):
        ctxt = {
            'token_flush': is_elected_leader(DC_RESOURCE_NAME)
        }
        return ctxt


class KeystoneFIDServiceProviderContext(context.OSContextGenerator):
    interfaces = ['keystone-fid-service-provider']

    def __call__(self):
        fid_sp_keys = ['protocol-name', 'remote-id-attribute']
        fid_sps = []
        for rid in relation_ids("keystone-fid-service-provider"):
            for unit in related_units(rid):
                rdata = relation_get(unit=unit, rid=rid)
                if set(rdata).issuperset(set(fid_sp_keys)):
                    fid_sps.append({
                        k: json.loads(v) for k, v in rdata.items()
                        if k in fid_sp_keys
                    })
        # populate the context with data from one or more
        # service providers
        ctxt = ({'fid_sps': fid_sps}
                if fid_sps else {})
        return ctxt


class WebSSOTrustedDashboardContext(context.OSContextGenerator):
    interfaces = ['websso-trusted-dashboard']

    def __call__(self):
        trusted_dashboard_keys = ['scheme', 'hostname', 'path']
        trusted_dashboards = set()
        for rid in relation_ids("websso-trusted-dashboard"):
            for unit in related_units(rid):
                rdata = relation_get(unit=unit, rid=rid)
                if set(rdata).issuperset(set(trusted_dashboard_keys)):
                    scheme = rdata.get('scheme')
                    hostname = rdata.get('hostname')
                    path = rdata.get('path')
                    url = '{}{}{}'.format(scheme, hostname, path)
                    trusted_dashboards.add(url)
        # populate the context with data from one or more
        # service providers
        ctxt = ({'trusted_dashboards': trusted_dashboards}
                if trusted_dashboards else {})
        return ctxt
