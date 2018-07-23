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

from mock import patch, MagicMock
with patch('charmhelpers.contrib.openstack.'
           'utils.snap_install_requested') as snap_install_requested:
    snap_install_requested.return_value = False
    import keystone_utils  # noqa
    import keystone_context as context

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'config',
    'determine_apache_port',
    'determine_api_port',
]


class TestKeystoneContexts(CharmTestCase):

    def setUp(self):
        super(TestKeystoneContexts, self).setUp(context, TO_PATCH)

    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    @patch('charmhelpers.contrib.openstack.ip.unit_get')
    @patch('charmhelpers.contrib.openstack.ip.service_name')
    @patch('charmhelpers.contrib.openstack.ip.config')
    @patch('keystone_utils.determine_ports')
    @patch('charmhelpers.contrib.openstack.context.config')
    @patch('charmhelpers.contrib.openstack.context.is_clustered')
    @patch('charmhelpers.contrib.openstack.context.determine_apache_port')
    @patch('charmhelpers.contrib.openstack.context.determine_api_port')
    @patch('charmhelpers.contrib.openstack.context.unit_get')
    @patch('charmhelpers.contrib.openstack.context.relation_ids')
    @patch('charmhelpers.contrib.openstack.context.https')
    def test_apache_ssl_context_service_enabled(self, mock_https,
                                                mock_relation_ids,
                                                mock_unit_get,
                                                mock_determine_api_port,
                                                mock_determine_apache_port,
                                                mock_is_clustered,
                                                mock_config,
                                                mock_determine_ports,
                                                mock_ip_config,
                                                mock_service_name,
                                                mock_ip_unit_get,
                                                mock_rel_ids,
                                                ):
        mock_https.return_value = True
        mock_unit_get.return_value = '1.2.3.4'
        mock_ip_unit_get.return_value = '1.2.3.4'
        mock_determine_api_port.return_value = '12'
        mock_determine_apache_port.return_value = '34'
        mock_is_clustered.return_value = False
        mock_config.return_value = None
        mock_ip_config.return_value = None
        mock_determine_ports.return_value = ['12']

        ctxt = context.ApacheSSLContext()
        ctxt.enable_modules = MagicMock()
        ctxt.configure_cert = MagicMock()
        ctxt.configure_ca = MagicMock()
        ctxt.canonical_names = MagicMock()
        self.assertEqual(ctxt(), {'endpoints': [('1.2.3.4',
                                                 '1.2.3.4',
                                                 34, 12)],
                                  'namespace': 'keystone',
                                  'ext_ports': [34]})
        self.assertTrue(mock_https.called)
        mock_unit_get.assert_called_with('private-address')

    @patch('charmhelpers.contrib.openstack.context.get_relation_ip')
    @patch('charmhelpers.contrib.openstack.context.mkdir')
    @patch('keystone_utils.api_port')
    @patch('charmhelpers.contrib.openstack.context.get_netmask_for_address')
    @patch('charmhelpers.contrib.openstack.context.get_address_in_network')
    @patch('charmhelpers.contrib.openstack.context.config')
    @patch('charmhelpers.contrib.openstack.context.relation_ids')
    @patch('charmhelpers.contrib.openstack.context.unit_get')
    @patch('charmhelpers.contrib.openstack.context.related_units')
    @patch('charmhelpers.contrib.openstack.context.relation_get')
    @patch('charmhelpers.contrib.openstack.context.log')
    @patch('charmhelpers.contrib.openstack.context.kv')
    @patch('__builtin__.open')
    def test_haproxy_context_service_enabled(
        self, mock_open, mock_kv, mock_log, mock_relation_get,
            mock_related_units, mock_unit_get, mock_relation_ids, mock_config,
            mock_get_address_in_network, mock_get_netmask_for_address,
            mock_api_port, mock_mkdir, mock_get_relation_ip):
        os.environ['JUJU_UNIT_NAME'] = 'keystone'

        mock_relation_ids.return_value = ['identity-service:0', ]
        mock_unit_get.return_value = '1.2.3.4'
        mock_get_relation_ip.return_value = '1.2.3.4'
        mock_relation_get.return_value = '10.0.0.0'
        mock_related_units.return_value = ['unit/0', ]
        mock_config.return_value = None
        mock_get_address_in_network.return_value = None
        mock_get_netmask_for_address.return_value = '255.255.255.0'
        self.determine_apache_port.return_value = '34'
        mock_api_port.return_value = '12'
        mock_kv().get.return_value = 'abcdefghijklmnopqrstuvwxyz123456'

        ctxt = context.HAProxyContext()

        self.maxDiff = None
        self.assertEqual(
            ctxt(),
            {'listen_ports': {'admin_port': '12',
                              'public_port': '12'},
             'local_host': '127.0.0.1',
             'haproxy_host': '0.0.0.0',
             'stat_port': '8888',
             'stat_password': 'abcdefghijklmnopqrstuvwxyz123456',
             'service_ports': {'admin-port': ['12', '34'],
                               'public-port': ['12', '34']},
             'default_backend': '1.2.3.4',
             'ipv6_enabled': True,
             'frontends': {'1.2.3.4': {
                 'network': '1.2.3.4/255.255.255.0',
                 'backends': {
                     'keystone': '1.2.3.4',
                     'unit-0': '10.0.0.0'
                 }
             }}
             }
        )

    @patch.object(context, 'config')
    def test_keystone_logger_context(self, mock_config):
        ctxt = context.KeystoneLoggingContext()

        mock_config.return_value = None
        self.assertEqual({'log_level': None,
                          'log_file': '/var/log/keystone/keystone.log'},
                         ctxt())

    @patch.object(context, 'is_elected_leader')
    def test_token_flush_context(self, mock_is_elected_leader):
        ctxt = context.TokenFlushContext()

        mock_is_elected_leader.return_value = False
        self.assertEqual({'token_flush': False}, ctxt())

        mock_is_elected_leader.return_value = True
        self.assertEqual({'token_flush': True}, ctxt())

    @patch.object(context, 'relation_ids')
    @patch.object(context, 'related_units')
    @patch.object(context, 'relation_get')
    def test_keystone_fid_service_provider_rdata(
            self, mock_relation_get, mock_related_units,
            mock_relation_ids):
        os.environ['JUJU_UNIT_NAME'] = 'keystone'

        def relation_ids_side_effect(rname):
            return {
                'keystone-fid-service-provider': {
                    'keystone-fid-service-provider:0',
                    'keystone-fid-service-provider:1',
                    'keystone-fid-service-provider:2'
                }
            }[rname]

        mock_relation_ids.side_effect = relation_ids_side_effect

        def related_units_side_effect(rid):
            return {
                'keystone-fid-service-provider:0': ['sp-mellon/0'],
                'keystone-fid-service-provider:1': ['sp-shib/0'],
                'keystone-fid-service-provider:2': ['sp-oidc/0'],
            }[rid]
        mock_related_units.side_effect = related_units_side_effect

        def relation_get_side_effect(unit, rid):
            # one unit only as the relation is container-scoped
            return {
                "keystone-fid-service-provider:0": {
                    "sp-mellon/0": {
                        "ingress-address": '10.0.0.10',
                        "protocol-name": '"saml2"',
                        "remote-id-attribute": '"MELLON_IDP"',
                    },
                },
                "keystone-fid-service-provider:1": {
                    "sp-shib/0": {
                        "ingress-address": '10.0.0.10',
                        "protocol-name": '"mapped"',
                        "remote-id-attribute": '"Shib-Identity-Provider"',
                    },
                },
                "keystone-fid-service-provider:2": {
                    "sp-oidc/0": {
                        "ingress-address": '10.0.0.10',
                        "protocol-name": '"oidc"',
                        "remote-id-attribute": '"HTTP_OIDC_ISS"',
                    },
                },
            }[rid][unit]

        mock_relation_get.side_effect = relation_get_side_effect
        ctxt = context.KeystoneFIDServiceProviderContext()

        self.maxDiff = None
        self.assertItemsEqual(
            ctxt(),
            {
                "fid_sps": [
                    {
                        "protocol-name": "saml2",
                        "remote-id-attribute": "MELLON_IDP",
                    },
                    {
                        "protocol-name": "mapped",
                        "remote-id-attribute": "Shib-Identity-Provider",
                    },
                    {
                        "protocol-name": "oidc",
                        "remote-id-attribute": "HTTP_OIDC_ISS",
                    },
                ]
            }
        )

    @patch.object(context, 'relation_ids')
    def test_keystone_fid_service_provider_empty(
            self, mock_relation_ids):
        os.environ['JUJU_UNIT_NAME'] = 'keystone'

        def relation_ids_side_effect(rname):
            return {
                'keystone-fid-service-provider': {}
            }[rname]

        mock_relation_ids.side_effect = relation_ids_side_effect
        ctxt = context.KeystoneFIDServiceProviderContext()

        self.maxDiff = None
        self.assertItemsEqual(ctxt(), {})

    @patch.object(context, 'relation_ids')
    @patch.object(context, 'related_units')
    @patch.object(context, 'relation_get')
    def test_websso_trusted_dashboard_urls_generated(
            self, mock_relation_get, mock_related_units,
            mock_relation_ids):
        os.environ['JUJU_UNIT_NAME'] = 'keystone'

        def relation_ids_side_effect(rname):
            return {
                'websso-trusted-dashboard': {
                    'websso-trusted-dashboard:0',
                    'websso-trusted-dashboard:1',
                    'websso-trusted-dashboard:2'
                }
            }[rname]

        mock_relation_ids.side_effect = relation_ids_side_effect

        def related_units_side_effect(rid):
            return {
                'websso-trusted-dashboard:0': ['dashboard-blue/0',
                                               'dashboard-blue/1'],
                'websso-trusted-dashboard:1': ['dashboard-red/0',
                                               'dashboard-red/1'],
                'websso-trusted-dashboard:2': ['dashboard-green/0',
                                               'dashboard-green/1']
            }[rid]
        mock_related_units.side_effect = related_units_side_effect

        def relation_get_side_effect(unit, rid):
            return {
                "websso-trusted-dashboard:0": {
                    "dashboard-blue/0": {  # dns-ha
                        "ingress-address": '10.0.0.10',
                        "scheme": "https://",
                        "hostname": "horizon.intranet.test",
                        "path": "/auth/websso/",
                    },
                    "dashboard-blue/1": {  # dns-ha
                        "ingress-address": '10.0.0.11',
                        "scheme": "https://",
                        "hostname": "horizon.intranet.test",
                        "path": "/auth/websso/",
                    },
                },
                "websso-trusted-dashboard:1": {
                    "dashboard-red/0": {  # vip
                        "ingress-address": '10.0.0.12',
                        "scheme": "https://",
                        "hostname": "10.0.0.100",
                        "path": "/auth/websso/",
                    },
                    "dashboard-red/1": {  # vip
                        "ingress-address": '10.0.0.13',
                        "scheme": "https://",
                        "hostname": "10.0.0.100",
                        "path": "/auth/websso/",
                    },
                },
                "websso-trusted-dashboard:2": {
                    "dashboard-green/0": {  # vip-less, dns-ha-less
                        "ingress-address": '10.0.0.14',
                        "scheme": "http://",
                        "hostname": "10.0.0.14",
                        "path": "/auth/websso/",
                    },
                    "dashboard-green/1": {
                        "ingress-address": '10.0.0.15',
                        "scheme": "http://",
                        "hostname": "10.0.0.15",
                        "path": "/auth/websso/",
                    },
                },
            }[rid][unit]

        mock_relation_get.side_effect = relation_get_side_effect
        ctxt = context.WebSSOTrustedDashboardContext()

        self.maxDiff = None
        self.assertEqual(
            ctxt(),
            {
                'trusted_dashboards': set([
                    'https://horizon.intranet.test/auth/websso/',
                    'https://10.0.0.100/auth/websso/',
                    'http://10.0.0.14/auth/websso/',
                    'http://10.0.0.15/auth/websso/',
                ])
            }
        )

    @patch.object(context, 'relation_ids')
    def test_websso_trusted_dashboard_empty(
            self, mock_relation_ids):
        os.environ['JUJU_UNIT_NAME'] = 'keystone'

        def relation_ids_side_effect(rname):
            return {
                'websso-trusted-dashboard': {}
            }[rname]

        mock_relation_ids.side_effect = relation_ids_side_effect
        ctxt = context.WebSSOTrustedDashboardContext()

        self.maxDiff = None
        self.assertItemsEqual(ctxt(), {})

    @patch.object(context, 'relation_ids')
    def test_ico_no_related_units(self, mock_relation_ids):

        os.environ['JUJU_UNIT_NAME'] = 'keystone'

        def relation_ids_side_effect(rname):
            return {
                'keystone-ico': {}
            }[rname]

        mock_relation_ids.side_effect = relation_ids_side_effect

        ctxt = context.ICOContext()
        self.assertEqual(ctxt(), {})

    @patch.object(context, 'relation_ids')
    @patch.object(context, 'related_units')
    @patch.object(context, 'relation_get')
    def test_ico_related_units(
        self, mock_relation_get, mock_related_units, mock_relation_ids):

        os.environ['JUJU_UNIT_NAME'] = 'keystone'

        def relation_ids_side_effect(rname):
            return {
                'keystone-ico': {
                    'keystone-ico:0',
                }
            }[rname]

        mock_relation_ids.side_effect = relation_ids_side_effect

        def related_units_side_effect(rid):
            return {
                'keystone-ico:0': ['keystone-ico/0'],
            }[rid]

        mock_related_units.side_effect = related_units_side_effect

        def relation_get_side_effect(unit, rid):
            return {
                "keystone-ico:0": {
                    "keystone-ico/0": {
                        "token-secret": 'foo',
                    },
                },
            }[rid][unit]

        mock_relation_get.side_effect = relation_get_side_effect

        ctxt = context.ICOContext()
        self.assertEqual(
            ctxt(), {'enable_ico': True, 'ico_token_secret': 'foo'})
