# -*- coding: utf-8 -*-
##############################################################################
#
#    OpenERP, Open Source Management Solution
#    Copyright (C) 2014 initOS GmbH & Co. KG (<http://www.initos.com>).
#    Author Peter Hahn <peter.hahn at initos.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
##############################################################################

import ldap

from openerp.osv import orm, fields
from openerp.tools.translate import _


class ldap_server(orm.Model):
    _name = 'ldap.server'

    _columns = {
        'name': fields.char('LDAP server description', required=True),
        'host': fields.char('LDAP server address', required=True),
        'port': fields.integer('LDAP server port', required=True),
        'binddn': fields.char('LDAP binddn', size=64, required=True,
            help=("The user account on the LDAP server that is used to query "
                  "the directory. Leave empty to connect anonymously.")),
        'password': fields.char('LDAP password', size=64,
            help=("The password of the user account on the LDAP server that is "
                  "used to query the directory.")),
        'basedn': fields.char('LDAP base dn',
            help=("The distinguished name of the root node where to start all searches on this server.")),
    }

    _defaults = {
        'host': '127.0.0.1',
        'port': 389,
        'binddn': 'cn=admin,dc=odoo,dc=com',
        'basedn': 'ou=people,dc=odoo,dc=com'
    }

    @staticmethod
    def _get_ldap_connection(host, port):
        url = 'ldap://{host}:{port}'
        return ldap.initialize(url.format(host=host, port=port))

    @staticmethod
    def close_ldap_connection(connection):
        try:
            if connection:
                connection.unbind()
        except:
            pass

    @classmethod
    def close_connection(cls, cr, uid, ids, connection, context=None):
        cls.close_ldap_connection(connection)

    def try_connect(self, cr, uid, ids, context=None):
        assert len(ids) == 1, 'This function should only be used for a single id at a time.'
        server = self.browse(cr, uid, ids[0], context)
        c = self._get_ldap_connection(server.host, server.port)
        passwd = server.password or (context and context.get('ldap_admin_server_passwd', ''))
        try:
            c.simple_bind_s(server.binddn or '', passwd)
        except:
            self.close_ldap_connection(c)
            raise
        return c

    def connect(self, cr, uid, ids, context=None):
        assert len(ids) == 1, 'This function should only be used for a single id at a time.'
        server = self.browse(cr, uid, ids[0], context)
        try:
            c = server.try_connect(context=context)
            return c
        except Exception, e:
            raise orm.except_orm(_("Connection Failed!"), unicode(e))

    def get_user_list(self, cr, uid, ids, context=None):
        assert len(ids) == 1, 'This function should only be used for a single id at a time.'
        res = []

        user_model = self.pool.get('ldap.admin.user') \
            if context and context.get('ldap_admin_reload_user_model') else False

        ## clear model contents
        if user_model:
            user_model.unlink(cr, uid, user_model.search(cr, uid, []))

        server = self.browse(cr, uid, ids[0], context)
        c = server.connect(context=context)
        if c:
            try:
                msg_id = c.search(server.basedn, ldap.SCOPE_SUBTREE, "(objectClass=posixAccount)",
                    ['uid', 'mail', 'loginShell', 'uidNumber', 'description', 'displayName'])
                while True:
                    __, data = c.result(msg_id, 0)
                    if not data:
                        break
                    _dn, dict = data[0]
                    dict = {
                        'name': dict['uid'][0],
                        'displayName': dict.get('displayName', [''])[0],
                        'email': dict.get('mail', [''])[0],
                        'descr': dict.get('description', [''])[0],
                        'login': False if dict.get('loginShell')[0] == '/bin/false' else True,
                        'server_id': ids[0],
                        'uidNumber': dict['uidNumber'][0],
                        'local': False,
                    }
                    res.append(dict)
                    if user_model:
                        user_model.create(cr, uid, dict, context)

            except Exception, e:
                raise orm.except_orm(_("Retrieving user list failed!"), unicode(e))
            finally:
                self.close_ldap_connection(c)
        return res

    def test_connection(self, cr, uid, ids, context=None):
        assert len(ids) == 1, 'This function should only be used for a single id at a time.'
        c = None
        try:
            c = self.try_connect(cr, uid, ids, context=context)
        finally:
            self.close_ldap_connection(c)

    def action_test_connection(self, cr, uid, ids, context=None):
        for server in self.browse(cr, uid, ids, context=context):
            c = None
            try:
                c = server.test_connection(context=context)
            except Exception, e:
                raise orm.except_orm(_("Connection Test Failed!"), _("Here is what we got instead:\n %s") % unicode(e))
            finally:
                self.close_ldap_connection(c)
        raise orm.except_orm(_("Connection Test Succeeded!"), _("Everything seems properly set up!"))
