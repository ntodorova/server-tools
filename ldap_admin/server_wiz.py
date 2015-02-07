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

from openerp.osv import orm, fields
from openerp.tools.translate import _


class select_server_wizard(orm.TransientModel):
    _name = 'select.server.wizard'

    _columns = {
        'server_id': fields.many2one('ldap.server', 'Server'),
        'password': fields.char('LDAP password', size=64,
                                help=("The password of the user account on the LDAP server that is "
                                      "used to query the directory."))
    }

    def action_server_selected(self, cr, uid, ids, context=None):
        assert len(ids) == 1, 'This option should only be used for a single id at a time.'
        wiz = self.browse(cr, uid, ids[0], context=context)
        server = wiz.server_id
        ctx = dict(context or {})

        passwd = server.password or wiz.password or ctx.get('ldap_admin_server_passwd')
        ctx.update({'ldap_admin_server_passwd': passwd, })
        try:
            server.test_connection(context=ctx)
        except:
            passwd = False

        if passwd:
            return self.action_manage_server(cr, uid, ids, context=ctx)
        else:
            return self.action_ask_passwd(cr, uid, ids, context=context)

    def action_ask_passwd(self, cr, uid, ids, context=None):
        assert len(ids) == 1, 'This option should only be used for a single id at a time.'

        model, res_id = self.pool.get('ir.model.data').get_object_reference(
            cr, uid, 'ldap_admin', 'action_ldap_admin_select_server_wizard1')

        action = self.pool.get(model).read(cr, uid, res_id, context=context)
        action['context'] = context # forward context
        action['res_id']  = ids[0] ## forward ID of this instance of the wizard model
        return action

    def action_manage_server(self, cr, uid, ids, context=None):
        assert len(ids) == 1, 'This option should only be used for a single id at a time.'
        wiz = self.browse(cr, uid, ids[0], context=context)

        server = wiz.server_id

        ## load data from selected LDAP server into model
        ctx = dict(context or {})
        ctx.update({'ldap_admin_reload_user_model': True, })
        server.get_user_list(context=ctx)

        ctx = dict(context or {})
        ctx.update({'ldap_admin_current_server_id': server.id,
                    'ldap_admin_sync_changes': True, })

        return {
            'type': 'ir.actions.act_window',
            'name': _('Manage LDAP users on server: ') + server.name,
            'view_type': 'form',
            'view_mode': 'tree,form',
            'res_model': "ldap.admin.user",
            #'res_id': None,
            'target': 'current',
            'context': ctx,
            }
