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
import ldap.dn
import ldap.filter
import ldap.modlist as modlist
from openerp.osv import orm, fields
from openerp.tools.translate import _
from datetime import datetime
from dateutil.parser import parse
from openerp.tools.misc import DEFAULT_SERVER_DATETIME_FORMAT
import string, base64, random, hashlib


def encryptPassword(password):
    # 16 char salt
    salt = ''.join(
        random.choice(string.letters + string.digits) for x in range(16))
    sha1 = hashlib.sha1()
    sha1.update(password)
    sha1.update(salt)
    return "{SSHA}" + base64.encodestring(sha1.digest() + salt).strip()


class ldap_user(orm.Model):
    _name = 'ldap.admin.user'

    _columns = {
        'name': fields.char('Username', required=True),
        'displayName': fields.char('Display Name'),
        'email': fields.char('Email'),
        'login': fields.boolean('Login-Shell'),
        'server_id': fields.many2one('ldap.server', 'Server'),
        'uidNumber': fields.integer('UID Number', readonly=True),
        'create_date': fields.datetime("Last sync time"),
        'descr': fields.char('Notes'),
        ## distinguish user entries synced from the server from user entries just created in odoo
        'local': fields.boolean('Unsynced',
                                help='Flag user entrys that are only local and not synced from the server.'),
        'password': fields.char('Password'),
        'password2': fields.char('Repeat Password'),
    }

    _defaults = {
        'uidNumber': False,
        'local': True,
        'password': False,
        'password2': False,
    }

    def _add_new_user(self, cr, uid, server, user, context=None):
        """create a new user"""

        c = server.connect()
        basedn = server.basedn

        try:
            # query ldap server if user with this name already exists
            filterstr="(&(objectClass=posixAccount)(|(uid={uname})(cn={uname})))".\
                format(uname=ldap.filter.escape_filter_chars(user.name))
            res = c.search_s(basedn, ldap.SCOPE_SUBTREE, filterstr=filterstr, attrlist=['uidNumber'])
            if res:
                raise orm.except_orm(_('User already exists'),
                                     _('A user with that username already exists on the server.'))

            # query local users to get the next available uidNumber
            next_uid = 0
            max_uid_user_id = self.search(cr, uid, [], limit=1, order="uidNumber desc")[0]
            if max_uid_user_id:
                next_uid = self.browse(cr, uid, max_uid_user_id, context=context).uidNumber + 1

            # query server if uidNumber is still available
            filterstr="(&(objectClass=posixAccount)(uidNumber={uid}))".\
                format(uid=ldap.filter.escape_filter_chars(str(next_uid)))
            res = c.search_s(basedn, ldap.SCOPE_SUBTREE, filterstr=filterstr, attrlist=['uidNumber'])
            if res:
                # todo handle this gracefully by finding the next available uid on the server
                raise orm.except_orm(_('Sync error'),
                                     _('A user with the requested user ID already exists on the server.'))

            # set uid
            user.write({'uidNumber': next_uid}, context=context)

            ## prepare data
            # todo automate mapping
            username = user.name.encode('utf8')
            usermail = user.email and user.email.encode('utf8') or ''
            displayName = user.displayName and user.displayName.encode('utf8') or ''
            attrs = {
                'objectclass': ['posixAccount', 'inetOrgPerson'],
                'uid': username,
                'sn': username,
                'cn': username,
                'gecos': username,
                'displayName': displayName,
                'mail': usermail,
                'homeDirectory': '/home/%s' % username,
                'loginShell': '/bin/bash' if user.login else '/bin/false',
                'uidNumber': "%d" % next_uid,
                'gidNumber': '100',
                'description': user.descr and user.descr.encode('utf8') or '',
                'userPassword': encryptPassword(user.password),
                }

            ldif = modlist.addModlist(attrs)

            ## create user
            dn="cn=%s,%s" % (ldap.dn.escape_dn_chars(username), basedn)

            c.add_s(dn, ldif)
            user.write({
                'create_date': fields.datetime.now(),
                'local': False,
                }, context=context)
        finally:
            server.close_connection(c)

    def _modify_user(self, cr, uid, server, user, context=None, remove=False):
        """ modify existing user """

        c = server.connect()
        basedn = server.basedn

        try:
            ## query modify date for this user on the server
            filterstr = "(&(objectClass=posixAccount)(uidNumber={uid}))".\
                format(uid=ldap.filter.escape_filter_chars(str(user.uidNumber)))
            msg_id = c.search(basedn, ldap.SCOPE_SUBTREE,
                              filterstr=filterstr, attrlist=['modifyTimestamp'])

            # prepare update data
            vals = {
                'loginShell': '/bin/bash' if user.login else '/bin/false',
                'mail': user.email and user.email.encode('utf8') or None,
                # thse fields are not allowed contain empty strings
                'description': user.descr and user.descr.encode('utf8') or None,
                'displayName': user.displayName and user.displayName.encode('utf8') or None,
            }

            if user.password:
                vals['userPassword'] = encryptPassword(user.password)

            ldif = [(ldap.MOD_REPLACE, key, val) for key, val in vals.iteritems()]

            # compare modify date, only change user if modify date on the server is older than create date
            # of this user (date of last sync)
            answer = c.result(msg_id, 0)[1]
            if not answer:
                raise orm.except_orm(_("Error: User dosn't exist"),_("The user to modify doesn't exist on the server."))

            dn, vals = answer[0]

            # both timestamps are in UTC
            sync_ts = datetime.strptime(user.create_date, DEFAULT_SERVER_DATETIME_FORMAT)
            ldap_ts = parse(vals['modifyTimestamp'][0]).replace(tzinfo=None)
            if sync_ts < ldap_ts:
                raise orm.except_orm(_("Error: Modified on server"),
                                     _("The user entry to modify has been changed on the server."))

            if remove:
                c.delete_s(dn)
            else:
                c.modify_s(dn, ldif)

            user.write({'create_date': fields.datetime.now()},context=context)
        finally:
            server.close_connection(c)

    def _sync_to_ldap(self, cr, uid, ids, context=None, remove=False):
        # check if request is comming from the client
        if not (context and context.get('ldap_admin_sync_changes')):
            return

        # avoid recursion through create() or write() calls issued from this function
        ctx = dict(context)
        del ctx['ldap_admin_sync_changes']

        server_model = self.pool.get('ldap.server')
        server = server_model.browse(cr, uid, ctx.get('ldap_admin_current_server_id'), ctx)

        for user in self.browse(cr, uid, ids, ctx):
            if user.local:
                self._add_new_user(cr, uid, server, user, context=ctx)
            else:
                self._modify_user(cr, uid, server, user, context=ctx, remove=remove)

    def create(self, cr, user, vals, context=None):
        # get server id from context if missing (when adding users from the client)
        if context and context.get('ldap_admin_current_server_id'):
            vals.update({'server_id': context['ldap_admin_current_server_id']})

        new_id = super(ldap_user, self).create(cr, user, vals, context=context)

        # sync changes back to LDAP
        self._sync_to_ldap(cr, user, [new_id], context)

        return new_id

    def write(self, cr, user, ids, vals, context=None):
        res = super(ldap_user, self).write(cr, user, ids, vals, context=context)

        # sync changes back to LDAP
        self._sync_to_ldap(cr, user, ids, context)

        return res

    def unlink(self, cr, uid, ids, context=None):
        self._sync_to_ldap(cr, uid, ids, context=context, remove=True)
        res = super(ldap_user, self).unlink(cr, uid, ids, context=context)
        return res

    def onchange_username(self, cr, uid, ids, name, context=None):
        res = {}

        name = str.strip(name)
        name = "".join(name.split())

        if name != ldap.dn.escape_dn_chars(name):
            res['warning'] = {'title': _('Invalid user name'),
                              'message': _('User name string contains characters special to LDAP.')}

        if self.search(cr, uid, [('name', '=', name)], count=True, context=context):
            res['warning'] = {'title': _('User already exists'),
                              'message': _('A user with that username already exists on the server.')}

        res['value'] = {'name': name}
        return res

    def onchange_displayname(self, cr, uid, ids, name, displayName, context=None):
        res = {}

        if not displayName:
            res['value'] = {'displayName': name}

        return res


    def onchange_check_pw(self, cr, uid, ids, password, password2, context=None):
        res = {}

        if password != password2:
            res['warning'] = {'title': _('Passwords not equal'),
                              'message': _("The passwords supplied don't match.")}

        return res


