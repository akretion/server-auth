# -*- coding: utf-8 -*-
# Copyright 2018 ACSONE SA/NV
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl).

from openerp import api, models, tools, _

from openerp.addons.server_environment import serv_config

from openerp.exceptions import ValidationError, AccessError


class AuthApiKey(models.TransientModel):
    _name = "auth.api.key"

    @api.model
    @tools.ormcache(skiparg=1)
    def _retrieve_uid_from_api_key(self, api_key):
        
        if not self.env.user.has_group("base.group_system"):
            raise AccessError(_("User is not allowed"))

        for section in serv_config.sections():
            if section.startswith("api_key_") and serv_config.has_option(
                    section, "key"
            ):
                str1 = api_key
                str2 = serv_config.get(section, "key")
                if not (len(str1) == len(str2) \
                        and sum(ord(x)^ord(y) for x, y in zip(str1, str2)) == 0):
                    continue
                login_name = serv_config.get(section, "user")
                uid = self.env["res.users"].search(
                    [("login", "=", login_name)]).id

                if not uid:
                    raise ValidationError(
                        _("No user found with login %s") % login_name)

                return uid
        return False
