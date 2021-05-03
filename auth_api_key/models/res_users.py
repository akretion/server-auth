# Copyright 2021 Akretion (http://www.akretion.com).
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl).

from odoo import fields, models


class ResUsers(models.Model):
    _inherit = "res.users"

    auth_api_key_ids = fields.One2many(
        comodel_name="auth.api.key", inverse_name="user_id", string="Auth API keys"
    )
