# Copyright 2026 Akretion (https://www.akretion.com).
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

from odoo import http
from odoo.http import request


class ImpersonateLoginPortal(http.Controller):
    @http.route(
        "/impersonate_login/back_to_origin",
        type="http",
        auth="user",
        website=True,
        methods=["POST"],
        sitemap=False,
    )
    def back_to_origin(self):
        if not request.session.impersonate_from_uid:
            return request.not_found()
        request.env["res.users"].back_to_origin_login()
        return request.redirect("/odoo")
