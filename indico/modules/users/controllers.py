# This file is part of Indico.
# Copyright (C) 2002 - 2015 European Organization for Nuclear Research (CERN).
#
# Indico is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# Indico is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Indico; if not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

from datetime import datetime

from flask import session, request
from pytz import timezone
from werkzeug.exceptions import Forbidden, NotFound

from indico.modules.users.views import WPUserDashboard, WPUserAccount
from indico.util.date_time import timedelta_split
from indico.util.redis import suggestions
from indico.util.redis import client as redis_client
from indico.util.redis import write_client as redis_write_client
from MaKaC.common.timezoneUtils import DisplayTZ
from MaKaC.user import AvatarHolder
from MaKaC.webinterface.rh.base import RHProtected


class RHUserBase(RHProtected):
    def _checkParams(self):
        if not session.user:
            return
        self.user = session.user
        if 'user_id' in request.view_args:
            self.user = AvatarHolder().getById(request.view_args['user_id'])
            if self.user is None:
                raise NotFound('This user does not exist')

    def _checkProtection(self):
        RHProtected._checkProtection(self)
        if not self._doProcess:  # not logged in
            return
        if not self.user.canUserModify(session.user):
            raise Forbidden('You cannot modify this user.')


class RHUserDashboard(RHUserBase):
    def _process(self):
        if redis_write_client:
            suggestions.schedule_check(self.user)

        tz = timezone(DisplayTZ().getDisplayTZ())
        hours, minutes = timedelta_split(tz.utcoffset(datetime.now()))[:2]
        return WPUserDashboard.render_template('dashboard.html', redis_enabled=bool(redis_client), timezone=unicode(tz),
                                               offset='{:+03d}:{:02d}'.format(hours, minutes), user=self.user,
                                               categories=self.user.getRelatedCategories(),
                                               suggested_categories=self.user.getSuggestedCategories())


class RHUserAccount(RHUserBase):
    def _process(self):
        display_tz = self.user.getDisplayTZMode() or "MyTimezone"
        show_past_events = int(self.user.getPersonalInfo().getShowPastEvents())
        return WPUserAccount.render_template('account.html', user=self.user, display_timezones=display_tz,
                                             show_past_events=show_past_events)
