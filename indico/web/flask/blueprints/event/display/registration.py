# -*- coding: utf-8 -*-
##
##
## This file is part of Indico.
## Copyright (C) 2002 - 2013 European Organization for Nuclear Research (CERN).
##
## Indico is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License as
## published by the Free Software Foundation; either version 3 of the
## License, or (at your option) any later version.
##
## Indico is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with Indico. If not, see <http://www.gnu.org/licenses/>.

from MaKaC.webinterface.rh import registrantsDisplay, registrationFormDisplay
from indico.web.flask.util import rh_as_view
from indico.web.flask.blueprints.event.display import event


# Registrants
event.add_url_rule('/registration/registrants', 'confRegistrantsDisplay-list',
                   rh_as_view(registrantsDisplay.RHRegistrantsList))

# Registration
event.add_url_rule('/registration/', 'confRegistrationFormDisplay',
                   rh_as_view(registrationFormDisplay.RHRegistrationForm))
event.add_url_rule('/registration/conditions', 'confRegistrationFormDisplay-conditions',
                   rh_as_view(registrationFormDisplay.RHRegistrationFormConditions))
event.add_url_rule('/registration/confirm', 'confRegistrationFormDisplay-confirmBooking',
                   rh_as_view(registrationFormDisplay.RHRegistrationFormconfirmBooking), methods=('GET', 'POST'))
event.add_url_rule('/registration/pay', 'confRegistrationFormDisplay-confirmBookingDone',
                   rh_as_view(registrationFormDisplay.RHRegistrationFormconfirmBookingDone))
event.add_url_rule('/registration/register', 'confRegistrationFormDisplay-creation',
                   rh_as_view(registrationFormDisplay.RHRegistrationFormCreation), methods=('POST',))
event.add_url_rule('/registration/register/success', 'confRegistrationFormDisplay-creationDone',
                   rh_as_view(registrationFormDisplay.RHRegistrationFormCreationDone))
event.add_url_rule('/registration/register', 'confRegistrationFormDisplay-display',
                   rh_as_view(registrationFormDisplay.RHRegistrationFormDisplay))
event.add_url_rule('/registration/modify', 'confRegistrationFormDisplay-modify',
                   rh_as_view(registrationFormDisplay.RHRegistrationFormModify))
event.add_url_rule('/registration/modify', 'confRegistrationFormDisplay-performModify',
                   rh_as_view(registrationFormDisplay.RHRegistrationFormPerformModify), methods=('POST',))
event.add_url_rule('/registration/signin', 'confRegistrationFormDisplay-signIn',
                   rh_as_view(registrationFormDisplay.RHRegistrationFormSignIn))