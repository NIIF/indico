# -*- coding: utf-8 -*-
##

from MaKaC.authentication.baseAuthentication import Authenthicator, PIdentity, SSOHandler
from indico.core.config import Config
from MaKaC.user import AvatarHolder, Avatar
from flask import request
import MaKaC.user as user
import bcrypt

class ShibbolethAuthenticator(Authenthicator, SSOHandler):
    idxName = "localidentities"
    id = "Shibboleth"
    name = "Shibboleth"
    desciption = "Shibboleth Login"

    def __init__(self):
        Authenthicator.__init__(self)

    def createIdentitySSO(self, login, avatar):
        return ShibbolethIdentity(login, None, avatar)

class ShibbolethIdentity(PIdentity):

    def __init__(self, login, password, user):
        PIdentity.__init__(self, login, user)
        self.setPassword(password)

    def setPassword(self, newPwd):
        self.algorithm = 'bcrypt'
        if newPwd is not None:
            self.password = bcrypt.hashpw(newPwd, bcrypt.gensalt())
        else:
            # This happens e.g. when SSO is used with Local identities.
            # The user can add the password later if he wants to anyway
            self.password = None

    def authenticate(self, id):
        if self.password is None:
            return None
        if self.getLogin() == id.getLogin() and self.password == bcrypt.hashpw(id.getPassword(), self.password):
            return self.user
        return None

    def getAuthenticatorTag(self):
        return ShibbolethAuthenticator.getId()
