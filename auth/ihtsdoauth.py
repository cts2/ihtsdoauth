# -*- coding: utf-8 -*-
# Copyright (c) 2013, Mayo Clinic
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#     Redistributions of source code must retain the above copyright notice, this
#     list of conditions and the following disclaimer.
#
#     Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#
#     Neither the name of the <ORGANIZATION> nor the names of its contributors
#     may be used to endorse or promote products derived from this software
#     without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
import cherrypy
import urlparse
import uuid
import os

from config.ConfigArgs import ConfigArg, ConfigArgs
from config.ConfigManager import ConfigManager
from rf2db.parameterparser.ParmParser import booleanparam


_curdir = os.path.join(os.getcwd(), os.path.dirname(__file__))
settings_filename = os.path.join(os.path.dirname(__file__), '..', '..','settings.conf')

config_parms = ConfigArgs( 'authentication',
                           [ConfigArg('autobypass', abbrev='a', type=bool, help='True means skip the authentication screen'),
                            ConfigArg('manualbypass', abbrev='m', type=bool, help='True means bypass=1 is allowed')
                           ])

settings = ConfigManager(config_parms)
license_html = open(os.path.join(_curdir, '..','html','license.html')).read()

SESSION_KEY = '_copyright_ack'
CHALLENGE   = '_challenge'
FROM_PAGE   = '_from_page'

def check_auth(*args, **kwargs):
    """ Check whether the user is authorized to use a page that has IHTSDO content.  A user can be authorized by:
        1. Setting tools.auth.no_auth to True in the class header

        2. Carrying the passed session key in the request header

        3. Setting autobypass in the settings to "True" (debug mode)

        4. Adding a "bypass" parameter to the request header and setting manualbypass in the settings to True
    """

    # Don't try if disabled
    if booleanparam.v(settings.autobypass, default=False) or kwargs.get('no_auth'):
        return

    # Check for already authenticated
    if cherrypy.session.get(SESSION_KEY) and cherrypy.session.get(SESSION_KEY) == cherrypy.session.get(CHALLENGE):
        return

    # If the kwargs include a bypass keyword, go on as well
    rqst = cherrypy.request.request_line.split()[1]
    if booleanparam.v(settings.manualbypass, default=False) and 'bypass' in urlparse.parse_qs(urlparse.urlsplit(rqst).query, True):
        return

    # Not authorized redirect it to the authorization session
    cherrypy.session[CHALLENGE] = uuid.uuid4()
    cherrypy.session[FROM_PAGE] = rqst
    raise cherrypy.HTTPRedirect(cherrypy.request.script_name + '/license')

cherrypy.tools.auth = cherrypy.Tool('before_handler', check_auth)



class License(object):
    _cp_config = {
        'tools.auth.no_auth': True}

    @cherrypy.expose
    @cherrypy.tools.allow()
    def index(self):
        return license_html % {'token':cherrypy.session.get(CHALLENGE, 'none')}

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST'])
    def submit(self, accept=None, cancel=None, token=None, fromPage=None):
        if accept and token == str(cherrypy.session.get(CHALLENGE, 'NoN')):
            cherrypy.session[SESSION_KEY] = cherrypy.session[CHALLENGE]
            print cherrypy.session[FROM_PAGE]
            raise cherrypy.HTTPRedirect(cherrypy.session.pop(FROM_PAGE))
        else:
            raise cherrypy.HTTPRedirect("http://ihtsdo.org/license")