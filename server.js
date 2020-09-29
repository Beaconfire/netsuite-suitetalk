'use strict';

const soap = require('soap');
const crypto = require('crypto');
const { ulid } = require('ulid');
var async = require('async');


/*
    To update:
    git add -A
    git commit -m ""
    git push origin master
    npm version patch
    npm publish

    On client side
    npm update
*/

class NetSuite
{
    constructor(options)
    {
        this.client = {};
        this.accountId = options.accountId;
        this.baseUrl = options.baseUrl || 'https://webservices.netsuite.com/services/NetSuitePort_2016_2';
        this.appId = options.appId;
        this.password = options.password;
        this.roleId = options.roleId;
        this.username = options.username;
        this.wsdlPath = options.wsdlPath || 'https://webservices.netsuite.com/wsdl/v2016_2_0/netsuite.wsdl';
        this.nsTarget = options.nstarget || '2016_2';
        this.nsEnvironment = 'production'; //options.nsenvironment || 'production'; // This is not totally working well so just assume prod
        this.consumerKey = options.consumerKey;
        this.consumerSecret = options.consumerSecret;
        this.token = options.token;
        this.tokenSecret = options.tokenSecret;
        //this.timestamp = Math.floor(+new Date() / 1000);
    }
}

NetSuite.prototype.initialize = function(callback)
{
    soap.createClient(this.wsdlPath, {}, (err, client) => {
        if (err)
        {
            console.log('Error: ' + err);
            return;
        }
        this.client = client;


        if(this.username && this.password){
            let soapHeader = {
                applicationInfo:{
                    applicationId: this.appId
                },
                passport:{
                    account: this.accountId,
                    email: this.username,
                    password: this.password,
                    role:{
                        attributes:{
                            internalId: this.roleId
                        }
                    }
                }
            };
            this.client.addSoapHeader(soapHeader);
        }else if(
            this.consumerKey &&
            this.consumerSecret &&
            this.token &&
            this.tokenSecret
        ){
            /*client.addSoapHeader(
                this.signNewTbaRequest(false, true)
            );*/
            this.signNewTbaRequest(false);
        }else{
            throw new Error('missing settings username/password or token settings config');
        }


        this.client.setEndpoint(this.baseUrl);
        callback();
    });
};

NetSuite.prototype.get = function(type, internalId, callback)
{
    if(!this.username && !this.password)
        this.signNewTbaRequest();

    var self = this;
    let wrappedData =
    {
        ':record':
        {
            'attributes':
            {
                'xmlns:listRel': 'urn:relationships_' + self.nsTarget + '.lists.webservices.netsuite.com',
                'xmlns:platformCore': 'urn:core_' + self.nsTarget + '.platform.webservices.netsuite.com',
                'xsi:type': 'platformCore:RecordRef',
                'type': type,
                'internalId': internalId
            }
        }
    };

    this.client.get(wrappedData, callback);
};

NetSuite.prototype.mapSso = function(email, password, account, role, authenticationToken, partnerId, callback)
{
    // The mapSso operation seems to want to require a separate login before calling mapSso.  It does not like
    // the request-level credentials method and throws an Ambiguous Authentication error.  So do not initialize
    // before calling login.
    var self = this;
    async.waterfall(
	[
        function(next)
	 	{
            login(self, function(err, client)
            {
                next(null, client);
            });
        },
        function(client, next)
        {
            let nsEnvironment = '';
            if (self.nsEnvironment !== 'production')
            {
                nsEnvironment = 'sandbox.';
            }

            let wrappedData =
            {
                ':ssoCredentials':
                {
                    'attributes':
                    {
                        'xmlns:platformCore': 'urn:core_' + self.nsTarget + '.platform.webservices.' + nsEnvironment + 'netsuite.com',
                        'xsi:type': 'platformCore:SsoCredentials'
                    },
                    'email': email,
                    'password': password,
                    'account': account,
                    'role':
                    {
                        'attributes':
                        {
                            'xsi:type': 'platformCore:RecordRef',
                            'internalId': role
                        }
                    },
                    'authenticationToken': authenticationToken,
                    'partnerId': partnerId
                }
            };

            client.mapSso(wrappedData, function(err, mapSsoResponse)
            {
                if (err)
                {
                    callback({error: err});
                }
                else
                {
                    next(null, client, mapSsoResponse);
                }
            });
        },
        function(client, mapSsoResponse, next)
        {
            client.logout(function()
            {
                callback(null, mapSsoResponse);
            });
        }
    ]);
};

NetSuite.prototype.update = function(type, internalId, fields, callback)
{
    if(!this.username && !this.password)
        this.signNewTbaRequest();

    var self = this;
    let wrappedData =
    {
        ':record':
        {
            'attributes':
            {
                'xmlns:listRel': 'urn:relationships_' + self.nsTarget + '.lists.webservices.netsuite.com',
                'xmlns:platformCore': 'urn:core_' + self.nsTarget + '.platform.webservices.netsuite.com',
                'xsi:type': 'listRel:' + type,
                'internalId': internalId
            }
        }
    };

    for (let property in fields)
    {
        if (property === 'customFieldList')
        {
            for (let customFieldProperty in fields.customFieldList)
            {
                //wrappedData[':record'].attributes['listRel:' + property] = fields[property];
            }
        }
        else
        {
            wrappedData[':record'].attributes['listRel:' + property] = fields[property];
        }
    }

    this.client.update(wrappedData, callback);
};

function login(settings, callback)
{
    soap.createClient(settings.wsdlPath, {}, (err, client) =>
    {
        if (err)
        {
            console.log('Error: ' + err);
            return;
        }

        client.addSoapHeader(
        {
            applicationInfo:
            {
                applicationId: settings.appId
            }
        });

        client.setEndpoint(settings.baseUrl);

        if(settings.username && settings.password){
            var passport =
                {
                    passport:
                        {
                            account: settings.accountId,
                            email: settings.username,
                            password: settings.password,
                            role:
                                {
                                    attributes:
                                        {
                                            internalId: settings.roleId
                                        }
                                }
                        }
                }
        }else if(
            settings.consumerKey &&
            settings.consumerSecret &&
            settings.token &&
            settings.tokenSecret
        ){
            const nonce = ulid();
            const timestamp = Math.floor(+new Date() / 1000);
            var passport =
                {
                    tokenPassport:
                        {
                            account: settings.accountId,
                            consumerKey: settings.consumerKey,
                            token: settings.token,
                            nonce: nonce,
                            timestamp: timestamp,
                            signature: signRequest(
                                settings.accountId,
                                settings.consumerKey,
                                settings.consumerSecret,
                                settings.token,
                                settings.tokenSecret,
                                nonce,
                                timestamp
                            )
                        }
                };
        }else{
            throw Error('missing settings username/password or settings token config')
        }

        client.login(passport, function(err, response)
        {
            callback(err, client);
        });
    });
};

NetSuite.prototype.signNewTbaRequest = function(bReplace, bReturn){
    if(typeof bReplace === 'undefined')
        bReplace = true;
    if(typeof bReturn === 'undefined')
        bReturn = false;
    const nonce = ulid();
    const timestamp = Math.floor(+new Date() / 1000)
    const soapHeader = {
        tokenPassport: {
            account: this.accountId,
            consumerKey: this.consumerKey,
            token: this.token,
            nonce: nonce,
            timestamp: timestamp,
            signature: {
                attributes: {
                    algorithm: 'HMAC-SHA256'
                },
                '$value': signRequest(
                    this.accountId,
                    this.consumerKey,
                    this.consumerSecret,
                    this.token,
                    this.tokenSecret,
                    nonce,
                    timestamp
                )
            }
        }
    };

    if(bReturn){
        return soapHeader;
    }else{
        if(bReplace){
            this.client.changeSoapHeader(0, soapHeader);
        }else{
            this.client.addSoapHeader(soapHeader);
        }
    }

}

function signRequest(accountId, consumerKey, secretKey, token, tokenSecret, nonce, timestamp){
    var baseString =  accountId+'&'+consumerKey+'&'+token+'&'+nonce+'&'+timestamp;
    var key = secretKey+'&'+tokenSecret;
    return crypto.createHmac('SHA256', key).update(baseString).digest('base64');
};

module.exports = NetSuite;
