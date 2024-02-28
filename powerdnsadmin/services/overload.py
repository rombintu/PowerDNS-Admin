from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils, OneLogin_Saml2_ValidationError
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request

class OneLogin_Saml2_Authn_Request_Sudis(OneLogin_Saml2_Authn_Request):
    def retime(self):
        self.issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now())

class OneLogin_Saml2_Response_Sudis(OneLogin_Saml2_Response):
    def is_valid(self, request_data, request_id=None, raise_exceptions=False):
        """
        Validates the response object.

        :param request_data: Request Data
        :type request_data: dict

        :param request_id: Optional argument. The ID of the AuthNRequest sent by this SP to the IdP
        :type request_id: string

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean

        :returns: True if the SAML Response is valid, False if not
        :rtype: bool
        """
        self._error = None
        try:
            # Checks SAML version
            if self.document.get('Version', None) != '2.0':
                raise OneLogin_Saml2_ValidationError(
                    'Unsupported SAML version',
                    OneLogin_Saml2_ValidationError.UNSUPPORTED_SAML_VERSION
                )

            # Checks that ID exists
            if self.document.get('ID', None) is None:
                raise OneLogin_Saml2_ValidationError(
                    'Missing ID attribute on SAML Response',
                    OneLogin_Saml2_ValidationError.MISSING_ID
                )

            # Checks that the response has the SUCCESS status
            self.check_status()

            # Checks that the response only has one assertion
            if not self.validate_num_assertions():
                raise OneLogin_Saml2_ValidationError(
                    'SAML Response must contain 1 assertion',
                    OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_ASSERTIONS
                )

            idp_data = self._settings.get_idp_data()
            idp_entity_id = idp_data['entityId']
            sp_data = self._settings.get_sp_data()
            sp_entity_id = sp_data['entityId']

            signed_elements = self.process_signed_elements()

            has_signed_response = '{%s}Response' % OneLogin_Saml2_Constants.NS_SAMLP in signed_elements
            has_signed_assertion = '{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML in signed_elements

            if self._settings.is_strict():
                no_valid_xml_msg = 'Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd'
                res = OneLogin_Saml2_XML.validate_xml(self.document, 'saml-schema-protocol-2.0.xsd', self._settings.is_debug_active())
                if isinstance(res, str):
                    raise OneLogin_Saml2_ValidationError(
                        no_valid_xml_msg,
                        OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
                    )

                # If encrypted, check also the decrypted document
                if self.encrypted:
                    res = OneLogin_Saml2_XML.validate_xml(self.decrypted_document, 'saml-schema-protocol-2.0.xsd', self._settings.is_debug_active())
                    if isinstance(res, str):
                        raise OneLogin_Saml2_ValidationError(
                            no_valid_xml_msg,
                            OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
                        )

                security = self._settings.get_security_data()
                current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

                # Check if the InResponseTo of the Response matchs the ID of the AuthNRequest (requestId) if provided
                in_response_to = self.get_in_response_to()
                if in_response_to is not None and request_id is not None:
                    if in_response_to != request_id:
                        raise OneLogin_Saml2_ValidationError(
                            'The InResponseTo of the Response: %s, does not match the ID of the AuthNRequest sent by the SP: %s' % (in_response_to, request_id),
                            OneLogin_Saml2_ValidationError.WRONG_INRESPONSETO
                        )

                if not self.encrypted and security['wantAssertionsEncrypted']:
                    raise OneLogin_Saml2_ValidationError(
                        'The assertion of the Response is not encrypted and the SP require it',
                        OneLogin_Saml2_ValidationError.NO_ENCRYPTED_ASSERTION
                    )

                if security['wantNameIdEncrypted']:
                    encrypted_nameid_nodes = self._query_assertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData')
                    if len(encrypted_nameid_nodes) != 1:
                        raise OneLogin_Saml2_ValidationError(
                            'The NameID of the Response is not encrypted and the SP require it',
                            OneLogin_Saml2_ValidationError.NO_ENCRYPTED_NAMEID
                        )

                # Checks that a Conditions element exists
                if not self.check_one_condition():
                    raise OneLogin_Saml2_ValidationError(
                        'The Assertion must include a Conditions element',
                        OneLogin_Saml2_ValidationError.MISSING_CONDITIONS
                    )

                # Validates Assertion timestamps
                self.validate_timestamps(raise_exceptions=True)

                # Checks that an AuthnStatement element exists and is unique
                if not self.check_one_authnstatement():
                    raise OneLogin_Saml2_ValidationError(
                        'The Assertion must include an AuthnStatement element',
                        OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_AUTHSTATEMENTS
                    )

                # Checks that the response has all of the AuthnContexts that we provided in the request.
                # Only check if failOnAuthnContextMismatch is true and requestedAuthnContext is set to a list.
                requested_authn_contexts = security['requestedAuthnContext']
                if security['failOnAuthnContextMismatch'] and requested_authn_contexts and requested_authn_contexts is not True:
                    authn_contexts = self.get_authn_contexts()
                    unmatched_contexts = set(authn_contexts).difference(requested_authn_contexts)
                    if unmatched_contexts:
                        raise OneLogin_Saml2_ValidationError(
                            'The AuthnContext "%s" was not a requested context "%s"' % (', '.join(unmatched_contexts), ', '.join(requested_authn_contexts)),
                            OneLogin_Saml2_ValidationError.AUTHN_CONTEXT_MISMATCH
                        )

                # Checks that there is at least one AttributeStatement if required
                attribute_statement_nodes = self._query_assertion('/saml:AttributeStatement')
                if security.get('wantAttributeStatement', True) and not attribute_statement_nodes:
                    raise OneLogin_Saml2_ValidationError(
                        'There is no AttributeStatement on the Response',
                        OneLogin_Saml2_ValidationError.NO_ATTRIBUTESTATEMENT
                    )

                encrypted_attributes_nodes = self._query_assertion('/saml:AttributeStatement/saml:EncryptedAttribute')
                if encrypted_attributes_nodes:
                    raise OneLogin_Saml2_ValidationError(
                        'There is an EncryptedAttribute in the Response and this SP not support them',
                        OneLogin_Saml2_ValidationError.ENCRYPTED_ATTRIBUTES
                    )

                # Checks destination
                destination = self.document.get('Destination', None)
                if destination:
                    if not OneLogin_Saml2_Utils.normalize_url(url=destination).startswith(OneLogin_Saml2_Utils.normalize_url(url=current_url)):
                        # TODO: Review if following lines are required, since we can control the
                        # request_data
                        #  current_url_routed = OneLogin_Saml2_Utils.get_self_routed_url_no_query(request_data)
                        #  if not destination.startswith(current_url_routed):
                        raise OneLogin_Saml2_ValidationError(
                            'The response was received at %s instead of %s' % (current_url, destination),
                            OneLogin_Saml2_ValidationError.WRONG_DESTINATION
                        )
                elif destination == '':
                    raise OneLogin_Saml2_ValidationError(
                        'The response has an empty Destination value',
                        OneLogin_Saml2_ValidationError.EMPTY_DESTINATION
                    )
                # Checks audience
                valid_audiences = self.get_audiences()
                if valid_audiences and sp_entity_id not in valid_audiences:
                    raise OneLogin_Saml2_ValidationError(
                        '%s is not a valid audience for this Response' % sp_entity_id,
                        OneLogin_Saml2_ValidationError.WRONG_AUDIENCE
                    )

                # Checks the issuers
                issuers = self.get_issuers()
                for issuer in issuers:
                    if issuer is None or issuer != idp_entity_id:
                        raise OneLogin_Saml2_ValidationError(
                            'Invalid issuer in the Assertion/Response (expected %(idpEntityId)s, got %(issuer)s)' %
                            {
                                'idpEntityId': idp_entity_id,
                                'issuer': issuer
                            },
                            OneLogin_Saml2_ValidationError.WRONG_ISSUER
                        )

                # Checks the session Expiration
                session_expiration = self.get_session_not_on_or_after()
                if session_expiration and session_expiration <= OneLogin_Saml2_Utils.now():
                    raise OneLogin_Saml2_ValidationError(
                        'The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response',
                        OneLogin_Saml2_ValidationError.SESSION_EXPIRED
                    )

                # Checks the SubjectConfirmation, at least one SubjectConfirmation must be valid
                any_subject_confirmation = False
                subject_confirmation_nodes = self._query_assertion('/saml:Subject/saml:SubjectConfirmation')

                for scn in subject_confirmation_nodes:
                    method = scn.get('Method', None)
                    if method and method != OneLogin_Saml2_Constants.CM_BEARER:
                        continue
                    sc_data = scn.find('saml:SubjectConfirmationData', namespaces=OneLogin_Saml2_Constants.NSMAP)
                    if sc_data is None:
                        continue
                    else:
                        irt = sc_data.get('InResponseTo', None)
                        if in_response_to and irt and irt != in_response_to:
                            continue
                        recipient = sc_data.get('Recipient', None)
                        if recipient and current_url not in recipient:
                            continue
                        nooa = sc_data.get('NotOnOrAfter', None)
                        if nooa:
                            parsed_nooa = OneLogin_Saml2_Utils.parse_SAML_to_time(nooa)
                            if parsed_nooa <= OneLogin_Saml2_Utils.now():
                                continue
                        nb = sc_data.get('NotBefore', None)
                        if nb:
                            parsed_nb = OneLogin_Saml2_Utils.parse_SAML_to_time(nb)
                            if parsed_nb > OneLogin_Saml2_Utils.now():
                                continue

                        if nooa:
                            self.valid_scd_not_on_or_after = OneLogin_Saml2_Utils.parse_SAML_to_time(nooa)

                        any_subject_confirmation = True
                        break

                if not any_subject_confirmation:
                    raise OneLogin_Saml2_ValidationError(
                        'A valid SubjectConfirmation was not found on this Response',
                        OneLogin_Saml2_ValidationError.WRONG_SUBJECTCONFIRMATION
                    )

                if security['wantAssertionsSigned'] and not has_signed_assertion:
                    raise OneLogin_Saml2_ValidationError(
                        'The Assertion of the Response is not signed and the SP require it',
                        OneLogin_Saml2_ValidationError.NO_SIGNED_ASSERTION
                    )

                if security['wantMessagesSigned'] and not has_signed_response:
                    raise OneLogin_Saml2_ValidationError(
                        'The Message of the Response is not signed and the SP require it',
                        OneLogin_Saml2_ValidationError.NO_SIGNED_MESSAGE
                    )

            # if not signed_elements or (not has_signed_response and not has_signed_assertion):
            #     raise OneLogin_Saml2_ValidationError(
            #         'No Signature found. SAML Response rejected',
            #         OneLogin_Saml2_ValidationError.NO_SIGNATURE_FOUND
            #     )
            # else:
            #     cert = self._settings.get_idp_cert()
            #     fingerprint = idp_data.get('certFingerprint', None)
            #     if fingerprint:
            #         fingerprint = OneLogin_Saml2_Utils.format_finger_print(fingerprint)
            #     fingerprintalg = idp_data.get('certFingerprintAlgorithm', None)

            #     multicerts = None
            #     if 'x509certMulti' in idp_data and 'signing' in idp_data['x509certMulti'] and idp_data['x509certMulti']['signing']:
            #         multicerts = idp_data['x509certMulti']['signing']

            #     # If find a Signature on the Response, validates it checking the original response
            #     if has_signed_response and not OneLogin_Saml2_Utils.validate_sign(self.document, cert, fingerprint, fingerprintalg, xpath=OneLogin_Saml2_Utils.RESPONSE_SIGNATURE_XPATH, multicerts=multicerts, raise_exceptions=False):
            #         raise OneLogin_Saml2_ValidationError(
            #             'Signature validation failed. SAML Response rejected',
            #             OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
            #         )

            #     document_check_assertion = self.decrypted_document if self.encrypted else self.document
            #     if has_signed_assertion and not OneLogin_Saml2_Utils.validate_sign(document_check_assertion, cert, fingerprint, fingerprintalg, xpath=OneLogin_Saml2_Utils.ASSERTION_SIGNATURE_XPATH, multicerts=multicerts, raise_exceptions=False):
            #         raise OneLogin_Saml2_ValidationError(
            #             'Signature validation failed. SAML Response rejected',
            #             OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
            #         )

            return True
        except Exception as err:
            self._error = str(err)
            debug = self._settings.is_debug_active()
            if debug:
                print(err)
            if raise_exceptions:
                raise
            return False